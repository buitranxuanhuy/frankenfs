#![forbid(unsafe_code)]
//! Extended attributes (xattr).
//!
//! Inline xattr storage (after inode extra fields within the inode table
//! entry) and external xattr block storage. Namespace routing for user,
//! system, security, and trusted attribute namespaces.

use ffs_error::{FfsError, Result};
use ffs_ondisk::{Ext4Inode, Ext4Xattr, parse_ibody_xattrs, parse_xattr_block};
use ffs_types::{
    EXT4_XATTR_INDEX_POSIX_ACL_ACCESS, EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
    EXT4_XATTR_INDEX_SECURITY, EXT4_XATTR_INDEX_SYSTEM, EXT4_XATTR_INDEX_TRUSTED,
    EXT4_XATTR_INDEX_USER, EXT4_XATTR_MAGIC, ParseError,
};

const INLINE_HEADER_LEN: usize = 4;
const EXTERNAL_HEADER_LEN: usize = 32;
const XATTR_ENTRY_HEADER_LEN: usize = 16;
const XATTR_NAME_MAX: usize = u8::MAX as usize;
const XATTR_VALUE_MAX: usize = 65_536;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn parse_to_ffs(err: &ParseError) -> FfsError {
    FfsError::Format(err.to_string())
}

fn parse_external_magic(block: &[u8]) -> Result<u32> {
    let Some(bytes) = block.get(0..4) else {
        return Err(FfsError::Format(
            "external xattr block shorter than 4-byte magic".to_owned(),
        ));
    };
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn parse_inline_entries(inode: &Ext4Inode) -> Result<Vec<Ext4Xattr>> {
    parse_ibody_xattrs(inode).map_err(|err| parse_to_ffs(&err))
}

fn parse_external_entries(block: &[u8], allow_zero_initialized: bool) -> Result<Vec<Ext4Xattr>> {
    if block.len() < EXTERNAL_HEADER_LEN {
        return Err(FfsError::Format(
            "external xattr block shorter than 32-byte header".to_owned(),
        ));
    }
    let magic = parse_external_magic(block)?;
    if magic != EXT4_XATTR_MAGIC {
        if allow_zero_initialized && block.iter().all(|b| *b == 0) {
            return Ok(Vec::new());
        }
        return Err(FfsError::Format(
            "external xattr block has invalid magic".to_owned(),
        ));
    }
    parse_xattr_block(block).map_err(|err| parse_to_ffs(&err))
}

fn entry_index(entries: &[Ext4Xattr], name_index: u8, name: &[u8]) -> Option<usize> {
    entries
        .iter()
        .position(|e| e.name_index == name_index && e.name == name)
}

fn encode_entries_region(region_capacity: usize, entries: &[Ext4Xattr]) -> Result<Vec<u8>> {
    let mut data = vec![0_u8; region_capacity];
    let mut next_entry = 0_usize;
    let mut value_tail = region_capacity;

    for entry in entries {
        if entry.name.len() > XATTR_NAME_MAX {
            return Err(FfsError::NameTooLong);
        }
        if entry.value.len() > XATTR_VALUE_MAX {
            return Err(FfsError::Format(
                "xattr value exceeds 65536-byte limit".to_owned(),
            ));
        }

        let entry_len = align4(
            XATTR_ENTRY_HEADER_LEN
                .checked_add(entry.name.len())
                .ok_or_else(|| FfsError::Format("xattr entry length overflow".to_owned()))?,
        );
        let value_start = value_tail
            .checked_sub(entry.value.len())
            .ok_or(FfsError::NoSpace)?;

        let entry_end = next_entry
            .checked_add(entry_len)
            .ok_or_else(|| FfsError::Format("xattr entry offset overflow".to_owned()))?;
        let entry_end_with_term = entry_end
            .checked_add(4)
            .ok_or_else(|| FfsError::Format("xattr terminator offset overflow".to_owned()))?;
        if entry_end_with_term > value_start {
            return Err(FfsError::NoSpace);
        }

        data[value_start..value_tail].copy_from_slice(&entry.value);
        value_tail = value_start;

        data[next_entry] = u8::try_from(entry.name.len()).map_err(|_| FfsError::NameTooLong)?;
        data[next_entry + 1] = entry.name_index;
        data[next_entry + 2..next_entry + 4].copy_from_slice(
            &u16::try_from(value_start)
                .map_err(|_| FfsError::Format("xattr value offset exceeds u16".to_owned()))?
                .to_le_bytes(),
        );
        data[next_entry + 4..next_entry + 8].copy_from_slice(
            &u32::try_from(entry.value.len())
                .map_err(|_| FfsError::Format("xattr value size exceeds u32".to_owned()))?
                .to_le_bytes(),
        );
        data[next_entry + XATTR_ENTRY_HEADER_LEN
            ..next_entry + XATTR_ENTRY_HEADER_LEN + entry.name.len()]
            .copy_from_slice(&entry.name);

        next_entry = entry_end;
    }

    Ok(data)
}

fn build_inline_ibody(ibody_len: usize, entries: &[Ext4Xattr]) -> Result<Vec<u8>> {
    if ibody_len == 0 {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        return Err(FfsError::NoSpace);
    }
    if ibody_len < INLINE_HEADER_LEN {
        return Err(FfsError::Format(
            "inline xattr region shorter than 4-byte header".to_owned(),
        ));
    }

    let mut out = vec![0_u8; ibody_len];
    if entries.is_empty() {
        return Ok(out);
    }

    out[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    let encoded = encode_entries_region(ibody_len - INLINE_HEADER_LEN, entries)?;
    out[INLINE_HEADER_LEN..].copy_from_slice(&encoded);
    Ok(out)
}

fn build_external_block(block_len: usize, entries: &[Ext4Xattr]) -> Result<Vec<u8>> {
    if block_len < EXTERNAL_HEADER_LEN {
        return Err(FfsError::Format(
            "external xattr block shorter than 32-byte header".to_owned(),
        ));
    }

    let mut out = vec![0_u8; block_len];
    if entries.is_empty() {
        return Ok(out);
    }

    out[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&1_u32.to_le_bytes()); // h_refcount
    out[8..12].copy_from_slice(&1_u32.to_le_bytes()); // h_blocks

    let encoded = encode_entries_region(block_len - EXTERNAL_HEADER_LEN, entries)?;
    out[EXTERNAL_HEADER_LEN..].copy_from_slice(&encoded);
    Ok(out)
}

fn ext4_name_index_from_full_name(full_name: &str) -> Result<(u8, Vec<u8>)> {
    if let Some(name) = full_name.strip_prefix("user.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after user. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_USER, name.as_bytes().to_vec()));
    }

    if let Some(name) = full_name.strip_prefix("trusted.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after trusted. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_TRUSTED, name.as_bytes().to_vec()));
    }

    if let Some(name) = full_name.strip_prefix("security.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after security. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_SECURITY, name.as_bytes().to_vec()));
    }

    if full_name == "system.posix_acl_access" {
        return Ok((EXT4_XATTR_INDEX_POSIX_ACL_ACCESS, Vec::new()));
    }
    if full_name == "system.posix_acl_default" {
        return Ok((EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT, Vec::new()));
    }

    if let Some(name) = full_name.strip_prefix("system.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after system. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_SYSTEM, name.as_bytes().to_vec()));
    }

    Err(FfsError::Format(format!(
        "unsupported xattr namespace in '{full_name}'"
    )))
}

/// Permission context used for namespace write checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XattrWriteAccess {
    pub is_owner: bool,
    pub has_cap_fowner: bool,
    pub has_cap_sys_admin: bool,
}

fn check_write_permissions(name_index: u8, access: XattrWriteAccess) -> Result<()> {
    let user_allowed = access.is_owner || access.has_cap_fowner || access.has_cap_sys_admin;
    match name_index {
        EXT4_XATTR_INDEX_USER => {
            if user_allowed {
                Ok(())
            } else {
                Err(FfsError::PermissionDenied)
            }
        }
        EXT4_XATTR_INDEX_TRUSTED
        | EXT4_XATTR_INDEX_SECURITY
        | EXT4_XATTR_INDEX_SYSTEM
        | EXT4_XATTR_INDEX_POSIX_ACL_ACCESS
        | EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT => {
            if access.has_cap_sys_admin {
                Ok(())
            } else {
                Err(FfsError::PermissionDenied)
            }
        }
        _ => Err(FfsError::UnsupportedFeature(format!(
            "unsupported xattr name index: {name_index}"
        ))),
    }
}

/// Where a successful xattr mutation was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrStorage {
    Inline,
    External,
}

/// Parse a full xattr name (`user.foo`, `security.selinux`, ...) into ext4 components.
pub fn parse_xattr_name(full_name: &str) -> Result<(u8, Vec<u8>)> {
    let (name_index, name) = ext4_name_index_from_full_name(full_name)?;
    if name.len() > XATTR_NAME_MAX {
        return Err(FfsError::NameTooLong);
    }
    Ok((name_index, name))
}

/// Set or replace one extended attribute.
///
/// Behavior:
/// - Enforces namespace write permissions.
/// - Updates existing entries in-place in their current storage location.
/// - For new entries, tries inline storage first, then external block.
/// - If an inline update no longer fits, spills that entry to external storage.
pub fn set_xattr(
    inode: &mut Ext4Inode,
    mut external_block: Option<&mut [u8]>,
    full_name: &str,
    value: &[u8],
    access: XattrWriteAccess,
) -> Result<XattrStorage> {
    if value.len() > XATTR_VALUE_MAX {
        return Err(FfsError::Format(
            "xattr value exceeds 65536-byte limit".to_owned(),
        ));
    }

    let (name_index, name) = parse_xattr_name(full_name)?;
    check_write_permissions(name_index, access)?;

    let mut inline_entries = parse_inline_entries(inode)?;
    let mut external_entries = if let Some(block) = external_block.as_deref() {
        parse_external_entries(block, true)?
    } else {
        Vec::new()
    };

    if let Some(pos) = entry_index(&external_entries, name_index, &name) {
        external_entries[pos].value = value.to_vec();
        let Some(block) = external_block.as_mut() else {
            return Err(FfsError::Format(
                "external xattr entries exist but no external block was provided".to_owned(),
            ));
        };
        let block = &mut **block;
        let new_block = build_external_block(block.len(), &external_entries)?;
        block.copy_from_slice(&new_block);
        return Ok(XattrStorage::External);
    }

    if let Some(pos) = entry_index(&inline_entries, name_index, &name) {
        inline_entries[pos].value = value.to_vec();
        if let Ok(new_ibody) = build_inline_ibody(inode.xattr_ibody.len(), &inline_entries) {
            inode.xattr_ibody = new_ibody;
            return Ok(XattrStorage::Inline);
        }

        let mut inline_without_target = inline_entries;
        inline_without_target.remove(pos);
        let new_ibody = build_inline_ibody(inode.xattr_ibody.len(), &inline_without_target)?;

        let Some(block) = external_block.as_mut() else {
            return Err(FfsError::NoSpace);
        };
        let block = &mut **block;
        external_entries.push(Ext4Xattr {
            name_index,
            name,
            value: value.to_vec(),
        });
        let new_block = build_external_block(block.len(), &external_entries)?;

        inode.xattr_ibody = new_ibody;
        block.copy_from_slice(&new_block);
        return Ok(XattrStorage::External);
    }

    let mut inline_candidate = inline_entries;
    inline_candidate.push(Ext4Xattr {
        name_index,
        name: name.clone(),
        value: value.to_vec(),
    });
    if let Ok(new_ibody) = build_inline_ibody(inode.xattr_ibody.len(), &inline_candidate) {
        inode.xattr_ibody = new_ibody;
        return Ok(XattrStorage::Inline);
    }

    let Some(block) = external_block.as_mut() else {
        return Err(FfsError::NoSpace);
    };
    let block = &mut **block;
    external_entries.push(Ext4Xattr {
        name_index,
        name,
        value: value.to_vec(),
    });
    let new_block = build_external_block(block.len(), &external_entries)?;
    block.copy_from_slice(&new_block);
    Ok(XattrStorage::External)
}

/// Remove one extended attribute by full name.
///
/// Returns `true` when an entry was removed.
pub fn remove_xattr(
    inode: &mut Ext4Inode,
    mut external_block: Option<&mut [u8]>,
    full_name: &str,
    access: XattrWriteAccess,
) -> Result<bool> {
    let (name_index, name) = parse_xattr_name(full_name)?;
    check_write_permissions(name_index, access)?;

    let mut inline_entries = parse_inline_entries(inode)?;
    if let Some(pos) = entry_index(&inline_entries, name_index, &name) {
        inline_entries.remove(pos);
        inode.xattr_ibody = build_inline_ibody(inode.xattr_ibody.len(), &inline_entries)?;
        return Ok(true);
    }

    let Some(block) = external_block.as_mut() else {
        if inode.file_acl != 0 {
            return Err(FfsError::Format(
                "inode references external xattr block but none was provided".to_owned(),
            ));
        }
        return Ok(false);
    };
    let block = &mut **block;

    let mut external_entries = parse_external_entries(block, true)?;
    let Some(pos) = entry_index(&external_entries, name_index, &name) else {
        return Ok(false);
    };
    external_entries.remove(pos);

    let new_block = build_external_block(block.len(), &external_entries)?;
    block.copy_from_slice(&new_block);
    if external_entries.is_empty() {
        inode.file_acl = 0;
    }
    Ok(true)
}

/// List all xattr names (`user.foo`, `security.selinux`, ...).
pub fn list_xattrs(inode: &Ext4Inode, external_block: Option<&[u8]>) -> Result<Vec<String>> {
    let mut names = Vec::new();

    let inline_entries = parse_inline_entries(inode)?;
    names.extend(inline_entries.into_iter().map(|e| e.full_name()));

    if inode.file_acl != 0 && external_block.is_none() {
        return Err(FfsError::Format(
            "inode references external xattr block but none was provided".to_owned(),
        ));
    }

    if let Some(block) = external_block {
        let ext_entries = parse_external_entries(block, true)?;
        names.extend(ext_entries.into_iter().map(|e| e.full_name()));
    }

    Ok(names)
}

/// Get one xattr value by full name.
pub fn get_xattr(
    inode: &Ext4Inode,
    external_block: Option<&[u8]>,
    full_name: &str,
) -> Result<Option<Vec<u8>>> {
    let (name_index, name) = parse_xattr_name(full_name)?;

    let inline_entries = parse_inline_entries(inode)?;
    if let Some(entry) = inline_entries
        .iter()
        .find(|e| e.name_index == name_index && e.name == name)
    {
        return Ok(Some(entry.value.clone()));
    }

    if inode.file_acl != 0 && external_block.is_none() {
        return Err(FfsError::Format(
            "inode references external xattr block but none was provided".to_owned(),
        ));
    }

    if let Some(block) = external_block {
        let external_entries = parse_external_entries(block, true)?;
        if let Some(entry) = external_entries
            .iter()
            .find(|e| e.name_index == name_index && e.name == name)
        {
            return Ok(Some(entry.value.clone()));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inode(ibody_len: usize) -> Ext4Inode {
        Ext4Inode {
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 0,
            blocks: 0,
            flags: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,
            projid: 0,
            extent_bytes: vec![0; 60],
            xattr_ibody: vec![0; ibody_len],
        }
    }

    #[test]
    fn parse_xattr_name_maps_namespaces() {
        let (idx_user, name_user) = parse_xattr_name("user.mime").unwrap();
        assert_eq!(idx_user, EXT4_XATTR_INDEX_USER);
        assert_eq!(name_user, b"mime".to_vec());

        let (idx_trusted, name_trusted) = parse_xattr_name("trusted.hash").unwrap();
        assert_eq!(idx_trusted, EXT4_XATTR_INDEX_TRUSTED);
        assert_eq!(name_trusted, b"hash".to_vec());

        let (idx_security, name_security) = parse_xattr_name("security.selinux").unwrap();
        assert_eq!(idx_security, EXT4_XATTR_INDEX_SECURITY);
        assert_eq!(name_security, b"selinux".to_vec());

        let (idx_acl, name_acl) = parse_xattr_name("system.posix_acl_access").unwrap();
        assert_eq!(idx_acl, EXT4_XATTR_INDEX_POSIX_ACL_ACCESS);
        assert!(name_acl.is_empty());
    }

    #[test]
    fn user_namespace_requires_owner_or_capability() {
        let mut inode = make_inode(96);
        let err = set_xattr(
            &mut inode,
            None,
            "user.test",
            b"v",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn set_get_list_remove_inline_xattr() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        let stored = set_xattr(&mut inode, None, "user.mime", b"image", access).unwrap();
        assert_eq!(stored, XattrStorage::Inline);

        let value = get_xattr(&inode, None, "user.mime").unwrap();
        assert_eq!(value, Some(b"image".to_vec()));

        let names = list_xattrs(&inode, None).unwrap();
        assert_eq!(names, vec!["user.mime".to_owned()]);

        let removed = remove_xattr(&mut inode, None, "user.mime", access).unwrap();
        assert!(removed);
        assert_eq!(get_xattr(&inode, None, "user.mime").unwrap(), None);
    }

    #[test]
    fn set_xattr_falls_back_to_external_when_inline_full() {
        let mut inode = make_inode(20);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.payload",
            b"value",
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);
        assert_eq!(
            u32::from_le_bytes([external[0], external[1], external[2], external[3]]),
            EXT4_XATTR_MAGIC
        );
        assert_eq!(
            get_xattr(&inode, Some(&external), "user.payload").unwrap(),
            Some(b"value".to_vec())
        );
    }

    #[test]
    fn remove_xattr_from_external_clears_block_and_pointer() {
        let mut inode = make_inode(20);
        inode.file_acl = 123;
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(
            &mut inode,
            Some(&mut external),
            "user.payload",
            b"value",
            access,
        )
        .unwrap();
        assert!(remove_xattr(&mut inode, Some(&mut external), "user.payload", access).unwrap());
        assert_eq!(inode.file_acl, 0);
        assert!(external.iter().all(|b| *b == 0));
    }

    #[test]
    fn trusted_namespace_requires_sys_admin() {
        let mut inode = make_inode(128);
        let err = set_xattr(
            &mut inode,
            None,
            "trusted.fsmeta",
            b"v",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn system_acl_write_allowed_for_sys_admin() {
        let mut inode = make_inode(128);
        let stored = set_xattr(
            &mut inode,
            None,
            "system.posix_acl_access",
            b"acl",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: false,
                has_cap_sys_admin: true,
            },
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::Inline);
    }

    #[test]
    fn value_size_limit_enforced() {
        let mut inode = make_inode(128);
        let too_large = vec![0_u8; XATTR_VALUE_MAX + 1];
        let err = set_xattr(
            &mut inode,
            None,
            "user.too_large",
            &too_large,
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    // ── Additional edge-case tests ───────────────────────────────────

    #[test]
    fn parse_xattr_name_rejects_unknown_namespace() {
        let err = parse_xattr_name("unknown.key").unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn parse_xattr_name_rejects_empty_after_prefix() {
        assert!(parse_xattr_name("user.").is_err());
        assert!(parse_xattr_name("trusted.").is_err());
        assert!(parse_xattr_name("security.").is_err());
        assert!(parse_xattr_name("system.").is_err());
    }

    #[test]
    fn get_xattr_returns_none_for_missing() {
        let inode = make_inode(128);
        let result = get_xattr(&inode, None, "user.nonexistent").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn remove_nonexistent_xattr_returns_false() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };
        let removed = remove_xattr(&mut inode, None, "user.nope", access).unwrap();
        assert!(!removed);
    }

    #[test]
    fn list_xattrs_empty_returns_empty() {
        let inode = make_inode(128);
        let names = list_xattrs(&inode, None).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn set_multiple_inline_xattrs() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(&mut inode, None, "user.a", b"v1", access).unwrap();
        set_xattr(&mut inode, None, "user.b", b"v2", access).unwrap();

        assert_eq!(
            get_xattr(&inode, None, "user.a").unwrap(),
            Some(b"v1".to_vec())
        );
        assert_eq!(
            get_xattr(&inode, None, "user.b").unwrap(),
            Some(b"v2".to_vec())
        );

        let mut names = list_xattrs(&inode, None).unwrap();
        names.sort();
        assert_eq!(names, vec!["user.a", "user.b"]);
    }

    #[test]
    fn set_xattr_updates_existing_value() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(&mut inode, None, "user.key", b"old", access).unwrap();
        set_xattr(&mut inode, None, "user.key", b"new", access).unwrap();

        assert_eq!(
            get_xattr(&inode, None, "user.key").unwrap(),
            Some(b"new".to_vec())
        );

        // Should still be just one entry.
        let names = list_xattrs(&inode, None).unwrap();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn cap_fowner_allows_user_xattr_write() {
        let mut inode = make_inode(128);
        let stored = set_xattr(
            &mut inode,
            None,
            "user.test",
            b"v",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: true,
                has_cap_sys_admin: false,
            },
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::Inline);
    }

    #[test]
    fn security_namespace_requires_sys_admin() {
        let mut inode = make_inode(128);
        let err = set_xattr(
            &mut inode,
            None,
            "security.selinux",
            b"context",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: true,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn no_inline_space_no_external_returns_error() {
        let mut inode = make_inode(0); // zero ibody space
        let err = set_xattr(
            &mut inode,
            None,
            "user.key",
            b"value",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn xattr_write_access_default_denies_all() {
        let access = XattrWriteAccess::default();
        assert!(!access.is_owner);
        assert!(!access.has_cap_fowner);
        assert!(!access.has_cap_sys_admin);
    }
}
