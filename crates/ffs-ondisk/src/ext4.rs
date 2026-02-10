#![forbid(unsafe_code)]

use ffs_types::{
    EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE, ParseError,
    ext4_block_size_from_log, read_fixed, read_le_u16, read_le_u32, trim_nul_padded,
};
use serde::{Deserialize, Serialize};

const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
const EXT_INIT_MAX_LEN: u16 = 1_u16 << 15;

// ext4 feature flags (incompat subset; not exhaustive)
const EXT4_FEATURE_INCOMPAT_COMPRESSION: u32 = 0x0001;
const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
const EXT4_FEATURE_INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const EXT4_FEATURE_INCOMPAT_META_BG: u32 = 0x0010;
const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
const EXT4_FEATURE_INCOMPAT_MMP: u32 = 0x0100;
const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
const EXT4_FEATURE_INCOMPAT_EA_INODE: u32 = 0x0400;
const EXT4_FEATURE_INCOMPAT_DIRDATA: u32 = 0x1000;
const EXT4_FEATURE_INCOMPAT_CSUM_SEED: u32 = 0x2000;
const EXT4_FEATURE_INCOMPAT_LARGEDIR: u32 = 0x4000;
const EXT4_FEATURE_INCOMPAT_INLINE_DATA: u32 = 0x8000;
const EXT4_FEATURE_INCOMPAT_ENCRYPT: u32 = 0x10000;
const EXT4_FEATURE_INCOMPAT_CASEFOLD: u32 = 0x20000;

const EXT4_INCOMPAT_REQUIRED_MASK: u32 =
    EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS;

// Bits FrankenFS v1 can parse/understand without failing mount validation.
const EXT4_INCOMPAT_ALLOWED_MASK: u32 = EXT4_FEATURE_INCOMPAT_FILETYPE
    | EXT4_FEATURE_INCOMPAT_EXTENTS
    | EXT4_FEATURE_INCOMPAT_RECOVER
    | EXT4_FEATURE_INCOMPAT_META_BG
    | EXT4_FEATURE_INCOMPAT_64BIT
    | EXT4_FEATURE_INCOMPAT_MMP
    | EXT4_FEATURE_INCOMPAT_FLEX_BG
    | EXT4_FEATURE_INCOMPAT_EA_INODE
    | EXT4_FEATURE_INCOMPAT_DIRDATA
    | EXT4_FEATURE_INCOMPAT_CSUM_SEED
    | EXT4_FEATURE_INCOMPAT_LARGEDIR;

const EXT4_INCOMPAT_REJECT_MASK: u32 = EXT4_FEATURE_INCOMPAT_COMPRESSION
    | EXT4_FEATURE_INCOMPAT_JOURNAL_DEV
    | EXT4_FEATURE_INCOMPAT_INLINE_DATA
    | EXT4_FEATURE_INCOMPAT_ENCRYPT
    | EXT4_FEATURE_INCOMPAT_CASEFOLD;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub reserved_blocks_count: u64,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub desc_size: u16,
    pub magic: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: String,
}

impl Ext4Superblock {
    /// Parse an ext4 superblock from a 1024-byte superblock region.
    pub fn parse_superblock_region(region: &[u8]) -> Result<Self, ParseError> {
        if region.len() < EXT4_SUPERBLOCK_SIZE {
            return Err(ParseError::InsufficientData {
                needed: EXT4_SUPERBLOCK_SIZE,
                offset: 0,
                actual: region.len(),
            });
        }

        let magic = read_le_u16(region, 0x38)?;
        if magic != EXT4_SUPER_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: u64::from(EXT4_SUPER_MAGIC),
                actual: u64::from(magic),
            });
        }

        let blocks_lo = u64::from(read_le_u32(region, 0x04)?);
        let blocks_hi = u64::from(read_le_u32(region, 0x150)?);

        let r_blocks_lo = u64::from(read_le_u32(region, 0x08)?);
        let r_blocks_hi = u64::from(read_le_u32(region, 0x154)?);

        let free_blocks_lo = u64::from(read_le_u32(region, 0x0C)?);
        let free_blocks_hi = u64::from(read_le_u32(region, 0x158)?);

        let log_block_size = read_le_u32(region, 0x18)?;
        let Some(block_size) = ext4_block_size_from_log(log_block_size) else {
            return Err(ParseError::InvalidField {
                field: "s_log_block_size",
                reason: "invalid shift",
            });
        };

        Ok(Self {
            inodes_count: read_le_u32(region, 0x00)?,
            blocks_count: blocks_lo | (blocks_hi << 32),
            reserved_blocks_count: r_blocks_lo | (r_blocks_hi << 32),
            free_blocks_count: free_blocks_lo | (free_blocks_hi << 32),
            free_inodes_count: read_le_u32(region, 0x10)?,
            first_data_block: read_le_u32(region, 0x14)?,
            block_size,
            blocks_per_group: read_le_u32(region, 0x20)?,
            inodes_per_group: read_le_u32(region, 0x28)?,
            inode_size: read_le_u16(region, 0x58)?,
            desc_size: read_le_u16(region, 0xFE)?,
            magic,
            feature_compat: read_le_u32(region, 0x5C)?,
            feature_incompat: read_le_u32(region, 0x60)?,
            feature_ro_compat: read_le_u32(region, 0x64)?,
            uuid: read_fixed::<16>(region, 0x68)?,
            volume_name: trim_nul_padded(&read_fixed::<16>(region, 0x78)?),
        })
    }

    /// Parse an ext4 superblock from a full disk image.
    pub fn parse_from_image(image: &[u8]) -> Result<Self, ParseError> {
        let end = EXT4_SUPERBLOCK_OFFSET
            .checked_add(EXT4_SUPERBLOCK_SIZE)
            .ok_or(ParseError::InvalidField {
                field: "superblock_offset",
                reason: "overflow",
            })?;

        if image.len() < end {
            return Err(ParseError::InsufficientData {
                needed: EXT4_SUPERBLOCK_SIZE,
                offset: EXT4_SUPERBLOCK_OFFSET,
                actual: image.len().saturating_sub(EXT4_SUPERBLOCK_OFFSET),
            });
        }

        Self::parse_superblock_region(&image[EXT4_SUPERBLOCK_OFFSET..end])
    }

    #[must_use]
    pub fn has_incompat(&self, mask: u32) -> bool {
        (self.feature_incompat & mask) != 0
    }

    #[must_use]
    pub fn group_desc_size(&self) -> u16 {
        if self.has_incompat(EXT4_FEATURE_INCOMPAT_64BIT) {
            self.desc_size.max(64)
        } else {
            32
        }
    }

    pub fn validate_v1(&self) -> Result<(), ParseError> {
        if !matches!(self.block_size, 1024 | 2048 | 4096) {
            return Err(ParseError::InvalidField {
                field: "block_size",
                reason: "unsupported (FrankenFS v1 supports 1K/2K/4K ext4 only)",
            });
        }

        if (self.feature_incompat & EXT4_INCOMPAT_REQUIRED_MASK) != EXT4_INCOMPAT_REQUIRED_MASK {
            return Err(ParseError::InvalidField {
                field: "s_feature_incompat",
                reason: "missing required FILETYPE/EXTENTS features",
            });
        }

        if (self.feature_incompat & EXT4_INCOMPAT_REJECT_MASK) != 0 {
            return Err(ParseError::InvalidField {
                field: "s_feature_incompat",
                reason: "contains explicitly unsupported incompatible feature flags",
            });
        }

        if (self.feature_incompat & !EXT4_INCOMPAT_ALLOWED_MASK) != 0 {
            return Err(ParseError::InvalidField {
                field: "s_feature_incompat",
                reason: "unknown incompatible feature flags present",
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4GroupDesc {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub used_dirs_count: u32,
    pub itable_unused: u32,
    pub flags: u16,
    pub checksum: u16,
}

impl Ext4GroupDesc {
    pub fn parse_from_bytes(bytes: &[u8], desc_size: u16) -> Result<Self, ParseError> {
        let desc_size_usize = usize::from(desc_size);
        if desc_size_usize < 32 {
            return Err(ParseError::InvalidField {
                field: "s_desc_size",
                reason: "descriptor size must be >= 32",
            });
        }
        if bytes.len() < desc_size_usize {
            return Err(ParseError::InsufficientData {
                needed: desc_size_usize,
                offset: 0,
                actual: bytes.len(),
            });
        }

        let block_bitmap_lo = u64::from(read_le_u32(bytes, 0x00)?);
        let inode_bitmap_lo = u64::from(read_le_u32(bytes, 0x04)?);
        let inode_table_lo = u64::from(read_le_u32(bytes, 0x08)?);
        let free_blocks_lo = u32::from(read_le_u16(bytes, 0x0C)?);
        let free_inodes_lo = u32::from(read_le_u16(bytes, 0x0E)?);
        let used_dirs_lo = u32::from(read_le_u16(bytes, 0x10)?);
        let flags = read_le_u16(bytes, 0x12)?;
        let itable_unused_lo = u32::from(read_le_u16(bytes, 0x1C)?);
        let checksum = read_le_u16(bytes, 0x1E)?;

        if desc_size_usize >= 64 {
            let block_bitmap_hi = u64::from(read_le_u32(bytes, 0x20)?);
            let inode_bitmap_hi = u64::from(read_le_u32(bytes, 0x24)?);
            let inode_table_hi = u64::from(read_le_u32(bytes, 0x28)?);

            let free_blocks_hi = u32::from(read_le_u16(bytes, 0x2C)?);
            let free_inodes_hi = u32::from(read_le_u16(bytes, 0x2E)?);
            let used_dirs_hi = u32::from(read_le_u16(bytes, 0x30)?);
            let itable_unused_hi = u32::from(read_le_u16(bytes, 0x32)?);

            Ok(Self {
                block_bitmap: block_bitmap_lo | (block_bitmap_hi << 32),
                inode_bitmap: inode_bitmap_lo | (inode_bitmap_hi << 32),
                inode_table: inode_table_lo | (inode_table_hi << 32),
                free_blocks_count: free_blocks_lo | (free_blocks_hi << 16),
                free_inodes_count: free_inodes_lo | (free_inodes_hi << 16),
                used_dirs_count: used_dirs_lo | (used_dirs_hi << 16),
                itable_unused: itable_unused_lo | (itable_unused_hi << 16),
                flags,
                checksum,
            })
        } else {
            Ok(Self {
                block_bitmap: block_bitmap_lo,
                inode_bitmap: inode_bitmap_lo,
                inode_table: inode_table_lo,
                free_blocks_count: free_blocks_lo,
                free_inodes_count: free_inodes_lo,
                used_dirs_count: used_dirs_lo,
                itable_unused: itable_unused_lo,
                flags,
                checksum,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4Inode {
    pub mode: u16,
    pub uid: u16,
    pub gid: u16,
    pub size: u64,
    pub links_count: u16,
    pub blocks_lo: u32,
    pub flags: u32,
    pub extent_bytes: Vec<u8>,
}

impl Ext4Inode {
    pub fn parse_from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 160 {
            return Err(ParseError::InsufficientData {
                needed: 160,
                offset: 0,
                actual: bytes.len(),
            });
        }

        let size_lo = u64::from(read_le_u32(bytes, 0x04)?);
        let size_high = u64::from(read_le_u32(bytes, 0x6C)?);

        Ok(Self {
            mode: read_le_u16(bytes, 0x00)?,
            uid: read_le_u16(bytes, 0x02)?,
            gid: read_le_u16(bytes, 0x18)?,
            size: size_lo | (size_high << 32),
            links_count: read_le_u16(bytes, 0x1A)?,
            blocks_lo: read_le_u32(bytes, 0x1C)?,
            flags: read_le_u32(bytes, 0x20)?,
            extent_bytes: read_fixed::<60>(bytes, 0x28)?.to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4ExtentHeader {
    pub magic: u16,
    pub entries: u16,
    pub max_entries: u16,
    pub depth: u16,
    pub generation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4Extent {
    pub logical_block: u32,
    pub raw_len: u16,
    pub physical_start: u64,
}

impl Ext4Extent {
    #[must_use]
    pub fn is_unwritten(self) -> bool {
        self.raw_len > EXT_INIT_MAX_LEN
    }

    #[must_use]
    pub fn actual_len(self) -> u16 {
        if self.raw_len <= EXT_INIT_MAX_LEN {
            self.raw_len
        } else {
            self.raw_len - EXT_INIT_MAX_LEN
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4ExtentIndex {
    pub logical_block: u32,
    pub leaf_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtentTree {
    Leaf(Vec<Ext4Extent>),
    Index(Vec<Ext4ExtentIndex>),
}

pub fn parse_extent_tree(bytes: &[u8]) -> Result<(Ext4ExtentHeader, ExtentTree), ParseError> {
    if bytes.len() < 12 {
        return Err(ParseError::InsufficientData {
            needed: 12,
            offset: 0,
            actual: bytes.len(),
        });
    }

    let header = Ext4ExtentHeader {
        magic: read_le_u16(bytes, 0x00)?,
        entries: read_le_u16(bytes, 0x02)?,
        max_entries: read_le_u16(bytes, 0x04)?,
        depth: read_le_u16(bytes, 0x06)?,
        generation: read_le_u32(bytes, 0x08)?,
    };

    if header.magic != EXT4_EXTENT_MAGIC {
        return Err(ParseError::InvalidMagic {
            expected: u64::from(EXT4_EXTENT_MAGIC),
            actual: u64::from(header.magic),
        });
    }

    if header.entries > header.max_entries {
        return Err(ParseError::InvalidField {
            field: "eh_entries",
            reason: "entries exceed max",
        });
    }

    let entries_len = usize::from(header.entries);
    let needed =
        12_usize
            .checked_add(entries_len.saturating_mul(12))
            .ok_or(ParseError::InvalidField {
                field: "extent_entries",
                reason: "overflow",
            })?;

    if bytes.len() < needed {
        return Err(ParseError::InsufficientData {
            needed,
            offset: 12,
            actual: bytes.len().saturating_sub(12),
        });
    }

    if header.depth == 0 {
        let mut extents = Vec::with_capacity(entries_len);
        for idx in 0..entries_len {
            let base = 12 + idx * 12;
            let logical_block = read_le_u32(bytes, base)?;
            let raw_len = read_le_u16(bytes, base + 4)?;
            let start_hi = u64::from(read_le_u16(bytes, base + 6)?);
            let start_lo = u64::from(read_le_u32(bytes, base + 8)?);
            let physical_start = start_lo | (start_hi << 32);

            extents.push(Ext4Extent {
                logical_block,
                raw_len,
                physical_start,
            });
        }

        Ok((header, ExtentTree::Leaf(extents)))
    } else {
        let mut indexes = Vec::with_capacity(entries_len);
        for idx in 0..entries_len {
            let base = 12 + idx * 12;
            let logical_block = read_le_u32(bytes, base)?;
            let leaf_lo = u64::from(read_le_u32(bytes, base + 4)?);
            let leaf_hi = u64::from(read_le_u16(bytes, base + 8)?);
            let leaf_block = leaf_lo | (leaf_hi << 32);

            indexes.push(Ext4ExtentIndex {
                logical_block,
                leaf_block,
            });
        }

        Ok((header, ExtentTree::Index(indexes)))
    }
}

pub fn parse_inode_extent_tree(
    inode: &Ext4Inode,
) -> Result<(Ext4ExtentHeader, ExtentTree), ParseError> {
    parse_extent_tree(&inode.extent_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ext4_superblock_region_smoke() {
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];

        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x00..0x04].copy_from_slice(&100_u32.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&200_u32.to_le_bytes());
        sb[0x10..0x14].copy_from_slice(&50_u32.to_le_bytes());
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&32768_u32.to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x5C..0x60].copy_from_slice(&1_u32.to_le_bytes());
        sb[0x60..0x64].copy_from_slice(&2_u32.to_le_bytes());
        sb[0x64..0x68].copy_from_slice(&4_u32.to_le_bytes());
        sb[0x78..0x7E].copy_from_slice(b"franks");

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("superblock parse");
        assert_eq!(parsed.inodes_count, 100);
        assert_eq!(parsed.blocks_count, 200);
        assert_eq!(parsed.block_size, 4096);
        assert_eq!(parsed.volume_name, "franks");
    }

    #[test]
    fn validate_superblock_features_v1() {
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // 4K

        // required incompat bits: FILETYPE + EXTENTS
        let incompat =
            (EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        parsed.validate_v1().expect("validate");

        let mut sb2 = sb;
        // add an unknown incompat bit
        let unknown =
            (EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS | (1_u32 << 31))
                .to_le_bytes();
        sb2[0x60..0x64].copy_from_slice(&unknown);
        let parsed2 = Ext4Superblock::parse_superblock_region(&sb2).expect("parse2");
        assert!(parsed2.validate_v1().is_err());
    }

    #[test]
    fn parse_group_desc_32_and_64() {
        let mut gd32 = [0_u8; 32];
        gd32[0x00..0x04].copy_from_slice(&123_u32.to_le_bytes());
        gd32[0x04..0x08].copy_from_slice(&456_u32.to_le_bytes());
        gd32[0x08..0x0C].copy_from_slice(&789_u32.to_le_bytes());
        gd32[0x0C..0x0E].copy_from_slice(&10_u16.to_le_bytes());
        gd32[0x0E..0x10].copy_from_slice(&11_u16.to_le_bytes());
        gd32[0x10..0x12].copy_from_slice(&12_u16.to_le_bytes());
        gd32[0x12..0x14].copy_from_slice(&0xAA55_u16.to_le_bytes());
        gd32[0x1C..0x1E].copy_from_slice(&99_u16.to_le_bytes());
        gd32[0x1E..0x20].copy_from_slice(&0x1234_u16.to_le_bytes());

        let parsed32 = Ext4GroupDesc::parse_from_bytes(&gd32, 32).expect("gd32");
        assert_eq!(parsed32.block_bitmap, 123);
        assert_eq!(parsed32.inode_bitmap, 456);
        assert_eq!(parsed32.inode_table, 789);
        assert_eq!(parsed32.free_blocks_count, 10);
        assert_eq!(parsed32.itable_unused, 99);
        assert_eq!(parsed32.flags, 0xAA55);
        assert_eq!(parsed32.checksum, 0x1234);

        let mut gd64 = [0_u8; 64];
        gd64[..32].copy_from_slice(&gd32);
        gd64[0x20..0x24].copy_from_slice(&1_u32.to_le_bytes());
        gd64[0x24..0x28].copy_from_slice(&2_u32.to_le_bytes());
        gd64[0x28..0x2C].copy_from_slice(&3_u32.to_le_bytes());
        gd64[0x2C..0x2E].copy_from_slice(&4_u16.to_le_bytes());
        gd64[0x2E..0x30].copy_from_slice(&5_u16.to_le_bytes());
        gd64[0x30..0x32].copy_from_slice(&6_u16.to_le_bytes());
        gd64[0x32..0x34].copy_from_slice(&7_u16.to_le_bytes());

        let parsed64 = Ext4GroupDesc::parse_from_bytes(&gd64, 64).expect("gd64");
        assert_eq!(parsed64.block_bitmap, (1_u64 << 32) | 0x007b_u64);
        assert_eq!(parsed64.inode_bitmap, (2_u64 << 32) | 0x01c8_u64);
        assert_eq!(parsed64.inode_table, (3_u64 << 32) | 0x0315_u64);
        assert_eq!(parsed64.free_blocks_count, 0x000a_u32 | (4_u32 << 16));
        assert_eq!(parsed64.free_inodes_count, 0x000b_u32 | (5_u32 << 16));
        assert_eq!(parsed64.used_dirs_count, 0x000c_u32 | (6_u32 << 16));
        assert_eq!(parsed64.itable_unused, 0x0063_u32 | (7_u32 << 16));
    }

    #[test]
    fn parse_inode_and_extent_leaf() {
        let mut inode = [0_u8; 256];
        inode[0x00..0x02].copy_from_slice(&0o100_644_u16.to_le_bytes());
        inode[0x04..0x08].copy_from_slice(&4096_u32.to_le_bytes());
        inode[0x6C..0x70].copy_from_slice(&0_u32.to_le_bytes());

        // extent header at i_block
        let i_block = 0x28;
        inode[i_block..i_block + 2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        inode[i_block + 2..i_block + 4].copy_from_slice(&1_u16.to_le_bytes());
        inode[i_block + 4..i_block + 6].copy_from_slice(&4_u16.to_le_bytes());
        inode[i_block + 6..i_block + 8].copy_from_slice(&0_u16.to_le_bytes());
        inode[i_block + 8..i_block + 12].copy_from_slice(&7_u32.to_le_bytes());
        // first extent entry
        let e = i_block + 12;
        inode[e..e + 4].copy_from_slice(&0_u32.to_le_bytes());
        inode[e + 4..e + 6].copy_from_slice(&8_u16.to_le_bytes());
        inode[e + 6..e + 8].copy_from_slice(&0_u16.to_le_bytes());
        inode[e + 8..e + 12].copy_from_slice(&1234_u32.to_le_bytes());

        let parsed_inode = Ext4Inode::parse_from_bytes(&inode).expect("inode parse");
        let (_, tree) = parse_inode_extent_tree(&parsed_inode).expect("extent parse");
        match tree {
            ExtentTree::Leaf(exts) => {
                assert_eq!(exts.len(), 1);
                assert_eq!(exts[0].logical_block, 0);
                assert_eq!(exts[0].actual_len(), 8);
                assert_eq!(exts[0].physical_start, 1234);
            }
            ExtentTree::Index(_) => panic!("expected leaf"),
        }
    }
}
