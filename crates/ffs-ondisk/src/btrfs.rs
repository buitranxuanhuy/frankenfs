#![forbid(unsafe_code)]

use ffs_types as crc32c;
use ffs_types::{
    BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, ParseError, read_fixed,
    read_le_u16, read_le_u32, read_le_u64, trim_nul_padded,
};
use serde::{Deserialize, Serialize};

const BTRFS_HEADER_SIZE: usize = 101;
const BTRFS_ITEM_SIZE: usize = 25;
/// Size of a btrfs_key_ptr on disk (key:17 + blockptr:u64 + generation:u64).
const BTRFS_KEY_PTR_SIZE: usize = 33;
/// Maximum tree depth in btrfs (kernel enforces 8 levels, 0-7).
const BTRFS_MAX_LEVEL: u8 = 7;
const BTRFS_SUPER_LABEL_OFFSET: usize = 0x12B;
const BTRFS_SUPER_LABEL_LEN: usize = 256;
const BTRFS_SYS_CHUNK_ARRAY_OFFSET: usize = 0x32B;
const BTRFS_SYS_CHUNK_ARRAY_MAX: usize = 2048;
/// Size of a btrfs_disk_key on disk (objectid:u64 + type:u8 + offset:u64).
const BTRFS_DISK_KEY_SIZE: usize = 17;
/// Minimum chunk size: header fields before the stripe array (48 bytes).
const BTRFS_CHUNK_FIXED_SIZE: usize = 48;
/// Size of one btrfs_stripe on disk (devid:u64 + offset:u64 + dev_uuid:16).
const BTRFS_STRIPE_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsSuperblock {
    pub csum: [u8; 32],
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub flags: u64,
    pub magic: u64,
    pub generation: u64,
    pub root: u64,
    pub chunk_root: u64,
    pub log_root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub stripesize: u32,
    pub compat_flags: u64,
    pub compat_ro_flags: u64,
    pub incompat_flags: u64,
    pub csum_type: u16,
    pub root_level: u8,
    pub chunk_root_level: u8,
    pub log_root_level: u8,
    pub label: String,
    pub sys_chunk_array_size: u32,
    pub sys_chunk_array: Vec<u8>,
}

impl BtrfsSuperblock {
    #[allow(clippy::too_many_lines)]
    pub fn parse_superblock_region(region: &[u8]) -> Result<Self, ParseError> {
        if region.len() < BTRFS_SUPER_INFO_SIZE {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_SUPER_INFO_SIZE,
                offset: 0,
                actual: region.len(),
            });
        }

        let magic = read_le_u64(region, 0x40)?;
        if magic != BTRFS_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: BTRFS_MAGIC,
                actual: magic,
            });
        }

        let sectorsize = read_le_u32(region, 0x90)?;
        let nodesize = read_le_u32(region, 0x94)?;
        let stripesize = read_le_u32(region, 0x9C)?;

        // Validate sectorsize: must be non-zero and power-of-two, 4K typical
        if sectorsize == 0 || !sectorsize.is_power_of_two() {
            return Err(ParseError::InvalidField {
                field: "sectorsize",
                reason: "must be non-zero power of two",
            });
        }
        // Validate nodesize: must be non-zero and power-of-two, typically 4K-64K
        if nodesize == 0 || !nodesize.is_power_of_two() {
            return Err(ParseError::InvalidField {
                field: "nodesize",
                reason: "must be non-zero power of two",
            });
        }
        // Validate stripesize: must be non-zero and power-of-two when set
        if stripesize != 0 && !stripesize.is_power_of_two() {
            return Err(ParseError::InvalidField {
                field: "stripesize",
                reason: "must be zero or power of two",
            });
        }
        // Sane upper bounds (256K for sector/stripe, 256K for node)
        if sectorsize > 256 * 1024 {
            return Err(ParseError::InvalidField {
                field: "sectorsize",
                reason: "exceeds 256K upper bound",
            });
        }
        if nodesize > 256 * 1024 {
            return Err(ParseError::InvalidField {
                field: "nodesize",
                reason: "exceeds 256K upper bound",
            });
        }

        // Parse sys_chunk_array_size and validate
        let sys_chunk_array_size = read_le_u32(region, 0xA0)?;
        let sys_array_len =
            usize::try_from(sys_chunk_array_size).map_err(|_| ParseError::IntegerConversion {
                field: "sys_chunk_array_size",
            })?;
        if sys_array_len > BTRFS_SYS_CHUNK_ARRAY_MAX {
            return Err(ParseError::InvalidField {
                field: "sys_chunk_array_size",
                reason: "exceeds 2048 byte limit",
            });
        }

        // Extract sys_chunk_array bytes
        let array_end = BTRFS_SYS_CHUNK_ARRAY_OFFSET
            .checked_add(sys_array_len)
            .ok_or(ParseError::InvalidField {
                field: "sys_chunk_array",
                reason: "offset overflow",
            })?;
        if array_end > region.len() {
            return Err(ParseError::InsufficientData {
                needed: array_end,
                offset: BTRFS_SYS_CHUNK_ARRAY_OFFSET,
                actual: region.len(),
            });
        }
        let sys_chunk_array = region[BTRFS_SYS_CHUNK_ARRAY_OFFSET..array_end].to_vec();

        Ok(Self {
            csum: read_fixed::<32>(region, 0x00)?,
            fsid: read_fixed::<16>(region, 0x20)?,
            bytenr: read_le_u64(region, 0x30)?,
            flags: read_le_u64(region, 0x38)?,
            magic,
            generation: read_le_u64(region, 0x48)?,
            root: read_le_u64(region, 0x50)?,
            chunk_root: read_le_u64(region, 0x58)?,
            log_root: read_le_u64(region, 0x60)?,
            total_bytes: read_le_u64(region, 0x70)?,
            bytes_used: read_le_u64(region, 0x78)?,
            root_dir_objectid: read_le_u64(region, 0x80)?,
            num_devices: read_le_u64(region, 0x88)?,
            sectorsize,
            nodesize,
            stripesize,
            compat_flags: read_le_u64(region, 0xAC)?,
            compat_ro_flags: read_le_u64(region, 0xB4)?,
            incompat_flags: read_le_u64(region, 0xBC)?,
            csum_type: read_le_u16(region, 0xC4)?,
            root_level: region[0xC6],
            chunk_root_level: region[0xC7],
            log_root_level: region[0xC8],
            label: trim_nul_padded(&read_fixed::<BTRFS_SUPER_LABEL_LEN>(
                region,
                BTRFS_SUPER_LABEL_OFFSET,
            )?),
            sys_chunk_array_size,
            sys_chunk_array,
        })
    }

    pub fn parse_from_image(image: &[u8]) -> Result<Self, ParseError> {
        let end = BTRFS_SUPER_INFO_OFFSET
            .checked_add(BTRFS_SUPER_INFO_SIZE)
            .ok_or(ParseError::InvalidField {
                field: "superblock_offset",
                reason: "overflow",
            })?;

        if image.len() < end {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_SUPER_INFO_SIZE,
                offset: BTRFS_SUPER_INFO_OFFSET,
                actual: image.len().saturating_sub(BTRFS_SUPER_INFO_OFFSET),
            });
        }

        Self::parse_superblock_region(&image[BTRFS_SUPER_INFO_OFFSET..end])
    }
}

// ── sys_chunk_array entry types ──────────────────────────────────────────────

/// A single stripe within a btrfs chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsStripe {
    pub devid: u64,
    pub offset: u64,
    pub dev_uuid: [u8; 16],
}

/// A parsed entry from the superblock's sys_chunk_array.
///
/// Each entry consists of a `btrfs_disk_key` followed by a `btrfs_chunk`
/// (which embeds one or more `btrfs_stripe` entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsChunkEntry {
    pub key: BtrfsKey,
    pub length: u64,
    pub owner: u64,
    pub stripe_len: u64,
    pub chunk_type: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub num_stripes: u16,
    pub sub_stripes: u16,
    pub stripes: Vec<BtrfsStripe>,
}

/// Parse all entries from a sys_chunk_array byte slice.
///
/// The array contains alternating `btrfs_disk_key` + `btrfs_chunk` entries.
/// Each chunk embeds `num_stripes` stripe descriptors.
pub fn parse_sys_chunk_array(data: &[u8]) -> Result<Vec<BtrfsChunkEntry>, ParseError> {
    let mut entries = Vec::new();
    let mut cur = 0_usize;

    while cur < data.len() {
        // Need at least a disk key (17 bytes)
        if cur + BTRFS_DISK_KEY_SIZE > data.len() {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_DISK_KEY_SIZE,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let key = BtrfsKey {
            objectid: read_le_u64(data, cur)?,
            item_type: data[cur + 8],
            offset: read_le_u64(data, cur + 9)?,
        };
        cur += BTRFS_DISK_KEY_SIZE;

        // Need at least the fixed chunk header (48 bytes) to read num_stripes
        if cur + BTRFS_CHUNK_FIXED_SIZE > data.len() {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_CHUNK_FIXED_SIZE,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let length = read_le_u64(data, cur)?;
        let owner = read_le_u64(data, cur + 8)?;
        let stripe_len = read_le_u64(data, cur + 16)?;
        let chunk_type = read_le_u64(data, cur + 24)?;
        let io_align = read_le_u32(data, cur + 32)?;
        let io_width = read_le_u32(data, cur + 36)?;
        let sector_size = read_le_u32(data, cur + 40)?;
        let num_stripes = read_le_u16(data, cur + 44)?;
        let sub_stripes = read_le_u16(data, cur + 46)?;
        cur += BTRFS_CHUNK_FIXED_SIZE;

        if num_stripes == 0 {
            return Err(ParseError::InvalidField {
                field: "num_stripes",
                reason: "chunk must have at least one stripe",
            });
        }

        let stripes_count = usize::from(num_stripes);
        let stripes_bytes =
            stripes_count
                .checked_mul(BTRFS_STRIPE_SIZE)
                .ok_or(ParseError::InvalidField {
                    field: "num_stripes",
                    reason: "stripe count overflow",
                })?;

        if cur + stripes_bytes > data.len() {
            return Err(ParseError::InsufficientData {
                needed: stripes_bytes,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let mut stripes = Vec::with_capacity(stripes_count);
        for _ in 0..stripes_count {
            stripes.push(BtrfsStripe {
                devid: read_le_u64(data, cur)?,
                offset: read_le_u64(data, cur + 8)?,
                dev_uuid: read_fixed::<16>(data, cur + 16)?,
            });
            cur += BTRFS_STRIPE_SIZE;
        }

        entries.push(BtrfsChunkEntry {
            key,
            length,
            owner,
            stripe_len,
            chunk_type,
            io_align,
            io_width,
            sector_size,
            num_stripes,
            sub_stripes,
            stripes,
        });
    }

    Ok(entries)
}

// ── Logical → physical mapping ──────────────────────────────────────────────

/// Result of a logical-to-physical bytenr mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsPhysicalMapping {
    pub devid: u64,
    pub physical: u64,
}

/// Map a logical byte address to a physical (device, offset) pair using
/// only the sys_chunk_array entries.
///
/// This is the bootstrap mapping needed to read the chunk tree and root
/// tree from a single-device btrfs image. For multi-device or RAID
/// layouts, the full chunk tree is required.
///
/// Returns `Ok(Some(mapping))` if the logical address is covered,
/// `Ok(None)` if no chunk covers it, or `Err` on malformed data.
pub fn map_logical_to_physical(
    chunks: &[BtrfsChunkEntry],
    logical: u64,
) -> Result<Option<BtrfsPhysicalMapping>, ParseError> {
    for chunk in chunks {
        let chunk_start = chunk.key.offset;
        let chunk_end = chunk_start
            .checked_add(chunk.length)
            .ok_or(ParseError::InvalidField {
                field: "chunk_length",
                reason: "logical range overflow",
            })?;

        if logical >= chunk_start && logical < chunk_end {
            let offset_within = logical - chunk_start;
            // Use the first stripe (single-device assumption).
            let stripe = chunk.stripes.first().ok_or(ParseError::InvalidField {
                field: "stripes",
                reason: "chunk has no stripes",
            })?;
            let physical =
                stripe
                    .offset
                    .checked_add(offset_within)
                    .ok_or(ParseError::InvalidField {
                        field: "stripe_offset",
                        reason: "physical address overflow",
                    })?;
            return Ok(Some(BtrfsPhysicalMapping {
                devid: stripe.devid,
                physical,
            }));
        }
    }
    Ok(None)
}

// ── Tree node types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub item_type: u8,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsHeader {
    pub csum: [u8; 32],
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub flags: u64,
    pub chunk_tree_uuid: [u8; 16],
    pub generation: u64,
    pub owner: u64,
    pub nritems: u32,
    pub level: u8,
}

impl BtrfsHeader {
    pub fn parse_from_block(block: &[u8]) -> Result<Self, ParseError> {
        if block.len() < BTRFS_HEADER_SIZE {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_HEADER_SIZE,
                offset: 0,
                actual: block.len(),
            });
        }

        Ok(Self {
            csum: read_fixed::<32>(block, 0x00)?,
            fsid: read_fixed::<16>(block, 0x20)?,
            bytenr: read_le_u64(block, 0x30)?,
            flags: read_le_u64(block, 0x38)?,
            chunk_tree_uuid: read_fixed::<16>(block, 0x40)?,
            generation: read_le_u64(block, 0x50)?,
            owner: read_le_u64(block, 0x58)?,
            nritems: read_le_u32(block, 0x60)?,
            level: block[0x64],
        })
    }

    /// Validate the header against the block it was parsed from.
    ///
    /// Checks:
    /// - `bytenr` matches `expected_bytenr` (if provided).
    /// - `nritems` fits within the block, considering item size (leaf vs internal).
    /// - `level` does not exceed `BTRFS_MAX_LEVEL`.
    pub fn validate(
        &self,
        block_size: usize,
        expected_bytenr: Option<u64>,
    ) -> Result<(), ParseError> {
        if let Some(expected) = expected_bytenr {
            if self.bytenr != expected {
                return Err(ParseError::InvalidField {
                    field: "bytenr",
                    reason: "header bytenr does not match expected",
                });
            }
        }

        if self.level > BTRFS_MAX_LEVEL {
            return Err(ParseError::InvalidField {
                field: "level",
                reason: "exceeds maximum tree depth",
            });
        }

        let payload_space = block_size.saturating_sub(BTRFS_HEADER_SIZE);
        let item_size = if self.level == 0 {
            BTRFS_ITEM_SIZE
        } else {
            BTRFS_KEY_PTR_SIZE
        };
        let max_items = payload_space / item_size;
        let nritems = usize::try_from(self.nritems)
            .map_err(|_| ParseError::IntegerConversion { field: "nritems" })?;

        if nritems > max_items {
            return Err(ParseError::InvalidField {
                field: "nritems",
                reason: "item count exceeds block capacity",
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsItem {
    pub key: BtrfsKey,
    pub data_offset: u32,
    pub data_size: u32,
}

/// An internal (non-leaf) node item: a key paired with a child block pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsKeyPtr {
    pub key: BtrfsKey,
    pub blockptr: u64,
    pub generation: u64,
}

pub fn parse_leaf_items(block: &[u8]) -> Result<(BtrfsHeader, Vec<BtrfsItem>), ParseError> {
    let header = BtrfsHeader::parse_from_block(block)?;
    if header.level != 0 {
        return Err(ParseError::InvalidField {
            field: "level",
            reason: "expected leaf level 0",
        });
    }

    let nritems = usize::try_from(header.nritems)
        .map_err(|_| ParseError::IntegerConversion { field: "nritems" })?;

    let item_table_bytes =
        nritems
            .checked_mul(BTRFS_ITEM_SIZE)
            .ok_or(ParseError::InvalidField {
                field: "items",
                reason: "overflow",
            })?;
    let items_end =
        BTRFS_HEADER_SIZE
            .checked_add(item_table_bytes)
            .ok_or(ParseError::InvalidField {
                field: "items",
                reason: "overflow",
            })?;

    if block.len() < items_end {
        return Err(ParseError::InsufficientData {
            needed: items_end,
            offset: BTRFS_HEADER_SIZE,
            actual: block.len().saturating_sub(BTRFS_HEADER_SIZE),
        });
    }

    let mut items = Vec::with_capacity(nritems);
    for idx in 0..nritems {
        let base = BTRFS_HEADER_SIZE + idx * BTRFS_ITEM_SIZE;
        let key = BtrfsKey {
            objectid: read_le_u64(block, base)?,
            item_type: block[base + 8],
            offset: read_le_u64(block, base + 9)?,
        };
        let data_offset = read_le_u32(block, base + 17)?;
        let data_size = read_le_u32(block, base + 21)?;

        let data_end = usize::try_from(data_offset)
            .ok()
            .and_then(|off| off.checked_add(usize::try_from(data_size).ok()?))
            .ok_or(ParseError::InvalidField {
                field: "item_offset",
                reason: "overflow",
            })?;

        if data_end > block.len() {
            return Err(ParseError::InvalidField {
                field: "item_offset",
                reason: "item points outside block",
            });
        }

        items.push(BtrfsItem {
            key,
            data_offset,
            data_size,
        });
    }

    Ok((header, items))
}

/// Parse a btrfs internal (non-leaf) node, returning the header and key-pointer items.
///
/// Internal nodes (level > 0) contain `btrfs_key_ptr` entries that point
/// to child blocks. Each entry is 33 bytes: key (17) + blockptr (8) + generation (8).
pub fn parse_internal_items(block: &[u8]) -> Result<(BtrfsHeader, Vec<BtrfsKeyPtr>), ParseError> {
    let header = BtrfsHeader::parse_from_block(block)?;
    if header.level == 0 {
        return Err(ParseError::InvalidField {
            field: "level",
            reason: "expected internal node (level > 0)",
        });
    }

    header.validate(block.len(), None)?;

    let nritems = usize::try_from(header.nritems)
        .map_err(|_| ParseError::IntegerConversion { field: "nritems" })?;

    let table_bytes = nritems
        .checked_mul(BTRFS_KEY_PTR_SIZE)
        .ok_or(ParseError::InvalidField {
            field: "key_ptrs",
            reason: "overflow",
        })?;
    let table_end = BTRFS_HEADER_SIZE
        .checked_add(table_bytes)
        .ok_or(ParseError::InvalidField {
            field: "key_ptrs",
            reason: "overflow",
        })?;

    if block.len() < table_end {
        return Err(ParseError::InsufficientData {
            needed: table_end,
            offset: BTRFS_HEADER_SIZE,
            actual: block.len().saturating_sub(BTRFS_HEADER_SIZE),
        });
    }

    let mut ptrs = Vec::with_capacity(nritems);
    for idx in 0..nritems {
        let base = BTRFS_HEADER_SIZE + idx * BTRFS_KEY_PTR_SIZE;
        let key = BtrfsKey {
            objectid: read_le_u64(block, base)?,
            item_type: block[base + 8],
            offset: read_le_u64(block, base + 9)?,
        };
        let blockptr = read_le_u64(block, base + 17)?;
        let generation = read_le_u64(block, base + 25)?;

        if blockptr == 0 {
            return Err(ParseError::InvalidField {
                field: "blockptr",
                reason: "child block pointer is zero",
            });
        }

        ptrs.push(BtrfsKeyPtr {
            key,
            blockptr,
            generation,
        });
    }

    Ok((header, ptrs))
}

// ── Checksum verification ───────────────────────────────────────────────────

/// Verify the CRC32C checksum of a btrfs superblock.
///
/// The checksum covers `region[0x20..]` (everything after the 32-byte `csum`
/// field). The expected checksum is stored as a little-endian u32 in
/// `region[0..4]`.
///
/// Only CRC32C (`csum_type == 0`) is currently supported. Other algorithms
/// return an error.
pub fn verify_superblock_checksum(region: &[u8]) -> Result<(), ParseError> {
    if region.len() < BTRFS_SUPER_INFO_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_SUPER_INFO_SIZE,
            offset: 0,
            actual: region.len(),
        });
    }

    let csum_type = read_le_u16(region, 0xC4)?;
    if csum_type != ffs_types::BTRFS_CSUM_TYPE_CRC32C {
        return Err(ParseError::InvalidField {
            field: "csum_type",
            reason: "only CRC32C (type 0) is currently supported",
        });
    }

    let stored = read_le_u32(region, 0)?;
    let computed = crc32c::crc32c(&region[0x20..BTRFS_SUPER_INFO_SIZE]);

    if stored != computed {
        return Err(ParseError::InvalidField {
            field: "superblock_csum",
            reason: "CRC32C checksum mismatch",
        });
    }

    Ok(())
}

/// Verify the CRC32C checksum of a btrfs tree block (leaf or internal node).
///
/// The checksum covers `block[0x20..block.len()]` (everything after the
/// 32-byte `csum` field in the header). The expected checksum is stored as a
/// little-endian u32 in `block[0..4]`.
///
/// Only CRC32C (`csum_type == 0`) is currently supported.
pub fn verify_tree_block_checksum(block: &[u8], csum_type: u16) -> Result<(), ParseError> {
    if block.len() < BTRFS_HEADER_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_HEADER_SIZE,
            offset: 0,
            actual: block.len(),
        });
    }

    if csum_type != ffs_types::BTRFS_CSUM_TYPE_CRC32C {
        return Err(ParseError::InvalidField {
            field: "csum_type",
            reason: "only CRC32C (type 0) is currently supported",
        });
    }

    let stored = read_le_u32(block, 0)?;
    let computed = crc32c::crc32c(&block[0x20..]);

    if stored != computed {
        return Err(ParseError::InvalidField {
            field: "tree_block_csum",
            reason: "CRC32C checksum mismatch",
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parse_superblock_smoke() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x30..0x38].copy_from_slice(&(BTRFS_SUPER_INFO_OFFSET as u64).to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&9_u64.to_le_bytes());
        sb[0x50..0x58].copy_from_slice(&4096_u64.to_le_bytes());
        sb[0x58..0x60].copy_from_slice(&8192_u64.to_le_bytes());
        sb[0x60..0x68].copy_from_slice(&12288_u64.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&1_000_000_u64.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&123_456_u64.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&6_u64.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&65536_u32.to_le_bytes());
        sb[0xC4..0xC6].copy_from_slice(&1_u16.to_le_bytes());
        sb[0xC6] = 0;
        sb[0xC7] = 1;
        sb[0xC8] = 2;
        sb[BTRFS_SUPER_LABEL_OFFSET..BTRFS_SUPER_LABEL_OFFSET + 3].copy_from_slice(b"ffs");

        let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("superblock parse");
        assert_eq!(parsed.magic, BTRFS_MAGIC);
        assert_eq!(parsed.sectorsize, 4096);
        assert_eq!(parsed.nodesize, 16384);
        assert_eq!(parsed.label, "ffs");
    }

    #[test]
    fn superblock_sys_chunk_array_parsed() {
        // Build a superblock with a single sys_chunk_array entry
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&65536_u32.to_le_bytes());

        // Build a sys_chunk_array entry: disk_key (17) + chunk_fixed (48) + 1 stripe (32) = 97
        let entry_size: u32 = 97;
        sb[0xA0..0xA4].copy_from_slice(&entry_size.to_le_bytes());

        let base = BTRFS_SYS_CHUNK_ARRAY_OFFSET;
        // disk_key: objectid=256, type=228 (CHUNK_ITEM_KEY), offset=0
        sb[base..base + 8].copy_from_slice(&256_u64.to_le_bytes());
        sb[base + 8] = 228;
        sb[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        // chunk: length=8MiB, owner=2, stripe_len=64K, type=2 (SYSTEM)
        let c = base + 17;
        sb[c..c + 8].copy_from_slice(&(8 * 1024 * 1024_u64).to_le_bytes());
        sb[c + 8..c + 16].copy_from_slice(&2_u64.to_le_bytes());
        sb[c + 16..c + 24].copy_from_slice(&(64 * 1024_u64).to_le_bytes());
        sb[c + 24..c + 32].copy_from_slice(&2_u64.to_le_bytes()); // type=SYSTEM
        sb[c + 32..c + 36].copy_from_slice(&4096_u32.to_le_bytes());
        sb[c + 36..c + 40].copy_from_slice(&4096_u32.to_le_bytes());
        sb[c + 40..c + 44].copy_from_slice(&4096_u32.to_le_bytes());
        sb[c + 44..c + 46].copy_from_slice(&1_u16.to_le_bytes()); // num_stripes=1
        sb[c + 46..c + 48].copy_from_slice(&0_u16.to_le_bytes()); // sub_stripes=0
        // stripe: devid=1, offset=0, uuid=zeros
        let s = c + 48;
        sb[s..s + 8].copy_from_slice(&1_u64.to_le_bytes());
        sb[s + 8..s + 16].copy_from_slice(&0_u64.to_le_bytes());

        let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("sb parse");
        assert_eq!(parsed.sys_chunk_array_size, entry_size);
        assert_eq!(parsed.sys_chunk_array.len(), 97);

        let entries = parse_sys_chunk_array(&parsed.sys_chunk_array).expect("chunk parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key.objectid, 256);
        assert_eq!(entries[0].key.item_type, 228);
        assert_eq!(entries[0].length, 8 * 1024 * 1024);
        assert_eq!(entries[0].num_stripes, 1);
        assert_eq!(entries[0].stripes[0].devid, 1);
    }

    #[test]
    fn superblock_rejects_non_power_of_two_sectorsize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&3000_u32.to_le_bytes()); // not power of 2
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "sectorsize",
                    ..
                }
            ),
            "expected sectorsize error, got: {err:?}"
        );
    }

    #[test]
    fn superblock_rejects_non_power_of_two_nodesize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&5000_u32.to_le_bytes()); // not power of 2
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nodesize",
                    ..
                }
            ),
            "expected nodesize error, got: {err:?}"
        );
    }

    #[test]
    fn map_logical_to_physical_hit() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000, // logical start = 16 MiB
            },
            length: 0x80_0000, // 8 MiB
            owner: 2,
            stripe_len: 0x1_0000,
            chunk_type: 2,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0x20_0000, // physical start = 2 MiB
                dev_uuid: [0; 16],
            }],
        }];

        // Hit: logical 16.5 MiB → physical 2.5 MiB
        let result = map_logical_to_physical(&chunks, 0x108_0000).expect("mapping should succeed");
        let mapping = result.expect("should find a mapping");
        assert_eq!(mapping.devid, 1);
        assert_eq!(mapping.physical, 0x28_0000);
    }

    #[test]
    fn map_logical_to_physical_miss() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000,
            },
            length: 0x80_0000,
            owner: 2,
            stripe_len: 0x1_0000,
            chunk_type: 2,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0x20_0000,
                dev_uuid: [0; 16],
            }],
        }];

        // Miss: logical address outside the chunk range
        let result = map_logical_to_physical(&chunks, 0x200_0000).expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn map_logical_to_physical_empty_chunks() {
        let result = map_logical_to_physical(&[], 0x1000).expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn parse_sys_chunk_array_empty() {
        let entries = parse_sys_chunk_array(&[]).expect("empty array is valid");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_sys_chunk_array_truncated_key() {
        let data = [0_u8; 10]; // too short for a disk_key
        let err = parse_sys_chunk_array(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn parse_leaf_items_smoke() {
        let mut block = vec![0_u8; 512];

        block[0x60..0x64].copy_from_slice(&1_u32.to_le_bytes());
        block[0x64] = 0;

        // first item at header+0
        let base = BTRFS_HEADER_SIZE;
        block[base..base + 8].copy_from_slice(&123_u64.to_le_bytes());
        block[base + 8] = 42;
        block[base + 9..base + 17].copy_from_slice(&999_u64.to_le_bytes());
        block[base + 17..base + 21].copy_from_slice(&400_u32.to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&8_u32.to_le_bytes());

        let (_, items) = parse_leaf_items(&block).expect("leaf parse");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].key.objectid, 123);
        assert_eq!(items[0].key.item_type, 42);
        assert_eq!(items[0].key.offset, 999);
    }

    /// Helper: build a minimal valid block with a header (zeros except nritems + level).
    fn make_block(size: usize, nritems: u32, level: u8) -> Vec<u8> {
        let mut block = vec![0_u8; size];
        block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        block[0x64] = level;
        block
    }

    #[test]
    fn parse_internal_items_smoke() {
        let mut block = make_block(4096, 2, 1);

        // Item 0: key(256, 132, 0) → blockptr=0x4000, gen=10
        let b0 = BTRFS_HEADER_SIZE;
        block[b0..b0 + 8].copy_from_slice(&256_u64.to_le_bytes());
        block[b0 + 8] = 132;
        block[b0 + 9..b0 + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[b0 + 17..b0 + 25].copy_from_slice(&0x4000_u64.to_le_bytes());
        block[b0 + 25..b0 + 33].copy_from_slice(&10_u64.to_le_bytes());

        // Item 1: key(512, 132, 100) → blockptr=0x8000, gen=10
        let b1 = BTRFS_HEADER_SIZE + BTRFS_KEY_PTR_SIZE;
        block[b1..b1 + 8].copy_from_slice(&512_u64.to_le_bytes());
        block[b1 + 8] = 132;
        block[b1 + 9..b1 + 17].copy_from_slice(&100_u64.to_le_bytes());
        block[b1 + 17..b1 + 25].copy_from_slice(&0x8000_u64.to_le_bytes());
        block[b1 + 25..b1 + 33].copy_from_slice(&10_u64.to_le_bytes());

        let (header, ptrs) = parse_internal_items(&block).expect("internal parse");
        assert_eq!(header.level, 1);
        assert_eq!(ptrs.len(), 2);
        assert_eq!(ptrs[0].key.objectid, 256);
        assert_eq!(ptrs[0].blockptr, 0x4000);
        assert_eq!(ptrs[0].generation, 10);
        assert_eq!(ptrs[1].key.objectid, 512);
        assert_eq!(ptrs[1].blockptr, 0x8000);
    }

    #[test]
    fn parse_internal_items_rejects_leaf() {
        let block = make_block(4096, 0, 0);
        let err = parse_internal_items(&block).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "level", .. }),
            "expected level error, got: {err:?}"
        );
    }

    #[test]
    fn parse_internal_items_rejects_zero_blockptr() {
        let mut block = make_block(4096, 1, 1);
        // key is valid but blockptr is zero
        let b0 = BTRFS_HEADER_SIZE;
        block[b0..b0 + 8].copy_from_slice(&256_u64.to_le_bytes());
        block[b0 + 8] = 132;
        // blockptr stays zero (from make_block)

        let err = parse_internal_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "blockptr",
                    ..
                }
            ),
            "expected blockptr error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_bytenr_mismatch() {
        let block = make_block(4096, 0, 0);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        // header.bytenr is 0, expected 0x1000
        let err = header.validate(4096, Some(0x1000)).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "bytenr",
                    ..
                }
            ),
            "expected bytenr error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_bytenr_match() {
        let mut block = make_block(4096, 0, 0);
        block[0x30..0x38].copy_from_slice(&0x1_0000_u64.to_le_bytes());
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        header.validate(4096, Some(0x1_0000)).expect("should match");
    }

    #[test]
    fn header_validate_nritems_overflow_leaf() {
        // A 4096-byte block can hold (4096-101)/25 = 159 leaf items max.
        let block = make_block(4096, 200, 0);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        let err = header.validate(4096, None).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nritems",
                    ..
                }
            ),
            "expected nritems error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_nritems_overflow_internal() {
        // A 4096-byte block can hold (4096-101)/33 = 121 internal items max.
        let block = make_block(4096, 130, 1);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        let err = header.validate(4096, None).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nritems",
                    ..
                }
            ),
            "expected nritems error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_level_too_high() {
        let block = make_block(4096, 0, 8); // max is 7
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        let err = header.validate(4096, None).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "level", .. }),
            "expected level error, got: {err:?}"
        );
    }

    #[test]
    fn parse_leaf_items_rejects_out_of_bounds_data() {
        let mut block = make_block(512, 1, 0);
        let base = BTRFS_HEADER_SIZE;
        block[base..base + 8].copy_from_slice(&1_u64.to_le_bytes());
        block[base + 8] = 1;
        // data_offset = 600, data_size = 10 — well beyond the 512-byte block
        block[base + 17..base + 21].copy_from_slice(&600_u32.to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&10_u32.to_le_bytes());

        let err = parse_leaf_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "item_offset",
                    ..
                }
            ),
            "expected item_offset error, got: {err:?}"
        );
    }

    #[test]
    fn parse_internal_items_block_too_small() {
        // Block is too small to hold the declared items
        let mut block = make_block(140, 2, 1);
        // Need 101 + 2*33 = 167 bytes, but only have 140
        // Put a valid blockptr for item 0 so we fail on size not on blockptr
        let b0 = BTRFS_HEADER_SIZE;
        block[b0 + 17..b0 + 25].copy_from_slice(&0x4000_u64.to_le_bytes());

        let err = parse_internal_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nritems",
                    ..
                }
            ),
            "expected nritems error, got: {err:?}"
        );
    }

    // ── Checksum verification tests ──────────────────────────────────

    /// Build a valid superblock with correct CRC32C checksum.
    fn make_checksummed_sb() -> Vec<u8> {
        let mut sb = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes()); // sectorsize
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes()); // nodesize
        sb[0xC4..0xC6].copy_from_slice(&0_u16.to_le_bytes()); // csum_type=CRC32C
        // Compute CRC32C over bytes[0x20..4096] and store in bytes[0..4]
        let csum = crc32c::crc32c(&sb[0x20..BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&csum.to_le_bytes());
        sb
    }

    #[test]
    fn verify_superblock_checksum_valid() {
        let sb = make_checksummed_sb();
        verify_superblock_checksum(&sb).expect("valid checksum");
    }

    #[test]
    fn verify_superblock_checksum_corrupt() {
        let mut sb = make_checksummed_sb();
        // Flip a bit in the payload
        sb[0x50] ^= 0x01;
        let err = verify_superblock_checksum(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "superblock_csum",
                    ..
                }
            ),
            "expected checksum mismatch, got: {err:?}"
        );
    }

    #[test]
    fn verify_superblock_checksum_unsupported_type() {
        let mut sb = make_checksummed_sb();
        // Change csum_type to XXHASH64
        sb[0xC4..0xC6].copy_from_slice(&1_u16.to_le_bytes());
        let err = verify_superblock_checksum(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "csum_type",
                    ..
                }
            ),
            "expected unsupported csum_type error, got: {err:?}"
        );
    }

    #[test]
    fn verify_tree_block_checksum_valid() {
        let mut block = vec![0_u8; 16384]; // nodesize=16K
        // Set up a minimal header
        block[0x64] = 0; // level=0 (leaf)
        block[0x60..0x64].copy_from_slice(&0_u32.to_le_bytes()); // nritems=0
        // Compute CRC32C over bytes[0x20..] and store in [0..4]
        let csum = crc32c::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
        verify_tree_block_checksum(&block, 0).expect("valid tree block checksum");
    }

    #[test]
    fn verify_tree_block_checksum_corrupt() {
        let mut block = vec![0_u8; 16384];
        let csum = crc32c::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
        // Corrupt a byte
        block[0x30] ^= 0xFF;
        let err = verify_tree_block_checksum(&block, 0).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "tree_block_csum",
                    ..
                }
            ),
            "expected tree block checksum mismatch, got: {err:?}"
        );
    }

    fn make_proptest_valid_btrfs_superblock(
        sectorsize: u32,
        nodesize: u32,
        sys_chunk_array: &[u8],
    ) -> [u8; BTRFS_SUPER_INFO_SIZE] {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        let sys_chunk_len_u32 =
            u32::try_from(sys_chunk_array.len()).expect("sys_chunk_array length fits in u32");

        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x30..0x38].copy_from_slice(&(BTRFS_SUPER_INFO_OFFSET as u64).to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&1_u64.to_le_bytes());
        sb[0x50..0x58].copy_from_slice(&0x1000_u64.to_le_bytes());
        sb[0x58..0x60].copy_from_slice(&0x2000_u64.to_le_bytes());
        sb[0x60..0x68].copy_from_slice(&0_u64.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&1_000_000_u64.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&123_456_u64.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&6_u64.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&sectorsize.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&nodesize.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&sectorsize.to_le_bytes());
        sb[0xA0..0xA4].copy_from_slice(&sys_chunk_len_u32.to_le_bytes());

        let array_end = BTRFS_SYS_CHUNK_ARRAY_OFFSET + sys_chunk_array.len();
        sb[BTRFS_SYS_CHUNK_ARRAY_OFFSET..array_end].copy_from_slice(sys_chunk_array);
        sb
    }

    fn make_proptest_header_block(block_size: usize, nritems: u32, level: u8) -> Vec<u8> {
        let mut block = vec![0_u8; block_size.max(BTRFS_HEADER_SIZE)];
        block[0x30..0x38].copy_from_slice(&0x1000_u64.to_le_bytes());
        block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        block[0x64] = level;
        block
    }

    // Reproduce any failing case with:
    // PROPTEST_CASES=1 PROPTEST_SEED=<seed> cargo test -p ffs-ondisk <test_name> -- --nocapture
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn btrfs_proptest_parse_superblock_region_no_panic(
            region in proptest::collection::vec(any::<u8>(), 0..=(BTRFS_SUPER_INFO_SIZE * 2)),
        ) {
            let _ = BtrfsSuperblock::parse_superblock_region(&region);
        }

        #[test]
        fn btrfs_proptest_parse_from_image_no_panic(
            image in proptest::collection::vec(
                any::<u8>(),
                0..=(BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE + 256),
            ),
        ) {
            let _ = BtrfsSuperblock::parse_from_image(&image);
        }

        #[test]
        fn btrfs_proptest_parse_sys_chunk_array_no_panic(
            data in proptest::collection::vec(any::<u8>(), 0..=BTRFS_SYS_CHUNK_ARRAY_MAX),
        ) {
            let _ = parse_sys_chunk_array(&data);
        }

        #[test]
        fn btrfs_proptest_parse_leaf_items_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let _ = parse_leaf_items(&block);
        }

        #[test]
        fn btrfs_proptest_parse_internal_items_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let _ = parse_internal_items(&block);
        }

        #[test]
        fn btrfs_proptest_header_parse_validate_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            if let Ok(header) = BtrfsHeader::parse_from_block(&block) {
                let _ = header.validate(block.len(), None);
            }
        }

        #[test]
        fn btrfs_proptest_structured_superblock_size_invariants(
            sector_shift in 12_u32..=18,
            node_shift in 12_u32..=18,
        ) {
            let sectorsize = 1_u32 << sector_shift;
            let nodesize = 1_u32 << node_shift;
            let sb = make_proptest_valid_btrfs_superblock(sectorsize, nodesize, &[]);
            let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("parse structured btrfs superblock");
            prop_assert!(parsed.sectorsize.is_power_of_two());
            prop_assert!(parsed.nodesize.is_power_of_two());
            prop_assert!(parsed.sectorsize <= 256 * 1024);
            prop_assert!(parsed.nodesize <= 256 * 1024);
        }

        #[test]
        fn btrfs_proptest_structured_sys_chunk_array_round_trip(
            sys_chunk_array in proptest::collection::vec(any::<u8>(), 0..=128),
        ) {
            let sb = make_proptest_valid_btrfs_superblock(4096, 16384, &sys_chunk_array);
            let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("parse structured btrfs superblock");
            prop_assert_eq!(usize::try_from(parsed.sys_chunk_array_size).ok(), Some(sys_chunk_array.len()));
            prop_assert_eq!(parsed.sys_chunk_array, sys_chunk_array);
        }

        #[test]
        fn btrfs_proptest_header_validate_leaf_capacity(nritems in 0_u32..=159) {
            let block_size = 4096_usize;
            let block = make_proptest_header_block(block_size, nritems, 0);
            let header = BtrfsHeader::parse_from_block(&block).expect("parse header");
            prop_assert!(header.validate(block_size, Some(0x1000)).is_ok());
        }

        #[test]
        fn btrfs_proptest_header_validate_internal_capacity(
            nritems in 0_u32..=121,
            level in 1_u8..=BTRFS_MAX_LEVEL,
        ) {
            let block_size = 4096_usize;
            let block = make_proptest_header_block(block_size, nritems, level);
            let header = BtrfsHeader::parse_from_block(&block).expect("parse header");
            prop_assert!(header.validate(block_size, Some(0x1000)).is_ok());
        }
    }
}
