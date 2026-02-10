#![forbid(unsafe_code)]

use ffs_types::{
    BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, ParseError, read_fixed,
    read_le_u16, read_le_u32, read_le_u64, trim_nul_padded,
};
use serde::{Deserialize, Serialize};

const BTRFS_HEADER_SIZE: usize = 101;
const BTRFS_ITEM_SIZE: usize = 25;
const BTRFS_SUPER_LABEL_OFFSET: usize = 0x12B;
const BTRFS_SUPER_LABEL_LEN: usize = 256;

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
}

impl BtrfsSuperblock {
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
        if sectorsize == 0 || nodesize == 0 {
            return Err(ParseError::InvalidField {
                field: "sectorsize/nodesize",
                reason: "zero value",
            });
        }

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
            stripesize: read_le_u32(region, 0x9C)?,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsItem {
    pub key: BtrfsKey,
    pub data_offset: u32,
    pub data_size: u32,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
