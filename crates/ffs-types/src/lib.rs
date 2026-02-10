#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
pub const EXT4_SUPERBLOCK_SIZE: usize = 1024;
pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;

pub const BTRFS_SUPER_INFO_OFFSET: usize = 64 * 1024;
pub const BTRFS_SUPER_INFO_SIZE: usize = 4096;
pub const BTRFS_MAGIC: u64 = 0x4D5F_5366_5248_425F;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockNumber(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InodeNumber(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TxnId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommitSeq(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub high: CommitSeq,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("insufficient data: need {needed} bytes at offset {offset}, got {actual}")]
    InsufficientData {
        needed: usize,
        offset: usize,
        actual: usize,
    },
    #[error("invalid magic: expected {expected:#x}, got {actual:#x}")]
    InvalidMagic { expected: u64, actual: u64 },
    #[error("invalid field: {field} ({reason})")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("integer conversion failed: {field}")]
    IntegerConversion { field: &'static str },
}

#[inline]
pub fn ensure_slice(data: &[u8], offset: usize, len: usize) -> Result<&[u8], ParseError> {
    let Some(end) = offset.checked_add(len) else {
        return Err(ParseError::InvalidField {
            field: "offset",
            reason: "overflow",
        });
    };

    if end > data.len() {
        return Err(ParseError::InsufficientData {
            needed: len,
            offset,
            actual: data.len().saturating_sub(offset),
        });
    }

    Ok(&data[offset..end])
}

#[inline]
pub fn read_le_u16(data: &[u8], offset: usize) -> Result<u16, ParseError> {
    let bytes = ensure_slice(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[inline]
pub fn read_le_u32(data: &[u8], offset: usize) -> Result<u32, ParseError> {
    let bytes = ensure_slice(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[inline]
pub fn read_le_u64(data: &[u8], offset: usize) -> Result<u64, ParseError> {
    let bytes = ensure_slice(data, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[inline]
pub fn read_fixed<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], ParseError> {
    let bytes = ensure_slice(data, offset, N)?;
    let mut out = [0_u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[must_use]
pub fn trim_nul_padded(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_owned()
}

#[must_use]
pub fn is_power_of_two_u32(value: u32) -> bool {
    value.is_power_of_two()
}

#[must_use]
pub fn ext4_block_size_from_log(log_block_size: u32) -> Option<u32> {
    let shift = 10_u32.checked_add(log_block_size)?;
    1_u32.checked_shl(shift)
}

impl fmt::Display for BlockNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_helpers() {
        let bytes = [0x34_u8, 0x12, 0x78, 0x56, 0xEF, 0xCD, 0xAB, 0x90];
        assert_eq!(read_le_u16(&bytes, 0).expect("u16"), 0x1234);
        assert_eq!(read_le_u32(&bytes, 0).expect("u32"), 0x5678_1234);
        assert_eq!(read_le_u32(&bytes, 4).expect("u32"), 0x90AB_CDEF);
    }

    #[test]
    fn test_trim_nul_padded() {
        let raw = b"ffs\0\0\0\0";
        assert_eq!(trim_nul_padded(raw), "ffs");
    }

    #[test]
    fn test_ext4_block_size_from_log() {
        assert_eq!(ext4_block_size_from_log(0), Some(1024));
        assert_eq!(ext4_block_size_from_log(1), Some(2048));
        assert_eq!(ext4_block_size_from_log(2), Some(4096));
    }
}
