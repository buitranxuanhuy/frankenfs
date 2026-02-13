//! Version chain compression for MVCC block versions.
//!
//! This module provides memory-efficient storage for block version chains
//! by deduplicating identical consecutive versions and enforcing configurable
//! chain length limits.
//!
//! # Strategies
//!
//! 1. **Identical-version dedup**: When a new version has bytes identical to
//!    the previous version in the chain, store an `Identical` marker instead
//!    of duplicating the data. The commit sequence is still recorded for
//!    correct FCW conflict detection.
//!
//! 2. **Chain length capping**: Configurable maximum chain length per block.
//!    When exceeded, the oldest versions beyond the limit are pruned
//!    (respecting active snapshots).
//!
//! # Resolving compressed versions
//!
//! Use [`resolve_data`] to walk backward through a version chain and find
//! the actual bytes for an `Identical` marker. This is O(k) where k is
//! the number of consecutive `Identical` markers (typically 1-2).

use serde::{Deserialize, Serialize};

/// Compressed representation of block version data.
///
/// Instead of always storing a full `Vec<u8>`, this enum allows
/// memory-efficient alternatives when the data hasn't changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionData {
    /// Full block data stored inline.
    Full(Vec<u8>),
    /// Data is byte-identical to the previous version in the chain.
    /// No data is stored; resolve by walking backward to the nearest `Full`.
    Identical,
}

impl VersionData {
    /// Returns the inline bytes if this is a `Full` variant, `None` for `Identical`.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            VersionData::Full(bytes) => Some(bytes),
            VersionData::Identical => None,
        }
    }

    /// Returns `true` if this version is a dedup marker (no data stored).
    #[must_use]
    pub fn is_identical(&self) -> bool {
        matches!(self, VersionData::Identical)
    }

    /// Returns `true` if this version stores full data inline.
    #[must_use]
    pub fn is_full(&self) -> bool {
        matches!(self, VersionData::Full(_))
    }

    /// Memory used by this version's data (0 for `Identical`).
    #[must_use]
    pub fn memory_bytes(&self) -> usize {
        match self {
            VersionData::Full(bytes) => bytes.len(),
            VersionData::Identical => 0,
        }
    }

    /// Consume and return the inner bytes, or `None` for `Identical`.
    #[must_use]
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            VersionData::Full(bytes) => Some(bytes),
            VersionData::Identical => None,
        }
    }
}

/// Resolve the actual bytes for a version at `index` in a chain.
///
/// If the version at `index` is `Identical`, walks backward through the
/// chain until a `Full` version is found. Returns `None` only if the chain
/// is malformed (starts with `Identical` at index 0 with no preceding `Full`).
///
/// # Arguments
///
/// * `chain` - Slice of `(VersionData, ...)` tuples or items with a `.data` field.
///   For flexibility, this takes a closure that extracts `&VersionData` from each element.
/// * `index` - Index of the version to resolve.
///
/// # Performance
///
/// O(k) where k is the number of consecutive `Identical` markers before the
/// nearest `Full` version. In practice k is usually 0 or 1.
pub fn resolve_data_with<T, F>(chain: &[T], index: usize, get_data: F) -> Option<&[u8]>
where
    F: Fn(&T) -> &VersionData,
{
    let mut i = index;
    loop {
        match get_data(&chain[i]) {
            VersionData::Full(bytes) => return Some(bytes),
            VersionData::Identical => {
                if i == 0 {
                    // Malformed chain: Identical at position 0 with no base.
                    return None;
                }
                i -= 1;
            }
        }
    }
}

/// Configuration for version chain compression behavior.
///
/// Controls dedup and chain length limits. The default configuration
/// enables dedup and caps chains at 64 versions.
#[derive(Debug, Clone)]
pub struct CompressionPolicy {
    /// Enable dedup of identical consecutive versions.
    /// When true, committing bytes identical to the latest version
    /// stores an `Identical` marker instead of duplicating the data.
    pub dedup_identical: bool,

    /// Maximum number of versions to retain per block.
    /// When exceeded after a commit, the oldest versions are pruned
    /// (keeping at least 1 version and respecting active snapshots).
    /// `None` means no limit (only watermark-based pruning applies).
    pub max_chain_length: Option<usize>,
}

impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            dedup_identical: true,
            max_chain_length: Some(64),
        }
    }
}

impl CompressionPolicy {
    /// Create a policy with no compression (full data always stored, no cap).
    #[must_use]
    pub fn none() -> Self {
        Self {
            dedup_identical: false,
            max_chain_length: None,
        }
    }

    /// Create a policy with dedup but no chain cap.
    #[must_use]
    pub fn dedup_only() -> Self {
        Self {
            dedup_identical: true,
            max_chain_length: None,
        }
    }
}

/// Statistics about compression effectiveness.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionStats {
    /// Number of versions stored as `Full`.
    pub full_versions: usize,
    /// Number of versions stored as `Identical` (deduped).
    pub identical_versions: usize,
    /// Total bytes saved by dedup (sum of block sizes that would have been stored).
    pub bytes_saved: usize,
    /// Total bytes stored (sum of Full version data).
    pub bytes_stored: usize,
}

impl CompressionStats {
    /// Dedup ratio: fraction of versions that were deduplicated.
    /// Returns 0.0 if no versions exist.
    #[must_use]
    pub fn dedup_ratio(&self) -> f64 {
        let total = self.full_versions + self.identical_versions;
        if total == 0 {
            return 0.0;
        }
        self.identical_versions as f64 / total as f64
    }

    /// Compression ratio: bytes_stored / (bytes_stored + bytes_saved).
    /// Returns 1.0 if nothing was saved, 0.0 if everything was deduped.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        let total = self.bytes_stored + self.bytes_saved;
        if total == 0 {
            return 1.0;
        }
        self.bytes_stored as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_data_full_roundtrip() {
        let data = VersionData::Full(vec![1, 2, 3]);
        assert!(data.is_full());
        assert!(!data.is_identical());
        assert_eq!(data.as_bytes(), Some(&[1, 2, 3][..]));
        assert_eq!(data.memory_bytes(), 3);
    }

    #[test]
    fn version_data_identical() {
        let data = VersionData::Identical;
        assert!(data.is_identical());
        assert!(!data.is_full());
        assert_eq!(data.as_bytes(), None);
        assert_eq!(data.memory_bytes(), 0);
    }

    #[test]
    fn resolve_full_at_index() {
        let chain = vec![
            VersionData::Full(vec![0xAA]),
            VersionData::Full(vec![0xBB]),
        ];
        let result = resolve_data_with(&chain, 1, |d| d);
        assert_eq!(result, Some(&[0xBB][..]));
    }

    #[test]
    fn resolve_identical_walks_back() {
        let chain = vec![
            VersionData::Full(vec![0xAA]),
            VersionData::Identical,
            VersionData::Identical,
        ];
        // Index 2 is Identical -> walks to 1 (Identical) -> walks to 0 (Full)
        let result = resolve_data_with(&chain, 2, |d| d);
        assert_eq!(result, Some(&[0xAA][..]));
    }

    #[test]
    fn resolve_identical_at_zero_returns_none() {
        let chain = vec![VersionData::Identical];
        let result = resolve_data_with(&chain, 0, |d| d);
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_mixed_chain() {
        let chain = vec![
            VersionData::Full(vec![1]),     // 0
            VersionData::Identical,          // 1 -> resolves to [1]
            VersionData::Full(vec![2]),      // 2
            VersionData::Identical,          // 3 -> resolves to [2]
            VersionData::Identical,          // 4 -> resolves to [2]
        ];
        assert_eq!(resolve_data_with(&chain, 0, |d| d), Some(&[1][..]));
        assert_eq!(resolve_data_with(&chain, 1, |d| d), Some(&[1][..]));
        assert_eq!(resolve_data_with(&chain, 2, |d| d), Some(&[2][..]));
        assert_eq!(resolve_data_with(&chain, 3, |d| d), Some(&[2][..]));
        assert_eq!(resolve_data_with(&chain, 4, |d| d), Some(&[2][..]));
    }

    #[test]
    fn compression_stats_dedup_ratio() {
        let stats = CompressionStats {
            full_versions: 7,
            identical_versions: 3,
            bytes_saved: 300,
            bytes_stored: 700,
        };
        let ratio = stats.dedup_ratio();
        assert!((ratio - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn compression_stats_empty() {
        let stats = CompressionStats::default();
        assert_eq!(stats.dedup_ratio(), 0.0);
        assert_eq!(stats.compression_ratio(), 1.0);
    }

    #[test]
    fn policy_defaults() {
        let policy = CompressionPolicy::default();
        assert!(policy.dedup_identical);
        assert_eq!(policy.max_chain_length, Some(64));
    }

    #[test]
    fn policy_none() {
        let policy = CompressionPolicy::none();
        assert!(!policy.dedup_identical);
        assert_eq!(policy.max_chain_length, None);
    }
}
