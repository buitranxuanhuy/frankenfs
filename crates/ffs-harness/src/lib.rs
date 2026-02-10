#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use ffs_ondisk::{BtrfsSuperblock, Ext4Superblock};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDomain {
    pub domain: String,
    pub implemented: u32,
    pub total: u32,
    pub coverage_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityReport {
    pub domains: Vec<CoverageDomain>,
    pub overall_implemented: u32,
    pub overall_total: u32,
    pub overall_coverage_percent: f64,
}

impl ParityReport {
    #[must_use]
    pub fn current() -> Self {
        let domains = vec![
            CoverageDomain::new("ext4 metadata parsing", 6, 19),
            CoverageDomain::new("btrfs metadata parsing", 4, 20),
            CoverageDomain::new("MVCC/COW core", 4, 14),
            CoverageDomain::new("FUSE surface", 1, 12),
            CoverageDomain::new("self-healing durability policy", 2, 10),
        ];

        let overall_implemented = domains.iter().map(|d| d.implemented).sum();
        let overall_total = domains.iter().map(|d| d.total).sum();
        let overall_coverage_percent = percentage(overall_implemented, overall_total);

        Self {
            domains,
            overall_implemented,
            overall_total,
            overall_coverage_percent,
        }
    }
}

impl CoverageDomain {
    #[must_use]
    pub fn new(domain: &str, implemented: u32, total: u32) -> Self {
        Self {
            domain: domain.to_owned(),
            implemented,
            total,
            coverage_percent: percentage(implemented, total),
        }
    }
}

#[must_use]
pub fn percentage(implemented: u32, total: u32) -> f64 {
    if total == 0 {
        0.0
    } else {
        (f64::from(implemented) / f64::from(total)) * 100.0
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SparseFixture {
    pub size: usize,
    pub writes: Vec<FixtureWrite>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FixtureWrite {
    pub offset: usize,
    pub hex: String,
}

pub fn load_sparse_fixture(path: &Path) -> Result<Vec<u8>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read fixture {}", path.display()))?;
    let fixture: SparseFixture = serde_json::from_str(&text)
        .with_context(|| format!("invalid fixture json {}", path.display()))?;

    let mut bytes = vec![0_u8; fixture.size];
    for write in fixture.writes {
        let payload = hex::decode(write.hex)
            .with_context(|| format!("invalid hex at offset {}", write.offset))?;

        let end = write
            .offset
            .checked_add(payload.len())
            .context("fixture offset overflow")?;
        if end > bytes.len() {
            bail!(
                "fixture write out of bounds: offset={} payload={} size={}",
                write.offset,
                payload.len(),
                bytes.len()
            );
        }

        bytes[write.offset..end].copy_from_slice(&payload);
    }

    Ok(bytes)
}

pub fn validate_ext4_fixture(path: &Path) -> Result<Ext4Superblock> {
    let data = load_sparse_fixture(path)?;
    Ext4Superblock::parse_superblock_region(&data)
        .with_context(|| format!("failed ext4 parse for fixture {}", path.display()))
}

pub fn validate_btrfs_fixture(path: &Path) -> Result<BtrfsSuperblock> {
    let data = load_sparse_fixture(path)?;
    BtrfsSuperblock::parse_superblock_region(&data)
        .with_context(|| format!("failed btrfs parse for fixture {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(rel: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .join("conformance")
            .join("fixtures")
            .join(rel)
    }

    #[test]
    fn ext4_fixture_parses() {
        let path = fixture_path("ext4_superblock_sparse.json");
        let sb = validate_ext4_fixture(&path).expect("ext4 fixture parse");
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.volume_name, "frankenfs");
    }

    #[test]
    fn btrfs_fixture_parses() {
        let path = fixture_path("btrfs_superblock_sparse.json");
        let sb = validate_btrfs_fixture(&path).expect("btrfs fixture parse");
        assert_eq!(sb.magic, ffs_types::BTRFS_MAGIC);
        assert_eq!(sb.label, "ffs-lab");
    }

    #[test]
    fn parity_report_is_non_zero() {
        let report = ParityReport::current();
        assert!(report.overall_total > 0);
        assert!(report.overall_implemented > 0);
        assert!(report.overall_coverage_percent > 0.0);
    }
}
