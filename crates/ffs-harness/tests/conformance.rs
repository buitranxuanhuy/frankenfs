#![forbid(unsafe_code)]

use ffs_harness::{ParityReport, validate_btrfs_fixture, validate_ext4_fixture};
use std::path::Path;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance")
        .join("fixtures")
        .join(name)
}

#[test]
fn ext4_and_btrfs_fixtures_conform() {
    let ext4 =
        validate_ext4_fixture(&fixture_path("ext4_superblock_sparse.json")).expect("ext4 fixture");
    let btrfs = validate_btrfs_fixture(&fixture_path("btrfs_superblock_sparse.json"))
        .expect("btrfs fixture");

    assert_eq!(ext4.block_size, 4096);
    assert_eq!(btrfs.sectorsize, 4096);
}

#[test]
fn parity_report_totals_are_consistent() {
    let report = ParityReport::current();
    let implemented_sum: u32 = report.domains.iter().map(|d| d.implemented).sum();
    let total_sum: u32 = report.domains.iter().map(|d| d.total).sum();

    assert_eq!(implemented_sum, report.overall_implemented);
    assert_eq!(total_sum, report.overall_total);
}
