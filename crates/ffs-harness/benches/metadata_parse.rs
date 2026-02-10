#![forbid(unsafe_code)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ffs_harness::load_sparse_fixture;
use ffs_ondisk::{BtrfsSuperblock, Ext4Superblock};
use std::path::Path;

fn bench_metadata_parse(c: &mut Criterion) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let ext4_path = root.join("conformance/fixtures/ext4_superblock_sparse.json");
    let btrfs_path = root.join("conformance/fixtures/btrfs_superblock_sparse.json");

    let ext4 = load_sparse_fixture(&ext4_path).expect("load ext4 fixture");
    let btrfs = load_sparse_fixture(&btrfs_path).expect("load btrfs fixture");

    c.bench_function("ext4_superblock_parse", |b| {
        b.iter(|| {
            Ext4Superblock::parse_superblock_region(black_box(&ext4)).expect("ext4 parse in bench")
        });
    });

    c.bench_function("btrfs_superblock_parse", |b| {
        b.iter(|| {
            BtrfsSuperblock::parse_superblock_region(black_box(&btrfs))
                .expect("btrfs parse in bench")
        });
    });
}

criterion_group!(metadata, bench_metadata_parse);
criterion_main!(metadata);
