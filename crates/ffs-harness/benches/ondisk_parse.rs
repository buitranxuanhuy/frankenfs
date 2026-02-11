#![forbid(unsafe_code)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ffs_harness::load_sparse_fixture;
use ffs_ondisk::{
    Ext4GroupDesc, Ext4Inode, parse_dir_block, parse_extent_tree, parse_sys_chunk_array,
};
use std::path::Path;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance/fixtures")
        .join(name)
}

fn bench_ext4_inode_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("load inode fixture");

    c.bench_function("ext4_inode_parse", |b| {
        b.iter(|| Ext4Inode::parse_from_bytes(black_box(&data)).expect("inode parse"));
    });
}

fn bench_ext4_group_desc_32(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_group_desc_32byte.json"))
        .expect("load gd32 fixture");

    c.bench_function("ext4_group_desc_32byte", |b| {
        b.iter(|| Ext4GroupDesc::parse_from_bytes(black_box(&data), 32).expect("gd32 parse"));
    });
}

fn bench_ext4_group_desc_64(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_group_desc_64byte.json"))
        .expect("load gd64 fixture");

    c.bench_function("ext4_group_desc_64byte", |b| {
        b.iter(|| Ext4GroupDesc::parse_from_bytes(black_box(&data), 64).expect("gd64 parse"));
    });
}

fn bench_ext4_dir_block_parse(c: &mut Criterion) {
    let data =
        load_sparse_fixture(&fixture_path("ext4_dir_block.json")).expect("load dir block fixture");

    c.bench_function("ext4_dir_block_parse", |b| {
        b.iter(|| {
            let entries = parse_dir_block(black_box(&data), 4096).expect("dir block parse");
            black_box(entries);
        });
    });
}

fn bench_ext4_extent_tree_parse(c: &mut Criterion) {
    // The inode fixture contains a 60-byte extent tree in the i_block region.
    let inode_data = load_sparse_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("load inode fixture");
    let inode = Ext4Inode::parse_from_bytes(&inode_data).expect("inode parse");

    c.bench_function("ext4_extent_tree_parse", |b| {
        b.iter(|| {
            let _ = black_box(parse_extent_tree(black_box(&inode.extent_bytes)));
        });
    });
}

fn bench_btrfs_sys_chunk_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("btrfs_superblock_with_chunks.json"))
        .expect("load btrfs chunks fixture");
    let sb = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(&data)
        .expect("parse btrfs superblock");

    c.bench_function("btrfs_sys_chunk_parse", |b| {
        b.iter(|| {
            let entries =
                parse_sys_chunk_array(black_box(&sb.sys_chunk_array)).expect("chunk parse");
            black_box(entries);
        });
    });
}

criterion_group!(
    ondisk,
    bench_ext4_inode_parse,
    bench_ext4_group_desc_32,
    bench_ext4_group_desc_64,
    bench_ext4_dir_block_parse,
    bench_ext4_extent_tree_parse,
    bench_btrfs_sys_chunk_parse,
);
criterion_main!(ondisk);
