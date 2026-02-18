//! Benchmark: succinct bitmap vs plain linear scan.
//!
//! Compares O(1) rank / O(log n) select via `SuccinctBitmap` against
//! the plain `bitmap_count_free` / `bitmap_find_free` O(n) helpers.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ffs_alloc::succinct::SuccinctBitmap;
use ffs_alloc::{bitmap_count_free, bitmap_find_free};

/// Build a realistic ext4-like bitmap: 4096 bytes (32768 bits),
/// ~5% free blocks scattered in clusters.
fn make_bitmap() -> Vec<u8> {
    let mut bm = vec![0xFF_u8; 4096];
    // Free a cluster every ~650 blocks (≈5% free).
    let mut pos = 100_usize;
    while pos + 32 < 32768 {
        for i in pos..pos + 32 {
            bm[i / 8] &= !(1 << (i % 8));
        }
        pos += 650;
    }
    bm
}

fn bench_count_free(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);

    let mut group = c.benchmark_group("count_free");

    group.bench_function("plain_O(n)", |b| {
        b.iter(|| black_box(bitmap_count_free(black_box(&bm), 32768)));
    });

    group.bench_function("succinct_O(1)", |b| {
        b.iter(|| black_box(sb.count_zeros()));
    });

    group.finish();
}

fn bench_find_free(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);

    let mut group = c.benchmark_group("find_free");

    group.bench_function("plain_O(n)", |b| {
        b.iter(|| black_box(bitmap_find_free(black_box(&bm), 32768, black_box(16000))));
    });

    group.bench_function("succinct_O(log_n)", |b| {
        b.iter(|| black_box(sb.find_free(black_box(16000))));
    });

    group.finish();
}

fn bench_rank(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);

    c.bench_function("succinct_rank0", |b| {
        b.iter(|| black_box(sb.rank0(black_box(20000))));
    });
}

fn bench_select(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);
    let target = sb.count_zeros() / 2; // select the middle free block

    c.bench_function("succinct_select0", |b| {
        b.iter(|| black_box(sb.select0(black_box(target))));
    });
}

fn bench_build(c: &mut Criterion) {
    let bm = make_bitmap();

    c.bench_function("succinct_build", |b| {
        b.iter(|| black_box(SuccinctBitmap::build(black_box(&bm), 32768)));
    });
}

criterion_group!(
    benches,
    bench_count_free,
    bench_find_free,
    bench_rank,
    bench_select,
    bench_build,
);
criterion_main!(benches);
