#![forbid(unsafe_code)]

//! WAL commit write throughput benchmark.
//!
//! Measures how fast `PersistentMvccStore` can persist commits to the WAL.
//! Target: 100K entries/sec.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_mvcc::persist::{PersistOptions, PersistentMvccStore};
use ffs_types::BlockNumber;
use tempfile::NamedTempFile;

fn bench_wal_commit_throughput(c: &mut Criterion) {
    let cx = Cx::for_testing();

    // 4 KiB block — typical filesystem block size.
    let block_data = vec![0xAB_u8; 4096];

    c.bench_function("wal_commit_4k_sync", |b| {
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let store = PersistentMvccStore::open_with_options(&cx, &path, PersistOptions::default())
            .expect("open");

        let mut block_id = 0_u64;

        b.iter(|| {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(block_id % 1024), block_data.clone());
            store.commit(txn).expect("commit");
            block_id += 1;
        });
    });

    c.bench_function("wal_commit_4k_nosync", |b| {
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let store = PersistentMvccStore::open_with_options(
            &cx,
            &path,
            PersistOptions {
                sync_on_commit: false,
            },
        )
        .expect("open");

        let mut block_id = 0_u64;

        b.iter(|| {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(block_id % 1024), block_data.clone());
            store.commit(txn).expect("commit");
            block_id += 1;
        });
    });

    // Multi-write commit: 4 blocks per transaction.
    c.bench_function("wal_commit_4x4k_nosync", |b| {
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let store = PersistentMvccStore::open_with_options(
            &cx,
            &path,
            PersistOptions {
                sync_on_commit: false,
            },
        )
        .expect("open");

        let mut block_id = 0_u64;

        b.iter(|| {
            let mut txn = store.begin();
            for j in 0..4_u64 {
                txn.stage_write(BlockNumber((block_id + j) % 4096), block_data.clone());
            }
            store.commit(txn).expect("commit");
            block_id += 4;
        });
    });
}

criterion_group!(wal_benches, bench_wal_commit_throughput);
criterion_main!(wal_benches);
