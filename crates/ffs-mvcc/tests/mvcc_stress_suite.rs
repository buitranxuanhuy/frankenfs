use asupersync::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;
use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_mvcc::{CommitError, CompressionAlgo, CompressionPolicy, GcBackpressureConfig, MvccStore};
use ffs_types::{BlockNumber, Snapshot};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

struct YieldOnce {
    yielded: bool,
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

async fn yield_now() {
    YieldOnce { yielded: false }.await;
}

#[derive(Clone, Copy)]
enum WorkloadPattern {
    Random,
    Hotspot,
    Sequential,
    Adversarial,
}

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    *state
}

fn choose_block(
    pattern: WorkloadPattern,
    op: u64,
    rng_state: &mut u64,
    block_count: u64,
) -> BlockNumber {
    debug_assert!(block_count > 0);
    let block = match pattern {
        WorkloadPattern::Random => lcg_next(rng_state) % block_count,
        WorkloadPattern::Hotspot => {
            let hotset = (block_count / 10).max(1);
            if lcg_next(rng_state) % 10 < 9 {
                lcg_next(rng_state) % hotset
            } else {
                lcg_next(rng_state) % block_count
            }
        }
        WorkloadPattern::Sequential => op % block_count,
        WorkloadPattern::Adversarial => 0,
    };
    BlockNumber(block)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "stress test intentionally keeps end-to-end orchestration in one place"
)]
fn stress_concurrent_rw() {
    const BLOCK_COUNT: u64 = 64;
    const WRITER_COUNT: u64 = 6;
    const READER_COUNT: u64 = 6;
    const OPS_PER_WRITER: u64 = 300;
    const READS_PER_READER: u64 = 300;

    for seed in 0_u64..8 {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(1_000_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let store = Arc::new(ShardedMvccStore::new(8));

        let mut seed_txn = store.begin();
        for block in 0_u64..BLOCK_COUNT {
            seed_txn.stage_write(BlockNumber(block), vec![0; 16]);
        }
        store.commit(seed_txn).expect("seed commit should succeed");

        let committed = Arc::new(AtomicU64::new(0));
        let conflicts = Arc::new(AtomicU64::new(0));
        let stable_reads = Arc::new(AtomicU64::new(0));

        let writer_patterns = [
            WorkloadPattern::Random,
            WorkloadPattern::Hotspot,
            WorkloadPattern::Sequential,
            WorkloadPattern::Adversarial,
            WorkloadPattern::Random,
            WorkloadPattern::Hotspot,
        ];

        for writer_id in 0_u64..WRITER_COUNT {
            let store = Arc::clone(&store);
            let committed = Arc::clone(&committed);
            let conflicts = Arc::clone(&conflicts);
            let pattern =
                writer_patterns[usize::try_from(writer_id).expect("writer id fits in usize")];
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let mut rng_state = seed
                        ^ writer_id
                            .wrapping_add(1)
                            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
                    for op in 0_u64..OPS_PER_WRITER {
                        yield_now().await;
                        let block = choose_block(pattern, op, &mut rng_state, BLOCK_COUNT);
                        let mut txn = store.begin();
                        let byte = u8::try_from((writer_id + op) % 251).expect("value fits in u8");
                        txn.stage_write(block, vec![byte; 16]);
                        match store.commit(txn) {
                            Ok(_) => {
                                committed.fetch_add(1, Ordering::Relaxed);
                            }
                            Err((CommitError::Conflict { .. }, _)) => {
                                conflicts.fetch_add(1, Ordering::Relaxed);
                            }
                            Err((err, _)) => {
                                panic!("seed {seed}: writer {writer_id} op {op} unexpected {err:?}")
                            }
                        }
                    }
                })
                .expect("create writer task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        for reader_id in 0_u64..READER_COUNT {
            let store = Arc::clone(&store);
            let stable_reads = Arc::clone(&stable_reads);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let mut rng_state = seed
                        ^ reader_id
                            .wrapping_add(1)
                            .wrapping_mul(0xA076_1D64_78BD_642F_u64);
                    for op in 0_u64..READS_PER_READER {
                        yield_now().await;
                        let snapshot = store.current_snapshot();
                        let base_block =
                            choose_block(WorkloadPattern::Hotspot, op, &mut rng_state, BLOCK_COUNT);
                        for offset in 0_u64..4 {
                            let block = BlockNumber((base_block.0 + offset) % BLOCK_COUNT);
                            let first = store
                                .read_visible(block, snapshot)
                                .expect("seeded block must remain readable");
                            let second = store
                                .read_visible(block, snapshot)
                                .expect("seeded block must remain readable");
                            assert_eq!(
                                first, second,
                                "seed {seed}: reader {reader_id} observed non-repeatable read at op {op} block {}",
                                block.0
                            );
                            stable_reads.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
                .expect("create reader task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        let commit_count = committed.load(Ordering::Relaxed);
        let conflict_count = conflicts.load(Ordering::Relaxed);
        let stable_read_count = stable_reads.load(Ordering::Relaxed);

        assert!(
            commit_count > 0,
            "seed {seed}: expected at least one committed write"
        );
        assert!(
            stable_read_count > 0,
            "seed {seed}: expected reader checks to run"
        );
        assert!(
            commit_count + conflict_count == WRITER_COUNT * OPS_PER_WRITER,
            "seed {seed}: commit+conflict accounting mismatch"
        );

        let latest = store.current_snapshot();
        for block in 0_u64..BLOCK_COUNT {
            let data = store
                .read_visible(BlockNumber(block), latest)
                .expect("seeded block remains visible");
            assert_eq!(
                data.len(),
                16,
                "seed {seed}: block {block} should retain 16-byte payloads"
            );
        }
    }
}

#[test]
fn stress_fcw_conflicts() {
    const WRITER_PAIRS_PER_SEED: u64 = 2_000;
    let hot_block = BlockNumber(1);

    for seed in 0_u64..16 {
        let store = ShardedMvccStore::new(1);

        let mut seed_txn = store.begin();
        seed_txn.stage_write(hot_block, vec![0; 8]);
        store.commit(seed_txn).expect("seed commit should succeed");

        let mut commit_count = 0_u64;
        let mut conflict_count = 0_u64;

        let mut rng_state = seed.wrapping_add(0xD1B5_4A32_D192_ED03);
        for pair in 0_u64..WRITER_PAIRS_PER_SEED {
            let mut txn_one = store.begin();
            let mut txn_two = store.begin();
            let byte_one = u8::try_from((lcg_next(&mut rng_state) + pair) % 251).expect("fits");
            let byte_two = u8::try_from((lcg_next(&mut rng_state) + pair + 1) % 251).expect("fits");
            txn_one.stage_write(hot_block, vec![byte_one; 8]);
            txn_two.stage_write(hot_block, vec![byte_two; 8]);

            let (first, second) = if lcg_next(&mut rng_state).is_multiple_of(2) {
                (txn_one, txn_two)
            } else {
                (txn_two, txn_one)
            };

            match store.commit(first) {
                Ok(_) => commit_count += 1,
                Err((err, _)) => panic!("seed {seed}: first commit in pair {pair} failed: {err:?}"),
            }
            match store.commit(second) {
                Ok(_) => panic!("seed {seed}: second commit in pair {pair} must conflict"),
                Err((CommitError::Conflict { .. }, _)) => conflict_count += 1,
                Err((err, _)) => {
                    panic!("seed {seed}: unexpected FCW error in pair {pair}: {err:?}")
                }
            }
        }

        assert!(
            commit_count > 0,
            "seed {seed}: at least one writer should commit"
        );
        assert!(
            conflict_count > 0,
            "seed {seed}: FCW stress should produce conflicts on hot block"
        );
        assert_eq!(
            commit_count, WRITER_PAIRS_PER_SEED,
            "seed {seed}: every first commit should succeed"
        );
        assert_eq!(
            conflict_count, WRITER_PAIRS_PER_SEED,
            "seed {seed}: every second commit should conflict"
        );

        let latest = store.current_snapshot();
        let data = store
            .read_visible(hot_block, latest)
            .expect("hot block must remain readable");
        assert_eq!(data.len(), 8, "seed {seed}: payload width should remain 8");
    }
}

#[test]
fn stress_ssi_write_skew() {
    let block_a = BlockNumber(100);
    let block_b = BlockNumber(200);

    for seed in 0_u64..128 {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(200_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let store = Arc::new(Mutex::new(MvccStore::new()));

        {
            let mut guard = store.lock().expect("store lock");
            let mut seed_txn = guard.begin();
            seed_txn.stage_write(block_a, vec![1]);
            seed_txn.stage_write(block_b, vec![1]);
            guard.commit_ssi(seed_txn).expect("seed commit");
        }

        let outcomes = Arc::new(Mutex::new((None, None)));
        let ((mut txn_one, a_ver), (mut txn_two, b_ver)) = {
            let mut guard = store.lock().expect("store lock");
            let first = guard.begin();
            let a_ver = guard.latest_commit_seq(block_a);
            let second = guard.begin();
            let b_ver = guard.latest_commit_seq(block_b);
            drop(guard);
            ((first, a_ver), (second, b_ver))
        };

        {
            let store = Arc::clone(&store);
            let outcomes = Arc::clone(&outcomes);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    if seed % 2 == 0 {
                        yield_now().await;
                    }
                    txn_one.record_read(block_a, a_ver);
                    txn_one.stage_write(block_b, vec![2]);
                    let result = store
                        .lock()
                        .expect("store lock")
                        .commit_ssi(txn_one)
                        .is_ok();
                    outcomes.lock().expect("outcomes lock").0 = Some(result);
                })
                .expect("create txn_one task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        {
            let store = Arc::clone(&store);
            let outcomes = Arc::clone(&outcomes);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    if seed % 2 == 1 {
                        yield_now().await;
                    }
                    txn_two.record_read(block_b, b_ver);
                    txn_two.stage_write(block_a, vec![2]);
                    let result = store
                        .lock()
                        .expect("store lock")
                        .commit_ssi(txn_two)
                        .is_ok();
                    outcomes.lock().expect("outcomes lock").1 = Some(result);
                })
                .expect("create txn_two task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        let (txn_one_ok, txn_two_ok) = {
            let guard = outcomes.lock().expect("outcomes lock");
            (
                guard.0.expect("txn_one completed"),
                guard.1.expect("txn_two completed"),
            )
        };
        assert!(
            txn_one_ok ^ txn_two_ok,
            "seed {seed}: SSI write-skew should allow exactly one commit, got txn_one={txn_one_ok}, txn_two={txn_two_ok}"
        );

        let guard = store.lock().expect("store lock");
        let snap = guard.current_snapshot();
        let a = guard.read_visible(block_a, snap).expect("A visible")[0];
        let b = guard.read_visible(block_b, snap).expect("B visible")[0];
        drop(guard);
        assert_eq!(
            a + b,
            3,
            "seed {seed}: SSI should prevent double-write skew (a={a}, b={b})"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "stress test intentionally combines writers, GC, and cleanup assertions"
)]
fn stress_gc_under_load() {
    const BLOCK_COUNT: u64 = 32;
    const WRITER_COUNT: u64 = 4;
    const OPS_PER_WRITER: u64 = 500;
    const MAX_CHAIN: usize = 48;

    let gc_config = GcBackpressureConfig {
        min_poll_quota: 0,
        throttle_sleep: Duration::from_millis(0),
    };

    for seed in 0_u64..6 {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(2_000_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let store = Arc::new(Mutex::new(MvccStore::with_compression_policy(
            CompressionPolicy {
                dedup_identical: false,
                max_chain_length: Some(MAX_CHAIN),
                algo: CompressionAlgo::None,
            },
        )));
        let held_snapshots: Arc<Mutex<VecDeque<Snapshot>>> = Arc::new(Mutex::new(VecDeque::new()));
        let gc_batches = Arc::new(AtomicU64::new(0));

        {
            let mut guard = store.lock().expect("store lock");
            let mut seed_txn = guard.begin();
            for block in 0_u64..BLOCK_COUNT {
                seed_txn.stage_write(BlockNumber(block), vec![0; 32]);
            }
            guard.commit(seed_txn).expect("seed commit");
        }

        for writer_id in 0_u64..WRITER_COUNT {
            let store = Arc::clone(&store);
            let held_snapshots = Arc::clone(&held_snapshots);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let mut rng_state = seed
                        ^ writer_id
                            .wrapping_add(5)
                            .wrapping_mul(0x517C_C1B7_2722_0A95);
                    for op in 0_u64..OPS_PER_WRITER {
                        yield_now().await;
                        let block =
                            choose_block(WorkloadPattern::Hotspot, op, &mut rng_state, BLOCK_COUNT);
                        let mut guard = store.lock().expect("store lock");
                        let mut txn = guard.begin();
                        let byte = u8::try_from((writer_id + op + seed) % 251).expect("fits in u8");
                        txn.stage_write(block, vec![byte; 32]);
                        match guard.commit(txn) {
                            Ok(_)
                            | Err(
                                CommitError::Conflict { .. }
                                | CommitError::ChainBackpressure { .. },
                            ) => {}
                            Err(err) => {
                                panic!("seed {seed}: writer {writer_id} op {op} unexpected {err:?}")
                            }
                        }

                        if op % 25 == 0 {
                            let snap = guard.current_snapshot();
                            guard.register_snapshot(snap);
                            let old = {
                                let mut held = held_snapshots.lock().expect("held snapshots");
                                held.push_back(snap);
                                (held.len() > 8)
                                    .then(|| held.pop_front().expect("existing snapshot"))
                            };
                            if let Some(old) = old {
                                let _ = guard.release_snapshot(old);
                            }
                        }

                        if op % 16 == 0 {
                            let _ = guard.prune_safe();
                        }
                    }
                })
                .expect("create writer task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        {
            let store = Arc::clone(&store);
            let gc_batches = Arc::clone(&gc_batches);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::for_testing();
                    for _ in 0_u64..(OPS_PER_WRITER / 2) {
                        yield_now().await;
                        let mut guard = store.lock().expect("store lock");
                        let _ = guard.prune_safe();
                        let _ = guard.run_gc_batch(&cx, gc_config);
                        guard.ebr_collect();
                        drop(guard);
                        gc_batches.fetch_add(1, Ordering::Relaxed);
                    }
                })
                .expect("create gc task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        {
            let cx = Cx::for_testing();
            let mut guard = store.lock().expect("store lock");
            let mut held = held_snapshots.lock().expect("held snapshots");
            while let Some(snapshot) = held.pop_front() {
                let _ = guard.release_snapshot(snapshot);
            }
            drop(held);

            for _ in 0..8 {
                let _ = guard.prune_safe();
                let _ = guard.run_gc_batch(&cx, gc_config);
                guard.ebr_collect();
            }

            let ebr_stats = guard.ebr_stats();
            let block_stats = guard.block_version_stats();
            assert_eq!(
                ebr_stats.pending_versions(),
                0,
                "seed {seed}: GC should drain pending retired versions"
            );
            assert!(
                block_stats.max_chain_length <= MAX_CHAIN,
                "seed {seed}: max chain {} exceeded cap {MAX_CHAIN}",
                block_stats.max_chain_length
            );
            drop(guard);
        }

        assert!(
            gc_batches.load(Ordering::Relaxed) > 0,
            "seed {seed}: expected gc batches to run"
        );
    }
}

#[test]
fn stress_version_chain_growth() {
    const MAX_CHAIN: usize = 32;
    const WRITER_COUNT: u64 = 4;
    const OPS_PER_WRITER: u64 = 1_200;
    let hot_block = BlockNumber(930);

    for seed in 0_u64..8 {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(2_500_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let store = Arc::new(Mutex::new(MvccStore::with_compression_policy(
            CompressionPolicy {
                dedup_identical: false,
                max_chain_length: Some(MAX_CHAIN),
                algo: CompressionAlgo::None,
            },
        )));
        let backpressure_events = Arc::new(AtomicU64::new(0));

        {
            let mut guard = store.lock().expect("store lock");
            let mut seed_txn = guard.begin();
            seed_txn.stage_write(hot_block, vec![0; 16]);
            guard.commit(seed_txn).expect("seed commit");
        }

        for writer_id in 0_u64..WRITER_COUNT {
            let store = Arc::clone(&store);
            let backpressure_events = Arc::clone(&backpressure_events);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    for op in 0_u64..OPS_PER_WRITER {
                        yield_now().await;
                        let mut guard = store.lock().expect("store lock");
                        let mut txn = guard.begin();
                        let byte = u8::try_from((writer_id + op + seed) % 251).expect("fits in u8");
                        txn.stage_write(hot_block, vec![byte; 16]);
                        match guard.commit(txn) {
                            Err(CommitError::ChainBackpressure { .. }) => {
                                backpressure_events.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(_) | Err(CommitError::Conflict { .. }) => {}
                            Err(err) => panic!("seed {seed}: unexpected commit error {err:?}"),
                        }
                        if op % 8 == 0 {
                            let _ = guard.prune_safe();
                        }
                    }
                })
                .expect("create writer task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        {
            let mut guard = store.lock().expect("store lock");
            let _ = guard.prune_safe();
            guard.ebr_collect();
            let block_stats = guard.block_version_stats();
            assert!(
                block_stats.max_chain_length <= MAX_CHAIN,
                "seed {seed}: chain length {} exceeded cap {MAX_CHAIN}",
                block_stats.max_chain_length
            );
            let latest = guard.current_snapshot();
            assert!(
                guard.read_visible(hot_block, latest).is_some(),
                "seed {seed}: latest value must remain visible"
            );
            drop(guard);
        }

        let _ = backpressure_events.load(Ordering::Relaxed);
    }
}
