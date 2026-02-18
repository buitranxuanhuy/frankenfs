#![forbid(unsafe_code)]
//! Benchmark: Bw-Tree vs Mutex-protected BTreeMap for concurrent extent index ops.
//!
//! Scenarios:
//! 1. Read-heavy (95% lookup, 5% insert)
//! 2. Write-heavy (30% lookup, 70% insert/delete)
//! 3. Mixed workload (50% lookup, 30% insert, 10% delete, 10% range scan)
//! 4. Single-threaded baseline
//! 5. Consolidation overhead

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_btree::bw_tree::{BwKey, BwValue, ConsolidationConfig, MappingTable, PageId};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier, Mutex};

const PAGE_CAPACITY: usize = 16;
const PREPOPULATE: u64 = 10_000;
const OPS_PER_THREAD: u64 = 5_000;

// ── Locked BTreeMap baseline ────────────────────────────────────────────

struct LockedBTree {
    inner: Mutex<BTreeMap<u64, u64>>,
}

impl LockedBTree {
    fn new() -> Self {
        Self {
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    fn insert(&self, key: u64, value: u64) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, value);
    }

    fn lookup(&self, key: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .copied()
    }

    fn delete(&self, key: u64) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key);
    }

    fn range_scan(&self, start: u64, count: usize) -> Vec<(u64, u64)> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .range(start..)
            .take(count)
            .map(|(&k, &v)| (k, v))
            .collect()
    }
}

// ── Deterministic RNG for workload generation ───────────────────────────

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// ── Scenario 1: Read-Heavy (95% lookup, 5% insert) ─────────────────────

fn bench_read_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_heavy");
    group.sample_size(10);

    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("bwtree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..PREPOPULATE {
                        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
                    }
                    // Consolidate before benchmark
                    let cfg = ConsolidationConfig::default();
                    let _ = table.consolidate_page(page, &cfg);

                    run_bwtree_workload(&table, page, thread_count, 95, 5, 0, 0);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("locked_btree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let tree = Arc::new(LockedBTree::new());
                    for i in 0..PREPOPULATE {
                        tree.insert(i, i);
                    }
                    run_locked_workload(&tree, thread_count, 95, 5, 0, 0);
                });
            },
        );
    }
    group.finish();
}

// ── Scenario 2: Write-Heavy (30% lookup, 70% insert/delete) ────────────

fn bench_write_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_heavy");
    group.sample_size(10);

    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("bwtree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..PREPOPULATE {
                        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
                    }
                    let cfg = ConsolidationConfig::default();
                    let _ = table.consolidate_page(page, &cfg);

                    run_bwtree_workload(&table, page, thread_count, 30, 40, 30, 0);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("locked_btree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let tree = Arc::new(LockedBTree::new());
                    for i in 0..PREPOPULATE {
                        tree.insert(i, i);
                    }
                    run_locked_workload(&tree, thread_count, 30, 40, 30, 0);
                });
            },
        );
    }
    group.finish();
}

// ── Scenario 3: Mixed workload ──────────────────────────────────────────

fn bench_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed");
    group.sample_size(10);

    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("bwtree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..PREPOPULATE {
                        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
                    }
                    let cfg = ConsolidationConfig::default();
                    let _ = table.consolidate_page(page, &cfg);

                    run_bwtree_workload(&table, page, thread_count, 50, 30, 10, 10);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("locked_btree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let tree = Arc::new(LockedBTree::new());
                    for i in 0..PREPOPULATE {
                        tree.insert(i, i);
                    }
                    run_locked_workload(&tree, thread_count, 50, 30, 10, 10);
                });
            },
        );
    }
    group.finish();
}

// ── Scenario 5: Consolidation overhead ──────────────────────────────────

fn bench_consolidation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("consolidation");
    group.sample_size(10);

    // Measure consolidation cost for varying chain lengths
    for chain_len in [10_u64, 50, 200] {
        group.bench_with_input(
            BenchmarkId::new("consolidate", chain_len),
            &chain_len,
            |b, &len| {
                b.iter(|| {
                    let table = MappingTable::with_capacity(1);
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..len {
                        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
                    }
                    let cfg = ConsolidationConfig {
                        chain_threshold: 1,
                        max_retries: 64,
                    };
                    table.consolidate_page(page, &cfg).expect("consolidate");
                });
            },
        );
    }
    group.finish();
}

// ── Workload runners ────────────────────────────────────────────────────

fn run_bwtree_workload(
    table: &Arc<MappingTable>,
    page: PageId,
    thread_count: usize,
    lookup_pct: u64,
    insert_pct: u64,
    delete_pct: u64,
    scan_pct: u64,
) {
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();
    let total = lookup_pct + insert_pct + delete_pct + scan_pct;

    for tid in 0..thread_count {
        let table = Arc::clone(table);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut rng = (tid as u64 + 1) * 6_364_136_223_846_793_005;
            for _ in 0..OPS_PER_THREAD {
                let op = xorshift64(&mut rng) % total;
                let key = xorshift64(&mut rng) % (PREPOPULATE * 2);
                if op < lookup_pct {
                    let _ = table.lookup(page, BwKey(key));
                } else if op < lookup_pct + insert_pct {
                    let _ = table.insert(page, BwKey(key), BwValue(key + 1));
                } else if op < lookup_pct + insert_pct + delete_pct {
                    let _ = table.delete(page, BwKey(key));
                } else {
                    // Range scan: materialize and check a few entries
                    let _ = table.materialize_page(page);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("no panic");
    }
}

fn run_locked_workload(
    tree: &Arc<LockedBTree>,
    thread_count: usize,
    lookup_pct: u64,
    insert_pct: u64,
    delete_pct: u64,
    scan_pct: u64,
) {
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();
    let total = lookup_pct + insert_pct + delete_pct + scan_pct;

    for tid in 0..thread_count {
        let tree = Arc::clone(tree);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut rng = (tid as u64 + 1) * 6_364_136_223_846_793_005;
            for _ in 0..OPS_PER_THREAD {
                let op = xorshift64(&mut rng) % total;
                let key = xorshift64(&mut rng) % (PREPOPULATE * 2);
                if op < lookup_pct {
                    let _ = tree.lookup(key);
                } else if op < lookup_pct + insert_pct {
                    tree.insert(key, key + 1);
                } else if op < lookup_pct + insert_pct + delete_pct {
                    tree.delete(key);
                } else {
                    let _ = tree.range_scan(key, 10);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("no panic");
    }
}

criterion_group!(
    benches,
    bench_read_heavy,
    bench_write_heavy,
    bench_mixed,
    bench_consolidation_overhead,
);
criterion_main!(benches);
