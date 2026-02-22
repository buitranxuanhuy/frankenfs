#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
//! E2E performance regression test for block cache operations.
//!
//! Runs a suite of deterministic workloads against in-memory block devices and
//! compares measured metrics against stored baselines. Fails if any operation
//! regresses beyond the configured threshold.
//!
//! Baselines are stored in `benchmarks/baselines/latest.json` and should be
//! updated via `scripts/bench_s3fifo_vs_arc.sh --rch` when intentional
//! performance changes are made.
//!
//! Run with `--nocapture` to see the full regression report:
//! ```sh
//! cargo test -p ffs-block --test perf_regression_e2e -- --nocapture
//! ```

use asupersync::Cx;
use ffs_block::{ArcCache, ArcWritePolicy, BlockBuf, BlockDevice, ByteBlockDevice, ByteDevice};
use ffs_error::Result;
use ffs_types::{BlockNumber, ByteOffset};
use parking_lot::Mutex;
use std::cmp::Ordering;
use std::time::{Duration, Instant};

const BLOCK_SIZE_4K: u32 = 4096;

// ── Regression thresholds ───────────────────────────────────────────────

/// Warn if p99 latency regresses by more than this percentage.
/// Latency checks are advisory-only (warn, never fail) because absolute
/// timings vary across heterogeneous CI hardware.
const WARN_THRESHOLD_PERCENT: f64 = 10.0;
/// Warn if hit rate drops by more than this many percentage points.
const HIT_RATE_WARN_PP: f64 = 2.0;
/// Fail if hit rate drops by more than this many percentage points.
const HIT_RATE_FAIL_PP: f64 = 5.0;

// ── Baselines (from benchmarks/baselines/latest.json, commit a923dd9) ───

/// Baseline hit rates captured on 2026-02-18.
const BASELINE_HIT_RATES: &[(&str, f64)] = &[
    ("sequential_scan", 0.000_000),
    ("zipf_distribution", 0.773_917),
    ("mixed_seq70_hot30", 0.310_292),
    ("compile_like", 0.153_893),
    ("database_like", 0.852_160),
];

/// Baseline p99 lookup latency in microseconds (Zipf workload, warm cache).
/// This is advisory-only — latency varies across hardware so regressions
/// are reported as warnings, not failures.
const BASELINE_LOOKUP_P99_US: f64 = 10.4;

/// Maximum allowed total test duration.
const MAX_TEST_DURATION: Duration = Duration::from_secs(120);

// ── In-memory ByteDevice ────────────────────────────────────────────────

#[derive(Debug)]
struct MemByteDevice {
    bytes: Mutex<Vec<u8>>,
}

impl MemByteDevice {
    fn new(size: usize) -> Self {
        Self {
            bytes: Mutex::new(vec![0u8; size]),
        }
    }
}

impl ByteDevice for MemByteDevice {
    fn len_bytes(&self) -> u64 {
        self.bytes.lock().len() as u64
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let off = offset.0 as usize;
        let guard = self.bytes.lock();
        buf.copy_from_slice(&guard[off..off + buf.len()]);
        drop(guard);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let off = offset.0 as usize;
        let mut guard = self.bytes.lock();
        guard[off..off + buf.len()].copy_from_slice(buf);
        drop(guard);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn make_cache(
    block_size: u32,
    block_count: usize,
    capacity: usize,
) -> ArcCache<ByteBlockDevice<MemByteDevice>> {
    let mem = MemByteDevice::new(block_size as usize * block_count);
    let dev = ByteBlockDevice::new(mem, block_size).expect("device");
    ArcCache::new(dev, capacity).expect("cache")
}

fn make_writeback_cache(
    block_size: u32,
    block_count: usize,
    capacity: usize,
) -> ArcCache<ByteBlockDevice<MemByteDevice>> {
    let mem = MemByteDevice::new(block_size as usize * block_count);
    let dev = ByteBlockDevice::new(mem, block_size).expect("device");
    ArcCache::new_with_policy(dev, capacity, ArcWritePolicy::WriteBack).expect("cache")
}

// ── Deterministic RNG ───────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Rng64 {
    state: u64,
}

impl Rng64 {
    fn seeded(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    fn next_usize(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            return 0;
        }
        (self.next_u64() % upper as u64) as usize
    }

    fn next_f64(&mut self) -> f64 {
        let value = self.next_u64() >> 11;
        value as f64 * (1.0 / (1_u64 << 53) as f64)
    }
}

fn zipf_cdf(domain: usize, exponent: f64) -> Vec<f64> {
    let mut cdf = Vec::with_capacity(domain);
    let mut total = 0.0_f64;
    for rank in 1..=domain {
        total += 1.0 / (rank as f64).powf(exponent);
        cdf.push(total);
    }
    if total > 0.0 {
        for probability in &mut cdf {
            *probability /= total;
        }
    }
    cdf
}

fn sample_zipf(cdf: &[f64], rng: &mut Rng64) -> usize {
    let needle = rng.next_f64();
    match cdf.binary_search_by(|value| value.partial_cmp(&needle).unwrap_or(Ordering::Less)) {
        Ok(pos) | Err(pos) => pos.min(cdf.len().saturating_sub(1)),
    }
}

// ── Workload definitions ────────────────────────────────────────────────

struct Workload {
    name: &'static str,
    block_count: usize,
    capacity: usize,
    trace: Vec<BlockNumber>,
}

fn sequential_scan_workload() -> Workload {
    let block_count = 4_096;
    let capacity = 512;
    let mut trace = Vec::with_capacity(block_count * 4);
    for _ in 0..4 {
        for block in 0..block_count as u64 {
            trace.push(BlockNumber(block));
        }
    }
    Workload {
        name: "sequential_scan",
        block_count,
        capacity,
        trace,
    }
}

fn zipf_workload() -> Workload {
    let block_count = 4_096;
    let capacity = 512;
    let zipf = zipf_cdf(block_count, 1.07);
    let mut rng = Rng64::seeded(0xA1A1_0002);
    let mut trace = Vec::with_capacity(24_000);
    for _ in 0..24_000 {
        trace.push(BlockNumber(sample_zipf(&zipf, &mut rng) as u64));
    }
    Workload {
        name: "zipf_distribution",
        block_count,
        capacity,
        trace,
    }
}

fn mixed_seq_hot_workload() -> Workload {
    let block_count = 4_096;
    let capacity = 512;
    let hot_set: Vec<BlockNumber> = (0..64_u64).map(BlockNumber).collect();
    let mut rng = Rng64::seeded(0xA1A1_0003);
    let mut cursor = 0_u64;
    let mut trace = Vec::with_capacity(24_000);
    for _ in 0..24_000 {
        if rng.next_f64() < 0.70 {
            trace.push(BlockNumber(cursor % block_count as u64));
            cursor = cursor.wrapping_add(1);
        } else {
            trace.push(hot_set[rng.next_usize(hot_set.len())]);
        }
    }
    Workload {
        name: "mixed_seq70_hot30",
        block_count,
        capacity,
        trace,
    }
}

fn compile_like_workload() -> Workload {
    let capacity = 640;
    let metadata_hot = 32_u64;
    let small_files = 1_536;
    let large_files = 24;
    let large_file_blocks = 96;
    let small_base = metadata_hot;
    let large_base = small_base + small_files as u64 + 128;
    let block_count = large_base as usize + large_files * large_file_blocks + 256;
    let mut rng = Rng64::seeded(0xA1A1_0004);
    let mut trace = Vec::with_capacity(16 * (32 + 320 + 6 * 96));
    for _ in 0..16 {
        for b in 0..metadata_hot {
            trace.push(BlockNumber(b));
        }
        for _ in 0..320 {
            trace.push(BlockNumber(small_base + rng.next_usize(small_files) as u64));
        }
        for _ in 0..6 {
            let large = rng.next_usize(large_files);
            let start = large_base + (large * large_file_blocks) as u64;
            for off in 0..large_file_blocks as u64 {
                trace.push(BlockNumber(start + off));
            }
        }
    }
    Workload {
        name: "compile_like",
        block_count,
        capacity,
        trace,
    }
}

fn database_like_workload() -> Workload {
    let capacity = 768;
    let root_pages = [0_u64, 1];
    let internal_start = 2_u64;
    let internal_pages = 128;
    let leaf_start = 512_u64;
    let leaf_pages = 8_192;
    let leaf_zipf = zipf_cdf(leaf_pages, 1.12);
    let block_count = leaf_start as usize + leaf_pages + 256;
    let mut rng = Rng64::seeded(0xA1A1_0005);
    let mut trace = Vec::with_capacity(12_000 * 4);
    for _ in 0..12_000 {
        trace.push(BlockNumber(root_pages[rng.next_usize(root_pages.len())]));
        trace.push(BlockNumber(
            internal_start + rng.next_usize(internal_pages) as u64,
        ));
        trace.push(BlockNumber(
            leaf_start + sample_zipf(&leaf_zipf, &mut rng) as u64,
        ));
        if rng.next_usize(100) < 2 {
            let scan_start = rng.next_usize(leaf_pages.saturating_sub(12));
            for off in 0..12 {
                trace.push(BlockNumber(leaf_start + (scan_start + off) as u64));
            }
        }
    }
    Workload {
        name: "database_like",
        block_count,
        capacity,
        trace,
    }
}

// ── Measurement helpers ─────────────────────────────────────────────────

struct WorkloadMeasurement {
    name: &'static str,
    hit_rate: f64,
}

fn measure_workload(w: &Workload) -> WorkloadMeasurement {
    let cx = Cx::for_testing();
    let cache = make_cache(BLOCK_SIZE_4K, w.block_count, w.capacity);
    for block in &w.trace {
        let _: BlockBuf = cache.read_block(&cx, *block).expect("cache read");
    }
    let m = cache.metrics();
    WorkloadMeasurement {
        name: w.name,
        hit_rate: m.hit_ratio(),
    }
}

struct LatencyMeasurement {
    p50: Duration,
    p95: Duration,
    p99: Duration,
}

fn measure_lookup_latency() -> LatencyMeasurement {
    let cx = Cx::for_testing();
    let cache = make_cache(BLOCK_SIZE_4K, 4096, 512);

    // Warm up with Zipf distribution
    let zipf = zipf_cdf(4096, 1.07);
    let mut rng = Rng64::seeded(0xBEEF_0001);
    for _ in 0..10_000 {
        let block = BlockNumber(sample_zipf(&zipf, &mut rng) as u64);
        let _ = cache.read_block(&cx, block).expect("warmup");
    }

    // Measure 1000 lookups
    let mut latencies = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let block = BlockNumber(sample_zipf(&zipf, &mut rng) as u64);
        let start = Instant::now();
        let _ = cache.read_block(&cx, block).expect("read");
        latencies.push(start.elapsed());
    }
    latencies.sort();

    LatencyMeasurement {
        p50: latencies[499],
        p95: latencies[949],
        p99: latencies[989],
    }
}

struct WritebackMeasurement {
    single_4k_duration: Duration,
    batch_100x4k_duration: Duration,
}

fn measure_writeback() -> WritebackMeasurement {
    let cx = Cx::for_testing();
    let payload = vec![0xAB; BLOCK_SIZE_4K as usize];

    // Single 4K write + sync
    let cache = make_writeback_cache(BLOCK_SIZE_4K, 512, 256);
    let start = Instant::now();
    for i in 0..100_u64 {
        cache
            .write_block(&cx, BlockNumber(i % 256), &payload)
            .expect("write");
        cache.sync(&cx).expect("sync");
    }
    let single_4k_duration = start.elapsed() / 100;

    // Batch 100x4K write + single sync
    let cache = make_writeback_cache(BLOCK_SIZE_4K, 2048, 1024);
    let start = Instant::now();
    for i in 0..100_u64 {
        cache
            .write_block(&cx, BlockNumber(i), &payload)
            .expect("write");
    }
    cache.sync(&cx).expect("sync");
    let batch_100x4k_duration = start.elapsed();

    WritebackMeasurement {
        single_4k_duration,
        batch_100x4k_duration,
    }
}

// ── Regression classification ───────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Warn => write!(f, "WARN"),
            Self::Fail => write!(f, "FAIL"),
        }
    }
}

fn classify_hit_rate(baseline: f64, current: f64) -> (Status, f64) {
    let delta_pp = (baseline - current) * 100.0; // positive = regression
    let status = if delta_pp > HIT_RATE_FAIL_PP {
        Status::Fail
    } else if delta_pp > HIT_RATE_WARN_PP {
        Status::Warn
    } else {
        Status::Pass
    };
    (status, delta_pp)
}

fn classify_latency(baseline_us: f64, current_us: f64) -> (Status, f64) {
    if baseline_us <= 0.0 {
        return (Status::Pass, 0.0);
    }
    let delta_pct = ((current_us - baseline_us) / baseline_us) * 100.0;
    // Latency is advisory-only (never fails the test) because absolute
    // timings vary across hardware.  Hit-rate checks are deterministic and
    // remain the hard regression gate.
    let status = if delta_pct > WARN_THRESHOLD_PERCENT {
        Status::Warn
    } else {
        Status::Pass
    };
    (status, delta_pct)
}

// ── Main E2E test ───────────────────────────────────────────────────────

/// Full performance regression test: run all workloads, measure latency and
/// writeback, compare against stored baselines.
#[test]
fn perf_regression_block_cache() {
    let test_start = Instant::now();
    let mut any_fail = false;
    let mut any_warn = false;

    eprintln!("\n========================================");
    eprintln!("  Block Cache Performance Regression");
    eprintln!("========================================\n");

    // ── Hit rate regression ─────────────────────────────────────────────
    let workloads = [
        sequential_scan_workload(),
        zipf_workload(),
        mixed_seq_hot_workload(),
        compile_like_workload(),
        database_like_workload(),
    ];

    eprintln!(
        "{:<20} {:>12} {:>12} {:>10} {:>8}",
        "Workload", "Baseline", "Current", "Delta(pp)", "Status"
    );
    eprintln!("{}", "-".repeat(66));

    for (i, w) in workloads.iter().enumerate() {
        let m = measure_workload(w);
        let (baseline_name, baseline_hit_rate) = BASELINE_HIT_RATES[i];
        assert_eq!(
            m.name, baseline_name,
            "workload order mismatch at index {i}"
        );

        let (status, delta_pp) = classify_hit_rate(baseline_hit_rate, m.hit_rate);
        if status == Status::Fail {
            any_fail = true;
        }
        if status == Status::Warn {
            any_warn = true;
        }

        eprintln!(
            "{:<20} {:>11.4}% {:>11.4}% {:>+10.2} {:>8}",
            m.name,
            baseline_hit_rate * 100.0,
            m.hit_rate * 100.0,
            -delta_pp,
            status,
        );
    }

    // ── Lookup latency regression ───────────────────────────────────────
    eprintln!(
        "\n{:<20} {:>12} {:>12} {:>10} {:>8}",
        "Latency", "Baseline", "Current", "Delta(%)", "Status"
    );
    eprintln!("{}", "-".repeat(66));

    let latency = measure_lookup_latency();
    let current_p99_us = latency.p99.as_nanos() as f64 / 1000.0;
    let (lat_status, lat_delta) = classify_latency(BASELINE_LOOKUP_P99_US, current_p99_us);
    if lat_status == Status::Fail {
        any_fail = true;
    }
    if lat_status == Status::Warn {
        any_warn = true;
    }

    eprintln!(
        "{:<20} {:>10.1}us {:>10.1}us {:>+10.1}% {:>8}",
        "lookup_p99", BASELINE_LOOKUP_P99_US, current_p99_us, lat_delta, lat_status,
    );

    let p50_us = latency.p50.as_nanos() as f64 / 1000.0;
    let p95_us = latency.p95.as_nanos() as f64 / 1000.0;
    eprintln!(
        "{:<20} {:>12} {:>10.1}us {:>10} {:>8}",
        "lookup_p50", "--", p50_us, "--", "INFO",
    );
    eprintln!(
        "{:<20} {:>12} {:>10.1}us {:>10} {:>8}",
        "lookup_p95", "--", p95_us, "--", "INFO",
    );

    // ── Writeback performance ───────────────────────────────────────────
    eprintln!("\n{:<20} {:>12} {:>12}", "Writeback", "Duration", "Status");
    eprintln!("{}", "-".repeat(46));

    let wb = measure_writeback();
    eprintln!(
        "{:<20} {:>12?} {:>12}",
        "single_4k_w+sync", wb.single_4k_duration, "INFO",
    );
    eprintln!(
        "{:<20} {:>12?} {:>12}",
        "batch_100x4k_sync", wb.batch_100x4k_duration, "INFO",
    );

    // ── Duration check ──────────────────────────────────────────────────
    let total_elapsed = test_start.elapsed();
    eprintln!("\nTotal test duration: {total_elapsed:?}");

    assert!(
        total_elapsed < MAX_TEST_DURATION,
        "Test exceeded {MAX_TEST_DURATION:?} time limit (took {total_elapsed:?})"
    );

    // ── Summary ─────────────────────────────────────────────────────────
    eprintln!("\n========================================");
    if any_fail {
        eprintln!("  RESULT: FAIL - Performance regression detected");
        eprintln!("========================================\n");
        panic!("Performance regression detected (see report above)");
    } else if any_warn {
        eprintln!("  RESULT: WARN - Minor performance changes detected");
        eprintln!("========================================\n");
        // Warnings don't fail the test, just alert
    } else {
        eprintln!("  RESULT: PASS - All metrics within thresholds");
        eprintln!("========================================\n");
    }
}

/// Verify that the test completes within the time budget.
#[test]
fn perf_regression_completes_under_120s() {
    let start = Instant::now();

    // Quick smoke test: just one workload to verify timing
    let w = zipf_workload();
    let _m = measure_workload(&w);
    let _lat = measure_lookup_latency();

    let elapsed = start.elapsed();
    eprintln!("Smoke test duration: {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(60),
        "Single workload took {elapsed:?}, full suite will exceed 120s"
    );
}
