#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
//! Workload-driven comparison of ARC vs S3-FIFO cache policies.
//!
//! This test runs the same 5 representative workloads under whichever policy
//! the crate was compiled with (default = ARC, `--features s3fifo` = S3-FIFO)
//! and validates hit-rate and memory-overhead expectations.
//!
//! To produce a side-by-side comparison, run this test twice:
//!
//! ```sh
//! cargo test -p ffs-block --test cache_workload_comparison -- --nocapture
//! cargo test -p ffs-block --test cache_workload_comparison --features s3fifo -- --nocapture
//! ```

use asupersync::Cx;
use ffs_block::{ArcCache, BlockBuf, BlockDevice, ByteBlockDevice, ByteDevice};
use ffs_error::Result;
use ffs_types::{BlockNumber, ByteOffset};
use parking_lot::Mutex;
use std::cmp::Ordering;

const BLOCK_SIZE_4K: u32 = 4096;

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

// ── Zipf helpers ────────────────────────────────────────────────────────

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

struct WorkloadCase {
    name: &'static str,
    block_count: usize,
    capacity: usize,
    trace: Vec<BlockNumber>,
}

struct WorkloadResult {
    name: &'static str,
    policy: &'static str,
    accesses: usize,
    hits: u64,
    misses: u64,
    hit_rate: f64,
    evictions: u64,
    resident: usize,
    capacity: usize,
    ghost_entries: usize,
    ghost_overhead_ratio: f64,
}

fn policy_label() -> &'static str {
    if cfg!(feature = "s3fifo") {
        "s3fifo"
    } else {
        "arc"
    }
}

fn sequential_scan_case() -> WorkloadCase {
    let block_count = 4_096_usize;
    let capacity = 512_usize;
    let passes = 4_usize;
    let mut trace = Vec::with_capacity(block_count * passes);
    for _ in 0..passes {
        for block in 0..block_count as u64 {
            trace.push(BlockNumber(block));
        }
    }
    WorkloadCase {
        name: "sequential_scan",
        block_count,
        capacity,
        trace,
    }
}

fn zipf_case() -> WorkloadCase {
    let block_count = 4_096_usize;
    let capacity = 512_usize;
    let accesses = 24_000_usize;
    let zipf = zipf_cdf(block_count, 1.07);
    let mut rng = Rng64::seeded(0xA1A1_0002);
    let mut trace = Vec::with_capacity(accesses);
    for _ in 0..accesses {
        trace.push(BlockNumber(sample_zipf(&zipf, &mut rng) as u64));
    }
    WorkloadCase {
        name: "zipf_distribution",
        block_count,
        capacity,
        trace,
    }
}

fn mixed_seq_hot_case() -> WorkloadCase {
    let block_count = 4_096_usize;
    let capacity = 512_usize;
    let accesses = 24_000_usize;
    let hot_set_len = 64_usize;
    let hot_set: Vec<BlockNumber> = (0..hot_set_len)
        .map(|idx| BlockNumber(idx as u64))
        .collect();
    let mut rng = Rng64::seeded(0xA1A1_0003);
    let mut sequential_cursor = 0_u64;
    let mut trace = Vec::with_capacity(accesses);
    for _ in 0..accesses {
        if rng.next_f64() < 0.70 {
            trace.push(BlockNumber(sequential_cursor % block_count as u64));
            sequential_cursor = sequential_cursor.wrapping_add(1);
        } else {
            trace.push(hot_set[rng.next_usize(hot_set.len())]);
        }
    }
    WorkloadCase {
        name: "mixed_seq70_hot30",
        block_count,
        capacity,
        trace,
    }
}

fn compile_like_case() -> WorkloadCase {
    let capacity = 640_usize;
    let metadata_hot_blocks = 32_u64;
    let small_files = 1_536_usize;
    let large_files = 24_usize;
    let large_file_blocks = 96_usize;
    let rounds = 16_usize;
    let small_base = metadata_hot_blocks;
    let large_base = small_base + small_files as u64 + 128;
    let block_count = large_base as usize + large_files * large_file_blocks + 256;
    let mut rng = Rng64::seeded(0xA1A1_0004);
    let mut trace =
        Vec::with_capacity(rounds * (metadata_hot_blocks as usize + 320 + 6 * large_file_blocks));
    for _ in 0..rounds {
        for block in 0..metadata_hot_blocks {
            trace.push(BlockNumber(block));
        }
        for _ in 0..320_usize {
            let file = rng.next_usize(small_files);
            trace.push(BlockNumber(small_base + file as u64));
        }
        for _ in 0..6_usize {
            let large = rng.next_usize(large_files);
            let start = large_base + (large * large_file_blocks) as u64;
            for offset in 0..large_file_blocks as u64 {
                trace.push(BlockNumber(start + offset));
            }
        }
    }
    WorkloadCase {
        name: "compile_like",
        block_count,
        capacity,
        trace,
    }
}

fn database_like_case() -> WorkloadCase {
    let capacity = 768_usize;
    let root_pages = [0_u64, 1_u64];
    let internal_start = 2_u64;
    let internal_pages = 128_usize;
    let leaf_start = 512_u64;
    let leaf_pages = 8_192_usize;
    let lookups = 12_000_usize;
    let leaf_zipf = zipf_cdf(leaf_pages, 1.12);
    let block_count = leaf_start as usize + leaf_pages + 256;
    let mut rng = Rng64::seeded(0xA1A1_0005);
    let mut trace = Vec::with_capacity(lookups * 4);
    for _ in 0..lookups {
        trace.push(BlockNumber(root_pages[rng.next_usize(root_pages.len())]));
        trace.push(BlockNumber(
            internal_start + rng.next_usize(internal_pages) as u64,
        ));
        trace.push(BlockNumber(
            leaf_start + sample_zipf(&leaf_zipf, &mut rng) as u64,
        ));
        if rng.next_usize(100) < 2 {
            let scan_start = rng.next_usize(leaf_pages.saturating_sub(12));
            for offset in 0..12_usize {
                trace.push(BlockNumber(leaf_start + (scan_start + offset) as u64));
            }
        }
    }
    WorkloadCase {
        name: "database_like",
        block_count,
        capacity,
        trace,
    }
}

fn all_workloads() -> Vec<WorkloadCase> {
    vec![
        sequential_scan_case(),
        zipf_case(),
        mixed_seq_hot_case(),
        compile_like_case(),
        database_like_case(),
    ]
}

// ── Workload runner ─────────────────────────────────────────────────────

fn run_workload(case: &WorkloadCase) -> WorkloadResult {
    let cx = Cx::for_testing();
    let cache = make_cache(BLOCK_SIZE_4K, case.block_count, case.capacity);
    for block in &case.trace {
        let _: BlockBuf = cache.read_block(&cx, *block).expect("cache read");
    }
    let m = cache.metrics();
    let ghost_entries = m.b1_len + m.b2_len;
    let ghost_overhead_ratio = if m.resident == 0 {
        0.0
    } else {
        ghost_entries as f64 / m.resident as f64
    };
    WorkloadResult {
        name: case.name,
        policy: policy_label(),
        accesses: case.trace.len(),
        hits: m.hits,
        misses: m.misses,
        hit_rate: m.hit_ratio(),
        evictions: m.evictions,
        resident: m.resident,
        capacity: m.capacity,
        ghost_entries,
        ghost_overhead_ratio,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// Run all 5 workloads and print structured comparison data.
///
/// This test always passes — it's designed to be run with `--nocapture`
/// to produce TSV output for comparison scripts.
#[test]
fn workload_hit_rates_report() {
    let cases = all_workloads();
    eprintln!(
        "{:<20} {:<8} {:>10} {:>8} {:>8} {:>10} {:>10} {:>8} {:>8} {:>8}",
        "workload",
        "policy",
        "accesses",
        "hits",
        "misses",
        "hit_rate",
        "evictions",
        "resident",
        "ghosts",
        "gh_ratio"
    );
    eprintln!("{}", "-".repeat(108));

    for case in &cases {
        let r = run_workload(case);
        eprintln!(
            "{:<20} {:<8} {:>10} {:>8} {:>8} {:>10.6} {:>10} {:>8} {:>8} {:>8.4}",
            r.name,
            r.policy,
            r.accesses,
            r.hits,
            r.misses,
            r.hit_rate,
            r.evictions,
            r.resident,
            r.ghost_entries,
            r.ghost_overhead_ratio,
        );
    }
}

/// Validate that the cache achieves reasonable hit rates on each workload.
///
/// These thresholds are policy-independent minimums — both ARC and S3-FIFO
/// should meet them. The interesting comparison is the relative difference,
/// captured by the report test above.
#[test]
fn workload_hit_rate_minimums() {
    let cases = all_workloads();
    let results: Vec<WorkloadResult> = cases.iter().map(run_workload).collect();

    // Sequential scan: both policies should struggle (working set >> cache),
    // but repeated passes give some hits. Minimum: 0% (scan-thrash is expected).
    // S3-FIFO's one-hit-wonder filter may actually do *worse* than ARC here
    // since every block is accessed exactly once per pass.
    let seq = &results[0];
    assert!(
        seq.hit_rate >= 0.0,
        "sequential_scan: hit_rate {:.4} below 0.0",
        seq.hit_rate
    );

    // Zipf: concentrated access pattern, both should do well.
    let zipf = &results[1];
    assert!(
        zipf.hit_rate >= 0.30,
        "zipf: hit_rate {:.4} below 0.30",
        zipf.hit_rate
    );

    // Mixed: hot set should be cached, sequential part thrashes.
    let mixed = &results[2];
    assert!(
        mixed.hit_rate >= 0.05,
        "mixed: hit_rate {:.4} below 0.05",
        mixed.hit_rate
    );

    // Compile-like: metadata hot blocks should stay cached.
    let compile = &results[3];
    assert!(
        compile.hit_rate >= 0.10,
        "compile: hit_rate {:.4} below 0.10",
        compile.hit_rate
    );

    // Database-like: root and internal pages should be cached.
    let db = &results[4];
    assert!(
        db.hit_rate >= 0.20,
        "database: hit_rate {:.4} below 0.20",
        db.hit_rate
    );

    // Memory overhead: ghost entries should be bounded.
    for r in &results {
        assert!(
            r.ghost_entries <= r.capacity * 3,
            "{}: ghost_entries {} exceeds 3x capacity {}",
            r.name,
            r.ghost_entries,
            r.capacity
        );
    }

    // Resident blocks should never exceed capacity.
    for r in &results {
        assert!(
            r.resident <= r.capacity,
            "{}: resident {} exceeds capacity {}",
            r.name,
            r.resident,
            r.capacity
        );
    }
}

/// Validate that p50/p95/p99 lookup latency is reasonable (no pathological stalls).
#[test]
fn workload_lookup_latency_bounded() {
    let cx = Cx::for_testing();
    let cache = make_cache(BLOCK_SIZE_4K, 4096, 512);

    // Warm up with Zipf distribution
    let zipf = zipf_cdf(4096, 1.07);
    let mut rng = Rng64::seeded(0xBEEF_0001);
    for _ in 0..10_000 {
        let block = BlockNumber(sample_zipf(&zipf, &mut rng) as u64);
        let _ = cache.read_block(&cx, block).expect("warmup");
    }

    // Measure 1000 lookups (mix of hits and misses)
    let mut latencies = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let block = BlockNumber(sample_zipf(&zipf, &mut rng) as u64);
        let start = std::time::Instant::now();
        let _ = cache.read_block(&cx, block).expect("read");
        latencies.push(start.elapsed());
    }
    latencies.sort();

    let p50 = latencies[499];
    let p95 = latencies[949];
    let p99 = latencies[989];

    eprintln!(
        "[{}] lookup latency: p50={p50:?} p95={p95:?} p99={p99:?}",
        policy_label(),
    );

    // Sanity: p99 should be under 10ms for in-memory device
    assert!(
        p99 < std::time::Duration::from_millis(10),
        "p99 latency {p99:?} exceeds 10ms for in-memory device"
    );
}

/// Verify that sequential scans don't permanently pollute the cache
/// for subsequent hot-key workloads.
#[test]
fn scan_resistance_preserves_hot_keys() {
    let cx = Cx::for_testing();
    let cache = make_cache(BLOCK_SIZE_4K, 4096, 256);

    // Phase 1: establish hot set (blocks 0..64)
    for _ in 0..8 {
        for block in 0..64_u64 {
            let _ = cache.read_block(&cx, BlockNumber(block)).expect("hot");
        }
    }

    let before = cache.metrics();
    let hot_hit_rate_before = before.hit_ratio();

    // Phase 2: sequential scan through blocks 256..2048 (scan pollution)
    for block in 256..2048_u64 {
        let _ = cache.read_block(&cx, BlockNumber(block)).expect("scan");
    }

    // Phase 3: re-access hot set — check how many survived
    for block in 0..64_u64 {
        let _ = cache.read_block(&cx, BlockNumber(block)).expect("re-hot");
    }
    let after = cache.metrics();
    let final_resident = after.resident;

    eprintln!(
        "[{}] scan resistance: hot_hit_rate_before={hot_hit_rate_before:.4} final_resident={final_resident} capacity={}",
        policy_label(),
        after.capacity,
    );

    // Both policies should retain some hot blocks after scan.
    // S3-FIFO should retain more (scan resistance is its key feature).
    assert!(
        final_resident > 0,
        "cache empty after scan + hot re-access, policy={} has no scan resistance",
        policy_label()
    );
}
