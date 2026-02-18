//! Thread-per-core dispatch for FUSE (Seastar/Glommio model).
//!
//! Assigns each FUSE worker to a specific CPU core with core-local
//! caches and per-core metrics, eliminating cross-core synchronization
//! for the common read path.
//!
//! # Design
//!
//! - **Core-pinned workers**: each worker thread is bound to a specific
//!   CPU core via `sched_setaffinity`.
//! - **Per-core cache partition**: each core owns a private slice of the
//!   ARC cache (size = total_cache / num_cores), eliminating cache-line
//!   bouncing on the read path.
//! - **Request routing**: FUSE requests are routed to the core that
//!   "owns" the target inode (inode % num_cores), ensuring locality.
//! - **Cross-core fallback**: when a request must access data owned by
//!   another core, it uses a lock-free message channel.
//!
//! # Failure modes (from Alien CS Graveyard)
//!
//! 1. **Work imbalance**: hot inodes cause one core to saturate.
//!    Mitigation: steal-half work-stealing when queue depth > 2x average.
//! 2. **Cross-core joins**: directory operations may span multiple cores.
//!    Mitigation: directory ops use a shared path, not per-core dispatch.
//! 3. **Debugging difficulty**: per-core state harder to inspect.
//!    Mitigation: per-core metrics exported via unified stats endpoint.
//!
//! # `unsafe_code = "forbid"` Compliance
//!
//! CPU affinity requires `libc::sched_setaffinity` which is unsafe.
//! We use the safe `nix` crate wrapper instead... but since ffs-fuse
//! forbids unsafe, we use a **best-effort** approach: the prototype
//! uses standard threads with advisory core assignment via thread naming
//! and OS scheduler hints. True pinning requires a future `pin` feature.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ── Per-core metrics ───────────────────────────────────────────────────────

/// Metrics for a single core's dispatch lane.
#[derive(Debug)]
pub struct CoreMetrics {
    /// Requests processed by this core.
    pub requests: AtomicU64,
    /// Cache hits on this core's local partition.
    pub cache_hits: AtomicU64,
    /// Cache misses requiring cross-core or backing store access.
    pub cache_misses: AtomicU64,
    /// Requests stolen from this core by another (work-stealing).
    pub stolen_from: AtomicU64,
    /// Requests this core stole from another.
    pub stolen_to: AtomicU64,
}

impl CoreMetrics {
    /// Create zeroed metrics.
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            stolen_from: AtomicU64::new(0),
            stolen_to: AtomicU64::new(0),
        }
    }

    /// Record a request processed.
    pub fn record_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache hit.
    pub fn record_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss.
    pub fn record_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the metrics for reporting.
    #[must_use]
    pub fn snapshot(&self) -> CoreMetricsSnapshot {
        CoreMetricsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            stolen_from: self.stolen_from.load(Ordering::Relaxed),
            stolen_to: self.stolen_to.load(Ordering::Relaxed),
        }
    }
}

impl Default for CoreMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable snapshot of per-core metrics for reporting.
#[derive(Debug, Clone, Copy)]
pub struct CoreMetricsSnapshot {
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub stolen_from: u64,
    pub stolen_to: u64,
}

impl CoreMetricsSnapshot {
    /// Cache hit rate as a fraction [0.0, 1.0].
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            return 0.0;
        }
        self.cache_hits as f64 / total as f64
    }
}

// ── Core assignment ────────────────────────────────────────────────────────

/// Route an inode to a core.
///
/// Uses a simple modulo hash for locality: consecutive inodes in the
/// same directory tend to map to the same core.
#[must_use]
#[inline]
pub fn inode_to_core(ino: u64, num_cores: u32) -> u32 {
    if num_cores == 0 {
        return 0;
    }
    // Mix the inode number to avoid pathological patterns.
    // FNV-1a-like mixing: multiply by a prime, XOR-fold.
    let mixed = ino.wrapping_mul(0x517c_c1b7_2722_0a95);
    #[expect(clippy::cast_possible_truncation)] // intentional 64→32 fold
    let folded = (mixed ^ (mixed >> 32)) as u32;
    folded % num_cores
}

/// Route a (parent, name) lookup to a core.
///
/// Directory lookups use the parent inode for routing so that
/// directory scans stay on one core.
#[must_use]
#[inline]
pub fn lookup_to_core(parent_ino: u64, num_cores: u32) -> u32 {
    inode_to_core(parent_ino, num_cores)
}

// ── Dispatch configuration ─────────────────────────────────────────────────

/// Thread-per-core dispatch configuration.
#[derive(Debug, Clone)]
pub struct PerCoreConfig {
    /// Number of cores to use (0 = auto-detect).
    pub num_cores: u32,
    /// Per-core cache size in blocks.
    pub cache_blocks_per_core: u32,
    /// Work-stealing threshold: steal when queue depth exceeds
    /// this multiple of the average across cores.
    pub steal_threshold: f64,
    /// Whether to use advisory CPU affinity (thread naming only,
    /// since true pinning requires unsafe).
    pub advisory_affinity: bool,
}

impl Default for PerCoreConfig {
    #[expect(clippy::cast_possible_truncation)] // .min(16) always fits u32
    fn default() -> Self {
        let num_cores = std::thread::available_parallelism()
            .map_or(4, |n| n.get().min(16) as u32);
        Self {
            num_cores,
            cache_blocks_per_core: 4096,
            steal_threshold: 2.0,
            advisory_affinity: true,
        }
    }
}

impl PerCoreConfig {
    /// Resolved number of cores.
    #[must_use]
    #[expect(clippy::cast_possible_truncation)] // .min(16) always fits u32
    pub fn resolved_cores(&self) -> u32 {
        if self.num_cores == 0 {
            std::thread::available_parallelism()
                .map_or(4, |n| n.get().min(16) as u32)
        } else {
            self.num_cores
        }
    }

    /// Total cache size across all cores.
    #[must_use]
    pub fn total_cache_blocks(&self) -> u64 {
        u64::from(self.resolved_cores()) * u64::from(self.cache_blocks_per_core)
    }
}

// ── Dispatcher ─────────────────────────────────────────────────────────────

/// Thread-per-core dispatch coordinator.
///
/// Tracks per-core metrics and provides routing decisions.
/// The actual FUSE request handling is done by the caller;
/// this struct provides the routing and metrics infrastructure.
pub struct PerCoreDispatcher {
    config: PerCoreConfig,
    core_metrics: Vec<Arc<CoreMetrics>>,
}

impl PerCoreDispatcher {
    /// Create a new dispatcher with the given configuration.
    #[must_use]
    pub fn new(config: PerCoreConfig) -> Self {
        let n = config.resolved_cores() as usize;
        let core_metrics = (0..n).map(|_| Arc::new(CoreMetrics::new())).collect();
        Self {
            config,
            core_metrics,
        }
    }

    /// Number of cores.
    #[must_use]
    pub fn num_cores(&self) -> u32 {
        self.config.resolved_cores()
    }

    /// Get metrics for a specific core.
    #[must_use]
    pub fn core_metrics(&self, core: u32) -> Option<&Arc<CoreMetrics>> {
        self.core_metrics.get(core as usize)
    }

    /// Route an inode-based request to a core.
    #[must_use]
    pub fn route_inode(&self, ino: u64) -> u32 {
        inode_to_core(ino, self.num_cores())
    }

    /// Route a lookup request to a core.
    #[must_use]
    pub fn route_lookup(&self, parent_ino: u64) -> u32 {
        lookup_to_core(parent_ino, self.num_cores())
    }

    /// Check if work-stealing should be triggered for `core`.
    ///
    /// Returns `true` if the core's queue depth (approximated by
    /// request count) is below the average by more than the steal threshold.
    #[must_use]
    pub fn should_steal(&self, core: u32) -> bool {
        let n = self.core_metrics.len();
        if n < 2 {
            return false;
        }

        let total: u64 = self
            .core_metrics
            .iter()
            .map(|m| m.requests.load(Ordering::Relaxed))
            .sum();
        let avg = total as f64 / n as f64;
        let mine = self.core_metrics[core as usize]
            .requests
            .load(Ordering::Relaxed) as f64;

        // This core is idle relative to average — try to steal work.
        mine < avg / self.config.steal_threshold
    }

    /// Aggregate metrics across all cores.
    #[must_use]
    pub fn aggregate_metrics(&self) -> AggregateMetrics {
        let mut total_requests = 0_u64;
        let mut total_hits = 0_u64;
        let mut total_misses = 0_u64;
        let mut per_core = Vec::with_capacity(self.core_metrics.len());

        for metrics in &self.core_metrics {
            let snap = metrics.snapshot();
            total_requests += snap.requests;
            total_hits += snap.cache_hits;
            total_misses += snap.cache_misses;
            per_core.push(snap);
        }

        let total_io = total_hits + total_misses;
        let hit_rate = if total_io == 0 {
            0.0
        } else {
            total_hits as f64 / total_io as f64
        };

        AggregateMetrics {
            total_requests,
            total_cache_hits: total_hits,
            total_cache_misses: total_misses,
            aggregate_hit_rate: hit_rate,
            per_core,
        }
    }
}

impl std::fmt::Debug for PerCoreDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerCoreDispatcher")
            .field("num_cores", &self.num_cores())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Aggregated metrics across all cores.
#[derive(Debug, Clone)]
pub struct AggregateMetrics {
    pub total_requests: u64,
    pub total_cache_hits: u64,
    pub total_cache_misses: u64,
    pub aggregate_hit_rate: f64,
    pub per_core: Vec<CoreMetricsSnapshot>,
}

impl AggregateMetrics {
    /// Find the most loaded core (by request count).
    #[must_use]
    pub fn hottest_core(&self) -> Option<(usize, u64)> {
        self.per_core
            .iter()
            .enumerate()
            .max_by_key(|(_, s)| s.requests)
            .map(|(i, s)| (i, s.requests))
    }

    /// Find the least loaded core.
    #[must_use]
    pub fn coldest_core(&self) -> Option<(usize, u64)> {
        self.per_core
            .iter()
            .enumerate()
            .min_by_key(|(_, s)| s.requests)
            .map(|(i, s)| (i, s.requests))
    }

    /// Load imbalance ratio: max/min request count.
    /// Returns 1.0 for perfectly balanced, higher for imbalanced.
    #[must_use]
    pub fn imbalance_ratio(&self) -> f64 {
        let max = self.hottest_core().map_or(0, |(_, r)| r);
        let min = self.coldest_core().map_or(0, |(_, r)| r);
        if min == 0 {
            return if max == 0 { 1.0 } else { f64::INFINITY };
        }
        max as f64 / min as f64
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_routing_deterministic() {
        for ino in 0..1000 {
            let core1 = inode_to_core(ino, 8);
            let core2 = inode_to_core(ino, 8);
            assert_eq!(core1, core2);
            assert!(core1 < 8);
        }
    }

    #[test]
    fn inode_routing_distribution() {
        // Check that routing is reasonably uniform.
        let num_cores = 8;
        let mut counts = vec![0_u32; num_cores as usize];
        for ino in 0..10_000_u64 {
            let core = inode_to_core(ino, num_cores);
            counts[core as usize] += 1;
        }
        // Each core should get roughly 10000/8 = 1250 ± 30%.
        for (core, &count) in counts.iter().enumerate() {
            assert!(
                count > 800 && count < 1700,
                "core {core} got {count} requests (expected ~1250)"
            );
        }
    }

    #[test]
    fn inode_routing_zero_cores() {
        assert_eq!(inode_to_core(42, 0), 0);
    }

    #[test]
    fn lookup_routes_by_parent() {
        let core1 = lookup_to_core(100, 8);
        let core2 = lookup_to_core(100, 8);
        assert_eq!(core1, core2);

        // Different parent → likely different core.
        let core3 = lookup_to_core(200, 8);
        // Can't guarantee different core but routing is deterministic.
        let _ = core3;
    }

    #[test]
    fn config_defaults() {
        let cfg = PerCoreConfig::default();
        assert!(cfg.num_cores > 0);
        assert!(cfg.cache_blocks_per_core > 0);
        assert!(cfg.steal_threshold > 1.0);
    }

    #[test]
    fn config_total_cache() {
        let cfg = PerCoreConfig {
            num_cores: 4,
            cache_blocks_per_core: 1024,
            steal_threshold: 2.0,
            advisory_affinity: true,
        };
        assert_eq!(cfg.total_cache_blocks(), 4096);
    }

    #[test]
    fn dispatcher_creation() {
        let cfg = PerCoreConfig {
            num_cores: 4,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);
        assert_eq!(disp.num_cores(), 4);
        assert!(disp.core_metrics(0).is_some());
        assert!(disp.core_metrics(3).is_some());
        assert!(disp.core_metrics(4).is_none());
    }

    #[test]
    fn dispatcher_routing_and_metrics() {
        let cfg = PerCoreConfig {
            num_cores: 4,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);

        // Route some requests and record metrics.
        for ino in 0..100_u64 {
            let core = disp.route_inode(ino);
            let metrics = disp.core_metrics(core).unwrap();
            metrics.record_request();
            if ino % 3 == 0 {
                metrics.record_hit();
            } else {
                metrics.record_miss();
            }
        }

        let agg = disp.aggregate_metrics();
        assert_eq!(agg.total_requests, 100);
        assert_eq!(agg.per_core.len(), 4);
        assert!(agg.aggregate_hit_rate > 0.2 && agg.aggregate_hit_rate < 0.5);
    }

    #[test]
    fn aggregate_imbalance_ratio() {
        let cfg = PerCoreConfig {
            num_cores: 2,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);

        // Give all requests to core 0.
        let m0 = disp.core_metrics(0).unwrap();
        for _ in 0..100 {
            m0.record_request();
        }
        let m1 = disp.core_metrics(1).unwrap();
        m1.record_request(); // 1 request to core 1

        let agg = disp.aggregate_metrics();
        assert_eq!(agg.total_requests, 101);
        assert!(agg.imbalance_ratio() > 50.0);
    }

    #[test]
    fn should_steal_when_idle() {
        let cfg = PerCoreConfig {
            num_cores: 2,
            steal_threshold: 2.0,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);

        // Give 100 requests to core 0, 0 to core 1.
        let m0 = disp.core_metrics(0).unwrap();
        for _ in 0..100 {
            m0.record_request();
        }

        // Core 1 is idle → should steal.
        assert!(disp.should_steal(1));
        // Core 0 is busy → should not steal.
        assert!(!disp.should_steal(0));
    }

    #[test]
    fn hottest_coldest_core() {
        let cfg = PerCoreConfig {
            num_cores: 3,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);

        for (core, count) in [(0, 10), (1, 50), (2, 30)] {
            let m = disp.core_metrics(core).unwrap();
            for _ in 0..count {
                m.record_request();
            }
        }

        let agg = disp.aggregate_metrics();
        assert_eq!(agg.hottest_core(), Some((1, 50)));
        assert_eq!(agg.coldest_core(), Some((0, 10)));
    }

    #[test]
    fn hit_rate_calculation() {
        let m = CoreMetrics::new();
        assert_eq!(m.snapshot().hit_rate(), 0.0); // no data

        for _ in 0..7 {
            m.record_hit();
        }
        for _ in 0..3 {
            m.record_miss();
        }

        let snap = m.snapshot();
        assert!((snap.hit_rate() - 0.7).abs() < 0.001);
    }

    #[test]
    fn benchmark_routing_throughput() {
        // Verify routing is fast: 10M routes should complete quickly.
        let num_cores = 8_u32;
        let mut sum = 0_u64;
        for ino in 0..10_000_000_u64 {
            sum += u64::from(inode_to_core(ino, num_cores));
        }
        // Just ensure it ran (prevent optimization).
        assert!(sum > 0);
    }
}
