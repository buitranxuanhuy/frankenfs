//! Bw-Tree mapping-table + delta-chain core.
//!
//! This module provides a safe (no-`unsafe`) foundation for Bw-Tree style
//! append-only delta chains:
//! - mapping table indirection (`PageId -> head delta`)
//! - CAS-style head replacement with retry loops
//! - delta traversal/materialization for lookup
//! - crossbeam-epoch deferred reclamation for replaced delta heads
//!
//! Note: this crate forbids `unsafe`, so this implementation uses `Arc` for
//! delta ownership and crossbeam-epoch for deferred reclamation handoff.

use crossbeam_epoch as epoch;
use ffs_error::{FfsError, Result};
use std::collections::BTreeMap;
use std::io::Error as IoError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{debug, trace, warn};

const MAX_CAS_RETRIES: usize = 1_024;
const MAX_CHAIN_DEPTH: usize = 16_384;
const DEFAULT_CONSOLIDATION_THRESHOLD: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BwKey(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BwValue(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PageId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageDelta {
    Insert {
        key: BwKey,
        value: BwValue,
        next: Arc<Self>,
    },
    Delete {
        key: BwKey,
        next: Arc<Self>,
    },
    Split {
        separator: BwKey,
        new_sibling: PageId,
        next: Arc<Self>,
    },
    Merge {
        removed_sibling: PageId,
        next: Arc<Self>,
    },
    Base {
        entries: BTreeMap<BwKey, BwValue>,
    },
}

impl PageDelta {
    #[must_use]
    pub fn empty_base() -> Arc<Self> {
        Arc::new(Self::Base {
            entries: BTreeMap::new(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PageSnapshot {
    pub epoch: u64,
    pub head: Arc<PageDelta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaMutation {
    Insert {
        key: BwKey,
        value: BwValue,
    },
    Delete {
        key: BwKey,
    },
    Split {
        separator: BwKey,
        new_sibling: PageId,
    },
    Merge {
        removed_sibling: PageId,
    },
}

#[derive(Debug)]
struct MappingEntry {
    head: RwLock<Arc<PageDelta>>,
    epoch: AtomicU64,
}

impl MappingEntry {
    fn new() -> Self {
        Self {
            head: RwLock::new(PageDelta::empty_base()),
            epoch: AtomicU64::new(0),
        }
    }
}

#[derive(Debug)]
pub struct MappingTable {
    pages: Vec<MappingEntry>,
    next_page_id: AtomicU64,
}

impl MappingTable {
    #[must_use]
    pub fn with_capacity(page_capacity: usize) -> Self {
        let pages = (0..page_capacity).map(|_| MappingEntry::new()).collect();
        Self {
            pages,
            next_page_id: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn page_capacity(&self) -> usize {
        self.pages.len()
    }

    pub fn allocate_page(&self) -> Result<PageId> {
        let page_raw = self.next_page_id.fetch_add(1, Ordering::AcqRel);
        let page_index = usize::try_from(page_raw).map_err(|_| FfsError::NoSpace)?;
        if page_index >= self.pages.len() {
            return Err(FfsError::NoSpace);
        }
        debug!(
            target: "ffs::bwtree",
            event = "bw_page_alloc",
            page_id = page_raw,
            capacity = self.pages.len()
        );
        Ok(PageId(page_raw))
    }

    pub fn get_page(&self, page_id: PageId) -> Result<PageSnapshot> {
        let entry = self.entry(page_id)?;
        let epoch = entry.epoch.load(Ordering::Acquire);
        let head = Arc::clone(&read_lock(&entry.head));
        Ok(PageSnapshot { epoch, head })
    }

    pub fn cas_page(
        &self,
        page_id: PageId,
        expected_epoch: u64,
        new_head: Arc<PageDelta>,
    ) -> Result<bool> {
        let entry = self.entry(page_id)?;
        trace!(
            target: "ffs::bwtree",
            event = "bw_cas_attempt",
            page_id = page_id.0,
            expected_epoch
        );
        let mut head_guard = write_lock(&entry.head);
        match entry.epoch.compare_exchange(
            expected_epoch,
            expected_epoch.saturating_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let old_head = Arc::clone(&head_guard);
                *head_guard = new_head;
                defer_reclaim(old_head);
                debug!(
                    target: "ffs::bwtree",
                    event = "bw_cas_commit",
                    page_id = page_id.0,
                    new_epoch = expected_epoch.saturating_add(1)
                );
                Ok(true)
            }
            Err(observed_epoch) => {
                drop(head_guard);
                trace!(
                    target: "ffs::bwtree",
                    event = "bw_cas_retry",
                    page_id = page_id.0,
                    expected_epoch,
                    observed_epoch
                );
                Ok(false)
            }
        }
    }

    pub fn append_delta(&self, page_id: PageId, mutation: DeltaMutation) -> Result<usize> {
        for attempt in 1..=MAX_CAS_RETRIES {
            let snapshot = self.get_page(page_id)?;
            let _guard = epoch::pin();
            let new_head = Arc::new(mutation.to_delta(snapshot.head));
            if self.cas_page(page_id, snapshot.epoch, new_head)? {
                return Ok(attempt);
            }
        }
        warn!(
            target: "ffs::bwtree",
            event = "bw_cas_retry_exhausted",
            page_id = page_id.0,
            max_retries = MAX_CAS_RETRIES
        );
        Err(FfsError::Io(IoError::other(
            "bw-tree CAS retries exhausted without progress",
        )))
    }

    pub fn insert(&self, page_id: PageId, key: BwKey, value: BwValue) -> Result<usize> {
        self.append_delta(page_id, DeltaMutation::Insert { key, value })
    }

    pub fn delete(&self, page_id: PageId, key: BwKey) -> Result<usize> {
        self.append_delta(page_id, DeltaMutation::Delete { key })
    }

    pub fn append_split_delta(
        &self,
        page_id: PageId,
        separator: BwKey,
        new_sibling: PageId,
    ) -> Result<usize> {
        self.append_delta(
            page_id,
            DeltaMutation::Split {
                separator,
                new_sibling,
            },
        )
    }

    pub fn append_merge_delta(&self, page_id: PageId, removed_sibling: PageId) -> Result<usize> {
        self.append_delta(page_id, DeltaMutation::Merge { removed_sibling })
    }

    pub fn lookup(&self, page_id: PageId, key: BwKey) -> Result<Option<BwValue>> {
        let state = self.materialize_page(page_id)?;
        Ok(state.get(&key).copied())
    }

    pub fn materialize_page(&self, page_id: PageId) -> Result<BTreeMap<BwKey, BwValue>> {
        let snapshot = self.get_page(page_id)?;
        let (state, chain_len) = materialize_from_head(&snapshot.head)?;
        debug!(
            target: "ffs::bwtree",
            event = "bw_lookup_chain_stats",
            page_id = page_id.0,
            chain_len,
            epoch = snapshot.epoch
        );
        Ok(state)
    }

    /// Consolidate a page's delta chain into a fresh base page.
    ///
    /// Materializes the current chain, creates a new `PageDelta::Base`,
    /// and atomically replaces the old chain via CAS. If the CAS fails
    /// (concurrent modification), retries up to `max_retries` times.
    ///
    /// Returns `Ok(result)` with consolidation statistics, or `Err` if
    /// retries are exhausted or the page is not found.
    pub fn consolidate_page(
        &self,
        page_id: PageId,
        config: &ConsolidationConfig,
    ) -> Result<ConsolidationResult> {
        for attempt in 1..=config.max_retries {
            let snapshot = self.get_page(page_id)?;
            let chain_len_before = chain_length(&snapshot.head);

            if chain_len_before <= 1 {
                // Already a base page (or single delta on base); nothing to do.
                trace!(
                    target: "ffs::bwtree",
                    event = "bw_consolidate_skip",
                    page_id = page_id.0,
                    chain_len = chain_len_before,
                    reason = "already_base"
                );
                return Ok(ConsolidationResult {
                    chain_len_before,
                    chain_len_after: chain_len_before,
                    entries_count: 0,
                    cas_attempts: 0,
                });
            }

            let _guard = epoch::pin();
            let (state, _) = materialize_from_head(&snapshot.head)?;
            let entries_count = state.len();
            let new_base = Arc::new(PageDelta::Base { entries: state });

            if self.cas_page(page_id, snapshot.epoch, new_base)? {
                debug!(
                    target: "ffs::bwtree",
                    event = "bw_consolidate_done",
                    page_id = page_id.0,
                    chain_len_before,
                    chain_len_after = 1,
                    entries_count,
                    cas_attempts = attempt
                );
                return Ok(ConsolidationResult {
                    chain_len_before,
                    chain_len_after: 1,
                    entries_count,
                    cas_attempts: attempt,
                });
            }

            trace!(
                target: "ffs::bwtree",
                event = "bw_consolidate_cas_retry",
                page_id = page_id.0,
                attempt
            );
        }

        warn!(
            target: "ffs::bwtree",
            event = "bw_consolidate_retry_exhausted",
            page_id = page_id.0,
            max_retries = config.max_retries
        );
        Err(FfsError::Io(IoError::other(
            "bw-tree consolidation CAS retries exhausted",
        )))
    }

    /// Scan all allocated pages and return page IDs whose delta chain
    /// length exceeds `threshold`.
    pub fn scan_for_consolidation(&self, threshold: usize) -> Vec<PageId> {
        let allocated = self.next_page_id.load(Ordering::Acquire);
        let mut candidates = Vec::new();
        for raw_id in 0..allocated {
            let page_id = PageId(raw_id);
            if let Ok(snapshot) = self.get_page(page_id) {
                let len = chain_length(&snapshot.head);
                if len > threshold {
                    candidates.push(page_id);
                }
            }
        }
        candidates
    }

    /// Consolidate all pages whose chain length exceeds the configured
    /// threshold. Returns the number of pages successfully consolidated.
    pub fn consolidate_all(&self, config: &ConsolidationConfig) -> Result<usize> {
        let candidates = self.scan_for_consolidation(config.chain_threshold);
        let mut consolidated = 0;
        for page_id in candidates {
            self.consolidate_page(page_id, config)?;
            consolidated += 1;
        }
        debug!(
            target: "ffs::bwtree",
            event = "bw_consolidate_all_done",
            consolidated,
            threshold = config.chain_threshold
        );
        Ok(consolidated)
    }

    fn entry(&self, page_id: PageId) -> Result<&MappingEntry> {
        let page_index = usize::try_from(page_id.0).map_err(|_| page_not_found(page_id))?;
        let allocated = self.next_page_id.load(Ordering::Acquire);
        if page_id.0 >= allocated {
            return Err(page_not_found(page_id));
        }
        self.pages
            .get(page_index)
            .ok_or_else(|| page_not_found(page_id))
    }
}

/// Configuration for delta chain consolidation.
#[derive(Debug, Clone)]
pub struct ConsolidationConfig {
    /// Consolidate when chain length exceeds this value.
    pub chain_threshold: usize,
    /// Maximum CAS retry attempts per consolidation.
    pub max_retries: usize,
}

impl Default for ConsolidationConfig {
    fn default() -> Self {
        Self {
            chain_threshold: DEFAULT_CONSOLIDATION_THRESHOLD,
            max_retries: MAX_CAS_RETRIES,
        }
    }
}

/// Result of a page consolidation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsolidationResult {
    /// Delta chain length before consolidation.
    pub chain_len_before: usize,
    /// Delta chain length after consolidation (always 1 on success).
    pub chain_len_after: usize,
    /// Number of key-value entries in the consolidated base page.
    pub entries_count: usize,
    /// Number of CAS attempts needed.
    pub cas_attempts: usize,
}

/// Count the number of delta nodes in a chain (including the base page).
#[must_use]
pub fn chain_length(head: &Arc<PageDelta>) -> usize {
    let mut cursor = Arc::clone(head);
    let mut len = 0_usize;
    loop {
        len += 1;
        if len > MAX_CHAIN_DEPTH {
            return len;
        }
        match cursor.as_ref() {
            PageDelta::Base { .. } => return len,
            PageDelta::Insert { next, .. }
            | PageDelta::Delete { next, .. }
            | PageDelta::Split { next, .. }
            | PageDelta::Merge { next, .. } => {
                cursor = Arc::clone(next);
            }
        }
    }
}

impl DeltaMutation {
    fn to_delta(self, next: Arc<PageDelta>) -> PageDelta {
        match self {
            Self::Insert { key, value } => PageDelta::Insert { key, value, next },
            Self::Delete { key } => PageDelta::Delete { key, next },
            Self::Split {
                separator,
                new_sibling,
            } => PageDelta::Split {
                separator,
                new_sibling,
                next,
            },
            Self::Merge { removed_sibling } => PageDelta::Merge {
                removed_sibling,
                next,
            },
        }
    }
}

fn page_not_found(page_id: PageId) -> FfsError {
    FfsError::NotFound(format!("bw-tree page {} is not allocated", page_id.0))
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaterializeOp {
    Insert { key: BwKey, value: BwValue },
    Delete { key: BwKey },
}

fn materialize_from_head(head: &Arc<PageDelta>) -> Result<(BTreeMap<BwKey, BwValue>, usize)> {
    let mut ops: Vec<MaterializeOp> = Vec::new();
    let mut cursor = Arc::clone(head);
    let mut chain_len = 0_usize;

    loop {
        chain_len = chain_len.saturating_add(1);
        if chain_len > MAX_CHAIN_DEPTH {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "bw-tree delta chain exceeded max depth ({MAX_CHAIN_DEPTH}) without base page"
                ),
            });
        }

        match cursor.as_ref() {
            PageDelta::Base { entries } => {
                let mut state = entries.clone();
                for op in ops.iter().rev().copied() {
                    apply_op(&mut state, op);
                }
                return Ok((state, chain_len));
            }
            PageDelta::Insert { key, value, next } => {
                ops.push(MaterializeOp::Insert {
                    key: *key,
                    value: *value,
                });
                cursor = Arc::clone(next);
            }
            PageDelta::Delete { key, next } => {
                ops.push(MaterializeOp::Delete { key: *key });
                cursor = Arc::clone(next);
            }
            PageDelta::Split { next, .. } | PageDelta::Merge { next, .. } => {
                cursor = Arc::clone(next);
            }
        }
    }
}

fn apply_op(state: &mut BTreeMap<BwKey, BwValue>, op: MaterializeOp) {
    match op {
        MaterializeOp::Insert { key, value } => {
            state.insert(key, value);
        }
        MaterializeOp::Delete { key } => {
            state.remove(&key);
        }
    }
}

fn defer_reclaim(delta: Arc<PageDelta>) {
    let guard = epoch::pin();
    guard.defer(move || drop(delta));
}

#[cfg(test)]
mod tests {
    use super::{
        BwKey, BwValue, ConsolidationConfig, MappingTable, PageDelta, PageId, chain_length,
    };
    use std::sync::{Arc, Barrier};

    #[test]
    fn single_thread_insert_delete_lookup_round_trip() {
        let table = MappingTable::with_capacity(4);
        let page = table
            .allocate_page()
            .expect("page allocation should succeed");

        assert_eq!(
            table
                .lookup(page, BwKey(10))
                .expect("lookup should succeed"),
            None
        );

        table
            .insert(page, BwKey(10), BwValue(111))
            .expect("insert key=10 should succeed");
        table
            .insert(page, BwKey(20), BwValue(222))
            .expect("insert key=20 should succeed");
        assert_eq!(
            table
                .lookup(page, BwKey(10))
                .expect("lookup should succeed"),
            Some(BwValue(111))
        );
        assert_eq!(
            table
                .lookup(page, BwKey(20))
                .expect("lookup should succeed"),
            Some(BwValue(222))
        );

        table
            .delete(page, BwKey(10))
            .expect("delete key=10 should succeed");
        assert_eq!(
            table
                .lookup(page, BwKey(10))
                .expect("lookup should succeed"),
            None
        );
        assert_eq!(
            table
                .lookup(page, BwKey(20))
                .expect("lookup should succeed"),
            Some(BwValue(222))
        );
    }

    #[test]
    fn delta_chain_materialization_merges_newest_state() {
        let table = MappingTable::with_capacity(2);
        let page = table
            .allocate_page()
            .expect("page allocation should succeed");

        table
            .insert(page, BwKey(5), BwValue(1))
            .expect("insert should succeed");
        table
            .insert(page, BwKey(5), BwValue(2))
            .expect("overwrite should succeed");
        table
            .insert(page, BwKey(9), BwValue(9))
            .expect("insert key=9 should succeed");
        table
            .append_split_delta(page, BwKey(7), PageId(1))
            .expect("split delta should succeed");
        table
            .delete(page, BwKey(9))
            .expect("delete key=9 should succeed");
        table
            .append_merge_delta(page, PageId(1))
            .expect("merge delta should succeed");

        let state = table
            .materialize_page(page)
            .expect("materialize should succeed");
        assert_eq!(state.get(&BwKey(5)).copied(), Some(BwValue(2)));
        assert!(!state.contains_key(&BwKey(9)));
    }

    #[test]
    fn concurrent_cas_append_preserves_all_updates() {
        let table = Arc::new(MappingTable::with_capacity(1));
        let page = table
            .allocate_page()
            .expect("page allocation should succeed");

        let workers = 4_u64;
        let keys_per_worker = 64_u64;
        let barrier = Arc::new(Barrier::new(usize::try_from(workers).unwrap_or(4)));
        let mut handles = Vec::new();

        for worker in 0..workers {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for slot in 0..keys_per_worker {
                    let key = BwKey(worker * 1_000 + slot);
                    let value = BwValue(key.0 + 10);
                    table
                        .insert(page, key, value)
                        .expect("concurrent insert should succeed");
                }
            }));
        }

        for handle in handles {
            handle.join().expect("worker should not panic");
        }

        let state = table
            .materialize_page(page)
            .expect("materialize should succeed");
        assert_eq!(
            u64::try_from(state.len()).expect("len conversion should succeed"),
            workers * keys_per_worker
        );

        for worker in 0..workers {
            for slot in 0..keys_per_worker {
                let key = BwKey(worker * 1_000 + slot);
                assert_eq!(state.get(&key).copied(), Some(BwValue(key.0 + 10)));
            }
        }
    }

    // ── Consolidation tests ─────────────────────────────────────────

    fn default_config() -> ConsolidationConfig {
        ConsolidationConfig {
            chain_threshold: 4,
            max_retries: 64,
        }
    }

    #[test]
    fn chain_length_of_empty_base_is_one() {
        let base = PageDelta::empty_base();
        assert_eq!(chain_length(&base), 1);
    }

    #[test]
    fn chain_length_grows_with_deltas() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");
        for i in 0..10 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }
        let snap = table.get_page(page).expect("get");
        assert_eq!(chain_length(&snap.head), 11); // 10 inserts + 1 base
    }

    #[test]
    fn consolidate_reduces_chain_to_one() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for i in 0..20 {
            table
                .insert(page, BwKey(i), BwValue(i * 10))
                .expect("insert");
        }
        let snap_before = table.get_page(page).expect("get");
        assert_eq!(chain_length(&snap_before.head), 21);

        let config = default_config();
        let result = table.consolidate_page(page, &config).expect("consolidate");
        assert_eq!(result.chain_len_before, 21);
        assert_eq!(result.chain_len_after, 1);
        assert_eq!(result.entries_count, 20);
        assert!(result.cas_attempts >= 1);

        let snap_after = table.get_page(page).expect("get");
        assert_eq!(chain_length(&snap_after.head), 1);
    }

    #[test]
    fn consolidate_preserves_all_data() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        // Build a chain with inserts, overwrites, and deletes
        for i in 0..50 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }
        // Overwrite even keys
        for i in (0..50).step_by(2) {
            table
                .insert(page, BwKey(i), BwValue(i + 1000))
                .expect("overwrite");
        }
        // Delete keys divisible by 5
        for i in (0..50).step_by(5) {
            table.delete(page, BwKey(i)).expect("delete");
        }

        let state_before = table.materialize_page(page).expect("materialize");

        let config = default_config();
        table.consolidate_page(page, &config).expect("consolidate");

        let state_after = table.materialize_page(page).expect("materialize");
        assert_eq!(state_before, state_after);
    }

    #[test]
    fn consolidate_skips_already_base_page() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        let config = default_config();
        let result = table.consolidate_page(page, &config).expect("consolidate");
        assert_eq!(result.chain_len_before, 1);
        assert_eq!(result.chain_len_after, 1);
        assert_eq!(result.cas_attempts, 0);
    }

    #[test]
    fn scan_for_consolidation_finds_long_chains() {
        let table = MappingTable::with_capacity(4);
        let p0 = table.allocate_page().expect("alloc");
        let p1 = table.allocate_page().expect("alloc");
        let _p2 = table.allocate_page().expect("alloc");

        // p0: 3 deltas (below threshold of 4)
        for i in 0..3 {
            table.insert(p0, BwKey(i), BwValue(i)).expect("insert");
        }
        // p1: 10 deltas (above threshold)
        for i in 0..10 {
            table.insert(p1, BwKey(i), BwValue(i)).expect("insert");
        }
        // p2: 1 delta (base only, below threshold)

        let candidates = table.scan_for_consolidation(4);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], p1);
    }

    #[test]
    fn consolidate_all_consolidates_only_long_chains() {
        let table = MappingTable::with_capacity(4);
        let p0 = table.allocate_page().expect("alloc");
        let p1 = table.allocate_page().expect("alloc");
        let p2 = table.allocate_page().expect("alloc");

        for i in 0..2 {
            table.insert(p0, BwKey(i), BwValue(i)).expect("insert");
        }
        for i in 0..10 {
            table.insert(p1, BwKey(i), BwValue(i)).expect("insert");
        }
        for i in 0..8 {
            table.insert(p2, BwKey(i), BwValue(i)).expect("insert");
        }

        let config = ConsolidationConfig {
            chain_threshold: 5,
            max_retries: 64,
        };
        let count = table.consolidate_all(&config).expect("consolidate_all");
        assert_eq!(count, 2); // p1 and p2

        // p0 should still have chain length > 1
        let snap0 = table.get_page(p0).expect("get");
        assert_eq!(chain_length(&snap0.head), 3);

        // p1 and p2 should be consolidated
        let snap1 = table.get_page(p1).expect("get");
        assert_eq!(chain_length(&snap1.head), 1);
        let snap2 = table.get_page(p2).expect("get");
        assert_eq!(chain_length(&snap2.head), 1);
    }

    #[test]
    fn concurrent_consolidation_and_inserts_preserve_data() {
        let table = Arc::new(MappingTable::with_capacity(1));
        let page = table.allocate_page().expect("alloc");

        // Seed with some initial data
        for i in 0..20 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }

        let barrier = Arc::new(Barrier::new(3)); // 1 consolidator + 2 inserters
        let mut handles = Vec::new();

        // Consolidator thread
        {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let config = ConsolidationConfig {
                    chain_threshold: 1,
                    max_retries: 256,
                };
                for _ in 0..5 {
                    let _ = table.consolidate_page(page, &config);
                }
            }));
        }

        // Inserter threads
        for worker in 0..2_u64 {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let base = 1000 + worker * 100;
                for i in 0..50 {
                    table
                        .insert(page, BwKey(base + i), BwValue(base + i + 10))
                        .expect("insert");
                }
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        // Verify all initial and inserted data is present
        let state = table.materialize_page(page).expect("materialize");
        for i in 0..20 {
            assert_eq!(
                state.get(&BwKey(i)).copied(),
                Some(BwValue(i)),
                "initial key {i} should be present"
            );
        }
        for worker in 0..2_u64 {
            let base = 1000 + worker * 100;
            for i in 0..50 {
                assert_eq!(
                    state.get(&BwKey(base + i)).copied(),
                    Some(BwValue(base + i + 10)),
                    "worker {worker} key {} should be present",
                    base + i
                );
            }
        }
    }

    #[test]
    fn consolidation_result_fields_are_correct() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        table.insert(page, BwKey(1), BwValue(10)).expect("insert");
        table.insert(page, BwKey(2), BwValue(20)).expect("insert");
        table.delete(page, BwKey(1)).expect("delete");

        let config = default_config();
        let result = table.consolidate_page(page, &config).expect("consolidate");

        // Chain was: delete -> insert(2) -> insert(1) -> base = 4 nodes
        assert_eq!(result.chain_len_before, 4);
        assert_eq!(result.chain_len_after, 1);
        // After materialization: only key 2 remains
        assert_eq!(result.entries_count, 1);
        assert_eq!(result.cas_attempts, 1);
    }

    #[test]
    fn consolidation_with_split_and_merge_deltas() {
        let table = MappingTable::with_capacity(4);
        let page = table.allocate_page().expect("alloc");
        let sibling = table.allocate_page().expect("alloc sibling");

        table.insert(page, BwKey(10), BwValue(100)).expect("insert");
        table.insert(page, BwKey(20), BwValue(200)).expect("insert");
        table
            .append_split_delta(page, BwKey(15), sibling)
            .expect("split");
        table.insert(page, BwKey(30), BwValue(300)).expect("insert");
        table.append_merge_delta(page, sibling).expect("merge");
        table.insert(page, BwKey(40), BwValue(400)).expect("insert");

        let state_before = table.materialize_page(page).expect("materialize");

        let config = default_config();
        table.consolidate_page(page, &config).expect("consolidate");

        let state_after = table.materialize_page(page).expect("materialize");
        assert_eq!(state_before, state_after);

        let snap = table.get_page(page).expect("get");
        assert_eq!(chain_length(&snap.head), 1);
    }

    #[test]
    fn repeated_consolidation_is_idempotent() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for i in 0..10 {
            table
                .insert(page, BwKey(i), BwValue(i * 2))
                .expect("insert");
        }

        let config = default_config();
        table.consolidate_page(page, &config).expect("first");
        let state1 = table.materialize_page(page).expect("mat1");

        table.consolidate_page(page, &config).expect("second");
        let state2 = table.materialize_page(page).expect("mat2");

        assert_eq!(state1, state2);
    }

    #[test]
    fn inserts_after_consolidation_build_new_chain() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for i in 0..10 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }

        let config = default_config();
        table.consolidate_page(page, &config).expect("consolidate");
        assert_eq!(chain_length(&table.get_page(page).expect("get").head), 1);

        // New inserts build on consolidated base
        for i in 10..15 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }
        assert_eq!(chain_length(&table.get_page(page).expect("get").head), 6);

        // All data still accessible
        for i in 0..15 {
            assert_eq!(
                table.lookup(page, BwKey(i)).expect("lookup"),
                Some(BwValue(i))
            );
        }
    }

    // ── Comprehensive unit tests (bd-1mdk.3) ─────────────────────

    #[test]
    fn crud_1000_keys_insert_lookup_delete() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        // Insert 1000 keys
        for i in 0..1000_u64 {
            table
                .insert(page, BwKey(i), BwValue(i * 3))
                .expect("insert");
        }

        // Verify all 1000 lookups
        for i in 0..1000_u64 {
            assert_eq!(
                table.lookup(page, BwKey(i)).expect("lookup"),
                Some(BwValue(i * 3)),
                "key {i} mismatch"
            );
        }

        // Delete even keys
        for i in (0..1000_u64).step_by(2) {
            table.delete(page, BwKey(i)).expect("delete");
        }

        // Verify: even keys gone, odd keys present
        for i in 0..1000_u64 {
            let result = table.lookup(page, BwKey(i)).expect("lookup");
            if i % 2 == 0 {
                assert_eq!(result, None, "deleted key {i} should be absent");
            } else {
                assert_eq!(
                    result,
                    Some(BwValue(i * 3)),
                    "odd key {i} should still exist"
                );
            }
        }

        let state = table.materialize_page(page).expect("materialize");
        assert_eq!(state.len(), 500);
    }

    #[test]
    fn duplicate_insert_uses_latest_value() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for round in 0..5_u64 {
            for i in 0..100_u64 {
                table
                    .insert(page, BwKey(i), BwValue(round * 1000 + i))
                    .expect("insert");
            }
        }

        // Only the last round's values should be visible
        for i in 0..100_u64 {
            assert_eq!(
                table.lookup(page, BwKey(i)).expect("lookup"),
                Some(BwValue(4000 + i)),
                "key {i} should reflect round 4"
            );
        }
    }

    #[test]
    fn materialized_page_is_sorted_by_key() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        // Insert in reverse order
        for i in (0..50_u64).rev() {
            table
                .insert(page, BwKey(i * 7), BwValue(i))
                .expect("insert");
        }

        let state = table.materialize_page(page).expect("materialize");
        let keys: Vec<u64> = state.keys().map(|k| k.0).collect();
        for pair in keys.windows(2) {
            assert!(
                pair[0] < pair[1],
                "keys should be sorted: {} < {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn concurrent_insert_lookup_no_corrupt_state() {
        let table = Arc::new(MappingTable::with_capacity(1));
        let page = table.allocate_page().expect("alloc");

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        // 4 writer threads, each inserting unique key ranges
        for worker in 0..4_u64 {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let base = worker * 1000;
                for i in 0..500 {
                    table
                        .insert(page, BwKey(base + i), BwValue(base + i + 10))
                        .expect("insert");
                }
            }));
        }

        // 4 reader threads doing lookups continuously
        for _ in 0..4 {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                // Readers must never see corrupt state
                for probe in 0..2000 {
                    let _ = table.lookup(page, BwKey(probe));
                }
            }));
        }

        for h in handles {
            h.join().expect("no panics");
        }

        // After all writers done: verify all 2000 keys present
        let state = table.materialize_page(page).expect("materialize");
        assert_eq!(state.len(), 2000);
        for worker in 0..4_u64 {
            let base = worker * 1000;
            for i in 0..500 {
                assert_eq!(
                    state.get(&BwKey(base + i)).copied(),
                    Some(BwValue(base + i + 10))
                );
            }
        }
    }

    #[test]
    fn concurrent_insert_delete_non_overlapping_ranges() {
        let table = Arc::new(MappingTable::with_capacity(1));
        let page = table.allocate_page().expect("alloc");

        // Pre-populate range 0..500 that will be deleted
        for i in 0..500_u64 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();

        // Thread 1: insert range 1000..1500
        {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for i in 1000..1500_u64 {
                    table
                        .insert(page, BwKey(i), BwValue(i + 10))
                        .expect("insert");
                }
            }));
        }

        // Thread 2: delete range 0..500
        {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for i in 0..500_u64 {
                    table.delete(page, BwKey(i)).expect("delete");
                }
            }));
        }

        for h in handles {
            h.join().expect("no panics");
        }

        let state = table.materialize_page(page).expect("materialize");
        // All 0..500 should be deleted
        for i in 0..500_u64 {
            assert!(!state.contains_key(&BwKey(i)), "key {i} should be deleted");
        }
        // All 1000..1500 should be present
        for i in 1000..1500_u64 {
            assert_eq!(
                state.get(&BwKey(i)).copied(),
                Some(BwValue(i + 10)),
                "key {i} should be present"
            );
        }
    }

    #[test]
    fn concurrent_insert_delete_overlapping_keys() {
        let table = Arc::new(MappingTable::with_capacity(1));
        let page = table.allocate_page().expect("alloc");

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();

        // Thread 1: repeatedly insert keys 0..100
        {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for round in 0..10_u64 {
                    for i in 0..100 {
                        table
                            .insert(page, BwKey(i), BwValue(round * 100 + i))
                            .expect("insert");
                    }
                }
            }));
        }

        // Thread 2: repeatedly delete keys 0..100
        {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..5 {
                    for i in 0..100_u64 {
                        let _ = table.delete(page, BwKey(i));
                    }
                }
            }));
        }

        for h in handles {
            h.join().expect("no panics");
        }

        // After both threads: we can't predict exact state,
        // but materialization must not panic or produce corrupt results.
        let state = table.materialize_page(page).expect("materialize");
        // All present keys must have valid values
        for (key, value) in &state {
            assert!(key.0 < 100, "unexpected key {}", key.0);
            assert!(value.0 < 1000, "unexpected value {}", value.0);
        }
    }

    #[test]
    fn empty_page_operations() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        // Lookup on empty page returns None
        assert_eq!(table.lookup(page, BwKey(0)).expect("lookup"), None);
        assert_eq!(table.lookup(page, BwKey(u64::MAX)).expect("lookup"), None);

        // Delete on empty page succeeds (no-op)
        table.delete(page, BwKey(42)).expect("delete");

        // Materialize empty page returns empty map
        let state = table.materialize_page(page).expect("materialize");
        assert!(state.is_empty());
    }

    #[test]
    fn single_element_all_operations() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        table.insert(page, BwKey(42), BwValue(99)).expect("insert");
        assert_eq!(
            table.lookup(page, BwKey(42)).expect("lookup"),
            Some(BwValue(99))
        );

        let state = table.materialize_page(page).expect("materialize");
        assert_eq!(state.len(), 1);

        table.delete(page, BwKey(42)).expect("delete");
        assert_eq!(table.lookup(page, BwKey(42)).expect("lookup"), None);

        let state = table.materialize_page(page).expect("materialize");
        assert!(state.is_empty());
    }

    #[test]
    fn unallocated_page_returns_not_found() {
        let table = MappingTable::with_capacity(4);
        // No pages allocated yet
        let result = table.lookup(PageId(0), BwKey(0));
        assert!(result.is_err());
    }

    #[test]
    fn page_allocation_exhaustion() {
        let table = MappingTable::with_capacity(2);
        table.allocate_page().expect("first alloc");
        table.allocate_page().expect("second alloc");
        let result = table.allocate_page();
        assert!(result.is_err(), "should fail when capacity exhausted");
    }

    #[test]
    fn consolidation_after_all_keys_deleted_produces_empty_base() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for i in 0..20_u64 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }
        for i in 0..20_u64 {
            table.delete(page, BwKey(i)).expect("delete");
        }

        let config = default_config();
        let result = table.consolidate_page(page, &config).expect("consolidate");
        assert_eq!(result.entries_count, 0);
        assert_eq!(result.chain_len_after, 1);

        let state = table.materialize_page(page).expect("materialize");
        assert!(state.is_empty());
    }

    #[test]
    fn consolidation_triggered_by_threshold_scan() {
        let table = MappingTable::with_capacity(2);
        let p0 = table.allocate_page().expect("alloc");
        let p1 = table.allocate_page().expect("alloc");

        // p0: exactly at threshold (should not be consolidated)
        for i in 0..4_u64 {
            table.insert(p0, BwKey(i), BwValue(i)).expect("insert");
        }
        // p1: above threshold
        for i in 0..20_u64 {
            table.insert(p1, BwKey(i), BwValue(i)).expect("insert");
        }

        let config = ConsolidationConfig {
            chain_threshold: 5,
            max_retries: 64,
        };
        let count = table.consolidate_all(&config).expect("consolidate_all");
        assert_eq!(count, 1); // only p1

        // p0 chain unchanged
        let snap0 = table.get_page(p0).expect("get");
        assert_eq!(chain_length(&snap0.head), 5); // 4 inserts + base

        // p1 consolidated
        let snap1 = table.get_page(p1).expect("get");
        assert_eq!(chain_length(&snap1.head), 1);
    }

    #[test]
    fn multiple_pages_independent_state() {
        let table = MappingTable::with_capacity(4);
        let pages: Vec<PageId> = (0..4)
            .map(|_| table.allocate_page().expect("alloc"))
            .collect();

        // Insert different data into each page
        for (idx, &page) in pages.iter().enumerate() {
            let base = (idx as u64) * 100;
            for i in 0..10_u64 {
                table
                    .insert(page, BwKey(base + i), BwValue(base + i))
                    .expect("insert");
            }
        }

        // Verify each page has only its own data
        for (idx, &page) in pages.iter().enumerate() {
            let state = table.materialize_page(page).expect("materialize");
            assert_eq!(state.len(), 10);
            let base = (idx as u64) * 100;
            for i in 0..10_u64 {
                assert_eq!(
                    state.get(&BwKey(base + i)).copied(),
                    Some(BwValue(base + i))
                );
            }
            // Should not have other pages' data
            for other_idx in 0..4 {
                if other_idx != idx {
                    let other_base = (other_idx as u64) * 100;
                    assert!(!state.contains_key(&BwKey(other_base)));
                }
            }
        }
    }

    #[test]
    fn consolidation_stress_interleaved() {
        let table = Arc::new(MappingTable::with_capacity(4));
        let pages: Vec<PageId> = (0..4)
            .map(|_| table.allocate_page().expect("alloc"))
            .collect();

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        // 4 inserter threads (one per page)
        for (idx, &page) in pages.iter().enumerate() {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let base = (idx as u64) * 1000;
                for i in 0..100 {
                    table
                        .insert(page, BwKey(base + i), BwValue(base + i))
                        .expect("insert");
                }
            }));
        }

        // 4 consolidator threads (one per page)
        for &page in &pages {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let config = ConsolidationConfig {
                    chain_threshold: 1,
                    max_retries: 512,
                };
                for _ in 0..10 {
                    let _ = table.consolidate_page(page, &config);
                    std::thread::yield_now();
                }
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        // Verify all data is intact
        for (idx, &page) in pages.iter().enumerate() {
            let state = table.materialize_page(page).expect("materialize");
            let base = (idx as u64) * 1000;
            assert_eq!(state.len(), 100);
            for i in 0..100 {
                assert_eq!(
                    state.get(&BwKey(base + i)).copied(),
                    Some(BwValue(base + i))
                );
            }
        }
    }
}
