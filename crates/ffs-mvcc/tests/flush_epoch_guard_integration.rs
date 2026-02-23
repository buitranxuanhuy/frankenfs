#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_block::{ArcCache, ArcWritePolicy, BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result as FfsResult};
use ffs_mvcc::{MvccStore, StoreBackedMvccFlushLifecycle};
use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
use parking_lot::{Condvar, Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct MemBlockDevice {
    blocks: RwLock<HashMap<BlockNumber, Vec<u8>>>,
    block_size: u32,
    block_count: u64,
}

impl MemBlockDevice {
    fn new(block_size: u32, block_count: u64) -> Self {
        Self {
            blocks: RwLock::new(HashMap::new()),
            block_size,
            block_count,
        }
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> FfsResult<BlockBuf> {
        let bs = usize::try_from(self.block_size)
            .map_err(|_| FfsError::Format("block_size overflow".to_owned()))?;
        let data = self
            .blocks
            .read()
            .get(&block)
            .cloned()
            .unwrap_or_else(|| vec![0_u8; bs]);
        Ok(BlockBuf::new(data))
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> FfsResult<()> {
        self.blocks.write().insert(block, data.to_vec());
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn sync(&self, _cx: &Cx) -> FfsResult<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct GateState {
    writes_started: usize,
    blocked: bool,
}

#[derive(Debug, Clone)]
struct GatedMemBlockDevice {
    inner: Arc<MemBlockDevice>,
    gate: Arc<(Mutex<GateState>, Condvar)>,
}

impl GatedMemBlockDevice {
    fn new(block_size: u32, block_count: u64) -> Self {
        Self {
            inner: Arc::new(MemBlockDevice::new(block_size, block_count)),
            gate: Arc::new((
                Mutex::new(GateState {
                    writes_started: 0,
                    blocked: true,
                }),
                Condvar::new(),
            )),
        }
    }

    fn wait_for_write_start(&self, timeout: Duration) -> bool {
        let (state_lock, cv) = &*self.gate;
        let mut state = state_lock.lock();
        let deadline = Instant::now() + timeout;
        while state.writes_started == 0 {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            cv.wait_for(&mut state, deadline.saturating_duration_since(now));
        }
        true
    }

    fn unblock_writes(&self) {
        let (state_lock, cv) = &*self.gate;
        let mut state = state_lock.lock();
        state.blocked = false;
        drop(state);
        cv.notify_all();
    }
}

impl BlockDevice for GatedMemBlockDevice {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> FfsResult<BlockBuf> {
        self.inner.read_block(cx, block)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> FfsResult<()> {
        let (state_lock, cv) = &*self.gate;
        let mut state = state_lock.lock();
        state.writes_started = state.writes_started.saturating_add(1);
        cv.notify_all();
        while state.blocked {
            cv.wait(&mut state);
        }
        drop(state);
        self.inner.write_block(cx, block, data)
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> FfsResult<()> {
        self.inner.sync(cx)
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "integration scenario intentionally validates flush pin lifecycle end-to-end"
)]
fn flush_epoch_guard_blocks_gc_until_writeback_finishes() {
    let cx = Cx::for_testing();
    let block = BlockNumber(335);
    let payload_v2 = vec![0x22; 4096];
    let payload_v3 = vec![0x33; 4096];

    let mut seed_store = MvccStore::new();
    for fill in [0x11_u8, 0x22, 0x33] {
        let mut txn = seed_store.begin();
        txn.stage_write(block, vec![fill; 4096]);
        seed_store.commit(txn).expect("seed commit");
    }

    let snapshot_v2 = Snapshot { high: CommitSeq(2) };
    assert_eq!(
        seed_store
            .read_visible(block, snapshot_v2)
            .expect("version 2 visible")
            .as_ref(),
        payload_v2.as_slice()
    );

    let shared_store = Arc::new(RwLock::new(seed_store));
    let lifecycle = Arc::new(StoreBackedMvccFlushLifecycle::new(Arc::clone(
        &shared_store,
    )));
    let gated_device = GatedMemBlockDevice::new(4096, 32);
    let gate_handle = gated_device.clone();

    let cache = Arc::new(
        ArcCache::new_with_policy_and_mvcc_lifecycle(
            gated_device,
            8,
            ArcWritePolicy::WriteBack,
            lifecycle.clone(),
        )
        .expect("cache"),
    );

    cache
        .stage_txn_write(&cx, TxnId(700), block, &payload_v2)
        .expect("stage dirty flush payload");
    cache
        .commit_staged_txn(&cx, TxnId(700), CommitSeq(2))
        .expect("commit staged txn");

    let cache_for_flush = Arc::clone(&cache);
    let flush_thread = std::thread::spawn(move || {
        let flush_cx = Cx::for_testing();
        cache_for_flush.flush_dirty(&flush_cx)
    });

    assert!(
        gate_handle.wait_for_write_start(Duration::from_secs(1)),
        "flush write should reach gated device"
    );
    assert_eq!(
        lifecycle.active_flush_pins(),
        1,
        "epoch guard must be held while flush is in-flight"
    );

    {
        let mut store = shared_store.write();
        let before = store.ebr_stats();
        let _ = store.prune_safe();
        store.ebr_collect();
        let during_flush = store.ebr_stats();

        assert_eq!(
            store
                .read_visible(block, snapshot_v2)
                .expect("version 2 pinned during flush")
                .as_ref(),
            payload_v2.as_slice(),
            "GC must not reclaim the flush-referenced version while guard is held"
        );
        assert_eq!(
            during_flush.retired_versions,
            before.retired_versions.saturating_add(1),
            "only the oldest pre-v2 version should retire while v2 is pinned"
        );
        assert_eq!(
            store
                .read_visible(block, Snapshot { high: CommitSeq(3) })
                .expect("latest version visible")
                .as_ref(),
            payload_v3.as_slice()
        );
        drop(store);
    }

    gate_handle.unblock_writes();
    flush_thread
        .join()
        .expect("flush thread join")
        .expect("flush completes");

    assert_eq!(
        lifecycle.active_flush_pins(),
        0,
        "epoch guard should release after flush completion"
    );
    assert_eq!(
        lifecycle.acquired_flush_pins(),
        lifecycle.released_flush_pins(),
        "every acquired flush guard should be released"
    );

    {
        let mut store = shared_store.write();
        let _ = store.prune_safe();
        store.ebr_collect();
        let v2_after = store.read_visible(block, snapshot_v2).map(std::borrow::Cow::into_owned);
        assert_ne!(
            v2_after,
            Some(payload_v2),
            "version 2 should be reclaimable once flush guard is released"
        );
        assert_eq!(
            store
                .read_visible(block, Snapshot { high: CommitSeq(3) })
                .expect("latest survives")
                .as_ref(),
            payload_v3.as_slice()
        );
        drop(store);
    }
}
