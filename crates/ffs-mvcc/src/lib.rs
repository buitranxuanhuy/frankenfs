#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::FfsError;
use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVersion {
    pub block: BlockNumber,
    pub commit_seq: CommitSeq,
    pub writer: TxnId,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TxnId,
    pub snapshot: Snapshot,
    writes: BTreeMap<BlockNumber, Vec<u8>>,
}

impl Transaction {
    pub fn stage_write(&mut self, block: BlockNumber, bytes: Vec<u8>) {
        self.writes.insert(block, bytes);
    }

    #[must_use]
    pub fn staged_write(&self, block: BlockNumber) -> Option<&[u8]> {
        self.writes.get(&block).map(Vec::as_slice)
    }

    #[must_use]
    pub fn pending_writes(&self) -> usize {
        self.writes.len()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommitError {
    #[error(
        "first-committer-wins conflict on block {block}: snapshot={snapshot:?}, observed={observed:?}"
    )]
    Conflict {
        block: BlockNumber,
        snapshot: CommitSeq,
        observed: CommitSeq,
    },
}

#[derive(Debug, Clone, Default)]
pub struct MvccStore {
    next_txn: u64,
    next_commit: u64,
    versions: BTreeMap<BlockNumber, Vec<BlockVersion>>,
}

impl MvccStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_txn: 1,
            next_commit: 1,
            versions: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn current_snapshot(&self) -> Snapshot {
        let high = self.next_commit.saturating_sub(1);
        Snapshot {
            high: CommitSeq(high),
        }
    }

    pub fn begin(&mut self) -> Transaction {
        let txn = Transaction {
            id: TxnId(self.next_txn),
            snapshot: self.current_snapshot(),
            writes: BTreeMap::new(),
        };
        self.next_txn = self.next_txn.saturating_add(1);
        txn
    }

    pub fn commit(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        for block in txn.writes.keys() {
            let latest = self.latest_commit_seq(*block);
            if latest > txn.snapshot.high {
                return Err(CommitError::Conflict {
                    block: *block,
                    snapshot: txn.snapshot.high,
                    observed: latest,
                });
            }
        }

        let commit_seq = CommitSeq(self.next_commit);
        self.next_commit = self.next_commit.saturating_add(1);

        for (block, bytes) in txn.writes {
            self.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn.id,
                bytes,
            });
        }

        Ok(commit_seq)
    }

    #[must_use]
    pub fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        self.versions
            .get(&block)
            .and_then(|v| v.last())
            .map_or(CommitSeq(0), |v| v.commit_seq)
    }

    #[must_use]
    pub fn read_visible(&self, block: BlockNumber, snapshot: Snapshot) -> Option<&[u8]> {
        self.versions.get(&block).and_then(|versions| {
            versions
                .iter()
                .rev()
                .find(|v| v.commit_seq <= snapshot.high)
                .map(|v| v.bytes.as_slice())
        })
    }

    pub fn prune_versions_older_than(&mut self, watermark: CommitSeq) {
        for versions in self.versions.values_mut() {
            if versions.len() <= 1 {
                continue;
            }

            let mut keep_from = 0_usize;
            while keep_from + 1 < versions.len() {
                if versions[keep_from + 1].commit_seq <= watermark {
                    keep_from += 1;
                } else {
                    break;
                }
            }

            if keep_from > 0 {
                versions.drain(0..keep_from);
            }
        }
    }
}

/// Snapshot-aware block device wrapper.
///
/// Reads check the `MvccStore` for a version visible at the configured
/// snapshot before falling back to the base device.  Writes stage data
/// into the version store immediately (write-through to the base device
/// is deferred to commit time).
///
/// # Concurrency
///
/// The `MvccStore` is behind a `parking_lot::RwLock`:
/// - **Reads** acquire a shared (`read`) lock — many concurrent readers.
/// - **Writes/commits** acquire an exclusive (`write`) lock.
/// - The base device read (fallback path) happens **outside** the lock.
#[derive(Debug)]
pub struct MvccBlockDevice<D: BlockDevice> {
    base: D,
    store: Arc<RwLock<MvccStore>>,
    snapshot: Snapshot,
}

impl<D: BlockDevice> MvccBlockDevice<D> {
    /// Create a new MVCC block device at a given snapshot.
    ///
    /// The `store` is shared across all devices/transactions that
    /// participate in the same MVCC group.
    pub fn new(base: D, store: Arc<RwLock<MvccStore>>, snapshot: Snapshot) -> Self {
        Self {
            base,
            store,
            snapshot,
        }
    }

    /// The snapshot this device reads at.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    /// Shared reference to the MVCC store.
    #[must_use]
    pub fn store(&self) -> &Arc<RwLock<MvccStore>> {
        &self.store
    }

    /// Reference to the underlying base device.
    #[must_use]
    pub fn base(&self) -> &D {
        &self.base
    }
}

impl<D: BlockDevice> BlockDevice for MvccBlockDevice<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
        // Check version store first (shared lock, no I/O).
        {
            let guard = self.store.read();
            if let Some(bytes) = guard.read_visible(block, self.snapshot) {
                return Ok(BlockBuf::new(bytes.to_vec()));
            }
        }
        // Fall back to base device (no lock held).
        self.base.read_block(cx, block)
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
        // Stage into a new single-block transaction and commit immediately.
        // For batched writes, callers should use the MvccStore API directly.
        let mut guard = self.store.write();
        let mut txn = guard.begin();
        txn.stage_write(block, data.to_vec());
        guard
            .commit(txn)
            .map_err(|e| FfsError::Format(e.to_string()))?;
        drop(guard);
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.base.block_size()
    }

    fn block_count(&self) -> u64 {
        self.base.block_count()
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.base.sync(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Simple in-memory block device for testing `MvccBlockDevice`.
    #[derive(Debug)]
    struct MemBlockDevice {
        blocks: parking_lot::RwLock<HashMap<BlockNumber, Vec<u8>>>,
        block_size: u32,
        block_count: u64,
    }

    impl MemBlockDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                blocks: parking_lot::RwLock::new(HashMap::new()),
                block_size,
                block_count,
            }
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
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

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
            self.blocks.write().insert(block, data.to_vec());
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            self.block_count
        }

        fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
            Ok(())
        }
    }

    fn test_cx() -> Cx {
        Cx::for_testing()
    }

    #[test]
    fn visibility_and_fcw_conflict() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(7), vec![1, 2, 3]);
        t2.stage_write(BlockNumber(7), vec![9, 9, 9]);

        let c1 = store.commit(t1).expect("t1 commit");
        assert_eq!(c1, CommitSeq(1));

        let err = store.commit(t2).expect_err("t2 should conflict");
        match err {
            CommitError::Conflict { block, .. } => assert_eq!(block, BlockNumber(7)),
        }
    }

    #[test]
    fn read_snapshot_visibility() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(1), vec![1]);
        let _ = store.commit(t1).expect("commit t1");

        let snap = store.current_snapshot();

        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(1), vec![2]);
        let _ = store.commit(t2).expect("commit t2");

        let visible = store
            .read_visible(BlockNumber(1), snap)
            .expect("visible data at snap");
        assert_eq!(visible, &[1]);
    }

    // ── MvccBlockDevice tests ────────────────────────────────────────────

    #[test]
    fn mvcc_device_read_falls_back_to_base() {
        let cx = test_cx();
        let base = MemBlockDevice::new(512, 16);
        // Pre-populate block 3 in base device.
        base.write_block(&cx, BlockNumber(3), &[0xAB; 512])
            .expect("base write");

        let store = Arc::new(RwLock::new(MvccStore::new()));
        let snap = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, store, snap);

        let buf = dev.read_block(&cx, BlockNumber(3)).expect("read block 3");
        assert_eq!(buf.as_slice(), &[0xAB; 512]);
    }

    #[test]
    fn mvcc_device_write_visible_to_reader_at_later_snapshot() {
        let cx = test_cx();
        let base = MemBlockDevice::new(512, 16);
        let store = Arc::new(RwLock::new(MvccStore::new()));

        let snap1 = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap1);

        // Write via the MVCC device.
        dev.write_block(&cx, BlockNumber(5), &[0xFF; 512])
            .expect("mvcc write");

        // A new snapshot taken after the write should see it.
        let snap2 = store.read().current_snapshot();
        let base2 = MemBlockDevice::new(512, 16);
        let dev2 = MvccBlockDevice::new(base2, Arc::clone(&store), snap2);

        let buf = dev2.read_block(&cx, BlockNumber(5)).expect("read block 5");
        assert_eq!(buf.as_slice(), &[0xFF; 512]);
    }

    #[test]
    fn mvcc_device_snapshot_isolation() {
        let cx = test_cx();
        let store = Arc::new(RwLock::new(MvccStore::new()));

        // Commit a version via the store directly.
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(BlockNumber(1), vec![1; 512]);
            guard.commit(txn).expect("commit v1");
        }

        // Capture snapshot after v1.
        let snap_after_v1 = store.read().current_snapshot();

        // Commit a second version.
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(BlockNumber(1), vec![2; 512]);
            guard.commit(txn).expect("commit v2");
        }

        // Device at snap_after_v1 should see v1, not v2.
        let base = MemBlockDevice::new(512, 16);
        let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap_after_v1);
        let buf = dev.read_block(&cx, BlockNumber(1)).expect("read");
        assert_eq!(buf.as_slice(), &[1; 512]);

        // Device at latest snapshot should see v2.
        let snap_after_v2 = store.read().current_snapshot();
        let base2 = MemBlockDevice::new(512, 16);
        let dev2 = MvccBlockDevice::new(base2, Arc::clone(&store), snap_after_v2);
        let buf2 = dev2.read_block(&cx, BlockNumber(1)).expect("read v2");
        assert_eq!(buf2.as_slice(), &[2; 512]);
    }

    #[test]
    fn mvcc_device_delegates_block_size_and_count() {
        let base = MemBlockDevice::new(4096, 128);
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let snap = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, store, snap);

        assert_eq!(dev.block_size(), 4096);
        assert_eq!(dev.block_count(), 128);
    }
}
