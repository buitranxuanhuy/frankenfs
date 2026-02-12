#![forbid(unsafe_code)]
//! Block I/O layer with ARC (Adaptive Replacement Cache).
//!
//! Provides the `BlockDevice` trait, cached block reads/writes with
//! `&Cx` capability context for cooperative cancellation, dirty page
//! tracking, and background flush coordination.

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_types::{
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, BlockNumber, ByteOffset,
    EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE,
};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;

#[inline]
fn cx_checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

/// Owned block buffer.
///
/// Invariant: length == device block size for the originating device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBuf {
    bytes: Vec<u8>,
}

impl BlockBuf {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

/// Byte-addressed device for fixed-offset I/O (pread/pwrite semantics).
pub trait ByteDevice: Send + Sync {
    /// Total length in bytes.
    fn len_bytes(&self) -> u64;

    /// Read exactly `buf.len()` bytes from `offset` into `buf`.
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()>;

    /// Write all bytes in `buf` to `offset`.
    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()>;

    /// Flush pending writes to stable storage.
    fn sync(&self, cx: &Cx) -> Result<()>;
}

/// File-backed byte device using Linux `pread`/`pwrite` style I/O.
///
/// This uses `std::os::unix::fs::FileExt`, which is thread-safe and does not
/// require a shared seek position.
#[derive(Debug, Clone)]
pub struct FileByteDevice {
    file: Arc<File>,
    len: u64,
    writable: bool,
}

impl FileByteDevice {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let (file, writable) = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.as_ref())
            .map(|file| (file, true))
            .or_else(|_| {
                OpenOptions::new()
                    .read(true)
                    .open(path.as_ref())
                    .map(|file| (file, false))
            })?;
        let len = file.metadata()?.len();
        Ok(Self {
            file: Arc::new(file),
            len,
            writable,
        })
    }

    #[must_use]
    pub fn file(&self) -> &Arc<File> {
        &self.file
    }
}

impl ByteDevice for FileByteDevice {
    fn len_bytes(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        let end = offset
            .0
            .checked_add(
                u64::try_from(buf.len())
                    .map_err(|_| FfsError::Format("read length overflows u64".to_owned()))?,
            )
            .ok_or_else(|| FfsError::Format("read range overflows u64".to_owned()))?;
        if end > self.len {
            return Err(FfsError::Format(format!(
                "read out of bounds: offset={offset} len={} file_len={}",
                buf.len(),
                self.len
            )));
        }

        self.file.read_exact_at(buf, offset.0)?;
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::PermissionDenied);
        }
        let end = offset
            .0
            .checked_add(
                u64::try_from(buf.len())
                    .map_err(|_| FfsError::Format("write length overflows u64".to_owned()))?,
            )
            .ok_or_else(|| FfsError::Format("write range overflows u64".to_owned()))?;
        if end > self.len {
            return Err(FfsError::Format(format!(
                "write out of bounds: offset={offset} len={} file_len={}",
                buf.len(),
                self.len
            )));
        }

        self.file.write_all_at(buf, offset.0)?;
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        cx_checkpoint(cx)?;
        self.file.sync_all()?;
        cx_checkpoint(cx)?;
        Ok(())
    }
}

/// Block-addressed I/O interface.
pub trait BlockDevice: Send + Sync {
    /// Read a block by number.
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf>;

    /// Write a block by number. `data.len()` MUST equal `block_size()`.
    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()>;

    /// Device block size in bytes.
    fn block_size(&self) -> u32;

    /// Total number of blocks.
    fn block_count(&self) -> u64;

    /// Flush pending writes to stable storage.
    fn sync(&self, cx: &Cx) -> Result<()>;
}

#[derive(Debug)]
pub struct ByteBlockDevice<D: ByteDevice> {
    inner: D,
    block_size: u32,
    block_count: u64,
}

impl<D: ByteDevice> ByteBlockDevice<D> {
    pub fn new(inner: D, block_size: u32) -> Result<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(FfsError::Format(format!(
                "invalid block_size={block_size} (must be power of two)"
            )));
        }

        let len = inner.len_bytes();
        let block_size_u64 = u64::from(block_size);
        let remainder = len % block_size_u64;
        if remainder != 0 {
            return Err(FfsError::Format(format!(
                "image length is not block-aligned: len_bytes={len} block_size={block_size} remainder={remainder}"
            )));
        }
        let block_count = len / block_size_u64;
        Ok(Self {
            inner,
            block_size,
            block_count,
        })
    }

    #[must_use]
    pub fn inner(&self) -> &D {
        &self.inner
    }
}

impl<D: ByteDevice> BlockDevice for ByteBlockDevice<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        cx_checkpoint(cx)?;
        if block.0 >= self.block_count {
            return Err(FfsError::Format(format!(
                "block out of range: block={} block_count={}",
                block.0, self.block_count
            )));
        }

        let offset = block
            .0
            .checked_mul(u64::from(self.block_size))
            .ok_or_else(|| FfsError::Format("block offset overflow".to_owned()))?;
        let mut buf = vec![
            0_u8;
            usize::try_from(self.block_size).map_err(|_| {
                FfsError::Format("block_size does not fit usize".to_owned())
            })?
        ];
        self.inner.read_exact_at(cx, ByteOffset(offset), &mut buf)?;
        cx_checkpoint(cx)?;
        Ok(BlockBuf::new(buf))
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        let expected = usize::try_from(self.block_size)
            .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;
        if data.len() != expected {
            return Err(FfsError::Format(format!(
                "write_block data size mismatch: got={} expected={expected}",
                data.len()
            )));
        }
        if block.0 >= self.block_count {
            return Err(FfsError::Format(format!(
                "block out of range: block={} block_count={}",
                block.0, self.block_count
            )));
        }

        let offset = block
            .0
            .checked_mul(u64::from(self.block_size))
            .ok_or_else(|| FfsError::Format("block offset overflow".to_owned()))?;
        self.inner.write_all_at(cx, ByteOffset(offset), data)?;
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.inner.sync(cx)
    }
}

/// Read the ext4 superblock region (1024 bytes at offset 1024).
pub fn read_ext4_superblock_region(
    cx: &Cx,
    dev: &dyn ByteDevice,
) -> Result<[u8; EXT4_SUPERBLOCK_SIZE]> {
    let mut buf = [0_u8; EXT4_SUPERBLOCK_SIZE];
    let offset = u64::try_from(EXT4_SUPERBLOCK_OFFSET)
        .map_err(|_| FfsError::Format("ext4 superblock offset does not fit u64".to_owned()))?;
    dev.read_exact_at(cx, ByteOffset(offset), &mut buf)?;
    Ok(buf)
}

/// Read the btrfs superblock region (4096 bytes at offset 64 KiB).
pub fn read_btrfs_superblock_region(
    cx: &Cx,
    dev: &dyn ByteDevice,
) -> Result<[u8; BTRFS_SUPER_INFO_SIZE]> {
    let mut buf = [0_u8; BTRFS_SUPER_INFO_SIZE];
    let offset = u64::try_from(BTRFS_SUPER_INFO_OFFSET)
        .map_err(|_| FfsError::Format("btrfs superblock offset does not fit u64".to_owned()))?;
    dev.read_exact_at(cx, ByteOffset(offset), &mut buf)?;
    Ok(buf)
}

/// Snapshot of ARC cache statistics.
///
/// Obtained via [`ArcCache::metrics()`] with a single lock acquisition.
/// All counters are monotonically increasing for the lifetime of the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheMetrics {
    /// Number of read requests satisfied from the cache.
    pub hits: u64,
    /// Number of read requests that required a device read.
    pub misses: u64,
    /// Number of resident blocks evicted to make room for new entries.
    pub evictions: u64,
    /// Number of dirty flushes (dirty blocks written during sync/eviction).
    pub dirty_flushes: u64,
    /// Current number of blocks in the T1 (recently accessed) list.
    pub t1_len: usize,
    /// Current number of blocks in the T2 (frequently accessed) list.
    pub t2_len: usize,
    /// Current number of ghost entries in B1 (evicted from T1).
    pub b1_len: usize,
    /// Current number of ghost entries in B2 (evicted from T2).
    pub b2_len: usize,
    /// Total number of resident (cached) blocks.
    pub resident: usize,
    /// Current number of dirty (modified but not yet flushed) blocks.
    pub dirty_blocks: usize,
    /// Maximum cache capacity in blocks.
    pub capacity: usize,
    /// Current adaptive target size for T1.
    pub p: usize,
}

impl CacheMetrics {
    /// Cache hit ratio in the range [0.0, 1.0].
    ///
    /// Returns 0.0 if no accesses have been made.
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArcList {
    T1,
    T2,
    B1,
    B2,
}

#[derive(Debug)]
struct ArcState {
    capacity: usize,
    /// Target size for the T1 list.
    p: usize,
    t1: VecDeque<BlockNumber>,
    t2: VecDeque<BlockNumber>,
    b1: VecDeque<BlockNumber>,
    b2: VecDeque<BlockNumber>,
    loc: HashMap<BlockNumber, ArcList>,
    resident: HashMap<BlockNumber, Vec<u8>>,
    /// Blocks that have been written and need flush accounting.
    /// We keep write-through semantics today, but intentionally track dirty
    /// metadata so sync/eviction paths are exercised for future write-back mode.
    dirty: HashSet<BlockNumber>,
    /// Dirty block payloads evicted before an explicit `sync`.
    /// These must be flushed even if the block is no longer resident.
    pending_flush: Vec<(BlockNumber, Vec<u8>)>,
    /// Monotonic hit counter (resident data found).
    hits: u64,
    /// Monotonic miss counter (device read required).
    misses: u64,
    /// Monotonic eviction counter (resident block displaced).
    evictions: u64,
    /// Monotonic dirty flush counter (dirty blocks written during sync/eviction).
    dirty_flushes: u64,
}

impl ArcState {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            p: 0,
            t1: VecDeque::new(),
            t2: VecDeque::new(),
            b1: VecDeque::new(),
            b2: VecDeque::new(),
            loc: HashMap::new(),
            resident: HashMap::new(),
            dirty: HashSet::new(),
            pending_flush: Vec::new(),
            hits: 0,
            misses: 0,
            evictions: 0,
            dirty_flushes: 0,
        }
    }

    fn resident_len(&self) -> usize {
        self.t1.len() + self.t2.len()
    }

    fn total_len(&self) -> usize {
        self.t1.len() + self.t2.len() + self.b1.len() + self.b2.len()
    }

    fn snapshot_metrics(&self) -> CacheMetrics {
        CacheMetrics {
            hits: self.hits,
            misses: self.misses,
            evictions: self.evictions,
            dirty_flushes: self.dirty_flushes,
            t1_len: self.t1.len(),
            t2_len: self.t2.len(),
            b1_len: self.b1.len(),
            b2_len: self.b2.len(),
            resident: self.resident_len(),
            dirty_blocks: self.dirty.len(),
            capacity: self.capacity,
            p: self.p,
        }
    }

    fn remove_from_list(list: &mut VecDeque<BlockNumber>, key: BlockNumber) -> bool {
        if let Some(pos) = list.iter().position(|k| *k == key) {
            let _ = list.remove(pos);
            return true;
        }
        false
    }

    fn evict_resident(&mut self, victim: BlockNumber) {
        if let Some(bytes) = self.resident.remove(&victim) {
            if self.is_dirty(victim) {
                self.pending_flush.push((victim, bytes));
                self.clear_dirty(victim);
            }
        } else {
            self.clear_dirty(victim);
        }
    }

    fn touch_mru(&mut self, key: BlockNumber) {
        let Some(list) = self.loc.get(&key).copied() else {
            return;
        };

        match list {
            ArcList::T1 => {
                let _ = Self::remove_from_list(&mut self.t1, key);
                self.t2.push_back(key);
                self.loc.insert(key, ArcList::T2);
            }
            ArcList::T2 => {
                let _ = Self::remove_from_list(&mut self.t2, key);
                self.t2.push_back(key);
            }
            ArcList::B1 | ArcList::B2 => {}
        }
    }

    fn replace(&mut self, incoming: BlockNumber) {
        // `replace()` is only meaningful when the resident set is full.
        // Guard against accidental calls during warm-up, which would cause
        // premature eviction and underutilize the cache.
        if self.resident_len() < self.capacity {
            return;
        }

        let t1_len = self.t1.len();
        if t1_len >= 1
            && (t1_len > self.p
                || (matches!(self.loc.get(&incoming), Some(ArcList::B2)) && t1_len == self.p))
        {
            if let Some(victim) = self.t1.pop_front() {
                self.loc.insert(victim, ArcList::B1);
                self.evict_resident(victim);
                self.b1.push_back(victim);
                self.evictions += 1;
            }
        } else if let Some(victim) = self.t2.pop_front() {
            self.loc.insert(victim, ArcList::B2);
            self.evict_resident(victim);
            self.b2.push_back(victim);
            self.evictions += 1;
        }

        while self.b1.len() > self.capacity {
            if let Some(victim) = self.b1.pop_front() {
                let _ = self.loc.remove(&victim);
            }
        }
        while self.b2.len() > self.capacity {
            if let Some(victim) = self.b2.pop_front() {
                let _ = self.loc.remove(&victim);
            }
        }
    }

    fn on_hit(&mut self, key: BlockNumber) {
        self.hits += 1;
        self.touch_mru(key);
    }

    fn on_miss_or_ghost_hit(&mut self, key: BlockNumber) {
        self.misses += 1;
        // Defensive: callers use `resident.contains_key()` to decide hit vs miss.
        // If we ever see a "miss" for a resident key, treat it as a hit to avoid
        // duplicating list entries.
        if matches!(self.loc.get(&key), Some(ArcList::T1 | ArcList::T2)) {
            debug_assert!(
                false,
                "ARC invariant violated: loc says resident but resident map is missing"
            );
            self.on_hit(key);
            return;
        }

        if matches!(self.loc.get(&key), Some(ArcList::B1)) {
            let b1_len = self.b1.len().max(1);
            let b2_len = self.b2.len().max(1);
            let delta = (b2_len / b1_len).max(1);
            self.p = (self.p + delta).min(self.capacity);
            let _ = Self::remove_from_list(&mut self.b1, key);
            self.replace(key);
            self.t2.push_back(key);
            self.loc.insert(key, ArcList::T2);
            return;
        }

        if matches!(self.loc.get(&key), Some(ArcList::B2)) {
            let b1_len = self.b1.len().max(1);
            let b2_len = self.b2.len().max(1);
            let delta = (b1_len / b2_len).max(1);
            self.p = self.p.saturating_sub(delta);
            let _ = Self::remove_from_list(&mut self.b2, key);
            self.replace(key);
            self.t2.push_back(key);
            self.loc.insert(key, ArcList::T2);
            return;
        }

        // Not present in any list.
        let l1_len = self.t1.len() + self.b1.len();
        let total_len = self.total_len();
        if l1_len == self.capacity {
            if self.t1.len() < self.capacity {
                let _ = self.b1.pop_front().and_then(|v| self.loc.remove(&v));
                self.replace(key);
            } else if let Some(victim) = self.t1.pop_front() {
                let _ = self.loc.remove(&victim);
                self.evict_resident(victim);
                self.evictions += 1;
            }
        } else if l1_len < self.capacity && total_len >= self.capacity {
            if total_len >= self.capacity.saturating_mul(2) {
                let _ = self.b2.pop_front().and_then(|v| self.loc.remove(&v));
            }
            self.replace(key);
        }

        self.t1.push_back(key);
        self.loc.insert(key, ArcList::T1);
    }

    /// Mark a block as dirty (written but not yet flushed to disk).
    fn mark_dirty(&mut self, block: BlockNumber) {
        self.dirty.insert(block);
    }

    /// Clear the dirty flag for a block (after flushing to disk).
    fn clear_dirty(&mut self, block: BlockNumber) {
        self.dirty.remove(&block);
    }

    /// Check if a block is dirty.
    fn is_dirty(&self, block: BlockNumber) -> bool {
        self.dirty.contains(&block)
    }

    /// Return list of dirty blocks that need flushing.
    fn dirty_blocks(&self) -> Vec<BlockNumber> {
        self.dirty.iter().copied().collect()
    }

    fn take_pending_flush(&mut self) -> Vec<(BlockNumber, Vec<u8>)> {
        std::mem::take(&mut self.pending_flush)
    }

    fn take_dirty_and_pending_flushes(&mut self) -> Vec<(BlockNumber, Vec<u8>)> {
        let mut flushes = self.take_pending_flush();
        let mut queued = HashSet::with_capacity(flushes.len());
        for (block, _) in &flushes {
            queued.insert(*block);
        }

        for block in self.dirty_blocks() {
            if queued.contains(&block) {
                continue;
            }
            if let Some(data) = self.resident.get(&block).cloned() {
                flushes.push((block, data));
                queued.insert(block);
            }
        }
        flushes
    }
}

/// ARC-cached wrapper around a [`BlockDevice`].
///
/// Current behavior:
/// - read caching of whole blocks
/// - default write-through (writes update cache and the underlying device immediately)
/// - optional write-back mode via [`ArcCache::new_with_policy`]
///
/// # Concurrency design
///
/// **Locking strategy:** A single `parking_lot::Mutex<ArcState>` protects all
/// cache metadata (T1/T2/B1/B2 lists, resident map, counters).  This is
/// sufficient because:
///
/// 1. The lock is **never held during I/O**.  `read_block` drops the lock
///    before issuing a device read and re-acquires it afterwards.
///    `write_block` writes through to the device first, then acquires the lock
///    only to update metadata.
/// 2. `parking_lot::Mutex` is non-poisoning and uses adaptive spinning, so
///    contention under typical FUSE workloads (many concurrent reads, few
///    writes) remains low.
///
/// **Future sharding:** If profiling reveals lock contention under heavy
/// parallel read workloads, the cache can be sharded by `BlockNumber` into N
/// independent `Mutex<ArcState>` segments (e.g. `block.0 % N`).  The current
/// single-lock design keeps the implementation simple and correct as a
/// baseline.
///
/// TODO: replace write-through with deferred write-back and async background flushing.
#[derive(Debug)]
pub struct ArcCache<D: BlockDevice> {
    inner: D,
    state: Mutex<ArcState>,
    write_policy: ArcWritePolicy,
}

/// Write policy for [`ArcCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcWritePolicy {
    /// Always write to the underlying device immediately.
    WriteThrough,
    /// Keep writes in cache until sync; dirty evictions still flush immediately.
    WriteBack,
}

impl<D: BlockDevice> ArcCache<D> {
    pub fn new(inner: D, capacity_blocks: usize) -> Result<Self> {
        Self::new_with_policy(inner, capacity_blocks, ArcWritePolicy::WriteThrough)
    }

    pub fn new_with_policy(
        inner: D,
        capacity_blocks: usize,
        write_policy: ArcWritePolicy,
    ) -> Result<Self> {
        if capacity_blocks == 0 {
            return Err(FfsError::Format(
                "ArcCache capacity_blocks must be > 0".to_owned(),
            ));
        }
        Ok(Self {
            inner,
            state: Mutex::new(ArcState::new(capacity_blocks)),
            write_policy,
        })
    }

    #[must_use]
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Take a snapshot of current cache metrics.
    ///
    /// Acquires the state lock briefly to read counters and list sizes.
    /// The returned [`CacheMetrics`] is a frozen point-in-time snapshot.
    #[must_use]
    pub fn metrics(&self) -> CacheMetrics {
        self.state.lock().snapshot_metrics()
    }

    #[must_use]
    pub fn write_policy(&self) -> ArcWritePolicy {
        self.write_policy
    }

    fn flush_blocks(&self, cx: &Cx, flushes: &[(BlockNumber, Vec<u8>)]) -> Result<()> {
        for (block, data) in flushes {
            cx_checkpoint(cx)?;
            self.inner.write_block(cx, *block, data)?;
        }
        Ok(())
    }

    fn flush_pending_evictions(
        &self,
        cx: &Cx,
        pending_flush: Vec<(BlockNumber, Vec<u8>)>,
    ) -> Result<()> {
        if pending_flush.is_empty() {
            return Ok(());
        }

        if let Err(err) = self.flush_blocks(cx, &pending_flush) {
            // Restore the pending queue on failure so callers can retry.
            let mut guard = self.state.lock();
            for (block, _) in &pending_flush {
                guard.mark_dirty(*block);
            }
            guard.pending_flush.extend(pending_flush);
            drop(guard);
            return Err(err);
        }

        let mut guard = self.state.lock();
        guard.dirty_flushes += pending_flush.len() as u64;
        drop(guard);
        Ok(())
    }
}

impl<D: BlockDevice> BlockDevice for ArcCache<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        cx_checkpoint(cx)?;
        {
            let mut guard = self.state.lock();
            if let Some(bytes) = guard.resident.get(&block).cloned() {
                guard.on_hit(block);
                drop(guard);
                return Ok(BlockBuf::new(bytes));
            }
        }

        let buf = self.inner.read_block(cx, block)?;

        let mut guard = self.state.lock();
        // Re-check: another thread may have populated this block while we
        // were reading from the device (TOCTOU race).  If so, treat as a hit
        // and discard our redundant device read.
        if guard.resident.contains_key(&block) {
            guard.on_hit(block);
        } else {
            guard.on_miss_or_ghost_hit(block);
            guard.resident.insert(block, buf.as_slice().to_vec());
        }
        let pending_flush = guard.take_pending_flush();
        drop(guard);
        self.flush_pending_evictions(cx, pending_flush)?;
        Ok(buf)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        if matches!(self.write_policy, ArcWritePolicy::WriteThrough) {
            self.inner.write_block(cx, block, data)?;
        } else {
            cx_checkpoint(cx)?;
        }
        let mut guard = self.state.lock();
        if guard.resident.contains_key(&block) {
            // Block already cached — just update data and touch for recency.
            guard.resident.insert(block, data.to_vec());
            guard.on_hit(block);
        } else {
            guard.on_miss_or_ghost_hit(block);
            guard.resident.insert(block, data.to_vec());
        }
        guard.mark_dirty(block);
        let pending_flush = guard.take_pending_flush();
        drop(guard);
        self.flush_pending_evictions(cx, pending_flush)?;
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        // Flush any dirty blocks before syncing the underlying device.
        // Even in write-through mode we keep dirty/eviction accounting active
        // so write-back paths are validated continuously.
        self.flush_dirty(cx)?;
        self.inner.sync(cx)
    }
}

impl<D: BlockDevice> ArcCache<D> {
    /// Flush all dirty blocks to the underlying device.
    ///
    /// Current write path still writes through immediately, but we also keep
    /// dirty metadata so sync/eviction paths remain exercised and ready for
    /// future deferred write-back mode.
    ///
    /// Returns Ok(()) if all dirty blocks were successfully flushed.
    pub fn flush_dirty(&self, cx: &Cx) -> Result<()> {
        cx_checkpoint(cx)?;

        // Collect all dirty payloads (resident + evicted pending) under lock.
        let flushes = {
            let mut guard = self.state.lock();
            guard.take_dirty_and_pending_flushes()
        };

        if let Err(err) = self.flush_blocks(cx, &flushes) {
            // Restore flush state on failure so retry logic can recover.
            let mut guard = self.state.lock();
            for (block, _) in &flushes {
                guard.mark_dirty(*block);
            }
            guard.pending_flush.extend(flushes);
            drop(guard);
            return Err(err);
        }

        if !flushes.is_empty() {
            let mut guard = self.state.lock();
            for (block, _) in &flushes {
                guard.clear_dirty(*block);
            }
            guard.dirty_flushes += flushes.len() as u64;
        }

        Ok(())
    }

    /// Return the number of currently dirty blocks.
    #[must_use]
    pub fn dirty_count(&self) -> usize {
        self.state.lock().dirty.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn arc_access(state: &mut ArcState, key: BlockNumber) {
        if state.resident.contains_key(&key) {
            state.on_hit(key);
        } else {
            state.on_miss_or_ghost_hit(key);
            state.resident.insert(key, vec![0_u8]);
        }

        // Invariants: loc is the source of truth for membership; resident contains
        // only T1/T2 entries.
        assert_eq!(state.resident.len(), state.t1.len() + state.t2.len());
        assert!(state.resident.len() <= state.capacity);
        assert!(state.total_len() <= state.capacity.saturating_mul(2));
        assert_eq!(state.loc.len(), state.total_len());

        for &k in &state.t1 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::T1)));
            assert!(state.resident.contains_key(&k));
        }
        for &k in &state.t2 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::T2)));
            assert!(state.resident.contains_key(&k));
        }
        for &k in &state.b1 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::B1)));
            assert!(!state.resident.contains_key(&k));
        }
        for &k in &state.b2 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::B2)));
            assert!(!state.resident.contains_key(&k));
        }
    }

    #[derive(Debug)]
    struct MemoryByteDevice {
        bytes: Mutex<Vec<u8>>,
    }

    impl MemoryByteDevice {
        fn new(len: usize) -> Self {
            Self {
                bytes: Mutex::new(vec![0_u8; len]),
            }
        }
    }

    impl ByteDevice for MemoryByteDevice {
        fn len_bytes(&self) -> u64 {
            u64::try_from(self.bytes.lock().len()).unwrap_or(0)
        }

        fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
            let offset = usize::try_from(offset.0)
                .map_err(|_| FfsError::Format("offset overflow".into()))?;
            let end = offset
                .checked_add(buf.len())
                .ok_or_else(|| FfsError::Format("range overflow".into()))?;
            let bytes = self.bytes.lock();
            if end > bytes.len() {
                return Err(FfsError::Format("oob".into()));
            }
            buf.copy_from_slice(&bytes[offset..end]);
            drop(bytes);
            Ok(())
        }

        fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
            let offset = usize::try_from(offset.0)
                .map_err(|_| FfsError::Format("offset overflow".into()))?;
            let end = offset
                .checked_add(buf.len())
                .ok_or_else(|| FfsError::Format("range overflow".into()))?;
            let mut bytes = self.bytes.lock();
            if end > bytes.len() {
                return Err(FfsError::Format("oob".into()));
            }
            bytes[offset..end].copy_from_slice(buf);
            drop(bytes);
            Ok(())
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct CountingBlockDevice<D: BlockDevice> {
        inner: D,
        writes: Mutex<Vec<BlockNumber>>,
        sync_calls: AtomicUsize,
    }

    impl<D: BlockDevice> CountingBlockDevice<D> {
        fn new(inner: D) -> Self {
            Self {
                inner,
                writes: Mutex::new(Vec::new()),
                sync_calls: AtomicUsize::new(0),
            }
        }

        fn write_count(&self) -> usize {
            self.writes.lock().len()
        }

        fn sync_count(&self) -> usize {
            self.sync_calls.load(Ordering::SeqCst)
        }
    }

    impl<D: BlockDevice> BlockDevice for CountingBlockDevice<D> {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            self.inner.read_block(cx, block)
        }

        fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.writes.lock().push(block);
            self.inner.write_block(cx, block, data)
        }

        fn block_size(&self) -> u32 {
            self.inner.block_size()
        }

        fn block_count(&self) -> u64 {
            self.inner.block_count()
        }

        fn sync(&self, cx: &Cx) -> Result<()> {
            self.sync_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.sync(cx)
        }
    }

    #[test]
    fn byte_block_device_round_trips() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");

        dev.write_block(&cx, BlockNumber(2), &[7_u8; 4096])
            .expect("write");
        let read = dev.read_block(&cx, BlockNumber(2)).expect("read");
        assert_eq!(read.as_slice(), &[7_u8; 4096]);
    }

    #[test]
    fn arc_cache_hits_after_first_read() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 2).expect("cache");

        cache
            .write_block(&cx, BlockNumber(1), &[3_u8; 4096])
            .expect("write");
        let r1 = cache.read_block(&cx, BlockNumber(1)).expect("read1");
        let r2 = cache.read_block(&cx, BlockNumber(1)).expect("read2");
        assert_eq!(r1.as_slice(), &[3_u8; 4096]);
        assert_eq!(r2.as_slice(), &[3_u8; 4096]);
    }

    #[test]
    fn arc_state_warms_up_without_premature_eviction() {
        let mut state = ArcState::new(2);
        arc_access(&mut state, BlockNumber(1));
        arc_access(&mut state, BlockNumber(2));

        assert_eq!(state.resident.len(), 2);
        assert!(state.resident.contains_key(&BlockNumber(1)));
        assert!(state.resident.contains_key(&BlockNumber(2)));
        assert_eq!(
            state.t1,
            VecDeque::from(vec![BlockNumber(1), BlockNumber(2)])
        );
        assert!(state.t2.is_empty());
        assert!(state.b1.is_empty());
        assert!(state.b2.is_empty());
    }

    #[test]
    fn arc_state_ghost_hits_adjust_p_and_eviction_policy() {
        let mut state = ArcState::new(2);

        // Warm up + create a mix of recency/frequency:
        // 1 seen twice -> T2, 2/3 seen once -> T1.
        arc_access(&mut state, BlockNumber(1)); // miss -> T1
        arc_access(&mut state, BlockNumber(1)); // hit  -> T2
        arc_access(&mut state, BlockNumber(2)); // miss -> T1
        arc_access(&mut state, BlockNumber(3)); // miss -> replaces -> B1 contains 2

        assert_eq!(state.p, 0);
        assert_eq!(state.t1, VecDeque::from(vec![BlockNumber(3)]));
        assert_eq!(state.t2, VecDeque::from(vec![BlockNumber(1)]));
        assert_eq!(state.b1, VecDeque::from(vec![BlockNumber(2)]));
        assert!(state.b2.is_empty());

        // Ghost hit in B1 should increase p and evict from T2 (since |T1| == p after bump).
        arc_access(&mut state, BlockNumber(2));
        assert_eq!(state.p, 1);
        assert_eq!(state.t1, VecDeque::from(vec![BlockNumber(3)]));
        assert_eq!(state.t2, VecDeque::from(vec![BlockNumber(2)]));
        assert!(state.b1.is_empty());
        assert_eq!(state.b2, VecDeque::from(vec![BlockNumber(1)]));

        // Ghost hit in B2 should decrease p and evict from T1 (since |T1| > p).
        arc_access(&mut state, BlockNumber(1));
        assert_eq!(state.p, 0);
        assert!(state.t1.is_empty());
        assert_eq!(
            state.t2,
            VecDeque::from(vec![BlockNumber(2), BlockNumber(1)])
        );
        assert_eq!(state.b1, VecDeque::from(vec![BlockNumber(3)]));
        assert!(state.b2.is_empty());
    }

    #[test]
    fn arc_cache_does_not_evict_before_capacity_is_full() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");

        // Populate underlying device; cache starts empty.
        dev.write_block(&cx, BlockNumber(0), &[1_u8; 4096])
            .expect("write0");
        dev.write_block(&cx, BlockNumber(1), &[2_u8; 4096])
            .expect("write1");
        dev.write_block(&cx, BlockNumber(2), &[3_u8; 4096])
            .expect("write2");

        let cache = ArcCache::new(dev, 2).expect("cache");

        let _ = cache.read_block(&cx, BlockNumber(0)).expect("read0");
        let _ = cache.read_block(&cx, BlockNumber(1)).expect("read1");

        let guard = cache.state.lock();
        assert_eq!(guard.resident.len(), 2);
        assert!(guard.resident.contains_key(&BlockNumber(0)));
        assert!(guard.resident.contains_key(&BlockNumber(1)));
        drop(guard);

        let _ = cache.read_block(&cx, BlockNumber(2)).expect("read2");
        let guard = cache.state.lock();
        assert_eq!(guard.resident.len(), 2);
        drop(guard);
    }

    #[test]
    fn arc_cache_sync_flushes_and_clears_dirty_tracking() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache = ArcCache::new(counted, 2).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[9_u8; 4096])
            .expect("write");
        assert_eq!(cache.dirty_count(), 1);
        assert_eq!(cache.inner().write_count(), 1);

        cache.sync(&cx).expect("sync");
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.inner().write_count(), 2);
        assert_eq!(cache.inner().sync_count(), 1);

        // Second sync should not rewrite flushed data.
        cache.sync(&cx).expect("sync again");
        assert_eq!(cache.inner().write_count(), 2);
        assert_eq!(cache.inner().sync_count(), 2);
    }

    #[test]
    fn arc_cache_evicts_dirty_blocks_via_pending_flush() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache = ArcCache::new(counted, 1).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[1_u8; 4096])
            .expect("write0");
        assert_eq!(cache.inner().write_count(), 1);
        assert_eq!(cache.dirty_count(), 1);

        cache
            .write_block(&cx, BlockNumber(1), &[2_u8; 4096])
            .expect("write1");

        // write1 (write-through) + pending eviction flush for dirty block0.
        assert_eq!(cache.inner().write_count(), 3);
        let guard = cache.state.lock();
        assert!(guard.pending_flush.is_empty());
        assert!(!guard.dirty.contains(&BlockNumber(0)));
        assert!(guard.dirty.contains(&BlockNumber(1)));
        drop(guard);
    }

    #[test]
    fn arc_cache_default_policy_is_write_through() {
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 1).expect("cache");
        assert_eq!(cache.write_policy(), ArcWritePolicy::WriteThrough);
    }

    #[test]
    fn arc_cache_write_back_defers_direct_write_until_sync() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 2, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[7_u8; 4096])
            .expect("write");
        assert_eq!(cache.inner().write_count(), 0);
        assert_eq!(cache.dirty_count(), 1);

        // Read must hit cache before sync.
        let read = cache.read_block(&cx, BlockNumber(0)).expect("read");
        assert_eq!(read.as_slice(), &[7_u8; 4096]);
        assert_eq!(cache.inner().write_count(), 0);

        cache.sync(&cx).expect("sync");
        assert_eq!(cache.inner().write_count(), 1);
        assert_eq!(cache.inner().sync_count(), 1);
        assert_eq!(cache.dirty_count(), 0);

        cache.sync(&cx).expect("sync again");
        assert_eq!(cache.inner().write_count(), 1);
    }

    #[test]
    fn arc_cache_write_back_flushes_dirty_evictions() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 1, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[1_u8; 4096])
            .expect("write0");
        assert_eq!(cache.inner().write_count(), 0);

        cache
            .write_block(&cx, BlockNumber(1), &[2_u8; 4096])
            .expect("write1");

        // Dirty block0 evicted and flushed, block1 still dirty and resident.
        assert_eq!(cache.inner().write_count(), 1);
        assert_eq!(cache.dirty_count(), 1);

        let read0 = cache.read_block(&cx, BlockNumber(0)).expect("read0");
        assert_eq!(read0.as_slice(), &[1_u8; 4096]);

        cache.sync(&cx).expect("sync");
        assert_eq!(cache.inner().write_count(), 2);
        assert_eq!(cache.dirty_count(), 0);
    }

    // ── CacheMetrics tests ──────────────────────────────────────────────

    #[test]
    fn cache_metrics_initial_state() {
        let state = ArcState::new(4);
        let m = state.snapshot_metrics();
        assert_eq!(m.hits, 0);
        assert_eq!(m.misses, 0);
        assert_eq!(m.evictions, 0);
        assert_eq!(m.t1_len, 0);
        assert_eq!(m.t2_len, 0);
        assert_eq!(m.b1_len, 0);
        assert_eq!(m.b2_len, 0);
        assert_eq!(m.resident, 0);
        assert_eq!(m.capacity, 4);
        assert_eq!(m.p, 0);
        assert!(m.hit_ratio().abs() < f64::EPSILON);
    }

    #[test]
    fn cache_metrics_track_hits_and_misses() {
        let mut state = ArcState::new(4);
        // First access to block 0: miss
        arc_access(&mut state, BlockNumber(0));
        let m = state.snapshot_metrics();
        assert_eq!(m.misses, 1);
        assert_eq!(m.hits, 0);

        // Second access to block 0: hit (it's now resident)
        arc_access(&mut state, BlockNumber(0));
        let m = state.snapshot_metrics();
        assert_eq!(m.misses, 1);
        assert_eq!(m.hits, 1);
        assert!((m.hit_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn cache_metrics_track_evictions() {
        let mut state = ArcState::new(2);
        // Fill cache: blocks 0, 1
        arc_access(&mut state, BlockNumber(0));
        arc_access(&mut state, BlockNumber(1));
        let m = state.snapshot_metrics();
        assert_eq!(m.evictions, 0);
        assert_eq!(m.resident, 2);

        // Block 2 causes eviction
        arc_access(&mut state, BlockNumber(2));
        let m = state.snapshot_metrics();
        assert_eq!(m.evictions, 1);
        assert_eq!(m.resident, 2);
    }

    #[test]
    fn cache_metrics_list_sizes() {
        let mut state = ArcState::new(4);
        arc_access(&mut state, BlockNumber(10));
        arc_access(&mut state, BlockNumber(20));
        let m = state.snapshot_metrics();
        assert_eq!(m.t1_len, 2); // both in T1 (first access)
        assert_eq!(m.t2_len, 0);

        // Hit block 10: moves T1 → T2
        arc_access(&mut state, BlockNumber(10));
        let m = state.snapshot_metrics();
        assert_eq!(m.t1_len, 1);
        assert_eq!(m.t2_len, 1);
    }

    #[test]
    fn arc_cache_metrics_via_block_device() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 4).expect("cache");

        let m = cache.metrics();
        assert_eq!(m.hits, 0);
        assert_eq!(m.misses, 0);

        let _ = cache.read_block(&cx, BlockNumber(0)).expect("read0");
        let m = cache.metrics();
        assert_eq!(m.misses, 1);
        assert_eq!(m.hits, 0);

        let _ = cache.read_block(&cx, BlockNumber(0)).expect("read0 again");
        let m = cache.metrics();
        assert_eq!(m.misses, 1);
        assert_eq!(m.hits, 1);
        assert!((m.hit_ratio() - 0.5).abs() < f64::EPSILON);
    }

    // ── Concurrency stress tests ────────────────────────────────────────

    #[test]
    fn arc_cache_concurrent_reads_no_deadlock() {
        use std::sync::Arc as StdArc;
        use std::thread;

        const NUM_THREADS: usize = 8;
        const OPS_PER_THREAD: usize = 500;
        const NUM_BLOCKS: usize = 16;
        const BLOCK_SIZE: u32 = 4096;
        const CACHE_CAPACITY: usize = 4;

        let mem = MemoryByteDevice::new(BLOCK_SIZE as usize * NUM_BLOCKS);
        let dev = ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device");

        // Pre-populate the device so reads succeed.
        let cx = Cx::for_testing();
        for i in 0..NUM_BLOCKS {
            let fill = u8::try_from(i & 0xFF).unwrap_or(0);
            let data = vec![fill; BLOCK_SIZE as usize];
            dev.write_block(&cx, BlockNumber(i as u64), &data)
                .expect("seed");
        }

        let cache = StdArc::new(ArcCache::new(dev, CACHE_CAPACITY).expect("cache"));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|t| {
                let cache = StdArc::clone(&cache);
                thread::spawn(move || {
                    let cx = Cx::for_testing();
                    for i in 0..OPS_PER_THREAD {
                        let idx = (t + i) % NUM_BLOCKS;
                        let block = BlockNumber(idx as u64);
                        let buf = cache.read_block(&cx, block).expect("read");
                        let expected = u8::try_from(idx & 0xFF).unwrap_or(0);
                        assert_eq!(buf.as_slice()[0], expected);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        let m = cache.metrics();
        let total_ops = u64::try_from(NUM_THREADS * OPS_PER_THREAD).expect("fits u64");
        assert_eq!(m.hits + m.misses, total_ops);
        assert!(m.hits > 0, "should have some cache hits");
    }

    #[test]
    fn arc_cache_concurrent_mixed_read_write() {
        use std::sync::Arc as StdArc;
        use std::thread;

        const READERS: usize = 4;
        const WRITERS: usize = 2;
        const OPS: usize = 200;
        const NUM_BLOCKS: usize = 8;
        const BLOCK_SIZE: u32 = 4096;

        let mem = MemoryByteDevice::new(BLOCK_SIZE as usize * NUM_BLOCKS);
        let dev = ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device");

        // Seed device.
        let cx = Cx::for_testing();
        for i in 0..NUM_BLOCKS {
            dev.write_block(&cx, BlockNumber(i as u64), &vec![0u8; BLOCK_SIZE as usize])
                .expect("seed");
        }

        let cache = StdArc::new(ArcCache::new(dev, 4).expect("cache"));

        let mut handles = Vec::new();

        // Reader threads.
        for t in 0..READERS {
            let cache = StdArc::clone(&cache);
            handles.push(thread::spawn(move || {
                let cx = Cx::for_testing();
                for i in 0..OPS {
                    let idx = (t + i) % NUM_BLOCKS;
                    let _ = cache
                        .read_block(&cx, BlockNumber(idx as u64))
                        .expect("read");
                }
            }));
        }

        // Writer threads.
        for t in 0..WRITERS {
            let cache = StdArc::clone(&cache);
            handles.push(thread::spawn(move || {
                let cx = Cx::for_testing();
                for i in 0..OPS {
                    let idx = (t + i) % NUM_BLOCKS;
                    let fill = u8::try_from((t + i) & 0xFF).unwrap_or(0);
                    let data = vec![fill; BLOCK_SIZE as usize];
                    cache
                        .write_block(&cx, BlockNumber(idx as u64), &data)
                        .expect("write");
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        let m = cache.metrics();
        assert!(m.hits + m.misses > 0, "should have recorded some accesses");
        assert!(m.resident <= 4, "resident should not exceed capacity");
    }
}
