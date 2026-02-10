#![forbid(unsafe_code)]
//! Block I/O layer with ARC (Adaptive Replacement Cache).
//!
//! Provides the `BlockDevice` trait, cached block reads/writes with
//! `&Cx` capability context for cooperative cancellation, dirty page
//! tracking, and background flush coordination.

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_types::{
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, BlockNumber, EXT4_SUPERBLOCK_OFFSET,
    EXT4_SUPERBLOCK_SIZE,
};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
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
    fn read_exact_at(&self, cx: &Cx, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Write all bytes in `buf` to `offset`.
    fn write_all_at(&self, cx: &Cx, offset: u64, buf: &[u8]) -> Result<()>;

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

    fn read_exact_at(&self, cx: &Cx, offset: u64, buf: &mut [u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        let end = offset
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

        self.file.read_exact_at(buf, offset)?;
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: u64, buf: &[u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::PermissionDenied);
        }
        let end = offset
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

        self.file.write_all_at(buf, offset)?;
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
        self.inner.read_exact_at(cx, offset, &mut buf)?;
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
        self.inner.write_all_at(cx, offset, data)?;
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
    dev.read_exact_at(cx, offset, &mut buf)?;
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
    dev.read_exact_at(cx, offset, &mut buf)?;
    Ok(buf)
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
        }
    }

    fn remove_from_list(list: &mut VecDeque<BlockNumber>, key: BlockNumber) -> bool {
        if let Some(pos) = list.iter().position(|k| *k == key) {
            let _ = list.remove(pos);
            return true;
        }
        false
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
        let t1_len = self.t1.len();
        if t1_len >= 1
            && (t1_len > self.p
                || (matches!(self.loc.get(&incoming), Some(ArcList::B2)) && t1_len == self.p))
        {
            if let Some(victim) = self.t1.pop_front() {
                self.loc.insert(victim, ArcList::B1);
                let _ = self.resident.remove(&victim);
                self.b1.push_back(victim);
            }
        } else if let Some(victim) = self.t2.pop_front() {
            self.loc.insert(victim, ArcList::B2);
            let _ = self.resident.remove(&victim);
            self.b2.push_back(victim);
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
        self.touch_mru(key);
    }

    fn on_miss_or_ghost_hit(&mut self, key: BlockNumber) {
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
        if self.t1.len() + self.b1.len() == self.capacity {
            if self.t1.len() < self.capacity {
                let _ = self.b1.pop_front().and_then(|v| self.loc.remove(&v));
                self.replace(key);
            } else if let Some(victim) = self.t1.pop_front() {
                let _ = self.loc.remove(&victim);
                let _ = self.resident.remove(&victim);
            }
        } else if (self.t1.len() + self.b1.len()) < self.capacity
            && (self.t1.len() + self.t2.len() + self.b1.len() + self.b2.len())
                >= self.capacity.saturating_mul(2)
        {
            let _ = self.b2.pop_front().and_then(|v| self.loc.remove(&v));
        }

        self.replace(key);
        self.t1.push_back(key);
        self.loc.insert(key, ArcList::T1);
    }
}

/// ARC-cached wrapper around a [`BlockDevice`].
///
/// Current behavior:
/// - read caching of whole blocks
/// - write-through (writes update cache and the underlying device immediately)
///
/// TODO: add write-back, dirty eviction, and background flush integration.
#[derive(Debug)]
pub struct ArcCache<D: BlockDevice> {
    inner: D,
    state: Mutex<ArcState>,
}

impl<D: BlockDevice> ArcCache<D> {
    pub fn new(inner: D, capacity_blocks: usize) -> Result<Self> {
        if capacity_blocks == 0 {
            return Err(FfsError::Format(
                "ArcCache capacity_blocks must be > 0".to_owned(),
            ));
        }
        Ok(Self {
            inner,
            state: Mutex::new(ArcState::new(capacity_blocks)),
        })
    }

    #[must_use]
    pub fn inner(&self) -> &D {
        &self.inner
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
        guard.on_miss_or_ghost_hit(block);
        guard.resident.insert(block, buf.as_slice().to_vec());
        drop(guard);
        Ok(buf)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.inner.write_block(cx, block, data)?;
        let mut guard = self.state.lock();
        guard.on_miss_or_ghost_hit(block);
        guard.resident.insert(block, data.to_vec());
        drop(guard);
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.inner.sync(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        fn read_exact_at(&self, _cx: &Cx, offset: u64, buf: &mut [u8]) -> Result<()> {
            let offset =
                usize::try_from(offset).map_err(|_| FfsError::Format("offset overflow".into()))?;
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

        fn write_all_at(&self, _cx: &Cx, offset: u64, buf: &[u8]) -> Result<()> {
            let offset =
                usize::try_from(offset).map_err(|_| FfsError::Format("offset overflow".into()))?;
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
}
