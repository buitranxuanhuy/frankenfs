#![forbid(unsafe_code)]

use asupersync::Cx;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ffs_block::{ArcCache, BlockBuf, BlockDevice, ByteBlockDevice, ByteDevice};
use ffs_error::Result;
use ffs_types::{BlockNumber, ByteOffset};
use parking_lot::Mutex;

// ── In-memory ByteDevice for benchmarks (no file I/O) ──────────────────

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

#[allow(clippy::cast_possible_truncation)]
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

#[allow(clippy::cast_possible_truncation)]
fn make_cache(
    block_size: u32,
    block_count: usize,
    capacity: usize,
) -> ArcCache<ByteBlockDevice<MemByteDevice>> {
    let mem = MemByteDevice::new(block_size as usize * block_count);
    let dev = ByteBlockDevice::new(mem, block_size).expect("device");
    ArcCache::new(dev, capacity).expect("cache")
}

// ── Benchmarks ──────────────────────────────────────────────────────────

fn bench_cache_hit(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let cache = make_cache(4096, 16, 8);

    // Warm up: read block 0 once (miss), then benchmark repeated hits.
    let _ = cache.read_block(&cx, BlockNumber(0)).expect("warmup");

    c.bench_function("arc_cache_hit_4k", |b| {
        b.iter(|| {
            let _buf: BlockBuf = cache
                .read_block(black_box(&cx), black_box(BlockNumber(0)))
                .expect("hit");
        });
    });
}

fn bench_cache_miss(c: &mut Criterion) {
    let cx = Cx::for_testing();
    // Capacity 1: every second distinct block evicts the previous one.
    let cache = make_cache(4096, 256, 1);

    let mut block_id = 0_u64;
    c.bench_function("arc_cache_miss_4k", |b| {
        b.iter(|| {
            let _buf: BlockBuf = cache
                .read_block(black_box(&cx), BlockNumber(block_id % 256))
                .expect("miss");
            block_id += 1;
        });
    });
}

fn bench_cache_mixed_workload(c: &mut Criterion) {
    let cx = Cx::for_testing();
    // 8-block capacity with a 16-block working set → ~50% hit rate.
    let cache = make_cache(4096, 16, 8);

    // Warm up all 16 blocks.
    for i in 0..16_u64 {
        let _ = cache.read_block(&cx, BlockNumber(i)).expect("warmup");
    }

    let mut iter = 0_u64;
    c.bench_function("arc_cache_mixed_4k", |b| {
        b.iter(|| {
            let block = BlockNumber(iter % 16);
            let _buf: BlockBuf = cache
                .read_block(black_box(&cx), black_box(block))
                .expect("read");
            iter += 1;
        });
    });
}

fn bench_metrics_snapshot(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let cache = make_cache(4096, 16, 8);

    // Generate some activity.
    for i in 0..16_u64 {
        let _ = cache.read_block(&cx, BlockNumber(i)).expect("warmup");
    }

    c.bench_function("arc_cache_metrics_snapshot", |b| {
        b.iter(|| {
            let _m = cache.metrics();
        });
    });
}

criterion_group!(
    cache_benches,
    bench_cache_hit,
    bench_cache_miss,
    bench_cache_mixed_workload,
    bench_metrics_snapshot,
);
criterion_main!(cache_benches);
