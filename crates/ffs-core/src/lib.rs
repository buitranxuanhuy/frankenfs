#![forbid(unsafe_code)]

use asupersync::{Cx, RaptorQConfig};
use ffs_block::{
    ByteDevice, FileByteDevice, read_btrfs_superblock_region, read_ext4_superblock_region,
};
use ffs_error::FfsError;
use ffs_mvcc::{CommitError, MvccStore, Transaction};
use ffs_ondisk::{BtrfsSuperblock, Ext4Superblock};
use ffs_types::{BlockNumber, CommitSeq, ParseError, Snapshot};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsFlavor {
    Ext4(Ext4Superblock),
    Btrfs(BtrfsSuperblock),
}

#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("image does not decode as supported ext4/btrfs superblock")]
    UnsupportedImage,
    #[error("I/O error while probing image: {0}")]
    Io(#[from] FfsError),
}

pub fn detect_filesystem(image: &[u8]) -> Result<FsFlavor, DetectionError> {
    if let Ok(ext4) = Ext4Superblock::parse_from_image(image) {
        return Ok(FsFlavor::Ext4(ext4));
    }

    if let Ok(btrfs) = BtrfsSuperblock::parse_from_image(image) {
        return Ok(FsFlavor::Btrfs(btrfs));
    }

    Err(DetectionError::UnsupportedImage)
}

pub fn detect_filesystem_on_device(
    cx: &Cx,
    dev: &dyn ByteDevice,
) -> Result<FsFlavor, DetectionError> {
    let len = dev.len_bytes();

    let ext4_end =
        u64::try_from(ffs_types::EXT4_SUPERBLOCK_OFFSET + ffs_types::EXT4_SUPERBLOCK_SIZE)
            .map_err(|_| FfsError::Format("ext4 superblock end offset overflows u64".to_owned()))?;
    if len >= ext4_end {
        let ext4_region = read_ext4_superblock_region(cx, dev)?;
        if let Ok(sb) = Ext4Superblock::parse_superblock_region(&ext4_region) {
            return Ok(FsFlavor::Ext4(sb));
        }
    }

    let btrfs_end =
        u64::try_from(ffs_types::BTRFS_SUPER_INFO_OFFSET + ffs_types::BTRFS_SUPER_INFO_SIZE)
            .map_err(|_| {
                FfsError::Format("btrfs superblock end offset overflows u64".to_owned())
            })?;
    if len >= btrfs_end {
        let btrfs_region = read_btrfs_superblock_region(cx, dev)?;
        if let Ok(sb) = BtrfsSuperblock::parse_superblock_region(&btrfs_region) {
            return Ok(FsFlavor::Btrfs(sb));
        }
    }

    Err(DetectionError::UnsupportedImage)
}

pub fn detect_filesystem_at_path(
    cx: &Cx,
    path: impl AsRef<Path>,
) -> Result<FsFlavor, DetectionError> {
    let dev = FileByteDevice::open(path)?;
    detect_filesystem_on_device(cx, &dev)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DurabilityPosterior {
    pub alpha: f64,
    pub beta: f64,
}

impl Default for DurabilityPosterior {
    fn default() -> Self {
        Self {
            alpha: 1.0,
            beta: 1.0,
        }
    }
}

impl DurabilityPosterior {
    /// Observe a single Bernoulli event ("did we see any corruption?").
    ///
    /// This is intentionally coarse; prefer `observe_blocks()` when scrub can
    /// report counts.
    pub fn observe_event(&mut self, corruption_event: bool) {
        self.observe_blocks(1, u64::from(corruption_event));
    }

    /// Observe scrub results as counts of scanned vs corrupted blocks.
    ///
    /// Uses a Beta-Binomial conjugate update where `alpha` counts "corrupt"
    /// and `beta` counts "clean".
    pub fn observe_blocks(&mut self, scanned_blocks: u64, corrupted_blocks: u64) {
        let scanned = scanned_blocks as f64;
        let corrupted = (corrupted_blocks.min(scanned_blocks)) as f64;
        let clean = (scanned - corrupted).max(0.0);
        self.alpha += corrupted;
        self.beta += clean;
    }

    #[must_use]
    pub fn expected_corruption_rate(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    #[must_use]
    pub fn variance(&self) -> f64 {
        let a = self.alpha;
        let b = self.beta;
        let denom = (a + b).powi(2) * (a + b + 1.0);
        if denom <= 0.0 {
            return 0.0;
        }
        (a * b) / denom
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DurabilityLossModel {
    pub corruption_cost: f64,
    pub redundancy_cost: f64,
    pub z_score: f64,
}

impl Default for DurabilityLossModel {
    fn default() -> Self {
        Self {
            corruption_cost: 10_000.0,
            redundancy_cost: 25.0,
            z_score: 3.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RedundancyDecision {
    pub repair_overhead: f64,
    pub expected_loss: f64,
    pub posterior_mean_corruption_rate: f64,
    pub posterior_hi_corruption_rate: f64,
    pub unrecoverable_risk_bound: f64,
    pub redundancy_loss: f64,
    pub corruption_loss: f64,
}

impl RedundancyDecision {
    #[must_use]
    pub fn to_raptorq_config(self, block_size: u32) -> RaptorQConfig {
        let mut cfg = RaptorQConfig::default();
        cfg.encoding.repair_overhead = self.repair_overhead;
        cfg.encoding.max_block_size = usize::try_from(block_size).unwrap_or(4096);
        cfg.encoding.symbol_size = u16::try_from(block_size.clamp(64, 1024)).unwrap_or(256);
        cfg
    }
}

#[derive(Debug, Clone, Default)]
pub struct DurabilityAutopilot {
    posterior: DurabilityPosterior,
    loss: DurabilityLossModel,
}

impl DurabilityAutopilot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_event(&mut self, corruption_event: bool) {
        self.posterior.observe_event(corruption_event);
    }

    pub fn observe_scrub(&mut self, scanned_blocks: u64, corrupted_blocks: u64) {
        self.posterior
            .observe_blocks(scanned_blocks, corrupted_blocks);
    }

    #[must_use]
    pub fn choose_overhead(&self, candidates: &[f64]) -> RedundancyDecision {
        self.choose_overhead_for_group(candidates, 32_768)
    }

    #[must_use]
    pub fn choose_overhead_for_group(
        &self,
        candidates: &[f64],
        source_block_count: u32,
    ) -> RedundancyDecision {
        const MIN_OVERHEAD: f64 = 1.01;
        const MAX_OVERHEAD: f64 = 1.10;
        const DEFAULT_OVERHEAD: f64 = 1.05;

        let p_mean = self.posterior.expected_corruption_rate();
        let p_hi = self
            .loss
            .z_score
            .mul_add(self.posterior.variance().sqrt(), p_mean)
            .clamp(0.0, 1.0);

        let mut best = RedundancyDecision {
            repair_overhead: DEFAULT_OVERHEAD,
            expected_loss: f64::INFINITY,
            posterior_mean_corruption_rate: p_mean,
            posterior_hi_corruption_rate: p_hi,
            unrecoverable_risk_bound: 1.0,
            redundancy_loss: 0.0,
            corruption_loss: f64::INFINITY,
        };

        let k = f64::from(source_block_count.max(1));
        let mut considered_any = false;

        for candidate in candidates {
            if !candidate.is_finite() || *candidate < MIN_OVERHEAD || *candidate > MAX_OVERHEAD {
                continue;
            }
            considered_any = true;

            // Repair budget fraction relative to source blocks.
            let rho = (candidate - 1.0).clamp(0.0, 1.0);

            // Conservative tail-risk estimate (Chernoff bound) for:
            //   P(N >= rho*K) where N ~ Binomial(K, p) and p is conservatively taken as p_hi.
            let risk_bound = if p_hi <= 0.0 {
                0.0
            } else if rho <= p_hi {
                1.0
            } else {
                let eps = 1e-12;
                let q = rho.clamp(eps, 1.0 - eps);
                let p = p_hi.clamp(eps, 1.0 - eps);
                let kl = q * (q / p).ln() + (1.0 - q) * ((1.0 - q) / (1.0 - p)).ln();
                (-k * kl.max(0.0)).exp()
            };

            let redundancy_loss = self.loss.redundancy_cost * rho;
            let corruption_loss = self.loss.corruption_cost * risk_bound;
            let expected_loss = redundancy_loss + corruption_loss;

            if expected_loss < best.expected_loss {
                best = RedundancyDecision {
                    repair_overhead: *candidate,
                    expected_loss,
                    posterior_mean_corruption_rate: p_mean,
                    posterior_hi_corruption_rate: p_hi,
                    unrecoverable_risk_bound: risk_bound,
                    redundancy_loss,
                    corruption_loss,
                };
            }
        }

        if !considered_any {
            best.repair_overhead = DEFAULT_OVERHEAD;
            best.redundancy_loss = self.loss.redundancy_cost * (DEFAULT_OVERHEAD - 1.0);
            best.corruption_loss = self.loss.corruption_cost;
            best.expected_loss = best.redundancy_loss + best.corruption_loss;
        }

        best
    }
}

#[derive(Debug, Default)]
pub struct FrankenFsEngine {
    store: MvccStore,
}

impl FrankenFsEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: MvccStore::new(),
        }
    }

    pub fn begin(&mut self) -> Transaction {
        self.store.begin()
    }

    pub fn commit(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        self.store.commit(txn)
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.store.current_snapshot()
    }

    #[must_use]
    pub fn read(&self, block: BlockNumber, snapshot: Snapshot) -> Option<&[u8]> {
        self.store.read_visible(block, snapshot)
    }

    pub fn checkpoint(cx: &Cx) -> Result<(), Box<asupersync::Error>> {
        cx.checkpoint().map_err(Box::new)
    }

    pub fn inspect_image(image: &[u8]) -> Result<FsFlavor, DetectionError> {
        detect_filesystem(image)
    }

    pub fn parse_ext4(image: &[u8]) -> Result<Ext4Superblock, ParseError> {
        Ext4Superblock::parse_from_image(image)
    }

    pub fn parse_btrfs(image: &[u8]) -> Result<BtrfsSuperblock, ParseError> {
        BtrfsSuperblock::parse_from_image(image)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_types::{
        BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, EXT4_SUPER_MAGIC,
        EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE,
    };

    #[test]
    fn detect_ext4_and_btrfs_images() {
        let mut ext4_img = vec![0_u8; EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE];
        let sb = EXT4_SUPERBLOCK_OFFSET;
        ext4_img[sb + 0x38..sb + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        ext4_img[sb + 0x18..sb + 0x1C].copy_from_slice(&0_u32.to_le_bytes());
        let ext4 = detect_filesystem(&ext4_img).expect("detect ext4");
        assert!(matches!(ext4, FsFlavor::Ext4(_)));

        let mut btrfs_img = vec![0_u8; BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE];
        let sb2 = BTRFS_SUPER_INFO_OFFSET;
        btrfs_img[sb2 + 0x40..sb2 + 0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        btrfs_img[sb2 + 0x90..sb2 + 0x94].copy_from_slice(&4096_u32.to_le_bytes());
        btrfs_img[sb2 + 0x94..sb2 + 0x98].copy_from_slice(&4096_u32.to_le_bytes());
        let btrfs = detect_filesystem(&btrfs_img).expect("detect btrfs");
        assert!(matches!(btrfs, FsFlavor::Btrfs(_)));
    }

    #[test]
    fn durability_autopilot_prefers_more_redundancy_when_failures_observed() {
        let candidates = [1.02, 1.05, 1.10];

        let mut clean = DurabilityAutopilot::new();
        clean.observe_scrub(10_000, 0);
        let clean_decision = clean.choose_overhead(&candidates);
        assert!((clean_decision.repair_overhead - 1.02).abs() < 1e-12);

        let mut dirty = DurabilityAutopilot::new();
        dirty.observe_scrub(10_000, 300);
        let dirty_decision = dirty.choose_overhead(&candidates);
        assert!(dirty_decision.repair_overhead >= 1.05);
    }
}
