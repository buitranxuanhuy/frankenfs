//! Single-command self-healing adoption wedge demo.
//!
//! This module builds a deterministic, raw 8 MiB image, writes 10 file-like
//! payloads, injects controlled corruption, repairs via RaptorQ symbols, and
//! verifies that all payload checksums are restored.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use ffs_block::{BlockDevice, ByteBlockDevice, FileByteDevice};
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use tracing::{info, warn};

use crate::codec::{decode_group, encode_group};

type RepairSymbolData = Vec<(u32, Vec<u8>)>;
type EncodedRepairBundle = ([u8; 16], RepairSymbolData);

/// Configuration for the self-healing demo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHealDemoConfig {
    pub image_size_bytes: u64,
    pub block_size: u32,
    pub file_count: u32,
    pub blocks_per_file: u32,
    pub corruption_percent: u32,
    pub repair_symbol_count: u32,
    pub seed: u64,
}

impl Default for SelfHealDemoConfig {
    fn default() -> Self {
        Self {
            image_size_bytes: 8 * 1024 * 1024,
            block_size: 4096,
            file_count: 10,
            blocks_per_file: 4,
            corruption_percent: 2,
            repair_symbol_count: 40,
            seed: 0x00C0_FFEE_F00D_BAAD,
        }
    }
}

/// Result from one demo run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHealDemoResult {
    pub corrupted_blocks: usize,
    pub repaired_blocks: usize,
    pub files_verified: u32,
    pub all_ok: bool,
    pub duration_ms: u128,
    pub output_lines: Vec<String>,
}

/// Run the full self-healing demo and return machine-friendly metrics plus
/// six README-friendly output lines.
pub fn run_self_heal_demo(cx: &Cx, config: &SelfHealDemoConfig) -> Result<SelfHealDemoResult> {
    validate_config(config)?;
    let source_block_count = source_block_count(config)?;
    let image_path = demo_image_path(config.seed);
    let block_device = setup_block_device(config, source_block_count, &image_path)?;

    info!(
        target: "ffs::repair::demo",
        image_size_bytes = config.image_size_bytes,
        file_count = config.file_count,
        corruption_pct = config.corruption_percent,
        "demo start"
    );

    let expected_hashes = write_file_payloads(cx, &block_device, config)?;
    block_device.sync(cx)?;
    let (fs_uuid, repair_symbols) =
        encode_repair_symbols(cx, &block_device, config, source_block_count)?;

    let corrupt_indices =
        select_corrupt_indices(source_block_count, config.corruption_percent, config.seed)?;
    inject_corruption(cx, &block_device, &corrupt_indices)?;
    block_device.sync(cx)?;
    info!(
        target: "ffs::repair::demo",
        blocks_corrupted = corrupt_indices.len(),
        seed = config.seed,
        "corruption injected"
    );

    let (repaired_blocks, duration_ms) = repair_corrupt_blocks(
        cx,
        &block_device,
        &fs_uuid,
        &corrupt_indices,
        &repair_symbols,
        source_block_count,
    )?;

    let all_ok = verify_payloads(cx, &block_device, config, &expected_hashes)?;
    info!(
        target: "ffs::repair::demo",
        files_verified = config.file_count,
        all_ok,
        "verification complete"
    );

    if !all_ok {
        return Err(FfsError::RepairFailed(
            "verification failed after recovery".to_owned(),
        ));
    }

    cleanup_image(&image_path);
    let output_lines = render_output_lines(
        config,
        source_block_count,
        corrupt_indices.len(),
        repaired_blocks,
        duration_ms,
        all_ok,
    );

    Ok(SelfHealDemoResult {
        corrupted_blocks: corrupt_indices.len(),
        repaired_blocks,
        files_verified: config.file_count,
        all_ok,
        duration_ms,
        output_lines,
    })
}

fn setup_block_device(
    config: &SelfHealDemoConfig,
    source_block_count: u32,
    image_path: &PathBuf,
) -> Result<ByteBlockDevice<FileByteDevice>> {
    create_image(image_path, config.image_size_bytes)?;
    let device = FileByteDevice::open(image_path)?;
    let block_device = ByteBlockDevice::new(device, config.block_size)?;
    if u64::from(source_block_count) > block_device.block_count() {
        return Err(FfsError::Format(format!(
            "source block count {source_block_count} exceeds image block count {}",
            block_device.block_count()
        )));
    }
    Ok(block_device)
}

fn encode_repair_symbols(
    cx: &Cx,
    block_device: &dyn BlockDevice,
    config: &SelfHealDemoConfig,
    source_block_count: u32,
) -> Result<EncodedRepairBundle> {
    let fs_uuid = derive_uuid(config.seed);
    let encoded = encode_group(
        cx,
        block_device,
        &fs_uuid,
        GroupNumber(0),
        BlockNumber(0),
        source_block_count,
        config.repair_symbol_count,
    )?;
    let repair_symbols = encoded
        .repair_symbols
        .iter()
        .map(|symbol| (symbol.esi, symbol.data.clone()))
        .collect();
    Ok((fs_uuid, repair_symbols))
}

fn repair_corrupt_blocks(
    cx: &Cx,
    block_device: &dyn BlockDevice,
    fs_uuid: &[u8; 16],
    corrupt_indices: &[u32],
    repair_symbols: &RepairSymbolData,
    source_block_count: u32,
) -> Result<(usize, u128)> {
    let repair_started = Instant::now();
    let decode_outcome = decode_group(
        cx,
        block_device,
        fs_uuid,
        GroupNumber(0),
        BlockNumber(0),
        source_block_count,
        corrupt_indices,
        repair_symbols,
    )?;
    for recovered in &decode_outcome.recovered {
        block_device.write_block(cx, recovered.block, &recovered.data)?;
    }
    block_device.sync(cx)?;
    let duration_ms = repair_started.elapsed().as_millis();
    let repaired_blocks = decode_outcome.recovered.len();

    info!(
        target: "ffs::repair::demo",
        blocks_repaired = repaired_blocks,
        duration_ms,
        "repair complete"
    );

    if !decode_outcome.complete || repaired_blocks != corrupt_indices.len() {
        return Err(FfsError::RepairFailed(
            "repair outcome did not reconstruct all corrupted blocks".to_owned(),
        ));
    }

    Ok((repaired_blocks, duration_ms))
}

fn cleanup_image(image_path: &PathBuf) {
    if let Err(err) = std::fs::remove_file(image_path) {
        warn!(
            target: "ffs::repair::demo",
            image_path = image_path.display().to_string(),
            error = %err,
            "failed to remove temporary demo image"
        );
    }
}

fn render_output_lines(
    config: &SelfHealDemoConfig,
    source_block_count: u32,
    corrupted_blocks: usize,
    repaired_blocks: usize,
    duration_ms: u128,
    all_ok: bool,
) -> Vec<String> {
    vec![
        format!(
            "demo start: image_size={}B file_count={} corruption_pct={} seed=0x{:016x}",
            config.image_size_bytes, config.file_count, config.corruption_percent, config.seed
        ),
        format!(
            "image created: wrote {} payload files across {} source blocks",
            config.file_count, source_block_count
        ),
        format!(
            "corruption injected: blocks_corrupted={} pct={}",
            corrupted_blocks, config.corruption_percent
        ),
        format!("repair complete: blocks_repaired={repaired_blocks} duration_ms={duration_ms}"),
        format!(
            "verification: files_verified={} all_ok={all_ok}",
            config.file_count
        ),
        "demo result: PASS".to_owned(),
    ]
}

fn validate_config(config: &SelfHealDemoConfig) -> Result<()> {
    if config.image_size_bytes == 0 {
        return Err(FfsError::Format("image_size_bytes must be > 0".to_owned()));
    }
    if config.block_size == 0 || !config.block_size.is_power_of_two() {
        return Err(FfsError::Format(format!(
            "block_size must be a non-zero power of two, got {}",
            config.block_size
        )));
    }
    if config.file_count == 0 {
        return Err(FfsError::Format("file_count must be > 0".to_owned()));
    }
    if config.blocks_per_file == 0 {
        return Err(FfsError::Format("blocks_per_file must be > 0".to_owned()));
    }
    if config.corruption_percent == 0 || config.corruption_percent > 100 {
        return Err(FfsError::Format(format!(
            "corruption_percent must be in 1..=100, got {}",
            config.corruption_percent
        )));
    }
    if config.repair_symbol_count == 0 {
        return Err(FfsError::Format(
            "repair_symbol_count must be > 0".to_owned(),
        ));
    }
    Ok(())
}

fn source_block_count(config: &SelfHealDemoConfig) -> Result<u32> {
    config
        .file_count
        .checked_mul(config.blocks_per_file)
        .ok_or_else(|| FfsError::Format("source block count overflowed u32".to_owned()))
}

fn payload_len_bytes(config: &SelfHealDemoConfig) -> Result<usize> {
    let block_size = usize::try_from(config.block_size)
        .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;
    let blocks_per_file = usize::try_from(config.blocks_per_file)
        .map_err(|_| FfsError::Format("blocks_per_file does not fit usize".to_owned()))?;
    block_size
        .checked_mul(blocks_per_file)
        .ok_or_else(|| FfsError::Format("payload length overflowed usize".to_owned()))
}

fn create_image(path: &PathBuf, image_size_bytes: u64) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(image_size_bytes)?;
    file.sync_all()?;
    Ok(())
}

fn demo_image_path(seed: u64) -> PathBuf {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u128, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "ffs_self_heal_demo_{seed:016x}_{}_{}.img",
        std::process::id(),
        now_nanos
    ))
}

fn derive_uuid(seed: u64) -> [u8; 16] {
    let digest = blake3::hash(&seed.to_le_bytes());
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&digest.as_bytes()[..16]);
    uuid
}

fn build_file_payload(seed: u64, file_index: u32, payload_len: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ffs-self-heal-demo");
    hasher.update(&seed.to_le_bytes());
    hasher.update(&file_index.to_le_bytes());

    let mut payload = vec![0_u8; payload_len];
    hasher.finalize_xof().fill(&mut payload);
    payload
}

fn write_file_payloads(
    cx: &Cx,
    block_device: &dyn BlockDevice,
    config: &SelfHealDemoConfig,
) -> Result<BTreeMap<u32, blake3::Hash>> {
    let payload_len = payload_len_bytes(config)?;
    let block_size = usize::try_from(config.block_size)
        .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;

    let mut expected_hashes = BTreeMap::new();
    for file_index in 0..config.file_count {
        let payload = build_file_payload(config.seed, file_index, payload_len);
        expected_hashes.insert(file_index, blake3::hash(&payload));

        let first_block = u64::from(file_index)
            .checked_mul(u64::from(config.blocks_per_file))
            .ok_or_else(|| FfsError::Format("file block range overflowed u64".to_owned()))?;
        for block_offset in 0..config.blocks_per_file {
            let start = usize::try_from(block_offset)
                .map_err(|_| FfsError::Format("block offset does not fit usize".to_owned()))?
                .checked_mul(block_size)
                .ok_or_else(|| FfsError::Format("payload start offset overflowed".to_owned()))?;
            let end = start
                .checked_add(block_size)
                .ok_or_else(|| FfsError::Format("payload end offset overflowed".to_owned()))?;
            let block = BlockNumber(first_block + u64::from(block_offset));
            block_device.write_block(cx, block, &payload[start..end])?;
        }
    }

    Ok(expected_hashes)
}

fn select_corrupt_indices(
    total_blocks: u32,
    corruption_percent: u32,
    seed: u64,
) -> Result<Vec<u32>> {
    if total_blocks == 0 {
        return Err(FfsError::Format(
            "cannot select corrupt blocks from an empty source range".to_owned(),
        ));
    }

    let total_blocks_u64 = u64::from(total_blocks);
    let corrupt_target_u64 = total_blocks_u64
        .checked_mul(u64::from(corruption_percent))
        .ok_or_else(|| FfsError::Format("corruption target overflowed u64".to_owned()))?
        .div_ceil(100)
        .max(1);
    let total_blocks_usize = usize::try_from(total_blocks_u64)
        .map_err(|_| FfsError::Format("total block count does not fit usize".to_owned()))?;
    let corrupt_target = usize::try_from(corrupt_target_u64)
        .map_err(|_| FfsError::Format("corrupt target does not fit usize".to_owned()))?
        .min(total_blocks_usize);

    let mut selected = BTreeSet::new();
    let mut state = seed ^ 0xD1CE_DA7A_5EED_1234;
    while selected.len() < corrupt_target {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let candidate_u64 = state % total_blocks_u64;
        let candidate = u32::try_from(candidate_u64)
            .map_err(|_| FfsError::Format("candidate index does not fit u32".to_owned()))?;
        selected.insert(candidate);
    }

    Ok(selected.into_iter().collect())
}

fn inject_corruption(
    cx: &Cx,
    block_device: &dyn BlockDevice,
    corrupt_indices: &[u32],
) -> Result<()> {
    for index in corrupt_indices {
        let block = BlockNumber(u64::from(*index));
        let mut bytes = block_device.read_block(cx, block)?.into_inner();
        for byte in &mut bytes {
            *byte ^= 0xA5;
        }
        block_device.write_block(cx, block, &bytes)?;
    }
    Ok(())
}

fn verify_payloads(
    cx: &Cx,
    block_device: &dyn BlockDevice,
    config: &SelfHealDemoConfig,
    expected_hashes: &BTreeMap<u32, blake3::Hash>,
) -> Result<bool> {
    let payload_len = payload_len_bytes(config)?;
    let block_size = usize::try_from(config.block_size)
        .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;

    for file_index in 0..config.file_count {
        let mut payload = vec![0_u8; payload_len];
        let first_block = u64::from(file_index)
            .checked_mul(u64::from(config.blocks_per_file))
            .ok_or_else(|| FfsError::Format("file block range overflowed u64".to_owned()))?;

        for block_offset in 0..config.blocks_per_file {
            let block = BlockNumber(first_block + u64::from(block_offset));
            let block_bytes = block_device.read_block(cx, block)?.into_inner();
            let start = usize::try_from(block_offset)
                .map_err(|_| FfsError::Format("block offset does not fit usize".to_owned()))?
                .checked_mul(block_size)
                .ok_or_else(|| FfsError::Format("payload start offset overflowed".to_owned()))?;
            let end = start
                .checked_add(block_size)
                .ok_or_else(|| FfsError::Format("payload end offset overflowed".to_owned()))?;
            payload[start..end].copy_from_slice(&block_bytes);
        }

        let Some(expected) = expected_hashes.get(&file_index) else {
            return Err(FfsError::Format(format!(
                "missing expected hash for file index {file_index}"
            )));
        };
        if blake3::hash(&payload) != *expected {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_output_has_expected_shape() {
        let cx = Cx::for_testing();
        let result = run_self_heal_demo(&cx, &SelfHealDemoConfig::default())
            .expect("default self-heal demo should succeed");

        assert_eq!(result.output_lines.len(), 6);
        assert!(result.output_lines[0].starts_with("demo start:"));
        assert!(result.output_lines[1].starts_with("image created:"));
        assert!(result.output_lines[2].starts_with("corruption injected:"));
        assert!(result.output_lines[3].starts_with("repair complete:"));
        assert!(result.output_lines[4].starts_with("verification:"));
        assert_eq!(result.output_lines[5], "demo result: PASS");
        assert!(result.all_ok);
        assert_eq!(result.corrupted_blocks, result.repaired_blocks);
    }
}
