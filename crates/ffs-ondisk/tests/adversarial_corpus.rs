#![forbid(unsafe_code)]

use ffs_ondisk::{
    BtrfsHeader, BtrfsSuperblock, Ext4GroupDesc, Ext4ImageReader, Ext4Inode, Ext4Superblock,
    iter_dir_block, map_logical_to_physical, parse_dir_block, parse_dx_root, parse_extent_tree,
    parse_internal_items, parse_leaf_items, parse_sys_chunk_array, parse_xattr_block,
    verify_btrfs_superblock_checksum, verify_btrfs_tree_block_checksum, verify_dir_block_checksum,
    verify_extent_block_checksum, verify_group_desc_checksum, verify_inode_checksum,
};
use ffs_types::{BTRFS_CSUM_TYPE_CRC32C, EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_SIZE, ParseError};
use std::collections::BTreeMap;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

#[derive(Debug, Default)]
struct ErrorCoverage {
    insufficient_data: u32,
    invalid_magic: u32,
    invalid_field: u32,
    integer_conversion: u32,
}

impl ErrorCoverage {
    fn observe(&mut self, err: &ParseError) {
        match err {
            ParseError::InsufficientData { .. } => self.insufficient_data += 1,
            ParseError::InvalidMagic { .. } => self.invalid_magic += 1,
            ParseError::InvalidField { .. } => self.invalid_field += 1,
            ParseError::IntegerConversion { .. } => self.integer_conversion += 1,
        }
    }
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("tests/fuzz_corpus")
}

fn load_corpus_samples() -> Vec<(String, Vec<u8>)> {
    let dir = corpus_dir();
    let mut entries = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("failed to read corpus dir {}: {err}", dir.display()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|err| panic!("failed to iterate corpus dir {}: {err}", dir.display()));
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut out = Vec::new();
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("bin") {
            continue;
        }
        let data = fs::read(&path)
            .unwrap_or_else(|err| panic!("failed to read corpus sample {}: {err}", path.display()));
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .map_or_else(|| path.display().to_string(), str::to_owned);
        out.push((name, data));
    }

    assert!(
        out.len() >= 50,
        "expected at least 50 adversarial samples, found {}",
        out.len()
    );
    out
}

fn run_parser<T, F>(
    sample_name: &str,
    parser_name: &'static str,
    parser_hits: &mut BTreeMap<&'static str, u32>,
    coverage: &mut ErrorCoverage,
    parser: F,
) -> bool
where
    F: FnOnce() -> Result<T, ParseError>,
{
    *parser_hits.entry(parser_name).or_default() += 1;
    match catch_unwind(AssertUnwindSafe(parser)) {
        Ok(Ok(_)) => false,
        Ok(Err(err)) => {
            coverage.observe(&err);
            true
        }
        Err(panic_payload) => {
            let _ = panic_payload;
            panic!("parser `{parser_name}` panicked on sample `{sample_name}`");
        }
    }
}

fn run_dir_iter(block: &[u8], block_size: u32) -> Result<(), ParseError> {
    let mut iter = iter_dir_block(block, block_size);
    for _ in 0..64 {
        match iter.next() {
            Some(Ok(_)) => {}
            Some(Err(err)) => return Err(err),
            None => return Ok(()),
        }
    }
    Ok(())
}

fn minimal_valid_ext4_superblock() -> Ext4Superblock {
    let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
    sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log_block_size=2 -> 4K
    sb[0x1C..0x20].copy_from_slice(&2_u32.to_le_bytes()); // log_cluster_size=2 -> 4K
    sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
    sb[0x04..0x08].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_count_lo
    sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
    sb[0x20..0x24].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_per_group
    sb[0x24..0x28].copy_from_slice(&32768_u32.to_le_bytes()); // clusters_per_group
    sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_per_group
    sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
    Ext4Superblock::parse_superblock_region(&sb).expect("valid ext4 superblock")
}

#[test]
#[allow(clippy::too_many_lines)]
fn adversarial_corpus_is_panic_free_and_exercises_parse_error_variants() {
    let samples = load_corpus_samples();
    let mut parser_hits = BTreeMap::new();
    let mut coverage = ErrorCoverage::default();

    for (name, bytes) in &samples {
        assert!(
            bytes.len() <= 64 * 1024,
            "sample `{name}` exceeds 64KiB limit"
        );

        let mut sample_had_error = false;

        sample_had_error |= run_parser(
            name,
            "ext4_parse_superblock_region",
            &mut parser_hits,
            &mut coverage,
            || Ext4Superblock::parse_superblock_region(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_from_image",
            &mut parser_hits,
            &mut coverage,
            || Ext4Superblock::parse_from_image(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_group_desc_parse",
            &mut parser_hits,
            &mut coverage,
            || Ext4GroupDesc::parse_from_bytes(bytes, 32),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_inode_parse",
            &mut parser_hits,
            &mut coverage,
            || Ext4Inode::parse_from_bytes(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_extent_tree",
            &mut parser_hits,
            &mut coverage,
            || parse_extent_tree(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_dir_block",
            &mut parser_hits,
            &mut coverage,
            || parse_dir_block(bytes, 4096),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_iter_dir_block",
            &mut parser_hits,
            &mut coverage,
            || run_dir_iter(bytes, 4096),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_dx_root",
            &mut parser_hits,
            &mut coverage,
            || parse_dx_root(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_xattr_block",
            &mut parser_hits,
            &mut coverage,
            || parse_xattr_block(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_verify_group_desc_checksum",
            &mut parser_hits,
            &mut coverage,
            || verify_group_desc_checksum(bytes, 0, 0, 32),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_verify_inode_checksum",
            &mut parser_hits,
            &mut coverage,
            || verify_inode_checksum(bytes, 0, 2, 256),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_verify_dir_block_checksum",
            &mut parser_hits,
            &mut coverage,
            || verify_dir_block_checksum(bytes, 0, 2, 0),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_verify_extent_block_checksum",
            &mut parser_hits,
            &mut coverage,
            || verify_extent_block_checksum(bytes, 0, 2, 0),
        );

        sample_had_error |= run_parser(
            name,
            "btrfs_parse_superblock_region",
            &mut parser_hits,
            &mut coverage,
            || BtrfsSuperblock::parse_superblock_region(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_parse_from_image",
            &mut parser_hits,
            &mut coverage,
            || BtrfsSuperblock::parse_from_image(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_parse_sys_chunk_array",
            &mut parser_hits,
            &mut coverage,
            || parse_sys_chunk_array(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_map_logical_to_physical",
            &mut parser_hits,
            &mut coverage,
            || {
                let chunks = parse_sys_chunk_array(bytes)?;
                let _ = map_logical_to_physical(&chunks, u64::MAX)?;
                Ok(())
            },
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_header_parse",
            &mut parser_hits,
            &mut coverage,
            || BtrfsHeader::parse_from_block(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_header_validate",
            &mut parser_hits,
            &mut coverage,
            || {
                let header = BtrfsHeader::parse_from_block(bytes)?;
                header.validate(bytes.len(), Some(0))
            },
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_parse_leaf_items",
            &mut parser_hits,
            &mut coverage,
            || parse_leaf_items(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_parse_internal_items",
            &mut parser_hits,
            &mut coverage,
            || parse_internal_items(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_verify_superblock_checksum",
            &mut parser_hits,
            &mut coverage,
            || verify_btrfs_superblock_checksum(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_verify_tree_block_checksum_crc32c",
            &mut parser_hits,
            &mut coverage,
            || verify_btrfs_tree_block_checksum(bytes, BTRFS_CSUM_TYPE_CRC32C),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_verify_tree_block_checksum_bad_type",
            &mut parser_hits,
            &mut coverage,
            || verify_btrfs_tree_block_checksum(bytes, 999),
        );

        assert!(
            sample_had_error,
            "sample `{name}` produced no parser errors across the adversarial harness"
        );
    }

    // Explicitly force IntegerConversion coverage through read_inode_data's
    // logical block cast (u64 -> u32).
    let mut inode = Ext4Inode::parse_from_bytes(&[0_u8; 128]).expect("minimal inode parses");
    let reader = Ext4ImageReader {
        sb: minimal_valid_ext4_superblock(),
    };
    let overflow_offset = (u64::from(u32::MAX) + 1) * u64::from(reader.sb.block_size);
    inode.size = overflow_offset + 1;
    let mut one_byte = [0_u8; 1];
    let err = reader
        .read_inode_data(&[], &inode, overflow_offset, &mut one_byte)
        .expect_err("forced logical_block conversion should fail");
    coverage.observe(&err);
    assert!(matches!(
        err,
        ParseError::IntegerConversion {
            field: "logical_block"
        }
    ));

    assert!(
        coverage.insufficient_data > 0,
        "expected InsufficientData coverage from adversarial corpus"
    );
    assert!(
        coverage.invalid_magic > 0,
        "expected InvalidMagic coverage from adversarial corpus"
    );
    assert!(
        coverage.invalid_field > 0,
        "expected InvalidField coverage from adversarial corpus"
    );
    assert!(
        coverage.integer_conversion > 0,
        "expected IntegerConversion coverage"
    );

    assert!(
        parser_hits.len() >= 20,
        "expected broad parser coverage, got only {} parser entry points",
        parser_hits.len()
    );
}
