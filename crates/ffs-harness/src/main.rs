#![forbid(unsafe_code)]

use anyhow::{Result, bail};
use ffs_harness::{ParityReport, validate_btrfs_fixture, validate_ext4_fixture};
use std::env;
use std::path::Path;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        print_usage();
        return Ok(());
    };

    match cmd.as_str() {
        "parity" => {
            let report = ParityReport::current();
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        "check-fixtures" => {
            let ext4 = Path::new("conformance/fixtures/ext4_superblock_sparse.json");
            let btrfs = Path::new("conformance/fixtures/btrfs_superblock_sparse.json");
            let ext4_sb = validate_ext4_fixture(ext4)?;
            let btrfs_sb = validate_btrfs_fixture(btrfs)?;

            println!(
                "ext4: block_size={} volume={}",
                ext4_sb.block_size, ext4_sb.volume_name
            );
            println!(
                "btrfs: nodesize={} label={}",
                btrfs_sb.nodesize, btrfs_sb.label
            );
            Ok(())
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        _ => {
            print_usage();
            bail!("unknown command: {cmd}")
        }
    }
}

fn print_usage() {
    println!("ffs-harness");
    println!();
    println!("USAGE:");
    println!("  ffs-harness parity");
    println!("  ffs-harness check-fixtures");
}
