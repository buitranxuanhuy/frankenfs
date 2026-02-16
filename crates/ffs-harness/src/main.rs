#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use ffs_harness::{
    ParityReport,
    e2e::{CrashReplaySuiteConfig, FsxStressConfig, run_crash_replay_suite, run_fsx_stress},
    extract_btrfs_superblock, extract_ext4_superblock, extract_region, validate_btrfs_fixture,
    validate_ext4_fixture,
};
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);

    match cmd {
        Some("parity") => {
            let report = ParityReport::current();
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("check-fixtures") => {
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
        Some("generate-fixture") => generate_fixture(&args[1..]),
        Some("run-crash-replay") => run_crash_replay(&args[1..]),
        Some("run-fsx-stress") => run_fsx_stress_cmd(&args[1..]),
        Some("--help" | "-h" | "help") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            print_usage();
            bail!("unknown command: {other}")
        }
    }
}

fn generate_fixture(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!(
            "usage: ffs-harness generate-fixture <image> [ext4-superblock|btrfs-superblock|region <offset> <len>]"
        );
    }

    let image_path = Path::new(&args[0]);
    let image_data =
        fs::read(image_path).with_context(|| format!("failed to read {}", image_path.display()))?;

    let kind = args.get(1).map_or("auto", String::as_str);

    let fixture = match kind {
        "ext4-superblock" => extract_ext4_superblock(&image_data)?,
        "btrfs-superblock" => extract_btrfs_superblock(&image_data)?,
        "region" => {
            let offset: usize = args
                .get(2)
                .context("region requires <offset>")?
                .parse()
                .context("invalid offset")?;
            let len: usize = args
                .get(3)
                .context("region requires <len>")?
                .parse()
                .context("invalid len")?;
            extract_region(&image_data, offset, len)?
        }
        "auto" => {
            // Try ext4 first, then btrfs.
            if let Ok(f) = extract_ext4_superblock(&image_data) {
                eprintln!("detected: ext4 superblock");
                f
            } else if let Ok(f) = extract_btrfs_superblock(&image_data) {
                eprintln!("detected: btrfs superblock");
                f
            } else {
                bail!("could not detect ext4 or btrfs superblock; use explicit mode");
            }
        }
        _ => bail!("unknown fixture kind: {kind}"),
    };

    println!("{}", serde_json::to_string_pretty(&fixture)?);
    Ok(())
}

fn run_crash_replay(args: &[String]) -> Result<()> {
    let mut config = CrashReplaySuiteConfig::default();
    let mut index = 0_usize;
    while index < args.len() {
        match args[index].as_str() {
            "--count" => {
                let raw = args.get(index + 1).context("--count requires a value")?;
                config.schedule_count = raw.parse().context("invalid --count value")?;
                index += 2;
            }
            "--seed" => {
                let raw = args.get(index + 1).context("--seed requires a value")?;
                config.base_seed = raw.parse().context("invalid --seed value")?;
                index += 2;
            }
            "--min-ops" => {
                let raw = args.get(index + 1).context("--min-ops requires a value")?;
                config.min_operations = raw.parse().context("invalid --min-ops value")?;
                index += 2;
            }
            "--max-ops" => {
                let raw = args.get(index + 1).context("--max-ops requires a value")?;
                config.max_operations = raw.parse().context("invalid --max-ops value")?;
                index += 2;
            }
            "--out" => {
                let raw = args.get(index + 1).context("--out requires a value")?;
                config.output_dir = Some(Path::new(raw).to_path_buf());
                index += 2;
            }
            other => {
                bail!("unknown run-crash-replay option: {other}");
            }
        }
    }

    let report = run_crash_replay_suite(&config)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.failed_schedules > 0 {
        bail!(
            "crash replay suite reported {} failing schedule(s)",
            report.failed_schedules
        );
    }
    Ok(())
}

fn run_fsx_stress_cmd(args: &[String]) -> Result<()> {
    let mut config = FsxStressConfig::default();
    let mut index = 0_usize;
    while index < args.len() {
        match args[index].as_str() {
            "--ops" => {
                let raw = args.get(index + 1).context("--ops requires a value")?;
                config.operation_count = raw.parse().context("invalid --ops value")?;
                index += 2;
            }
            "--seed" => {
                let raw = args.get(index + 1).context("--seed requires a value")?;
                config.seed = raw.parse().context("invalid --seed value")?;
                index += 2;
            }
            "--max-file-bytes" => {
                let raw = args
                    .get(index + 1)
                    .context("--max-file-bytes requires a value")?;
                config.max_file_size_bytes =
                    raw.parse().context("invalid --max-file-bytes value")?;
                index += 2;
            }
            "--corrupt-every" => {
                let raw = args
                    .get(index + 1)
                    .context("--corrupt-every requires a value")?;
                config.corruption_every_ops =
                    raw.parse().context("invalid --corrupt-every value")?;
                index += 2;
            }
            "--verify-every" => {
                let raw = args
                    .get(index + 1)
                    .context("--verify-every requires a value")?;
                config.full_verify_every_ops =
                    raw.parse().context("invalid --verify-every value")?;
                index += 2;
            }
            "--out" => {
                let raw = args.get(index + 1).context("--out requires a value")?;
                config.output_dir = Some(Path::new(raw).to_path_buf());
                index += 2;
            }
            other => {
                bail!("unknown run-fsx-stress option: {other}");
            }
        }
    }

    let report = run_fsx_stress(&config)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.passed {
        bail!("fsx stress reported a mismatch");
    }
    Ok(())
}

fn print_usage() {
    println!("ffs-harness — fixture management and parity reporting");
    println!();
    println!("USAGE:");
    println!("  ffs-harness parity");
    println!("  ffs-harness check-fixtures");
    println!(
        "  ffs-harness generate-fixture <image> [ext4-superblock|btrfs-superblock|region <offset> <len>]"
    );
    println!(
        "  ffs-harness run-crash-replay [--count N] [--seed S] [--min-ops N] [--max-ops N] [--out DIR]"
    );
    println!(
        "  ffs-harness run-fsx-stress [--ops N] [--seed S] [--max-file-bytes N] [--corrupt-every N] [--verify-every N] [--out DIR]"
    );
    println!();
    println!("FIXTURE GENERATION:");
    println!("  Extracts sparse JSON fixtures from real filesystem images.");
    println!("  In 'auto' mode (default), detects ext4/btrfs and extracts the superblock.");
    println!("  Use 'region' mode to extract arbitrary byte ranges for group descriptors,");
    println!("  inodes, directory blocks, or any other metadata structure.");
    println!();
    println!("CRASH REPLAY:");
    println!("  Runs deterministic crash/replay schedules and emits a JSON summary.");
    println!("  Use --out DIR to persist schedule artifacts + repro pack.");
    println!();
    println!("FSX STRESS:");
    println!(
        "  Runs weighted fsx-style read/write/truncate/fsync/fallocate/punch-hole/reopen operations."
    );
    println!(
        "  Periodically injects corruption and verifies deterministic repair + full-file integrity."
    );
    println!();
    println!("EXAMPLES:");
    println!("  ffs-harness generate-fixture my_ext4.img > conformance/fixtures/my_ext4.json");
    println!(
        "  ffs-harness generate-fixture my_ext4.img region 2048 32 > conformance/fixtures/gd.json"
    );
    println!("  ffs-harness run-crash-replay --count 500 --out artifacts/crash_replay");
    println!("  ffs-harness run-fsx-stress --ops 100000 --seed 123 --out artifacts/fsx");
}
