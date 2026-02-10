#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_core::{FsFlavor, detect_filesystem_at_path};
use ftui::{Style, Theme};
use serde::Serialize;
use std::env;
use std::path::Path;

#[derive(Debug, Serialize)]
#[serde(tag = "filesystem", rename_all = "lowercase")]
enum InspectOutput {
    Ext4 {
        block_size: u32,
        inodes_count: u32,
        blocks_count: u64,
        volume_name: String,
    },
    Btrfs {
        sectorsize: u32,
        nodesize: u32,
        generation: u64,
        label: String,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Ok(());
    };

    match command.as_str() {
        "inspect" => {
            let Some(path) = args.next() else {
                bail!("inspect requires a path argument");
            };
            let json = args.any(|arg| arg == "--json");
            inspect(Path::new(&path), json)
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        _ => {
            print_usage();
            bail!("unknown command: {command}")
        }
    }
}

fn print_usage() {
    println!("ffs-cli\n");
    println!("USAGE:");
    println!("  ffs-cli inspect <image-path> [--json]");
}

fn inspect(path: &Path, json: bool) -> Result<()> {
    let cx = Cx::for_testing();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    let _theme = Theme::default();
    let _headline = Style::new().bold().underline();

    let output = match flavor {
        FsFlavor::Ext4(sb) => InspectOutput::Ext4 {
            block_size: sb.block_size,
            inodes_count: sb.inodes_count,
            blocks_count: sb.blocks_count,
            volume_name: sb.volume_name,
        },
        FsFlavor::Btrfs(sb) => InspectOutput::Btrfs {
            sectorsize: sb.sectorsize,
            nodesize: sb.nodesize,
            generation: sb.generation,
            label: sb.label,
        },
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize output")?
        );
    } else {
        println!("FrankenFS Inspector");
        match output {
            InspectOutput::Ext4 {
                block_size,
                inodes_count,
                blocks_count,
                volume_name,
            } => {
                println!("filesystem: ext4");
                println!("block_size: {block_size}");
                println!("inodes_count: {inodes_count}");
                println!("blocks_count: {blocks_count}");
                println!("volume_name: {volume_name}");
            }
            InspectOutput::Btrfs {
                sectorsize,
                nodesize,
                generation,
                label,
            } => {
                println!("filesystem: btrfs");
                println!("sectorsize: {sectorsize}");
                println!("nodesize: {nodesize}");
                println!("generation: {generation}");
                println!("label: {label}");
            }
        }
    }

    Ok(())
}
