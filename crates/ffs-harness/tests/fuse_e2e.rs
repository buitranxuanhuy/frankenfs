#![forbid(unsafe_code)]
//! E2E tests that mount an ext4 image via FUSE and verify file operations
//! through the kernel VFS.
//!
//! These tests require:
//! - `/dev/fuse` to exist (FUSE kernel module)
//! - `mkfs.ext4` and `debugfs` on `$PATH`
//! - `fusermount3` permission to mount (may fail in containers)
//!
//! Tests are gated with `#[ignore = "requires /dev/fuse"]` so they only run when explicitly requested
//! via `cargo test -- --ignored` or `cargo test -- --include-ignored`.
//! If FUSE mounting fails (e.g. in restricted environments), the tests skip
//! gracefully rather than panicking.

use asupersync::Cx;
use ffs_core::{Ext4JournalReplayMode, OpenFs, OpenOptions};
use ffs_fuse::{MountOptions, mount_background};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Check if FUSE E2E prerequisites are met.
fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
        && Command::new("which")
            .arg("mkfs.ext4")
            .output()
            .is_ok_and(|o| o.status.success())
        && Command::new("which")
            .arg("debugfs")
            .output()
            .is_ok_and(|o| o.status.success())
}

/// Create a small ext4 image and populate it with test files using debugfs.
fn create_test_image(dir: &Path) -> std::path::PathBuf {
    let image = dir.join("test.ext4");

    // Create a 4 MiB sparse image.
    let f = fs::File::create(&image).expect("create image");
    f.set_len(4 * 1024 * 1024).expect("set image size");
    drop(f);

    // mkfs.ext4
    let out = Command::new("mkfs.ext4")
        .args([
            "-F",
            "-b",
            "4096",
            "-L",
            "ffs-fuse-e2e",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.ext4");
    assert!(
        out.status.success(),
        "mkfs.ext4 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Populate with test files via debugfs.
    let hello_path = dir.join("hello_src.txt");
    let nested_path = dir.join("nested_src.txt");
    fs::write(&hello_path, b"Hello from FrankenFS E2E!\n").expect("write hello src");
    fs::write(&nested_path, b"Nested file content.\n").expect("write nested src");

    // Create directory
    let out = Command::new("debugfs")
        .args(["-w", "-R", "mkdir testdir", image.to_str().unwrap()])
        .output()
        .expect("debugfs mkdir");
    assert!(
        out.status.success(),
        "debugfs mkdir failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Write hello.txt
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("write {} hello.txt", hello_path.display()),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs write hello.txt");
    assert!(
        out.status.success(),
        "debugfs write hello.txt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Write nested.txt
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("write {} testdir/nested.txt", nested_path.display()),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs write nested.txt");
    assert!(
        out.status.success(),
        "debugfs write nested.txt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    image
}

/// Try to mount an ext4 image via FrankenFS FUSE (read-only).
///
/// Returns `None` if FUSE mounting fails (e.g. permission denied in containers).
fn try_mount_ffs(image: &Path, mountpoint: &Path) -> Option<fuser::BackgroundSession> {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
    };
    let fs = OpenFs::open_with_options(&cx, image, &opts).expect("open ext4 image");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };
    match mount_background(Box::new(fs), mountpoint, &mount_opts) {
        Ok(session) => {
            // Give FUSE a moment to initialize.
            thread::sleep(Duration::from_millis(300));
            Some(session)
        }
        Err(e) => {
            eprintln!("FUSE mount failed (skipping test): {e}");
            None
        }
    }
}

#[test]
#[ignore = "requires /dev/fuse"]
fn fuse_read_hello_txt() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Read hello.txt through FUSE.
    let content = fs::read_to_string(mnt.join("hello.txt")).expect("read hello.txt via FUSE");
    assert_eq!(content, "Hello from FrankenFS E2E!\n");
}

#[test]
#[ignore = "requires /dev/fuse"]
fn fuse_readdir_root() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Read root directory entries.
    let entries: Vec<String> = fs::read_dir(&mnt)
        .expect("readdir root via FUSE")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    assert!(
        entries.contains(&"hello.txt".to_owned()),
        "root should contain hello.txt, got: {entries:?}"
    );
    assert!(
        entries.contains(&"testdir".to_owned()),
        "root should contain testdir, got: {entries:?}"
    );
    assert!(
        entries.contains(&"lost+found".to_owned()),
        "root should contain lost+found, got: {entries:?}"
    );
}

#[test]
#[ignore = "requires /dev/fuse"]
fn fuse_read_nested_file() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Read nested file through FUSE.
    let content =
        fs::read_to_string(mnt.join("testdir/nested.txt")).expect("read nested.txt via FUSE");
    assert_eq!(content, "Nested file content.\n");
}

#[test]
#[ignore = "requires /dev/fuse"]
fn fuse_getattr_file_metadata() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Check file metadata.
    let meta = fs::metadata(mnt.join("hello.txt")).expect("stat hello.txt via FUSE");
    assert!(meta.is_file(), "hello.txt should be a regular file");
    assert_eq!(
        meta.len(),
        25,
        "hello.txt should be 25 bytes ('Hello from FrankenFS E2E!\\n')"
    );

    // Check directory metadata.
    let dir_meta = fs::metadata(mnt.join("testdir")).expect("stat testdir via FUSE");
    assert!(dir_meta.is_dir(), "testdir should be a directory");
}

#[test]
#[ignore = "requires /dev/fuse"]
fn fuse_readlink_and_symlink_detection() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());

    // Add a symlink via debugfs.
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "symlink link.txt hello.txt",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs symlink");
    assert!(
        out.status.success(),
        "debugfs symlink failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Reading the symlink target.
    let target = fs::read_link(mnt.join("link.txt")).expect("readlink via FUSE");
    assert_eq!(
        target.to_str().unwrap(),
        "hello.txt",
        "symlink should point to hello.txt"
    );

    // Following the symlink should give the same content.
    let content = fs::read_to_string(mnt.join("link.txt")).expect("read through symlink via FUSE");
    assert_eq!(content, "Hello from FrankenFS E2E!\n");
}
