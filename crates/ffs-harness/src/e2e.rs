//! E2E test framework for FrankenFS.
//!
//! Provides reusable infrastructure for end-to-end testing:
//! - [`E2eTestContext`]: fixture lifecycle (create, mount, verify, cleanup)
//! - [`MountHandle`]: RAII mount/unmount with panic safety
//! - Structured JSON logging for every test step
//! - Artifact collection for post-mortem debugging
//!
//! Downstream consumers: ext4 RW, btrfs RW, FUSE, corruption recovery, degradation.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::panic;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

// ── Structured JSON log types ───────────────────────────────────────────────

/// A single structured log entry for an E2E test step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eLogEntry {
    pub ts: String,
    pub test: String,
    pub step: String,
    pub input: serde_json::Value,
    pub output: serde_json::Value,
    pub duration_us: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl E2eLogEntry {
    fn now_iso8601() -> String {
        // Use SystemTime for a portable ISO8601 timestamp.
        let since_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let secs = since_epoch.as_secs();
        // Simple formatting without chrono dependency.
        format!("{secs}")
    }

    /// Create a successful log entry.
    #[must_use]
    pub fn ok(
        test: &str,
        step: &str,
        input: serde_json::Value,
        output: serde_json::Value,
        duration: Duration,
    ) -> Self {
        Self {
            ts: Self::now_iso8601(),
            test: test.to_owned(),
            step: step.to_owned(),
            input,
            output,
            duration_us: u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
            status: "ok".to_owned(),
            error: None,
        }
    }

    /// Create an error log entry.
    #[must_use]
    pub fn err(
        test: &str,
        step: &str,
        input: serde_json::Value,
        duration: Duration,
        error: &str,
    ) -> Self {
        Self {
            ts: Self::now_iso8601(),
            test: test.to_owned(),
            step: step.to_owned(),
            input,
            output: serde_json::Value::Object(serde_json::Map::new()),
            duration_us: u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
            status: "error".to_owned(),
            error: Some(error.to_owned()),
        }
    }

    /// Create a skip log entry.
    #[must_use]
    pub fn skip(test: &str, step: &str, reason: &str) -> Self {
        Self {
            ts: Self::now_iso8601(),
            test: test.to_owned(),
            step: step.to_owned(),
            input: serde_json::json!({"reason": reason}),
            output: serde_json::Value::Object(serde_json::Map::new()),
            duration_us: 0,
            status: "skip".to_owned(),
            error: None,
        }
    }
}

/// Collects structured log entries for an E2E test run.
#[derive(Debug, Clone, Default)]
pub struct E2eLog {
    entries: Vec<E2eLogEntry>,
}

impl E2eLog {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn push(&mut self, entry: E2eLogEntry) {
        self.entries.push(entry);
    }

    #[must_use]
    pub fn entries(&self) -> &[E2eLogEntry] {
        &self.entries
    }

    /// Serialize all entries as a newline-delimited JSON string.
    pub fn to_ndjson(&self) -> Result<String> {
        let mut out = String::new();
        for entry in &self.entries {
            let line = serde_json::to_string(entry).context("failed to serialize log entry")?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }

    /// Write logs to a file.
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let ndjson = self.to_ndjson()?;
        fs::write(path, ndjson).with_context(|| format!("write log to {}", path.display()))?;
        Ok(())
    }

    /// Whether any entry has status "error".
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.entries.iter().any(|e| e.status == "error")
    }
}

// ── Image type ──────────────────────────────────────────────────────────────

/// Filesystem type for E2E test fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    Ext4,
    Btrfs,
}

impl std::fmt::Display for ImageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ext4 => write!(f, "ext4"),
            Self::Btrfs => write!(f, "btrfs"),
        }
    }
}

/// Options for fixture creation.
#[derive(Debug, Clone)]
pub struct FixtureOptions {
    /// Image size in megabytes.
    pub size_mb: u64,
    /// Volume label.
    pub label: String,
    /// Extra mkfs arguments.
    pub extra_args: Vec<String>,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            size_mb: 64,
            label: "ffs-e2e".to_owned(),
            extra_args: Vec::new(),
        }
    }
}

// ── E2eTestContext ──────────────────────────────────────────────────────────

/// Reusable E2E test context with fixture lifecycle management.
///
/// Creates a temp directory, manages image creation, mounting, verification,
/// and artifact collection.  Cleanup is guaranteed via Drop.
pub struct E2eTestContext {
    /// Human-readable test name.
    pub name: String,
    /// Filesystem type.
    pub image_type: ImageType,
    /// Temp directory (cleaned up on drop unless artifacts are collected).
    pub workdir: PathBuf,
    /// Path to the created image file.
    pub image_path: PathBuf,
    /// Path to the mountpoint directory.
    pub mountpoint: PathBuf,
    /// Structured log for this test.
    log: Arc<Mutex<E2eLog>>,
    /// Whether to preserve workdir on drop (set by collect_artifacts).
    preserve: bool,
}

impl E2eTestContext {
    /// Create a new E2E test context.
    ///
    /// Creates a temp directory under `/tmp/ffs-e2e-*` and prepares paths.
    pub fn new(name: &str, image_type: ImageType, options: &FixtureOptions) -> Result<Self> {
        let workdir = std::env::temp_dir().join(format!("ffs-e2e-{}-{}", name, std::process::id()));
        fs::create_dir_all(&workdir)
            .with_context(|| format!("create workdir {}", workdir.display()))?;

        let ext = match image_type {
            ImageType::Ext4 => "ext4",
            ImageType::Btrfs => "btrfs",
        };
        let image_path = workdir.join(format!("image.{ext}"));
        let mountpoint = workdir.join("mnt");
        fs::create_dir_all(&mountpoint)
            .with_context(|| format!("create mountpoint {}", mountpoint.display()))?;

        let ctx = Self {
            name: name.to_owned(),
            image_type,
            workdir,
            image_path,
            mountpoint,
            log: Arc::new(Mutex::new(E2eLog::new())),
            preserve: false,
        };

        // Log context creation.
        ctx.log_ok(
            "create_context",
            serde_json::json!({
                "fs": image_type.to_string(),
                "size_mb": options.size_mb,
                "label": &options.label,
            }),
            serde_json::json!({
                "workdir": ctx.workdir.display().to_string(),
            }),
            Duration::ZERO,
        );

        Ok(ctx)
    }

    /// Create a fixture image using mkfs.
    ///
    /// For ext4: uses `mkfs.ext4`.  For btrfs: uses `mkfs.btrfs`.
    /// Skips if the tool is not available (CI-safe).
    pub fn create_fixture(&self, options: &FixtureOptions) -> Result<bool> {
        let start = Instant::now();

        // Create sparse image file.
        let size_bytes = options.size_mb * 1024 * 1024;
        let f = fs::File::create(&self.image_path)
            .with_context(|| format!("create image {}", self.image_path.display()))?;
        f.set_len(size_bytes)
            .with_context(|| format!("set image size to {size_bytes}"))?;

        let (mkfs_cmd, mut args) = match self.image_type {
            ImageType::Ext4 => (
                "mkfs.ext4",
                vec![
                    "-F".to_owned(),
                    "-L".to_owned(),
                    options.label.clone(),
                    self.image_path.display().to_string(),
                ],
            ),
            ImageType::Btrfs => (
                "mkfs.btrfs",
                vec![
                    "-f".to_owned(),
                    "-L".to_owned(),
                    options.label.clone(),
                    self.image_path.display().to_string(),
                ],
            ),
        };

        args.extend(options.extra_args.iter().cloned());

        // Check if mkfs tool is available.
        let tool_check = Command::new("which").arg(mkfs_cmd).output();
        if tool_check.is_err() || !tool_check.unwrap().status.success() {
            self.log_skip("create_fixture", &format!("{mkfs_cmd} not found"));
            return Ok(false);
        }

        let output = Command::new(mkfs_cmd)
            .args(&args)
            .output()
            .with_context(|| format!("run {mkfs_cmd}"))?;

        let elapsed = start.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            self.log_err(
                "create_fixture",
                serde_json::json!({
                    "cmd": mkfs_cmd,
                    "args": args,
                }),
                elapsed,
                &format!("{mkfs_cmd} failed: {stderr}"),
            );
            bail!("{mkfs_cmd} failed: {stderr}");
        }

        self.log_ok(
            "create_fixture",
            serde_json::json!({
                "fs": self.image_type.to_string(),
                "size_mb": options.size_mb,
                "label": &options.label,
            }),
            serde_json::json!({
                "path": self.image_path.display().to_string(),
                "size_bytes": size_bytes,
            }),
            elapsed,
        );

        Ok(true)
    }

    /// Verify a file exists and has the expected content (by SHA256).
    pub fn verify_file_sha256(&self, path: &Path, expected_sha256: &str) -> Result<bool> {
        let start = Instant::now();
        let input = serde_json::json!({
            "path": path.display().to_string(),
            "expected_sha256": expected_sha256,
        });

        if !path.exists() {
            self.log_err("verify_file", input, start.elapsed(), "file does not exist");
            return Ok(false);
        }

        let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;

        // Compute SHA256 using a simple approach (no extra dependency).
        let actual_hex = sha256_hex(&data);
        let matched = actual_hex == expected_sha256;

        self.log_ok(
            "verify_file",
            serde_json::json!({
                "path": path.display().to_string(),
                "expected_sha256": expected_sha256,
            }),
            serde_json::json!({
                "actual_sha256": actual_hex,
                "match": matched,
                "size": data.len(),
            }),
            start.elapsed(),
        );

        Ok(matched)
    }

    /// Verify file content matches expected bytes exactly.
    pub fn verify_file_content(&self, path: &Path, expected: &[u8]) -> Result<bool> {
        let start = Instant::now();
        let input = serde_json::json!({
            "path": path.display().to_string(),
            "expected_size": expected.len(),
        });

        if !path.exists() {
            self.log_err(
                "verify_content",
                input,
                start.elapsed(),
                "file does not exist",
            );
            return Ok(false);
        }

        let actual = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let matched = actual == expected;

        self.log_ok(
            "verify_content",
            serde_json::json!({
                "path": path.display().to_string(),
                "expected_size": expected.len(),
            }),
            serde_json::json!({
                "actual_size": actual.len(),
                "match": matched,
            }),
            start.elapsed(),
        );

        Ok(matched)
    }

    /// Inject corruption at a specific offset in the image file.
    pub fn inject_corruption(&self, offset: u64, bytes: &[u8]) -> Result<()> {
        let start = Instant::now();

        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&self.image_path)
            .with_context(|| format!("open image for corruption {}", self.image_path.display()))?;
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(bytes)?;
        f.flush()?;

        self.log_ok(
            "inject_corruption",
            serde_json::json!({
                "offset": offset,
                "bytes_len": bytes.len(),
            }),
            serde_json::json!({
                "image": self.image_path.display().to_string(),
            }),
            start.elapsed(),
        );

        Ok(())
    }

    /// Collect artifacts (logs, evidence) to an output directory.
    pub fn collect_artifacts(&mut self, dir: &Path) -> Result<()> {
        let start = Instant::now();
        fs::create_dir_all(dir)
            .with_context(|| format!("create artifact dir {}", dir.display()))?;

        // Write the structured log.
        let log_path = dir.join("e2e_log.json");
        self.log.lock().unwrap().write_to(&log_path)?;

        // Copy the image if it exists.
        if self.image_path.exists() {
            let dest = dir.join(self.image_path.file_name().unwrap_or_default());
            fs::copy(&self.image_path, &dest).ok();
        }

        self.preserve = true;

        self.log_ok(
            "collect_artifacts",
            serde_json::json!({"dir": dir.display().to_string()}),
            serde_json::json!({"log_path": log_path.display().to_string()}),
            start.elapsed(),
        );

        Ok(())
    }

    /// Get a reference to the test log.
    #[must_use]
    pub fn log(&self) -> Arc<Mutex<E2eLog>> {
        Arc::clone(&self.log)
    }

    /// Run a closure with panic safety, logging the outcome.
    ///
    /// If the closure panics, the panic is caught, logged as an error,
    /// and the error is returned (not re-raised).
    pub fn run_step<F, T>(&self, step_name: &str, input: serde_json::Value, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T> + panic::UnwindSafe,
    {
        let start = Instant::now();

        match panic::catch_unwind(f) {
            Ok(Ok(value)) => {
                self.log_ok(step_name, input, serde_json::json!({}), start.elapsed());
                Ok(value)
            }
            Ok(Err(e)) => {
                self.log_err(step_name, input, start.elapsed(), &format!("{e:#}"));
                Err(e)
            }
            Err(panic_payload) => {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .map(ToString::to_string)
                    .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".to_owned());
                self.log_err(step_name, input, start.elapsed(), &format!("PANIC: {msg}"));
                bail!("step '{step_name}' panicked: {msg}");
            }
        }
    }

    // ── Internal logging helpers ────────────────────────────────────────

    fn log_ok(
        &self,
        step: &str,
        input: serde_json::Value,
        output: serde_json::Value,
        duration: Duration,
    ) {
        self.log
            .lock()
            .unwrap()
            .push(E2eLogEntry::ok(&self.name, step, input, output, duration));
    }

    fn log_err(&self, step: &str, input: serde_json::Value, duration: Duration, error: &str) {
        self.log
            .lock()
            .unwrap()
            .push(E2eLogEntry::err(&self.name, step, input, duration, error));
    }

    fn log_skip(&self, step: &str, reason: &str) {
        self.log
            .lock()
            .unwrap()
            .push(E2eLogEntry::skip(&self.name, step, reason));
    }
}

impl Drop for E2eTestContext {
    fn drop(&mut self) {
        if !self.preserve && self.workdir.exists() {
            let _ = fs::remove_dir_all(&self.workdir);
        }
    }
}

// ── MountHandle ─────────────────────────────────────────────────────────────

/// RAII mount handle.  Unmounts the filesystem on drop.
///
/// Holds a child process (the FUSE daemon) and the mountpoint path.
/// On drop, kills the child process and runs `fusermount -u`.
pub struct MountHandle {
    /// The FUSE daemon child process.
    child: Option<std::process::Child>,
    /// Mountpoint path.
    mountpoint: PathBuf,
    /// Log reference.
    log: Arc<Mutex<E2eLog>>,
    /// Test name (for logging).
    test_name: String,
}

impl MountHandle {
    /// Create a mount handle from a child process and mountpoint.
    pub fn new(
        child: std::process::Child,
        mountpoint: PathBuf,
        test_name: &str,
        log: Arc<Mutex<E2eLog>>,
    ) -> Self {
        Self {
            child: Some(child),
            mountpoint,
            log,
            test_name: test_name.to_owned(),
        }
    }

    /// The mountpoint path.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Execute a closure with access to the mountpoint path.
    ///
    /// The mount is guaranteed to still be active during the closure.
    pub fn exec_in_mount<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Path) -> Result<T>,
    {
        f(&self.mountpoint)
    }

    /// Unmount explicitly (also called on Drop).
    pub fn unmount(&mut self) -> Result<()> {
        let start = Instant::now();

        // Kill the child process if it's still running.
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;

        // Attempt fusermount -u.
        let output = Command::new("fusermount")
            .args(["-u", &self.mountpoint.display().to_string()])
            .output();

        let status = match output {
            Ok(out) if out.status.success() => "ok",
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                // Not fatal — maybe already unmounted.
                self.log.lock().unwrap().push(E2eLogEntry::err(
                    &self.test_name,
                    "unmount",
                    serde_json::json!({"mountpoint": self.mountpoint.display().to_string()}),
                    start.elapsed(),
                    &format!("fusermount -u failed (non-fatal): {stderr}"),
                ));
                return Ok(());
            }
            Err(_) => {
                // fusermount not available.
                "skip"
            }
        };

        if status == "ok" {
            self.log.lock().unwrap().push(E2eLogEntry::ok(
                &self.test_name,
                "unmount",
                serde_json::json!({"mountpoint": self.mountpoint.display().to_string()}),
                serde_json::json!({}),
                start.elapsed(),
            ));
        }

        Ok(())
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        let _ = self.unmount();
    }
}

// ── Utilities ───────────────────────────────────────────────────────────────

/// Simple SHA256 using the system's `sha256sum` command.
///
/// Falls back to a zero hash if the command is not available.
fn sha256_hex(data: &[u8]) -> String {
    let Ok(mut child) = Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return "sha256sum_not_available".to_owned();
    };

    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(data);
    }
    // Close stdin to signal EOF.
    drop(child.stdin.take());

    match child.wait_with_output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // sha256sum output is: "<hash>  -\n" or "<hash>  <filename>\n"
            stdout.split_whitespace().next().unwrap_or("").to_owned()
        }
        Err(_) => "sha256sum_failed".to_owned(),
    }
}

/// Check if a command is available on the system.
#[must_use]
pub fn command_available(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// E2E test result summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eTestResult {
    pub test_name: String,
    pub passed: bool,
    pub steps_total: usize,
    pub steps_ok: usize,
    pub steps_error: usize,
    pub steps_skip: usize,
    pub duration_us: u64,
    pub artifacts_dir: Option<String>,
}

impl E2eTestResult {
    /// Build a result summary from a log.
    #[must_use]
    pub fn from_log(
        test_name: &str,
        log: &E2eLog,
        duration: Duration,
        artifacts_dir: Option<&Path>,
    ) -> Self {
        let steps_ok = log.entries().iter().filter(|e| e.status == "ok").count();
        let steps_error = log.entries().iter().filter(|e| e.status == "error").count();
        let steps_skip = log.entries().iter().filter(|e| e.status == "skip").count();

        Self {
            test_name: test_name.to_owned(),
            passed: steps_error == 0,
            steps_total: log.entries().len(),
            steps_ok,
            steps_error,
            steps_skip,
            duration_us: u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
            artifacts_dir: artifacts_dir.map(|p| p.display().to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_log_entry_ok() {
        let entry = E2eLogEntry::ok(
            "test1",
            "create_fixture",
            serde_json::json!({"fs": "ext4"}),
            serde_json::json!({"path": "/tmp/test"}),
            Duration::from_micros(12345),
        );
        assert_eq!(entry.test, "test1");
        assert_eq!(entry.step, "create_fixture");
        assert_eq!(entry.status, "ok");
        assert_eq!(entry.duration_us, 12345);
        assert!(entry.error.is_none());
    }

    #[test]
    fn e2e_log_entry_err() {
        let entry = E2eLogEntry::err(
            "test1",
            "mount",
            serde_json::json!({}),
            Duration::from_millis(100),
            "mount failed",
        );
        assert_eq!(entry.status, "error");
        assert_eq!(entry.error.as_deref(), Some("mount failed"));
    }

    #[test]
    fn e2e_log_entry_skip() {
        let entry = E2eLogEntry::skip("test1", "create_fixture", "mkfs.ext4 not found");
        assert_eq!(entry.status, "skip");
        assert_eq!(entry.duration_us, 0);
    }

    #[test]
    fn e2e_log_ndjson_roundtrip() {
        let mut log = E2eLog::new();
        log.push(E2eLogEntry::ok(
            "t",
            "s1",
            serde_json::json!({}),
            serde_json::json!({}),
            Duration::ZERO,
        ));
        log.push(E2eLogEntry::err(
            "t",
            "s2",
            serde_json::json!({}),
            Duration::ZERO,
            "oops",
        ));

        let ndjson = log.to_ndjson().unwrap();
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON.
        for line in lines {
            let parsed: E2eLogEntry = serde_json::from_str(line).unwrap();
            assert_eq!(parsed.test, "t");
        }
    }

    #[test]
    fn e2e_log_has_errors() {
        let mut log = E2eLog::new();
        assert!(!log.has_errors());
        log.push(E2eLogEntry::ok(
            "t",
            "s",
            serde_json::json!({}),
            serde_json::json!({}),
            Duration::ZERO,
        ));
        assert!(!log.has_errors());
        log.push(E2eLogEntry::err(
            "t",
            "s",
            serde_json::json!({}),
            Duration::ZERO,
            "e",
        ));
        assert!(log.has_errors());
    }

    #[test]
    fn context_creates_workdir_and_cleans_up() {
        let opts = FixtureOptions::default();
        let workdir;
        {
            let ctx = E2eTestContext::new("cleanup_test", ImageType::Ext4, &opts).unwrap();
            workdir = ctx.workdir.clone();
            assert!(workdir.exists());
            assert!(ctx.mountpoint.exists());
        }
        // After drop, workdir should be cleaned up.
        assert!(!workdir.exists());
    }

    #[test]
    fn context_create_fixture_ext4() {
        let opts = FixtureOptions {
            size_mb: 8,
            ..Default::default()
        };
        let ctx = E2eTestContext::new("fixture_ext4", ImageType::Ext4, &opts).unwrap();
        let created = ctx.create_fixture(&opts).unwrap();
        if created {
            assert!(ctx.image_path.exists());
            let meta = fs::metadata(&ctx.image_path).unwrap();
            assert!(meta.len() >= 8 * 1024 * 1024);
        }
        // If not created, mkfs.ext4 was not available (CI-safe skip).
    }

    #[test]
    fn context_corruption_injection() {
        let opts = FixtureOptions {
            size_mb: 1,
            ..Default::default()
        };
        let ctx = E2eTestContext::new("corruption_test", ImageType::Ext4, &opts).unwrap();

        // Create a minimal image file.
        fs::write(&ctx.image_path, vec![0u8; 1024 * 1024]).unwrap();

        // Inject corruption.
        ctx.inject_corruption(512, &[0xFF, 0xFE, 0xFD]).unwrap();

        // Verify corruption was applied.
        let data = fs::read(&ctx.image_path).unwrap();
        assert_eq!(data[512], 0xFF);
        assert_eq!(data[513], 0xFE);
        assert_eq!(data[514], 0xFD);
    }

    #[test]
    fn context_verify_file_content() {
        let opts = FixtureOptions::default();
        let ctx = E2eTestContext::new("verify_test", ImageType::Ext4, &opts).unwrap();

        let test_file = ctx.workdir.join("test.txt");
        fs::write(&test_file, b"hello world").unwrap();

        assert!(ctx.verify_file_content(&test_file, b"hello world").unwrap());
        assert!(
            !ctx.verify_file_content(&test_file, b"wrong content")
                .unwrap()
        );
    }

    #[test]
    fn context_collect_artifacts() {
        let opts = FixtureOptions::default();
        let mut ctx = E2eTestContext::new("artifacts_test", ImageType::Ext4, &opts).unwrap();

        let artifact_dir =
            std::env::temp_dir().join(format!("ffs-e2e-artifacts-{}", std::process::id()));

        ctx.collect_artifacts(&artifact_dir).unwrap();

        let log_path = artifact_dir.join("e2e_log.json");
        assert!(log_path.exists());

        // Log should be valid NDJSON.
        let content = fs::read_to_string(&log_path).unwrap();
        assert!(!content.is_empty());

        // Cleanup.
        let _ = fs::remove_dir_all(&artifact_dir);
    }

    #[test]
    fn context_run_step_catches_panic() {
        let opts = FixtureOptions::default();
        let ctx = E2eTestContext::new("panic_test", ImageType::Ext4, &opts).unwrap();

        let result: Result<()> = ctx.run_step("panic_step", serde_json::json!({}), || {
            panic!("test panic");
        });

        assert!(result.is_err());
        let last_status = ctx
            .log
            .lock()
            .unwrap()
            .entries()
            .last()
            .unwrap()
            .status
            .clone();
        let has_panic = ctx
            .log
            .lock()
            .unwrap()
            .entries()
            .last()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("PANIC");
        assert_eq!(last_status, "error");
        assert!(has_panic);
    }

    #[test]
    fn context_run_step_logs_error() {
        let opts = FixtureOptions::default();
        let ctx = E2eTestContext::new("error_test", ImageType::Ext4, &opts).unwrap();

        let result: Result<()> = ctx.run_step("fail_step", serde_json::json!({}), || {
            bail!("intentional failure");
        });

        assert!(result.is_err());
        let has_errors = ctx.log.lock().unwrap().has_errors();
        assert!(has_errors);
    }

    #[test]
    fn e2e_test_result_from_log() {
        let mut log = E2eLog::new();
        log.push(E2eLogEntry::ok(
            "t",
            "s1",
            serde_json::json!({}),
            serde_json::json!({}),
            Duration::ZERO,
        ));
        log.push(E2eLogEntry::ok(
            "t",
            "s2",
            serde_json::json!({}),
            serde_json::json!({}),
            Duration::ZERO,
        ));
        log.push(E2eLogEntry::skip("t", "s3", "skipped"));

        let result = E2eTestResult::from_log("test1", &log, Duration::from_secs(1), None);
        assert!(result.passed);
        assert_eq!(result.steps_total, 3);
        assert_eq!(result.steps_ok, 2);
        assert_eq!(result.steps_skip, 1);
        assert_eq!(result.steps_error, 0);
    }

    #[test]
    fn sha256_hex_works() {
        if !command_available("sha256sum") {
            return;
        }
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn mount_handle_unmount_on_drop() {
        // Test that MountHandle doesn't panic when dropping without a real mount.
        let log = Arc::new(Mutex::new(E2eLog::new()));
        let mountpoint = std::env::temp_dir().join("ffs-e2e-mount-test");
        let _ = fs::create_dir_all(&mountpoint);

        // Create a handle with a dummy child (cat, which exits immediately).
        if let Ok(child) = Command::new("sleep").arg("0").spawn() {
            let handle = MountHandle::new(child, mountpoint.clone(), "mount_test", log);
            drop(handle);
            // Should not panic.
        }

        let _ = fs::remove_dir_all(&mountpoint);
    }

    #[test]
    fn image_type_display() {
        assert_eq!(ImageType::Ext4.to_string(), "ext4");
        assert_eq!(ImageType::Btrfs.to_string(), "btrfs");
    }

    #[test]
    fn command_available_check() {
        // `ls` should always be available.
        assert!(command_available("ls"));
        // Nonexistent command.
        assert!(!command_available("definitely_not_a_real_command_12345"));
    }
}
