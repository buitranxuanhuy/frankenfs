# FrankenFS E2E Tests

End-to-end smoke tests for FrankenFS that exercise user-facing workflows.

## Quick Start

```bash
# Run the main smoke test
./scripts/e2e/ffs_smoke.sh

# Run ext4 read-write smoke + crash checks
./scripts/e2e/ffs_ext4_rw_smoke.sh

# Run ext4 read-only round-trip (debugfs reference vs FUSE view)
./scripts/e2e/ffs_ext4_ro_roundtrip.sh

# Run btrfs read-write smoke + persistence checks
./scripts/e2e/ffs_btrfs_rw_smoke.sh

# Run btrfs read-only FUSE smoke
./scripts/e2e/ffs_btrfs_ro_smoke.sh

# Run production FUSE runtime E2E suite
./scripts/e2e/ffs_fuse_production.sh

# Run write-back durability scenarios
./scripts/e2e/ffs_writeback_e2e.sh

# Run graceful degradation stress suite
./scripts/e2e/ffs_degradation_stress.sh

# Run deterministic corruption-injection + recovery smoke
./scripts/e2e/ffs_repair_recovery_smoke.sh

# Plan/run curated xfstests generic+ext4 subsets
./scripts/e2e/ffs_xfstests_e2e.sh
```

## What It Tests

The smoke test exercises:

1. **Build** - `cargo build --workspace`
2. **CLI Commands**
   - `ffs inspect` - Parse and display filesystem metadata
   - `ffs scrub` - Validate filesystem integrity
   - `ffs parity` - Show feature parity report
3. **FUSE Mount** (if `/dev/fuse` available)
   - Mount an ext4 image read-only
   - List directory contents
   - Read file contents
   - Unmount cleanly

The production FUSE runtime suite exercises:

1. Mount lifecycle checks for RW/RO startup and clean teardown
2. Concurrent read/write worker probes against mounted ext4 fixtures
3. Xattr operations (`set`, `get`, `list`, `remove`) for runtime surface validation
4. SIGTERM shutdown durability verification with remount validation
5. Throughput/latency baseline capture to `perf_baseline.json`
6. Optional btrfs inspect smoke when `mkfs.btrfs` is available
7. JUnit report generation at `artifacts/e2e/<timestamp>_ffs_fuse_production/junit.xml`

The write-back E2E suite exercises:

1. Basic flush correctness (1000 committed blocks)
2. Clean shutdown flush-all behavior
3. Simulated SIGKILL durability boundary (fsync vs non-fsync)
4. Abort lifecycle discard behavior
5. Backpressure under sustained write load
6. Concurrent commit/abort transactions with daemon flush

The graceful degradation stress suite exercises:

1. Deterministic degradation FSM and backpressure gates (`ffs-core` targeted tests)
2. FUSE surface regression checks under the current backpressure wiring (`ffs-fuse` tests)
3. Optional host pressure probe with `stress-ng` while monitor tests execute
4. Optional live mount pressure probe (`FFS_RUN_MOUNT_STRESS=1`) that verifies reads stay functional under CPU stress

The ext4 read-write smoke suite exercises:

1. Rootless fixture lifecycle: create `base.ext4`, copy to `work.ext4`, mount only the work image
2. RW operations: create/write/overwrite, mkdir/rmdir, rename, unlink
3. Metadata checks (phase-gated): chmod verification and mtime monotonicity
4. Clean shutdown persistence: remount read-only and re-verify post-unmount state
5. Deterministic crash phase: write + fsync 500 baseline files, run continuous in-flight writes, SIGKILL mount daemon, remount read-only, and verify baseline + fsync durability invariants

The ext4 read-only round-trip suite exercises:

1. Fixture lifecycle: use configured/default ext4 fixture image (or create deterministic fallback)
2. Reference extraction: `debugfs rdump` of the full filesystem tree to a host-side reference directory
3. Metadata assertions: `ffs inspect --json` checks for superblock fields, free-space accounting consistency, and orphan diagnostics shape
4. Read-only FUSE mount and full tree walk comparison against reference extraction
5. Per-file BLAKE3 digest comparison (`b3sum`) between reference tree and mounted view
6. Journal replay reporting check when crash recovery is triggered by the image state
7. Runtime guard: suite fails if elapsed duration exceeds configured bound (default 30 seconds)

The btrfs read-write smoke suite exercises:

1. Fixture lifecycle: create a fresh 256MiB mkfs.btrfs image, then fallback to a known-good btrfs fixture if current parser support is incomplete
2. RW operations: create/write/overwrite (small/4KB/1MB), append, truncate extend/shrink
3. Directory/name/link operations: mkdir/rmdir, rename within/across dir, rename-overwrite, unlink, symlink, hardlink, and inode-sharing checks
4. COW-oriented checks: repeated rewrites of a hot file with superblock generation/root snapshots before/after write bursts
5. Persistence checks: clean unmount, read-only remount, and post-remount data/metadata validation
6. CI artifacts: structured per-test timing logs and a `junit.xml` report under the suite artifact directory

The btrfs read-only smoke suite exercises:

1. Runtime btrfs fixture generation via `scripts/fixtures/make_btrfs_reference_image.sh`
2. `ffs inspect --json` geometry capture (sectorsize/nodesize logged in test header)
3. Read-only `ffs mount` behavior through `/dev/fuse`
4. Basic black-box operations: `ls`, `stat`, bounded `find`, and `cat` of a known fixture file when present
5. Reliable unmount with actionable mount-log diagnostics on failure

The repair recovery smoke suite exercises:

1. Deterministic bounded random block corruption across repair groups (currently 5% in the test harness)
2. Background scrub daemon auto-detection and auto-recovery
3. Full before/after block digest equivalence checks
4. Structured evidence ledger capture and artifact export under `artifacts/e2e/<timestamp>_ffs_repair_recovery_smoke/repair/`

If rch offload runs the test but does not materialize custom artifact files locally, the script exits with `SKIPPED` unless `FFS_REPAIR_LOCAL_ARTIFACT_FALLBACK=1` is set.

The xfstests E2E suite exercises:

1. Curated generic/ext4 subset selection from tracked list files
2. Planning artifacts for CI (`selected_tests.txt`, `summary.json`)
3. Optional direct `xfstests check` execution when a configured checkout is available
4. Structured result artifacts (`results.json`, `junit.xml`) for per-commit tracking
5. Regression guard enforcement in run mode (`must_pass`, `min_pass_count`, `min_pass_rate`)
6. Safe skip/fail behavior via strictness toggle

## Output

Test artifacts are stored in `artifacts/e2e/<timestamp>/`:

```
artifacts/e2e/20260212_161500_ffs_smoke/
└── run.log    # Complete test log with timestamps
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Rust log level (trace, debug, info, warn, error) |
| `RUST_BACKTRACE` | `1` | Enable backtraces on panic |
| `SKIP_MOUNT` | `0` | Set to `1` to skip FUSE mount tests |
| `FFS_AUTO_UNMOUNT` | `0` (for ext4 RW smoke, btrfs RW smoke, and fuse production) | Passed through to `ffs mount`; set `0` to avoid implicit `allow_other` on rootless fuse3 setups |
| `FFS_ALLOW_OTHER` | `0` | For `ffs_fuse_production.sh`: if `1`, passes `--allow-other` to `ffs mount` |
| `FFS_CLI_BIN` | `target/release/ffs-cli` | Path to local `ffs-cli` binary used by RW mount/inspect steps |
| `EXT4_ROUNDTRIP_IMAGE` | *(unset)* | Optional path to ext4 image for `ffs_ext4_ro_roundtrip.sh`; if unset, defaults to `tests/fixtures/images/ext4_small.img` and falls back to generated image when missing |
| `EXT4_ROUNDTRIP_MAX_SECS` | `30` | Max allowed runtime (seconds) for `ffs_ext4_ro_roundtrip.sh` |
| `BASELINE_FILE_COUNT` | `500` | Number of fsync-backed baseline files written before SIGKILL phase |
| `CRASH_WRITER_RUNTIME_SECS` | `2` | Duration to run background in-flight writer before sending SIGKILL |
| `CRASH_WRITER_SLEEP_SECS` | `0.01` | Per-write pacing interval for crash in-flight writer |
| `FFS_REPAIR_LOCAL_ARTIFACT_FALLBACK` | `0` | For `ffs_repair_recovery_smoke.sh`: if `1`, re-run repair test locally when rch offload does not materialize artifact files |
| `FFS_USE_RCH` | `1` | For `ffs_degradation_stress.sh`, `ffs_fuse_production.sh`, `ffs_btrfs_rw_smoke.sh`, and `ffs_ext4_ro_roundtrip.sh`: offload cargo commands via `rch exec -- cargo ...` when available |
| `FFS_RUN_MOUNT_STRESS` | `0` | For `ffs_degradation_stress.sh`: if `1`, attempt optional live FUSE mount pressure probe |
| `DEGRADATION_STRESS_DURATION_SECS` | `20` | Duration for host `stress-ng` probe in `ffs_degradation_stress.sh` |
| `DEGRADATION_STRESS_CPU_WORKERS` | `4` | CPU workers for host `stress-ng` probe in `ffs_degradation_stress.sh` |
| `DEGRADATION_STRESS_VM_WORKERS` | `1` | VM workers for host `stress-ng` probe in `ffs_degradation_stress.sh` |
| `DEGRADATION_STRESS_VM_BYTES` | `60%` | VM memory pressure setting for host `stress-ng` probe in `ffs_degradation_stress.sh` |
| `DEGRADATION_MOUNT_STRESS_DURATION_SECS` | `15` | Duration for optional mount pressure probe in `ffs_degradation_stress.sh` |
| `DEGRADATION_MOUNT_STRESS_CPU_WORKERS` | `4` | CPU workers for optional mount pressure probe in `ffs_degradation_stress.sh` |
| `XFSTESTS_MODE` | `auto` | `auto`, `plan`, or `run` for `ffs_xfstests_e2e.sh` |
| `XFSTESTS_DIR` | *(unset)* | Path to xfstests checkout containing `check` |
| `XFSTESTS_DRY_RUN` | `1` | In run mode, pass `-n` to `check` (selection validation without executing tests) |
| `XFSTESTS_FILTER` | `all` | Select `all`, `generic`, or `ext4` curated subsets |
| `XFSTESTS_STRICT` | `0` | If `1`, missing xfstests prerequisites fail instead of skip |
| `XFSTESTS_REGRESSION_GUARD_JSON` | `scripts/e2e/xfstests_regression_guard.json` | Regression guard config used in run mode to fail on must-pass or pass-rate regressions |

## Requirements

- Rust toolchain (nightly)
- `python3` (used by concurrency/perf probes in `ffs_fuse_production.sh`)
- `mkfs.ext4` and `debugfs` (e2fsprogs)
- `b3sum` (required by `ffs_ext4_ro_roundtrip.sh` for BLAKE3 digest verification)
- `mkfs.btrfs` and `btrfs` (btrfs-progs)
- `/dev/fuse` accessible (for mount tests)
- `fusermount` or `fusermount3` (for unmounting)
- `mountpoint` utility (used for readiness checks)
- Optional for xfstests execution mode: an `xfstests-dev` checkout with built prerequisites

## Skipping Mount Tests

Mount tests are automatically skipped if:
- `/dev/fuse` doesn't exist
- `/dev/fuse` isn't readable/writable
- `mkfs.btrfs` / `btrfs` tools are unavailable for btrfs fixture generation
- `fuse3` rejects implicit `allow_other` because `user_allow_other` is not enabled in `/etc/fuse.conf`
- `fusermount` returns `Permission denied` / `Operation not permitted` for the current runtime environment
- `SKIP_MOUNT=1` is set

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed (or skipped with message) |
| 1 | Test failure |

## Troubleshooting

### "Permission denied" on /dev/fuse

Add your user to the `fuse` group:
```bash
sudo usermod -aG fuse $USER
# Log out and back in
```

Or run with sudo (not recommended).

### Mount times out

Check if another FUSE process is hanging:
```bash
ps aux | grep ffs
fusermount -u /path/to/mount
```

### Build fails

Ensure dependencies are available:
```bash
# Check for asupersync and ftui in parent directory
ls -la /dp/asupersync /dp/frankentui
```

## CI Integration

The E2E tests can be run in CI by:

1. Installing dependencies:
   ```bash
   sudo apt-get install -y e2fsprogs fuse3
   ```

2. Running with mount tests skipped (if FUSE not available):
   ```bash
   SKIP_MOUNT=1 ./scripts/e2e/ffs_smoke.sh
   ```

3. Running xfstests subset planning (CI-safe, no xfstests checkout required):
   ```bash
   XFSTESTS_MODE=plan ./scripts/e2e/ffs_xfstests_e2e.sh
   ```

4. Running xfstests subset execution (requires configured checkout):
   ```bash
   XFSTESTS_MODE=run XFSTESTS_DIR=/path/to/xfstests-dev ./scripts/e2e/ffs_xfstests_e2e.sh
   ```

5. Adjusting regression thresholds:
   ```bash
   cat scripts/e2e/xfstests_regression_guard.json
   ```

## Adding New Tests

1. Source `lib.sh` for helpers
2. Use `e2e_step`, `e2e_run`, `e2e_assert` for structure
3. Use `e2e_skip` for optional features
4. Use `e2e_fail` for failures
5. Call `e2e_pass` at the end

Example:
```bash
#!/usr/bin/env bash
cd "$(dirname "$0")/../.."
source scripts/e2e/lib.sh

e2e_init "my_test"
e2e_print_env

e2e_step "My Test"
e2e_assert cargo test -p my-crate

e2e_pass
```
