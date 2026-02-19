# Baselines

This directory stores reproducible benchmark snapshots for CLI and harness workflows.

## Record a Baseline

```bash
scripts/benchmark_record.sh --compare
```

Short rerun (faster smoke path):

```bash
scripts/benchmark_record.sh --warmup 1 --runs 2 --compare
```

What this does:

1. Runs `scripts/verify_golden.sh` as a preflight conformance gate (unless `--skip-verify-golden` is set).
2. Builds release binaries once (via `rch exec -- cargo ...`).
3. Captures `ffs-block` cache workload metric snapshots (ARC and S3-FIFO feature modes) from `ArcCache::metrics()` into TSV reports:
   - `sequential_scan`
   - `zipf_distribution`
   - `mixed_seq70_hot30`
   - `compile_like`
   - `database_like`
4. Runs `hyperfine` with JSON export for:
   - `ffs-cli inspect <ext4 reference> --json` (if image exists)
   - `ffs-cli scrub <ext4 reference> --json` (if image exists)
   - `ffs-cli parity --json`
   - `ffs-harness parity`
   - `ffs-harness check-fixtures`
   - `ffs-block` ARC criterion workload commands for the five workloads above
   - `ffs-block` S3-FIFO criterion workload commands for the same five workloads
   - `ffs-block` write-path and fsync-path criterion commands:
     - `writeback_write_seq_4k`
     - `writeback_write_random_4k`
     - `writeback_sync_single_4k`
     - `writeback_sync_100x4k`
5. Writes artifacts to:
   - `baselines/baseline-YYYYMMDD.md`
   - `baselines/hyperfine/YYYYMMDD/*.json`
   - `baselines/hyperfine/YYYYMMDD/ffs_block_cache_workloads_arc.tsv`
   - `baselines/hyperfine/YYYYMMDD/ffs_block_cache_workloads_s3fifo.tsv`
   - `artifacts/baselines/perf_baseline.json`
   - `artifacts/baselines/perf_baseline-YYYYMMDD.json`

`perf_baseline.json` always carries the full target operation matrix; operations not yet automated or unsupported on the current host are emitted with `"status": "pending"` so progress is explicit and machine-auditable. `benchmark_record.sh` now attempts rootless FUSE mount probes (`mount_cold`, `mount_warm`, `mount_recovery`) via `scripts/mount_benchmark_probe.sh` whenever a local `target/release/ffs-cli` binary and `/dev/fuse` are available. `mount_recovery` uses a journal-enabled probe image so journal replay scanning is exercised during mount. If rootless FUSE is blocked but passwordless sudo exists, you can opt in to privileged probes with `FFS_MOUNT_PROBE_USE_SUDO=1` (or `--mount-probe-use-sudo`). If a probe still fails, the script records the concrete failure reason in the relevant pending entry. Cache workload metric rows are also embedded under `cache_workload_metrics`.

## Regression Policy (p99)

- Warn if regression is greater than 10%.
- Fail if regression is greater than 20%.

`--compare` checks current p99 values against the latest prior baseline directory under `baselines/hyperfine/`.
