#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

WARMUP=3
RUNS=10
COMPARE=0
VERIFY_GOLDEN=1
DATE_TAG="$(date -u +%Y%m%d)"
REF_IMAGE="conformance/golden/ext4_8mb_reference.ext4"
P99_WARN_THRESHOLD=10
P99_FAIL_THRESHOLD=20
P99_FAIL_THRESHOLD_OVERRIDE=""
MOUNT_PROBE_USE_SUDO="${FFS_MOUNT_PROBE_USE_SUDO:-0}"
PERF_BASELINE_PATH="artifacts/baselines/perf_baseline.json"
THRESHOLDS_PATH="benchmarks/thresholds.toml"
BENCHMARK_BASELINE_LATEST_PATH="benchmarks/baselines/latest.json"
BENCHMARK_BASELINE_HISTORY_PATH=""
declare -A OP_WARN_THRESHOLDS=()
declare -A OP_FAIL_THRESHOLDS=()
CACHE_WORKLOAD_METRICS_JSON='[]'

cargo_exec() {
    rch exec -- cargo "$@"
}

extract_cache_report_from_log() {
    local log_file="$1"
    local report_tsv="$2"
    awk -F'\t' '
        $1 == "policy" && $2 == "workload" {
            print;
            saw_header = 1;
            next;
        }
        saw_header && ($1 == "arc" || $1 == "s3fifo") {
            print;
            row_count += 1;
        }
        END {
            if (!saw_header || row_count == 0) {
                exit 1;
            }
        }
    ' "$log_file" > "$report_tsv"
}

usage() {
    cat <<'USAGE'
Usage:
  scripts/benchmark_record.sh [--date YYYYMMDD] [--warmup N] [--runs N] [--compare] [--skip-verify-golden] [--thresholds PATH] [--p99-fail-threshold N] [--mount-probe-use-sudo] [--out-json PATH]

Options:
  --date YYYYMMDD          Override date-tag for output paths (default: today)
  --warmup N               Hyperfine warmup runs (default: 3)
  --runs N                 Hyperfine measured runs (default: 10)
  --compare                Compare current p99 against latest prior baseline (warn >10%, fail >20%)
  --skip-verify-golden     Skip scripts/verify_golden.sh preflight
  --thresholds PATH        Read warn/fail thresholds from TOML (default: benchmarks/thresholds.toml)
  --p99-fail-threshold N   Fail compare if p99 regression exceeds N percent (default: 20)
  --mount-probe-use-sudo   Run mount probe helper via `sudo -n` (or set FFS_MOUNT_PROBE_USE_SUDO=1)
  --out-json PATH          Structured baseline JSON output path (default: artifacts/baselines/perf_baseline.json)
  -h, --help               Show this help
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --date)
            [ $# -ge 2 ] || { echo "missing value for --date" >&2; exit 2; }
            DATE_TAG="$2"
            shift 2
            ;;
        --warmup)
            [ $# -ge 2 ] || { echo "missing value for --warmup" >&2; exit 2; }
            WARMUP="$2"
            shift 2
            ;;
        --runs)
            [ $# -ge 2 ] || { echo "missing value for --runs" >&2; exit 2; }
            RUNS="$2"
            shift 2
            ;;
        --compare)
            COMPARE=1
            shift
            ;;
        --skip-verify-golden)
            VERIFY_GOLDEN=0
            shift
            ;;
        --p99-fail-threshold)
            [ $# -ge 2 ] || { echo "missing value for --p99-fail-threshold" >&2; exit 2; }
            P99_FAIL_THRESHOLD_OVERRIDE="$2"
            shift 2
            ;;
        --mount-probe-use-sudo)
            MOUNT_PROBE_USE_SUDO=1
            shift
            ;;
        --thresholds)
            [ $# -ge 2 ] || { echo "missing value for --thresholds" >&2; exit 2; }
            THRESHOLDS_PATH="$2"
            shift 2
            ;;
        --out-json)
            [ $# -ge 2 ] || { echo "missing value for --out-json" >&2; exit 2; }
            PERF_BASELINE_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

load_thresholds() {
    if [ ! -f "$THRESHOLDS_PATH" ]; then
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo "warning: python3 unavailable; skipping thresholds file ${THRESHOLDS_PATH}" >&2
        return 0
    fi

    local threshold_json
    if ! threshold_json="$(
        python3 - "$THRESHOLDS_PATH" <<'PY'
import json
import sys
import tomllib

path = sys.argv[1]
with open(path, "rb") as fh:
    data = tomllib.load(fh)

defaults = data.get("default", {})
warn = defaults.get("warn_percent", 10)
fail = defaults.get("fail_percent", 20)
ops = data.get("operation_thresholds", {})

out = {
    "default": {"warn_percent": warn, "fail_percent": fail},
    "operations": {},
}
for name, cfg in ops.items():
    if isinstance(cfg, dict):
        out["operations"][name] = {
            "warn_percent": cfg.get("warn_percent"),
            "fail_percent": cfg.get("fail_percent"),
        }
print(json.dumps(out))
PY
    )"; then
        echo "warning: failed to parse thresholds file ${THRESHOLDS_PATH}; using defaults" >&2
        return 0
    fi

    P99_WARN_THRESHOLD="$(jq -r '.default.warn_percent // 10' <<<"$threshold_json")"
    P99_FAIL_THRESHOLD="$(jq -r '.default.fail_percent // 20' <<<"$threshold_json")"

    while IFS=$'\t' read -r operation warn fail; do
        [ -n "$operation" ] || continue
        if [ "$warn" != "null" ] && [ -n "$warn" ]; then
            OP_WARN_THRESHOLDS["$operation"]="$warn"
        fi
        if [ "$fail" != "null" ] && [ -n "$fail" ]; then
            OP_FAIL_THRESHOLDS["$operation"]="$fail"
        fi
    done < <(
        jq -r '
            .operations
            | to_entries[]
            | [.key, (.value.warn_percent // "null"), (.value.fail_percent // "null")]
            | @tsv
        ' <<<"$threshold_json"
    )
}

load_thresholds
if [ -n "$P99_FAIL_THRESHOLD_OVERRIDE" ]; then
    P99_FAIL_THRESHOLD="$P99_FAIL_THRESHOLD_OVERRIDE"
fi

OUT_DIR="baselines/hyperfine/${DATE_TAG}"
REPORT_PATH="baselines/baseline-${DATE_TAG}.md"
BENCHMARK_BASELINE_HISTORY_PATH="benchmarks/baselines/history/${DATE_TAG}.json"
if [[ "$PERF_BASELINE_PATH" == *.json ]]; then
    PERF_BASELINE_DATED_PATH="${PERF_BASELINE_PATH%.json}-${DATE_TAG}.json"
else
    PERF_BASELINE_DATED_PATH="${PERF_BASELINE_PATH}-${DATE_TAG}.json"
fi

mkdir -p \
    "$OUT_DIR" \
    "$(dirname "$PERF_BASELINE_PATH")" \
    "$(dirname "$BENCHMARK_BASELINE_LATEST_PATH")" \
    "$(dirname "$BENCHMARK_BASELINE_HISTORY_PATH")"

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    TARGET_DIR="${CARGO_TARGET_DIR}"
else
    TARGET_DIR="$(cargo metadata --format-version=1 --no-deps | jq -r '.target_directory')"
fi

if [ "$VERIFY_GOLDEN" -eq 1 ]; then
    echo "=== Golden Verification Gate ==="
    scripts/verify_golden.sh
    echo ""
fi

echo "=== FrankenFS Baseline Recorder (${DATE_TAG}) ==="
echo "Output directory: ${OUT_DIR}"
echo ""

echo "Building release binaries once..."
cargo_exec build -p ffs-cli --release --quiet
cargo_exec build -p ffs-harness --release --quiet
echo ""

CLI_BIN="${TARGET_DIR}/release/ffs-cli"
HARNESS_BIN="${TARGET_DIR}/release/ffs-harness"
USE_LOCAL_RELEASE_BINS=1
if [ ! -x "$CLI_BIN" ] || [ ! -x "$HARNESS_BIN" ]; then
    # In environments with a non-default CARGO_TARGET_DIR, rch artifact
    # retrieval often materializes under ./target. Prefer that local path
    # before degrading to remote cargo run per benchmark sample.
    local_target_dir="target"
    local_cli_fallback="${local_target_dir}/release/ffs-cli"
    local_harness_fallback="${local_target_dir}/release/ffs-harness"
    if [ -x "$local_cli_fallback" ] && [ -x "$local_harness_fallback" ]; then
        TARGET_DIR="$local_target_dir"
        CLI_BIN="$local_cli_fallback"
        HARNESS_BIN="$local_harness_fallback"
        echo "warning: missing local release binaries under original target directory; using ${TARGET_DIR}/release fallback" >&2
    else
        USE_LOCAL_RELEASE_BINS=0
        echo "warning: missing local release binaries under ${TARGET_DIR}; falling back to rch cargo run commands" >&2
    fi
fi

declare -a BENCH_LABELS=()
declare -a BENCH_COMMANDS=()
declare -a BENCH_FILES=()
declare -a BENCH_OPERATIONS=()
declare -a BENCH_PAYLOAD_MB=()
declare -a SKIPPED_LABELS=()
declare -a CACHE_WORKLOAD_REPORT_PATHS=()
declare -a CACHE_WORKLOAD_REPORT_POLICIES=()
declare -A PENDING_REASONS=(
    ["mount_cold"]="mount latency benchmark requires a FUSE-capable CI runner and automated mount lifecycle probe"
    ["mount_warm"]="warm mount benchmark requires repeated FUSE mount lifecycle automation in benchmark_record.sh"
    ["mount_recovery"]="recovery mount benchmark requires journal-enabled probe image mount automation"
)

MOUNT_BENCH_IMAGE=""
MOUNT_RECOVERY_IMAGE=""
MOUNT_BENCH_ROOT=""

add_bench() {
    BENCH_LABELS+=("$1")
    BENCH_COMMANDS+=("$2")
    BENCH_FILES+=("$3")
    BENCH_OPERATIONS+=("$4")
    BENCH_PAYLOAD_MB+=("${5:-0}")
}

single_line_text() {
    tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//'
}

set_mount_pending_reasons() {
    local reason="$1"
    local recovery_reason="$2"
    PENDING_REASONS["mount_cold"]="$reason"
    PENDING_REASONS["mount_warm"]="$reason"
    PENDING_REASONS["mount_recovery"]="$recovery_reason"
}

record_mount_pending_labels() {
    local operation
    for operation in mount_cold mount_warm mount_recovery; do
        if [ -n "${PENDING_REASONS[$operation]:-}" ]; then
            SKIPPED_LABELS+=("${operation} (pending: ${PENDING_REASONS[$operation]})")
        fi
    done
}

configure_mount_benchmarks() {
    local recovery_reason
    recovery_reason="mount recovery benchmark requires journal-enabled ext4 probe image + automated recovery mount probe"
    local -a mount_probe_prefix=()
    local mount_probe_prefix_str=""

    if [ "$MOUNT_PROBE_USE_SUDO" -eq 1 ]; then
        if ! command -v sudo >/dev/null 2>&1; then
            set_mount_pending_reasons \
                "FFS_MOUNT_PROBE_USE_SUDO=1 requested but sudo is unavailable" \
                "$recovery_reason"
            return
        fi
        if ! sudo -n true >/dev/null 2>&1; then
            set_mount_pending_reasons \
                "FFS_MOUNT_PROBE_USE_SUDO=1 requested but sudo -n is not permitted on this host" \
                "$recovery_reason"
            return
        fi
        mount_probe_prefix=(sudo -n)
        mount_probe_prefix_str="sudo -n "
    fi

    if [ "$USE_LOCAL_RELEASE_BINS" -ne 1 ] || [ ! -x "$CLI_BIN" ]; then
        set_mount_pending_reasons \
            "mount benchmarks require a local release ffs-cli binary at ${CLI_BIN} (rch remote binaries cannot mount local FUSE)" \
            "$recovery_reason"
        return
    fi

    if [ ! -e /dev/fuse ] || [ ! -r /dev/fuse ] || [ ! -w /dev/fuse ]; then
        set_mount_pending_reasons \
            "/dev/fuse is unavailable or lacks rw access on this host" \
            "$recovery_reason"
        return
    fi

    if ! command -v mkfs.ext4 >/dev/null 2>&1; then
        set_mount_pending_reasons \
            "mkfs.ext4 is required for mount probe image generation" \
            "$recovery_reason"
        return
    fi

    if ! command -v mountpoint >/dev/null 2>&1; then
        set_mount_pending_reasons \
            "mountpoint utility is required for FUSE readiness checks" \
            "$recovery_reason"
        return
    fi

    if [ ! -x "scripts/mount_benchmark_probe.sh" ]; then
        set_mount_pending_reasons \
            "scripts/mount_benchmark_probe.sh is missing or not executable" \
            "$recovery_reason"
        return
    fi

    MOUNT_BENCH_IMAGE="${OUT_DIR}/mount_probe.ext4"
    MOUNT_RECOVERY_IMAGE="${OUT_DIR}/mount_recovery_probe.ext4"
    MOUNT_BENCH_ROOT="${OUT_DIR}/mount_probe_mounts"
    mkdir -p "$MOUNT_BENCH_ROOT"

    if ! dd if=/dev/zero of="$MOUNT_BENCH_IMAGE" bs=1M count=16 status=none; then
        set_mount_pending_reasons \
            "failed to create mount probe image at ${MOUNT_BENCH_IMAGE}" \
            "$recovery_reason"
        return
    fi

    if ! mkfs.ext4 -F -O extent,filetype,^has_journal -L ffs_mount_probe "$MOUNT_BENCH_IMAGE" >/dev/null 2>&1; then
        set_mount_pending_reasons \
            "mkfs.ext4 failed while preparing mount probe image" \
            "$recovery_reason"
        return
    fi

    if ! dd if=/dev/zero of="$MOUNT_RECOVERY_IMAGE" bs=1M count=32 status=none; then
        set_mount_pending_reasons \
            "failed to create recovery mount probe image at ${MOUNT_RECOVERY_IMAGE}" \
            "$recovery_reason"
        return
    fi

    if ! mkfs.ext4 -F -O extent,filetype -L ffs_mount_recovery_probe "$MOUNT_RECOVERY_IMAGE" >/dev/null 2>&1; then
        set_mount_pending_reasons \
            "mkfs.ext4 failed while preparing recovery mount probe image" \
            "$recovery_reason"
        return
    fi

    local probe_err
    probe_err="${OUT_DIR}/ffs_cli_mount_probe.stderr"
    if "${mount_probe_prefix[@]}" scripts/mount_benchmark_probe.sh \
        --bin "$CLI_BIN" \
        --image "$MOUNT_BENCH_IMAGE" \
        --mount-root "$MOUNT_BENCH_ROOT" \
        --mode cold \
        >/dev/null 2>"$probe_err"; then
        local cmd_base
        cmd_base="${mount_probe_prefix_str}scripts/mount_benchmark_probe.sh --bin $(printf '%q' "$CLI_BIN") --image $(printf '%q' "$MOUNT_BENCH_IMAGE") --mount-root $(printf '%q' "$MOUNT_BENCH_ROOT")"

        add_bench "ffs-cli mount cold ext4 probe (fuse)" \
            "${cmd_base} --mode cold" \
            "ffs_cli_mount_cold_probe.json" \
            "mount_cold" \
            "0"
        add_bench "ffs-cli mount warm ext4 probe (fuse)" \
            "${cmd_base} --mode warm" \
            "ffs_cli_mount_warm_probe.json" \
            "mount_warm" \
            "0"

        unset 'PENDING_REASONS[mount_cold]'
        unset 'PENDING_REASONS[mount_warm]'

        local recovery_probe_err
        recovery_probe_err="${OUT_DIR}/ffs_cli_mount_recovery_probe.stderr"
        local recovery_cmd_base
        recovery_cmd_base="${mount_probe_prefix_str}scripts/mount_benchmark_probe.sh --bin $(printf '%q' "$CLI_BIN") --image $(printf '%q' "$MOUNT_RECOVERY_IMAGE") --mount-root $(printf '%q' "$MOUNT_BENCH_ROOT")"
        if "${mount_probe_prefix[@]}" scripts/mount_benchmark_probe.sh \
            --bin "$CLI_BIN" \
            --image "$MOUNT_RECOVERY_IMAGE" \
            --mount-root "$MOUNT_BENCH_ROOT" \
            --mode recovery \
            >/dev/null 2>"$recovery_probe_err"; then
            add_bench "ffs-cli mount recovery ext4 probe (journal replay)" \
                "${recovery_cmd_base} --mode recovery" \
                "ffs_cli_mount_recovery_probe.json" \
                "mount_recovery" \
                "0"
            unset 'PENDING_REASONS[mount_recovery]'
        else
            local recovery_probe_reason
            recovery_probe_reason="$(single_line_text < "$recovery_probe_err")"
            if [ -z "$recovery_probe_reason" ]; then
                recovery_probe_reason="mount recovery probe failed with unknown error"
            fi
            PENDING_REASONS["mount_recovery"]="mount recovery probe failed on this host: ${recovery_probe_reason} (set FFS_MOUNT_PROBE_USE_SUDO=1 or --mount-probe-use-sudo if passwordless sudo is available)"
        fi
    else
        local probe_reason
        probe_reason="$(single_line_text < "$probe_err")"
        if [ -z "$probe_reason" ]; then
            probe_reason="mount benchmark probe failed with unknown error"
        fi
        set_mount_pending_reasons \
            "mount benchmark probe failed on this host: ${probe_reason} (set FFS_MOUNT_PROBE_USE_SUDO=1 or --mount-probe-use-sudo if passwordless sudo is available)" \
            "$recovery_reason"
    fi
}

if [ "$USE_LOCAL_RELEASE_BINS" -eq 1 ]; then
    add_bench "ffs-cli parity --json" \
        "${CLI_BIN} parity --json" \
        "ffs_cli_parity.json" \
        "metadata_parity_cli" \
        "0"

    add_bench "ffs-harness parity" \
        "${HARNESS_BIN} parity" \
        "ffs_harness_parity.json" \
        "metadata_parity_harness" \
        "0"

    add_bench "ffs-harness check-fixtures" \
        "${HARNESS_BIN} check-fixtures" \
        "ffs_harness_check_fixtures.json" \
        "fixture_validation" \
        "0"
else
    add_bench "ffs-cli parity --json" \
        "rch exec -- cargo run -p ffs-cli --release --quiet -- parity --json" \
        "ffs_cli_parity.json" \
        "metadata_parity_cli" \
        "0"

    add_bench "ffs-harness parity" \
        "rch exec -- cargo run -p ffs-harness --release --quiet -- parity" \
        "ffs_harness_parity.json" \
        "metadata_parity_harness" \
        "0"

    add_bench "ffs-harness check-fixtures" \
        "rch exec -- cargo run -p ffs-harness --release --quiet -- check-fixtures" \
        "ffs_harness_check_fixtures.json" \
        "fixture_validation" \
        "0"
fi

if [ -f "$REF_IMAGE" ]; then
    probe_stderr="${OUT_DIR}/ffs_cli_inspect_probe.stderr"
    scrub_probe_stderr="${OUT_DIR}/ffs_cli_scrub_probe.stderr"
    if [ "$USE_LOCAL_RELEASE_BINS" -eq 1 ]; then
        if "$CLI_BIN" inspect "$REF_IMAGE" --json >/dev/null 2>"$probe_stderr"; then
            add_bench "ffs-cli inspect ext4_8mb_reference.ext4 --json" \
                "${CLI_BIN} inspect ${REF_IMAGE} --json" \
                "ffs_cli_inspect_ext4_8mb_reference.json" \
                "read_metadata_inspect_ext4_reference" \
                "8"
            if "$CLI_BIN" scrub "$REF_IMAGE" --json >/dev/null 2>"$scrub_probe_stderr"; then
                add_bench "ffs-cli scrub ext4_8mb_reference.ext4 --json" \
                    "${CLI_BIN} scrub ${REF_IMAGE} --json" \
                    "ffs_cli_scrub_ext4_8mb_reference.json" \
                    "read_metadata_scrub_ext4_reference" \
                    "8"
            else
                scrub_probe_reason="$(single_line_text < "$scrub_probe_stderr")"
                if [ -z "$scrub_probe_reason" ]; then
                    scrub_probe_reason="scrub probe returned non-zero with no stderr output"
                fi
                SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (scrub probe failed: ${scrub_probe_reason})")
            fi
        else
            probe_reason="$(tr '\n' ' ' < "$probe_stderr" | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')"
            SKIPPED_LABELS+=("ffs-cli inspect ext4_8mb_reference.ext4 --json (unsupported by current parser: ${probe_reason})")
            SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (skipped because inspect probe failed)")
        fi
    else
        if rch exec -- cargo run -p ffs-cli --release --quiet -- inspect "$REF_IMAGE" --json >/dev/null 2>"$probe_stderr"; then
            add_bench "ffs-cli inspect ext4_8mb_reference.ext4 --json" \
                "rch exec -- cargo run -p ffs-cli --release --quiet -- inspect ${REF_IMAGE} --json" \
                "ffs_cli_inspect_ext4_8mb_reference.json" \
                "read_metadata_inspect_ext4_reference" \
                "8"
            if rch exec -- cargo run -p ffs-cli --release --quiet -- scrub "$REF_IMAGE" --json >/dev/null 2>"$scrub_probe_stderr"; then
                add_bench "ffs-cli scrub ext4_8mb_reference.ext4 --json" \
                    "rch exec -- cargo run -p ffs-cli --release --quiet -- scrub ${REF_IMAGE} --json" \
                    "ffs_cli_scrub_ext4_8mb_reference.json" \
                    "read_metadata_scrub_ext4_reference" \
                    "8"
            else
                scrub_probe_reason="$(single_line_text < "$scrub_probe_stderr")"
                if [ -z "$scrub_probe_reason" ]; then
                    scrub_probe_reason="scrub probe returned non-zero with no stderr output"
                fi
                SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (scrub probe failed: ${scrub_probe_reason})")
            fi
        else
            probe_reason="$(tr '\n' ' ' < "$probe_stderr" | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')"
            SKIPPED_LABELS+=("ffs-cli inspect ext4_8mb_reference.ext4 --json (unsupported by current parser: ${probe_reason})")
            SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (skipped because inspect probe failed)")
        fi
    fi
else
    SKIPPED_LABELS+=("ffs-cli inspect ext4_8mb_reference.ext4 --json (missing ${REF_IMAGE})")
    SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (missing ${REF_IMAGE})")
fi

add_bench "ffs-block arc sequential scan (criterion)" \
    "rch exec -- cargo bench -p ffs-block --bench arc_cache -- block_cache_arc_sequential_scan" \
    "ffs_block_arc_sequential_scan.json" \
    "block_cache_arc_sequential_scan" \
    "0"

add_bench "ffs-block arc zipf distribution (criterion)" \
    "rch exec -- cargo bench -p ffs-block --bench arc_cache -- block_cache_arc_zipf_distribution" \
    "ffs_block_arc_zipf_distribution.json" \
    "block_cache_arc_zipf_distribution" \
    "0"

add_bench "ffs-block arc mixed seq70 hot30 (criterion)" \
    "rch exec -- cargo bench -p ffs-block --bench arc_cache -- block_cache_arc_mixed_seq70_hot30" \
    "ffs_block_arc_mixed_seq70_hot30.json" \
    "block_cache_arc_mixed_seq70_hot30" \
    "0"

add_bench "ffs-block arc compile-like (criterion)" \
    "rch exec -- cargo bench -p ffs-block --bench arc_cache -- block_cache_arc_compile_like" \
    "ffs_block_arc_compile_like.json" \
    "block_cache_arc_compile_like" \
    "0"

add_bench "ffs-block arc database-like (criterion)" \
    "rch exec -- cargo bench -p ffs-block --bench arc_cache -- block_cache_arc_database_like" \
    "ffs_block_arc_database_like.json" \
    "block_cache_arc_database_like" \
    "0"

add_bench "ffs-block s3fifo sequential scan (criterion)" \
    "rch exec -- cargo bench -p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_sequential_scan" \
    "ffs_block_s3fifo_sequential_scan.json" \
    "block_cache_s3fifo_sequential_scan" \
    "0"

add_bench "ffs-block s3fifo zipf distribution (criterion)" \
    "rch exec -- cargo bench -p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_zipf_distribution" \
    "ffs_block_s3fifo_zipf_distribution.json" \
    "block_cache_s3fifo_zipf_distribution" \
    "0"

add_bench "ffs-block s3fifo mixed seq70 hot30 (criterion)" \
    "rch exec -- cargo bench -p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_mixed_seq70_hot30" \
    "ffs_block_s3fifo_mixed_seq70_hot30.json" \
    "block_cache_s3fifo_mixed_seq70_hot30" \
    "0"

add_bench "ffs-block s3fifo compile-like (criterion)" \
    "rch exec -- cargo bench -p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_compile_like" \
    "ffs_block_s3fifo_compile_like.json" \
    "block_cache_s3fifo_compile_like" \
    "0"

add_bench "ffs-block s3fifo database-like (criterion)" \
    "rch exec -- cargo bench -p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_database_like" \
    "ffs_block_s3fifo_database_like.json" \
    "block_cache_s3fifo_database_like" \
    "0"

add_bench "ffs-block writeback write seq 4k (criterion)" \
    "rch exec -- cargo bench -p ffs-block --bench arc_cache -- writeback_write_seq_4k" \
    "ffs_block_writeback_write_seq_4k.json" \
    "write_seq_4k" \
    "0.00390625"

add_bench "ffs-block writeback write random 4k (criterion)" \
    "rch exec -- cargo bench -p ffs-block --bench arc_cache -- writeback_write_random_4k" \
    "ffs_block_writeback_write_random_4k.json" \
    "write_random_4k" \
    "0.00390625"

add_bench "ffs-block writeback fsync single write (criterion)" \
    "rch exec -- cargo bench -p ffs-block --bench arc_cache -- writeback_sync_single_4k" \
    "ffs_block_writeback_sync_single_4k.json" \
    "fsync_single_write" \
    "0.00390625"

add_bench "ffs-block writeback fsync batch 100x4k (criterion)" \
    "rch exec -- cargo bench -p ffs-block --bench arc_cache -- writeback_sync_100x4k" \
    "ffs_block_writeback_sync_100x4k.json" \
    "fsync_batch_100" \
    "0.390625"

configure_mount_benchmarks
record_mount_pending_labels

json_mean() {
    jq -r '.results[0].mean' "$1"
}

json_stddev() {
    jq -r '.results[0].stddev' "$1"
}

json_percentile() {
    local json_file="$1"
    local percentile="$2"
    jq -r --argjson p "$percentile" '
        .results[0].times as $times
        | ($times | length) as $n
        | if $n == 0 then
              0
          else
              ($times | sort) as $sorted
              | ((($n - 1) * $p) | floor) as $idx
              | $sorted[$idx]
          end
    ' "$json_file"
}

json_p50() {
    json_percentile "$1" 0.50
}

json_p95() {
    json_percentile "$1" 0.95
}

json_p99() {
    json_percentile "$1" 0.99
}

valid_number() {
    awk -v v="$1" 'BEGIN {
        if (v ~ /^-?[0-9]+([.][0-9]+)?([eE][-+]?[0-9]+)?$/) {
            exit 0;
        }
        exit 1;
    }'
}

sec_to_ms() {
    awk -v v="$1" 'BEGIN { printf "%.3f", v * 1000.0 }'
}

sec_to_us() {
    awk -v v="$1" 'BEGIN { printf "%.0f", v * 1000000.0 }'
}

ops_per_sec() {
    awk -v v="$1" 'BEGIN {
        if (v <= 0) {
            printf "0";
        } else {
            printf "%.6f", 1.0 / v;
        }
    }'
}

mb_per_sec() {
    awk -v mb="$1" -v sec="$2" 'BEGIN {
        if (mb <= 0 || sec <= 0) {
            printf "0";
        } else {
            printf "%.6f", mb / sec;
        }
    }'
}

pct_change() {
    awk -v base="$1" -v cur="$2" 'BEGIN {
        if (base == 0) {
            printf "0.00";
        } else {
            printf "%.2f", ((cur - base) / base) * 100.0;
        }
    }'
}

run_cache_workload_report() {
    local policy="$1"
    local report_tsv="$2"
    local log_file="${report_tsv%.tsv}.txt"
    local -a command

    if [ "$policy" = "s3fifo" ]; then
        command=(
            rch exec -- env "FFS_BLOCK_CACHE_WORKLOAD_REPORT=-" cargo bench -p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_sequential_scan
        )
    else
        command=(
            rch exec -- env "FFS_BLOCK_CACHE_WORKLOAD_REPORT=-" cargo bench -p ffs-block --bench arc_cache -- block_cache_arc_sequential_scan
        )
    fi

    echo ""
    echo "--- ffs-block cache metrics (${policy}) ---"
    if "${command[@]}" >"$log_file" 2>&1; then
        if [ -s "$report_tsv" ] || extract_cache_report_from_log "$log_file" "$report_tsv"; then
            CACHE_WORKLOAD_REPORT_PATHS+=("$report_tsv")
            CACHE_WORKLOAD_REPORT_POLICIES+=("$policy")
        else
            SKIPPED_LABELS+=("ffs-block cache metrics (${policy}) missing report TSV; see ${log_file}")
        fi
    else
        SKIPPED_LABELS+=("ffs-block cache metrics (${policy}) failed; see ${log_file}")
    fi
}

collect_cache_workload_metrics_json() {
    local tmp_json
    tmp_json="$(mktemp)"
    for report_tsv in "${CACHE_WORKLOAD_REPORT_PATHS[@]}"; do
        if [ ! -f "$report_tsv" ]; then
            continue
        fi
        jq -Rsn --arg source_tsv "$report_tsv" '
            [inputs
            | select(length > 0)
            | split("\t")
            | select(.[0] != "policy")
            | {
                policy: .[0],
                workload: .[1],
                accesses: (.[2] | tonumber),
                hits: (.[3] | tonumber),
                misses: (.[4] | tonumber),
                hit_rate: (.[5] | tonumber),
                resident: (.[6] | tonumber),
                capacity: (.[7] | tonumber),
                b1_len: (.[8] | tonumber),
                b2_len: (.[9] | tonumber),
                memory_overhead_per_cached_block: (.[10] | tonumber),
                seed: (.[11] | tonumber),
                source_tsv: $source_tsv
              }
            ]
        ' < "$report_tsv" >> "$tmp_json"
    done

    if [ -s "$tmp_json" ]; then
        jq -s 'add // []' "$tmp_json"
    else
        echo '[]'
    fi
    rm -f "$tmp_json"
}

run_cache_workload_report "arc" "${OUT_DIR}/ffs_block_cache_workloads_arc.tsv"
run_cache_workload_report "s3fifo" "${OUT_DIR}/ffs_block_cache_workloads_s3fifo.tsv"
CACHE_WORKLOAD_METRICS_JSON="$(collect_cache_workload_metrics_json)"

echo "Running hyperfine benchmarks..."
for i in "${!BENCH_LABELS[@]}"; do
    label="${BENCH_LABELS[$i]}"
    cmd="${BENCH_COMMANDS[$i]}"
    json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
    txt_file="${json_file%.json}.txt"

    echo ""
    echo "--- ${label} ---"
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --export-json "$json_file" \
        "$cmd" | tee "$txt_file"
done
echo ""

build_pending_json() {
    local pending_json
    pending_json='[]'
    local operation
    for operation in mount_cold mount_warm mount_recovery; do
        local reason
        reason="${PENDING_REASONS[$operation]:-}"
        if [ -z "$reason" ]; then
            continue
        fi
        pending_json="$(
            jq -n \
                --argjson prior "$pending_json" \
                --arg operation "$operation" \
                --arg reason "$reason" \
                '$prior + [{
                    operation: $operation,
                    metric: "latency",
                    command: "",
                    source_json: "",
                    p50_us: 0,
                    p95_us: 0,
                    p99_us: 0,
                    throughput_ops_sec: 0,
                    throughput_mb_sec: 0,
                    status: "pending",
                    reason: $reason
                }]'
        )"
    done
    echo "$pending_json"
}

write_perf_baseline_json() {
    local tmp_measurements
    tmp_measurements="$(mktemp)"
    for i in "${!BENCH_LABELS[@]}"; do
        local json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
        local mean_s
        local p50_s
        local p95_s
        local p99_s
        local p50_us
        local p95_us
        local p99_us
        local throughput_ops_sec
        local throughput_mb_sec
        mean_s="$(json_mean "$json_file")"
        p50_s="$(json_p50 "$json_file")"
        p95_s="$(json_p95 "$json_file")"
        p99_s="$(json_p99 "$json_file")"
        p50_us="$(sec_to_us "$p50_s")"
        p95_us="$(sec_to_us "$p95_s")"
        p99_us="$(sec_to_us "$p99_s")"
        throughput_ops_sec="$(ops_per_sec "$mean_s")"
        throughput_mb_sec="$(mb_per_sec "${BENCH_PAYLOAD_MB[$i]}" "$mean_s")"

        jq -n \
            --arg operation "${BENCH_OPERATIONS[$i]}" \
            --arg metric "latency" \
            --arg command "${BENCH_COMMANDS[$i]}" \
            --arg source_json "$json_file" \
            --argjson p50_us "$p50_us" \
            --argjson p95_us "$p95_us" \
            --argjson p99_us "$p99_us" \
            --argjson throughput_ops_sec "$throughput_ops_sec" \
            --argjson throughput_mb_sec "$throughput_mb_sec" \
            '{
                operation: $operation,
                metric: $metric,
                command: $command,
                source_json: $source_json,
                p50_us: $p50_us,
                p95_us: $p95_us,
                p99_us: $p99_us,
                throughput_ops_sec: $throughput_ops_sec,
                throughput_mb_sec: $throughput_mb_sec,
                status: "measured"
            }' >> "$tmp_measurements"
    done

    local measured_json
    local measurements_json
    local pending_json
    measured_json="$(jq -s '.' "$tmp_measurements")"
    pending_json="$(build_pending_json)"
    measurements_json="$(jq -n --argjson measured "$measured_json" --argjson pending "$pending_json" '$measured + $pending')"

    jq -n \
        --arg generated_at "$date_iso" \
        --arg date_tag "$DATE_TAG" \
        --arg commit "$git_sha" \
        --arg branch "$git_branch" \
        --arg thresholds_file "$THRESHOLDS_PATH" \
        --arg cpu_model "$cpu_model" \
        --arg kernel "$kernel_ver" \
        --arg rustc "$rustc_ver" \
        --arg cargo "$cargo_ver" \
        --arg hyperfine "$hyperfine_ver" \
        --argjson warmup_runs "$WARMUP" \
        --argjson measured_runs "$RUNS" \
        --argjson p99_warn_threshold_percent "$P99_WARN_THRESHOLD" \
        --argjson p99_fail_threshold_percent "$P99_FAIL_THRESHOLD" \
        --argjson measurements "$measurements_json" \
        --argjson cache_workload_metrics "$CACHE_WORKLOAD_METRICS_JSON" \
        --argjson measured_count "$(jq 'map(select(.status == "measured")) | length' <<<"$measurements_json")" \
        --argjson pending_count "$(jq 'map(select(.status == "pending")) | length' <<<"$measurements_json")" \
        --argjson cache_workload_metric_count "$(jq 'length' <<<"$CACHE_WORKLOAD_METRICS_JSON")" \
        '{
            generated_at: $generated_at,
            date_tag: $date_tag,
            commit: $commit,
            branch: $branch,
            environment: {
                cpu_model: $cpu_model,
                kernel: $kernel,
                rustc: $rustc,
                cargo: $cargo,
                hyperfine: $hyperfine
            },
            warmup_runs: $warmup_runs,
            measured_runs: $measured_runs,
            thresholds_file: $thresholds_file,
            p99_warn_threshold_percent: $p99_warn_threshold_percent,
            p99_fail_threshold_percent: $p99_fail_threshold_percent,
            measurement_coverage: {
                measured_count: $measured_count,
                pending_count: $pending_count,
                cache_workload_metric_count: $cache_workload_metric_count
            },
            measurements: $measurements,
            cache_workload_metrics: $cache_workload_metrics
        }' > "$PERF_BASELINE_PATH"

    cp "$PERF_BASELINE_PATH" "$PERF_BASELINE_DATED_PATH"
    cp "$PERF_BASELINE_PATH" "$BENCHMARK_BASELINE_LATEST_PATH"
    cp "$PERF_BASELINE_PATH" "$BENCHMARK_BASELINE_HISTORY_PATH"
    rm -f "$tmp_measurements"
}

cpu_model="$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
if [ -z "${cpu_model}" ]; then
    cpu_model="unknown"
fi

git_sha="$(git rev-parse HEAD)"
git_branch="$(git branch --show-current)"
rustc_ver="$(rustc --version)"
cargo_ver="$(cargo --version)"
hyperfine_ver="$(hyperfine --version)"
kernel_ver="$(uname -srmo)"
date_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
    echo "# FrankenFS Baseline — ${DATE_TAG}"
    echo ""
    echo "## Metadata"
    echo ""
    echo "- Date (UTC): \`${date_iso}\`"
    echo "- Commit: \`${git_sha}\`"
    echo "- Branch: \`${git_branch}\`"
    echo "- Host kernel: \`${kernel_ver}\`"
    echo "- CPU: \`${cpu_model}\`"
    echo "- rustc: \`${rustc_ver}\`"
    echo "- cargo: \`${cargo_ver}\`"
    echo "- hyperfine: \`${hyperfine_ver}\`"
    echo "- Warmup runs: \`${WARMUP}\`"
    echo "- Measured runs: \`${RUNS}\`"
    echo "- Thresholds file: \`${THRESHOLDS_PATH}\`"
    echo "- Warn threshold (default): \`${P99_WARN_THRESHOLD}%\`"
    echo "- Fail threshold (default): \`${P99_FAIL_THRESHOLD}%\`"
    echo ""
    echo "## Preflight Conformance Gate"
    echo ""
    if [ "$VERIFY_GOLDEN" -eq 1 ]; then
        echo "- \`scripts/verify_golden.sh\`: **PASS**"
    else
        echo "- \`scripts/verify_golden.sh\`: SKIPPED (\`--skip-verify-golden\`)"
    fi
    echo ""
    echo "## Commands"
    echo ""
    for i in "${!BENCH_LABELS[@]}"; do
        echo "- \`${BENCH_COMMANDS[$i]}\`"
    done
    if [ "${#CACHE_WORKLOAD_REPORT_PATHS[@]}" -gt 0 ]; then
        echo ""
        echo "### Cache Metrics Reports"
        echo ""
        for i in "${!CACHE_WORKLOAD_REPORT_PATHS[@]}"; do
            echo "- policy \`${CACHE_WORKLOAD_REPORT_POLICIES[$i]}\` -> \`${CACHE_WORKLOAD_REPORT_PATHS[$i]}\`"
        done
    fi
    if [ "${#SKIPPED_LABELS[@]}" -gt 0 ]; then
        echo ""
        echo "### Skipped"
        echo ""
        for skipped in "${SKIPPED_LABELS[@]}"; do
            echo "- ${skipped}"
        done
    fi
    echo ""
    echo "## Hyperfine Summary"
    echo ""
    echo "| Command | Mean (ms) | Stddev (ms) | p50 (ms) | p95 (ms) | p99 (ms) | JSON |"
    echo "|---|---:|---:|---:|---:|---:|---|"
    for i in "${!BENCH_LABELS[@]}"; do
        json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
        mean_s="$(json_mean "$json_file")"
        std_s="$(json_stddev "$json_file")"
        p50_s="$(json_p50 "$json_file")"
        p95_s="$(json_p95 "$json_file")"
        p99_s="$(json_p99 "$json_file")"
        mean_ms="$(sec_to_ms "$mean_s")"
        std_ms="$(sec_to_ms "$std_s")"
        p50_ms="$(sec_to_ms "$p50_s")"
        p95_ms="$(sec_to_ms "$p95_s")"
        p99_ms="$(sec_to_ms "$p99_s")"
        echo "| ${BENCH_LABELS[$i]} | ${mean_ms} | ${std_ms} | ${p50_ms} | ${p95_ms} | ${p99_ms} | \`${json_file}\` |"
    done
    echo ""
    echo "## Cache Workload Metrics (ArcCache::metrics)"
    echo ""
    if [ "$(jq 'length' <<<"$CACHE_WORKLOAD_METRICS_JSON")" -eq 0 ]; then
        echo "No cache workload metrics were captured."
    else
        echo "| Policy | Workload | Accesses | Hit Rate | Memory Overhead / Cached Block | Hits | Misses | Resident | Capacity | Ghost (B1+B2) | Source |"
        echo "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|"
        while IFS=$'\t' read -r policy workload accesses hit_rate overhead hits misses resident capacity ghost source_tsv; do
            echo "| ${policy} | ${workload} | ${accesses} | ${hit_rate} | ${overhead} | ${hits} | ${misses} | ${resident} | ${capacity} | ${ghost} | \`${source_tsv}\` |"
        done < <(
            jq -r '
                .[]
                | [
                    .policy,
                    .workload,
                    .accesses,
                    .hit_rate,
                    .memory_overhead_per_cached_block,
                    .hits,
                    .misses,
                    .resident,
                    .capacity,
                    (.b1_len + .b2_len),
                    .source_tsv
                ]
                | @tsv
            ' <<<"$CACHE_WORKLOAD_METRICS_JSON"
        )
    fi
} > "$REPORT_PATH"

write_perf_baseline_json

COMPARE_STATUS=0
COMPARE_SUMMARY=""
if [ "$COMPARE" -eq 1 ]; then
    if [ -d "baselines/hyperfine" ]; then
        previous_tag="$(find baselines/hyperfine -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | grep -v "^${DATE_TAG}\$" | tail -n1 || true)"
    else
        previous_tag=""
    fi

    if [ -n "$previous_tag" ]; then
        previous_dir="baselines/hyperfine/${previous_tag}"
        COMPARE_SUMMARY+="## Regression Check (vs ${previous_tag})"$'\n\n'
        COMPARE_SUMMARY+="Threshold defaults: warn if p99 regresses >${P99_WARN_THRESHOLD}%; fail if >${P99_FAIL_THRESHOLD}%."$'\n\n'
        COMPARE_SUMMARY+="| Command | Baseline p99 (ms) | Current p99 (ms) | Delta % | Warn % | Fail % | Status |"$'\n'
        COMPARE_SUMMARY+="|---|---:|---:|---:|---:|---:|---|"$'\n'

        for i in "${!BENCH_LABELS[@]}"; do
            cur_json="${OUT_DIR}/${BENCH_FILES[$i]}"
            prev_json="${previous_dir}/${BENCH_FILES[$i]}"
            op="${BENCH_OPERATIONS[$i]}"
            warn_threshold="${OP_WARN_THRESHOLDS[$op]:-$P99_WARN_THRESHOLD}"
            fail_threshold="${OP_FAIL_THRESHOLDS[$op]:-$P99_FAIL_THRESHOLD}"
            if [ ! -f "$prev_json" ]; then
                COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | n/a | n/a | n/a | ${warn_threshold} | ${fail_threshold} | SKIP (no prior file) |"$'\n'
                continue
            fi

            cur_p99_s="$(json_p99 "$cur_json" 2>/dev/null || true)"
            prev_p99_s="$(json_p99 "$prev_json" 2>/dev/null || true)"
            if [ -z "$cur_p99_s" ] || [ -z "$prev_p99_s" ] || ! valid_number "$cur_p99_s" || ! valid_number "$prev_p99_s"; then
                COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | n/a | n/a | n/a | ${warn_threshold} | ${fail_threshold} | SKIP (invalid hyperfine JSON) |"$'\n'
                continue
            fi
            if awk -v base="$prev_p99_s" 'BEGIN { exit !(base <= 0.0) }'; then
                COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | n/a | n/a | n/a | ${warn_threshold} | ${fail_threshold} | SKIP (baseline p99 <= 0) |"$'\n'
                continue
            fi

            cur_p99_ms="$(sec_to_ms "$cur_p99_s")"
            prev_p99_ms="$(sec_to_ms "$prev_p99_s")"
            delta_pct="$(pct_change "$prev_p99_s" "$cur_p99_s")"

            status="OK"
            if awk -v d="$delta_pct" -v threshold="$fail_threshold" 'BEGIN { exit !(d > threshold) }'; then
                status="FAIL"
                COMPARE_STATUS=1
            elif awk -v d="$delta_pct" -v threshold="$warn_threshold" 'BEGIN { exit !(d > threshold) }'; then
                status="WARN"
            fi
            COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | ${prev_p99_ms} | ${cur_p99_ms} | ${delta_pct}% | ${warn_threshold} | ${fail_threshold} | ${status} |"$'\n'
        done
    else
        COMPARE_SUMMARY+="## Regression Check"$'\n\n'
        COMPARE_SUMMARY+="No prior baseline directory found under \`baselines/hyperfine/\`; compare skipped."$'\n'
    fi

    {
        echo ""
        echo "${COMPARE_SUMMARY}"
    } >> "$REPORT_PATH"
fi

echo "Wrote baseline report: ${REPORT_PATH}"
echo "Wrote structured baseline JSON: ${PERF_BASELINE_PATH}"
echo "Wrote dated structured baseline JSON: ${PERF_BASELINE_DATED_PATH}"
echo "Wrote baseline latest JSON: ${BENCHMARK_BASELINE_LATEST_PATH}"
echo "Wrote baseline history JSON: ${BENCHMARK_BASELINE_HISTORY_PATH}"
echo "Wrote hyperfine exports:"
for i in "${!BENCH_LABELS[@]}"; do
    echo "  - ${OUT_DIR}/${BENCH_FILES[$i]}"
done
if [ "${#CACHE_WORKLOAD_REPORT_PATHS[@]}" -gt 0 ]; then
    echo "Wrote cache workload metric reports:"
    for report_path in "${CACHE_WORKLOAD_REPORT_PATHS[@]}"; do
        echo "  - ${report_path}"
    done
fi
if [ "${#SKIPPED_LABELS[@]}" -gt 0 ]; then
    echo "Skipped commands:"
    for skipped in "${SKIPPED_LABELS[@]}"; do
        echo "  - ${skipped}"
    done
fi

if [ "$COMPARE" -eq 1 ]; then
    echo ""
    echo "Regression check summary:"
    echo "${COMPARE_SUMMARY}"
fi

exit "$COMPARE_STATUS"
