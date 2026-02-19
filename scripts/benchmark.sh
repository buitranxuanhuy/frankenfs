#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

REF_IMAGE="conformance/golden/ext4_8mb_reference.ext4"
WARMUP=3
RUNS=10
USE_RCH=1

usage() {
    cat <<'USAGE'
Usage:
  scripts/benchmark.sh [--warmup N] [--runs N] [--local|--rch]

Options:
  --warmup N   Hyperfine warmup runs (default: 3)
  --runs N     Hyperfine measured runs (default: 10)
  --local      Run cargo commands locally (default is rch offload mode)
  --rch        Force rch offload mode (default)
  -h, --help   Show this help
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
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
        --local)
            USE_RCH=0
            shift
            ;;
        --rch)
            USE_RCH=1
            shift
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

cargo_exec() {
    if [ "$USE_RCH" -eq 1 ]; then
        if command -v rch >/dev/null 2>&1; then
            rch exec -- cargo "$@"
        else
            echo "warning: rch not found; falling back to local cargo" >&2
            cargo "$@"
        fi
    else
        cargo "$@"
    fi
}

quote_cmd() {
    local out=""
    local arg
    for arg in "$@"; do
        if [ -n "$out" ]; then
            out+=" "
        fi
        out+="$(printf '%q' "$arg")"
    done
    printf '%s\n' "$out"
}

echo "=== FrankenFS Benchmark Suite ==="
echo ""
if [ "$USE_RCH" -eq 1 ]; then
    echo "Cargo mode: rch offload (rch exec -- cargo)"
else
    echo "Cargo mode: local cargo"
fi
echo ""

# Build release binary once so hyperfine measures only runtime.
cargo_exec build -p ffs-cli --release --quiet
cargo_exec build -p ffs-harness --release --quiet

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    TARGET_DIR="${CARGO_TARGET_DIR}"
else
    TARGET_DIR="$(cargo metadata --format-version=1 --no-deps | jq -r '.target_directory')"
fi

CLI_BIN="${TARGET_DIR}/release/ffs-cli"
HARNESS_BIN="${TARGET_DIR}/release/ffs-harness"
if [ ! -x "$CLI_BIN" ] || [ ! -x "$HARNESS_BIN" ]; then
    if [ -x "target/release/ffs-cli" ] && [ -x "target/release/ffs-harness" ]; then
        TARGET_DIR="target"
        CLI_BIN="target/release/ffs-cli"
        HARNESS_BIN="target/release/ffs-harness"
        echo "warning: using fallback local binaries under target/release" >&2
    else
        echo "error: missing release binaries after build: $CLI_BIN and/or $HARNESS_BIN" >&2
        exit 1
    fi
fi

CLI_INSPECT_CMD="$(quote_cmd "$CLI_BIN" inspect "$REF_IMAGE" --json)"
CLI_SCRUB_CMD="$(quote_cmd "$CLI_BIN" scrub "$REF_IMAGE" --json)"
CLI_PARITY_CMD="$(quote_cmd "$CLI_BIN" parity --json)"
HARNESS_PARITY_CMD="$(quote_cmd "$HARNESS_BIN" parity)"
HARNESS_CHECK_CMD="$(quote_cmd "$HARNESS_BIN" check-fixtures)"

# ── 1. CLI command latency (release binary) ─────────────────────────────────
echo "--- CLI command latency (hyperfine, release) ---"

if [ -f "$REF_IMAGE" ]; then
    hyperfine --warmup "$WARMUP" --runs "$RUNS" \
        "$CLI_INSPECT_CMD" \
        "$CLI_SCRUB_CMD"
else
    echo "SKIP: $REF_IMAGE not found (run kernel_reference tests to generate)"
fi

hyperfine --warmup "$WARMUP" --runs "$RUNS" \
    "$CLI_PARITY_CMD"

# ── 2. Harness command latency ──────────────────────────────────────────────
echo ""
echo "--- Harness command latency ---"
hyperfine --warmup "$WARMUP" --runs "$RUNS" \
    "$HARNESS_PARITY_CMD" \
    "$HARNESS_CHECK_CMD"

# ── 3. Criterion microbenchmarks ────────────────────────────────────────────
echo ""
echo "--- Criterion: metadata_parse ---"
cargo_exec bench -p ffs-harness --bench metadata_parse

echo ""
echo "--- Criterion: ondisk_parse ---"
cargo_exec bench -p ffs-harness --bench ondisk_parse

echo ""
echo "--- Criterion: writeback fsync latency ---"
cargo_exec bench -p ffs-block --bench arc_cache -- writeback_sync_

echo ""
echo "=== Benchmark suite complete ==="
