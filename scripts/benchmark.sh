#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

REF_IMAGE="conformance/golden/ext4_8mb_reference.ext4"

echo "=== FrankenFS Benchmark Suite ==="
echo ""

# Build release binary once so hyperfine measures only runtime.
cargo build -p ffs-cli --release --quiet 2>/dev/null
cargo build -p ffs-harness --release --quiet 2>/dev/null

# ── 1. CLI command latency (release binary) ─────────────────────────────────
echo "--- CLI command latency (hyperfine, release) ---"

if [ -f "$REF_IMAGE" ]; then
    hyperfine --warmup 3 --runs 10 \
        "cargo run -p ffs-cli --release -q -- inspect $REF_IMAGE --json" \
        "cargo run -p ffs-cli --release -q -- scrub $REF_IMAGE --json"
else
    echo "SKIP: $REF_IMAGE not found (run kernel_reference tests to generate)"
fi

hyperfine --warmup 3 --runs 10 \
    "cargo run -p ffs-cli --release -q -- parity --json"

# ── 2. Harness command latency ──────────────────────────────────────────────
echo ""
echo "--- Harness command latency ---"
hyperfine --warmup 3 --runs 10 \
    "cargo run -p ffs-harness --release -q -- parity" \
    "cargo run -p ffs-harness --release -q -- check-fixtures"

# ── 3. Criterion microbenchmarks ────────────────────────────────────────────
echo ""
echo "--- Criterion: metadata_parse ---"
cargo bench -p ffs-harness --bench metadata_parse

echo ""
echo "--- Criterion: ondisk_parse ---"
cargo bench -p ffs-harness --bench ondisk_parse

echo ""
echo "--- Criterion: writeback fsync latency ---"
cargo bench -p ffs-block --bench arc_cache -- writeback_sync_

echo ""
echo "=== Benchmark suite complete ==="
