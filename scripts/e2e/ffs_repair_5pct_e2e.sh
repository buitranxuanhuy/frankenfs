#!/usr/bin/env bash
# ffs_repair_5pct_e2e.sh - Deterministic 5% corruption auto-repair E2E
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

source "$REPO_ROOT/scripts/e2e/lib.sh"

e2e_init "ffs_repair_5pct_e2e"
e2e_print_env

e2e_step "Run 5% corruption auto-repair scenario"
ARTIFACT_DIR="$E2E_LOG_DIR/repair_5pct"
mkdir -p "$ARTIFACT_DIR"

# Keep this runner isolated from other in-flight cargo jobs.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target-codex-ruby}"
export FFS_REPAIR_E2E_ARTIFACT_DIR="$ARTIFACT_DIR"

e2e_assert cargo test -p ffs-repair e2e_survive_five_percent_random_block_corruption_with_daemon -- --nocapture

e2e_step "Validate generated artifacts"
e2e_assert_file "$ARTIFACT_DIR/before_checksums.txt"
e2e_assert_file "$ARTIFACT_DIR/after_checksums.txt"
e2e_assert_file "$ARTIFACT_DIR/corruption_plan.json"
e2e_assert_file "$ARTIFACT_DIR/recovery_evidence.jsonl"

# End-to-end guarantee: recovered content must exactly match baseline.
e2e_assert cmp "$ARTIFACT_DIR/before_checksums.txt" "$ARTIFACT_DIR/after_checksums.txt"

if command -v python3 >/dev/null 2>&1; then
    e2e_assert python3 -c "import json, pathlib; p = pathlib.Path('$ARTIFACT_DIR/corruption_plan.json'); d = json.loads(p.read_text()); assert d['corruption_percent'] == 5; assert d['total_corrupted_blocks'] > 0"
fi

e2e_run wc -l "$ARTIFACT_DIR/recovery_evidence.jsonl"

e2e_pass
