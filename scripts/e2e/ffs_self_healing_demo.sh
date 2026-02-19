#!/usr/bin/env bash
# ffs_self_healing_demo.sh - E2E test: self-healing demo runs and produces correct output
#
# Validates:
#   1. Demo runs successfully (exit code 0)
#   2. Structured output lines present (6 lines: start, created, injected, repaired, verified, PASS)
#   3. Zero data loss: corrupted_blocks == repaired_blocks
#   4. Evidence ledger integration (write + parse round-trip)
#   5. Completes within 30 seconds
#   6. Deterministic with fixed seed
#
# Usage:
#   ./scripts/e2e/ffs_self_healing_demo.sh [--rch]

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target-codex-ruby}"

USE_RCH=false
for arg in "$@"; do
    case "$arg" in
        --rch) USE_RCH=true ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

CARGO_CMD="cargo"
if $USE_RCH; then
    if ! command -v rch >/dev/null 2>&1; then
        e2e_skip "rch not found; pass --rch only when rch is available"
    fi
    CARGO_CMD="rch exec -- cargo"
fi

e2e_init "ffs_self_healing_demo"
e2e_print_env

# ── Phase 1: prerequisites ───────────────────────────────────────────────────

e2e_step "Phase 1: prerequisites"

# Verify the demo test exists
DEMO_TEST_FILE="$REPO_ROOT/crates/ffs-repair/tests/self_healing_demo_e2e.rs"
e2e_assert_file "$DEMO_TEST_FILE"

# Verify the demo module exists
DEMO_MODULE="$REPO_ROOT/crates/ffs-repair/src/demo.rs"
e2e_assert_file "$DEMO_MODULE"

# ── Phase 2: run self-healing demo E2E tests ─────────────────────────────────

e2e_step "Phase 2: run self-healing demo E2E test suite"

e2e_assert $CARGO_CMD test -p ffs-repair --test self_healing_demo_e2e -- --nocapture

# ── Phase 3: verify single-command binary path ───────────────────────────────

e2e_step "Phase 3: verify ffs-demo binary command"

e2e_assert $CARGO_CMD run -p ffs-repair --bin ffs-demo -- self-healing

# ── Phase 4: run existing unit-level demo test ───────────────────────────────

e2e_step "Phase 4: run demo unit test"

e2e_assert $CARGO_CMD test -p ffs-repair demo::tests::demo_output_has_expected_shape -- --nocapture

# ── Phase 5: run basic integration test ──────────────────────────────────────

e2e_step "Phase 5: run basic integration test"

e2e_assert $CARGO_CMD test -p ffs-repair --test self_heal_demo -- --nocapture

# ── Phase 6: summary ────────────────────────────────────────────────────────

e2e_step "Phase 6: summary"
e2e_log "All self-healing demo E2E tests passed:"
e2e_log "  - Output structure: 6 structured lines with expected prefixes"
e2e_log "  - Zero data loss: corrupted_blocks == repaired_blocks (2% and 5%)"
e2e_log "  - Timing: completes within 30 seconds"
e2e_log "  - Determinism: fixed seed produces identical results"
e2e_log "  - Evidence ledger: corruption/repair lifecycle captured and parsed"
e2e_log "  - Metrics parsing: output lines contain expected config values"

e2e_pass
