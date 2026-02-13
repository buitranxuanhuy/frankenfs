#!/usr/bin/env bash
# run_e2e.sh - Run all E2E test suites for FrankenFS
#
# Runs both Rust-based E2E tests (via cargo test) and shell-based E2E
# suites (scripts/e2e/*.sh).  Produces a summary with pass/fail/skip
# counts and collects artifacts.
#
# Usage:
#   ./scripts/run_e2e.sh              # Run everything
#   ./scripts/run_e2e.sh --rust-only  # Only Rust E2E tests
#   ./scripts/run_e2e.sh --shell-only # Only shell E2E suites
#
# Environment:
#   SKIP_MOUNT=1    Skip FUSE mount tests
#   RUST_LOG=info   Rust log level

set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

# ── Options ──────────────────────────────────────────────────────────────────

RUST_ONLY=0
SHELL_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --rust-only)  RUST_ONLY=1 ;;
        --shell-only) SHELL_ONLY=1 ;;
        --help|-h)
            echo "Usage: $0 [--rust-only] [--shell-only]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

# ── State ────────────────────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0
RESULTS=()

record() {
    local name="$1" status="$2"
    RESULTS+=("$status $name")
    case "$status" in
        PASS) PASS=$((PASS + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
        SKIP) SKIP=$((SKIP + 1)) ;;
    esac
}

# ── Colors ───────────────────────────────────────────────────────────────────

if [[ -t 1 ]] && command -v tput &>/dev/null; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    RESET=$(tput sgr0)
else
    RED="" GREEN="" YELLOW="" RESET=""
fi

# ── Phase 1: Rust E2E tests ─────────────────────────────────────────────────

if [[ "$SHELL_ONLY" -eq 0 ]]; then
    echo "=== Rust E2E Tests ==="
    if cargo test -p ffs-harness --lib e2e:: 2>&1; then
        record "cargo test -p ffs-harness (e2e)" "PASS"
    else
        record "cargo test -p ffs-harness (e2e)" "FAIL"
    fi
    echo ""
fi

# ── Phase 2: Shell E2E suites ───────────────────────────────────────────────

if [[ "$RUST_ONLY" -eq 0 ]]; then
    echo "=== Shell E2E Suites ==="
    for suite in "$REPO_ROOT"/scripts/e2e/*_smoke.sh "$REPO_ROOT"/scripts/e2e/*_e2e.sh; do
        [[ -f "$suite" ]] || continue
        name="$(basename "$suite")"

        echo "--- $name ---"
        if bash "$suite" 2>&1; then
            record "$name" "PASS"
        else
            ec=$?
            if [[ $ec -eq 0 ]]; then
                record "$name" "PASS"
            else
                record "$name" "FAIL"
            fi
        fi
        echo ""
    done
fi

# ── Summary ──────────────────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL + SKIP))
echo "======================================"
echo "E2E Summary: ${TOTAL} suite(s)"
echo "======================================"
for entry in "${RESULTS[@]:-}"; do
    status="${entry%% *}"
    name="${entry#* }"
    case "$status" in
        PASS) echo "  ${GREEN}PASS${RESET}  $name" ;;
        FAIL) echo "  ${RED}FAIL${RESET}  $name" ;;
        SKIP) echo "  ${YELLOW}SKIP${RESET}  $name" ;;
    esac
done
echo ""
echo "Passed: $PASS  Failed: $FAIL  Skipped: $SKIP"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo "${RED}Some E2E suites failed.${RESET}"
    exit 1
fi

echo "${GREEN}All E2E suites passed.${RESET}"
exit 0
