#!/usr/bin/env bash
# ffs_xfstests_e2e.sh - xfstests subset planning/execution for FrankenFS
#
# This suite tracks a curated generic/ext4 subset for FrankenFS and can:
# - plan mode: validate list files + emit subset artifacts
# - run mode: invoke xfstests `check` against the selected subset
#
# Defaults are intentionally CI-safe:
# - `XFSTESTS_MODE=auto` resolves to plan mode unless a usable xfstests tree is found.
# - `XFSTESTS_STRICT=0` causes missing prerequisites to skip (exit 0) with artifacts.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

e2e_init "ffs_xfstests_e2e"
e2e_print_env

XFSTESTS_MODE="${XFSTESTS_MODE:-auto}"        # auto | plan | run
XFSTESTS_STRICT="${XFSTESTS_STRICT:-0}"       # 0 | 1
XFSTESTS_DRY_RUN="${XFSTESTS_DRY_RUN:-1}"     # 0 | 1 (run mode only)
XFSTESTS_FILTER="${XFSTESTS_FILTER:-all}"     # all | generic | ext4
XFSTESTS_DIR="${XFSTESTS_DIR:-}"
XFSTESTS_GENERIC_LIST="${XFSTESTS_GENERIC_LIST:-$REPO_ROOT/scripts/e2e/xfstests_generic.list}"
XFSTESTS_EXT4_LIST="${XFSTESTS_EXT4_LIST:-$REPO_ROOT/scripts/e2e/xfstests_ext4.list}"

ARTIFACT_DIR="$E2E_LOG_DIR/xfstests"
SELECTED_FILE="$ARTIFACT_DIR/selected_tests.txt"
SUMMARY_JSON="$ARTIFACT_DIR/summary.json"
CHECK_LOG="$ARTIFACT_DIR/check.log"
mkdir -p "$ARTIFACT_DIR"

declare -a GENERIC_TESTS=()
declare -a EXT4_TESTS=()
declare -a SELECTED_TESTS=()

resolve_xfstests_dir() {
    if [[ -n "$XFSTESTS_DIR" ]]; then
        return 0
    fi

    local candidate
    for candidate in \
        "$REPO_ROOT/third_party/xfstests-dev" \
        "/opt/xfstests-dev" \
        "$HOME/src/xfstests-dev"; do
        if [[ -x "$candidate/check" ]]; then
            XFSTESTS_DIR="$candidate"
            return 0
        fi
    done
}

write_summary() {
    local status="$1"
    local mode="$2"
    local reason="${3:-}"
    local safe_reason="${reason//\"/\\\"}"
    local safe_dir="${XFSTESTS_DIR//\"/\\\"}"

    cat >"$SUMMARY_JSON" <<EOF
{
  "status": "$status",
  "mode": "$mode",
  "filter": "$XFSTESTS_FILTER",
  "dry_run": $XFSTESTS_DRY_RUN,
  "strict": $XFSTESTS_STRICT,
  "xfstests_dir": "$safe_dir",
  "generic_count": ${#GENERIC_TESTS[@]},
  "ext4_count": ${#EXT4_TESTS[@]},
  "selected_count": ${#SELECTED_TESTS[@]},
  "reason": "$safe_reason"
}
EOF
}

skip_or_fail() {
    local reason="$1"
    write_summary "skipped" "$EFFECTIVE_MODE" "$reason"
    if [[ "$XFSTESTS_STRICT" == "1" ]]; then
        e2e_fail "$reason"
    fi
    e2e_skip "$reason"
}

load_test_list() {
    local list_path="$1"
    local kind="$2"
    local -n output_ref="$3"

    if [[ ! -f "$list_path" ]]; then
        e2e_fail "Test list not found: $list_path"
    fi

    mapfile -t output_ref < <(awk '{
        line = $0
        sub(/#.*/, "", line)
        gsub(/^[ \t]+|[ \t]+$/, "", line)
        if (line != "") print line
    }' "$list_path")

    if [[ ${#output_ref[@]} -eq 0 ]]; then
        e2e_fail "Test list is empty: $list_path"
    fi

    local test_id
    for test_id in "${output_ref[@]}"; do
        if [[ ! "$test_id" =~ ^${kind}/[0-9]{3}$ ]]; then
            e2e_fail "Invalid test id '$test_id' in $list_path (expected ${kind}/NNN)"
        fi
    done
}

build_selection() {
    local -a raw_selection=()
    case "$XFSTESTS_FILTER" in
        all)
            raw_selection=("${GENERIC_TESTS[@]}" "${EXT4_TESTS[@]}")
            ;;
        generic)
            raw_selection=("${GENERIC_TESTS[@]}")
            ;;
        ext4)
            raw_selection=("${EXT4_TESTS[@]}")
            ;;
        *)
            e2e_fail "Invalid XFSTESTS_FILTER='$XFSTESTS_FILTER' (expected all|generic|ext4)"
            ;;
    esac

    declare -A seen=()
    local test_id
    for test_id in "${raw_selection[@]}"; do
        if [[ -z "${seen[$test_id]+x}" ]]; then
            seen[$test_id]=1
            SELECTED_TESTS+=("$test_id")
        fi
    done

    if [[ ${#SELECTED_TESTS[@]} -eq 0 ]]; then
        e2e_fail "No tests selected after applying filter '$XFSTESTS_FILTER'"
    fi
}

verify_tests_exist() {
    local -a missing=()
    local test_id
    for test_id in "${SELECTED_TESTS[@]}"; do
        if [[ ! -f "$XFSTESTS_DIR/tests/$test_id" ]]; then
            missing+=("$test_id")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        e2e_log "Missing tests in $XFSTESTS_DIR/tests:"
        printf '%s\n' "${missing[@]}" | while IFS= read -r line; do
            e2e_log "  $line"
        done
        e2e_fail "Selected xfstests ids missing from xfstests checkout"
    fi
}

run_xfstests_subset() {
    local -a check_args=()
    if [[ "$XFSTESTS_DRY_RUN" == "1" ]]; then
        check_args+=("-n")
    fi
    check_args+=("${SELECTED_TESTS[@]}")

    e2e_log "Running xfstests command from $XFSTESTS_DIR:"
    e2e_log "  ./check ${check_args[*]}"

    local rc=0
    (cd "$XFSTESTS_DIR" && ./check "${check_args[@]}") >"$CHECK_LOG" 2>&1 || rc=$?

    if [[ $rc -ne 0 ]]; then
        if grep -qiE "not found or executable|must be run as root|Permission denied" "$CHECK_LOG"; then
            skip_or_fail "xfstests prerequisites unavailable for execution (see $CHECK_LOG)"
        fi
        e2e_log "xfstests check failed; tailing log:"
        e2e_run tail -n 120 "$CHECK_LOG" || true
        e2e_fail "xfstests check failed with exit code $rc"
    fi

    e2e_log "xfstests check completed successfully"
}

e2e_step "Load curated xfstests subsets"
load_test_list "$XFSTESTS_GENERIC_LIST" "generic" GENERIC_TESTS
load_test_list "$XFSTESTS_EXT4_LIST" "ext4" EXT4_TESTS
build_selection

printf '%s\n' "${SELECTED_TESTS[@]}" >"$SELECTED_FILE"
e2e_log "Selected tests written to: $SELECTED_FILE"
e2e_log "Selected test count: ${#SELECTED_TESTS[@]}"

resolve_xfstests_dir
EFFECTIVE_MODE="$XFSTESTS_MODE"
if [[ "$EFFECTIVE_MODE" == "auto" ]]; then
    if [[ -n "$XFSTESTS_DIR" ]] && [[ -x "$XFSTESTS_DIR/check" ]]; then
        EFFECTIVE_MODE="run"
    else
        EFFECTIVE_MODE="plan"
    fi
fi

if [[ "$EFFECTIVE_MODE" == "plan" ]]; then
    e2e_step "Plan mode"
    write_summary "planned" "$EFFECTIVE_MODE" "subset materialized; execution not requested"
    e2e_log "Plan summary: $SUMMARY_JSON"
    e2e_pass
    exit 0
fi

if [[ "$EFFECTIVE_MODE" != "run" ]]; then
    e2e_fail "Invalid XFSTESTS_MODE='$XFSTESTS_MODE' (expected auto|plan|run)"
fi

if [[ -z "$XFSTESTS_DIR" ]]; then
    skip_or_fail "XFSTESTS_DIR is not set and no default xfstests checkout was found"
fi
if [[ ! -x "$XFSTESTS_DIR/check" ]]; then
    skip_or_fail "xfstests check runner not found at $XFSTESTS_DIR/check"
fi

e2e_step "Run xfstests subset"
e2e_log "XFSTESTS_DIR: $XFSTESTS_DIR"
e2e_log "XFSTESTS_DRY_RUN: $XFSTESTS_DRY_RUN"
verify_tests_exist
run_xfstests_subset

write_summary "passed" "$EFFECTIVE_MODE" "xfstests subset check completed"
e2e_log "Run summary: $SUMMARY_JSON"
e2e_pass
exit 0
