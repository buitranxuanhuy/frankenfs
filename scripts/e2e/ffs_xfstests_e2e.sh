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
XFSTESTS_REGRESSION_GUARD_JSON="${XFSTESTS_REGRESSION_GUARD_JSON:-$REPO_ROOT/scripts/e2e/xfstests_regression_guard.json}"

ARTIFACT_DIR="$E2E_LOG_DIR/xfstests"
SELECTED_FILE="$ARTIFACT_DIR/selected_tests.txt"
SUMMARY_JSON="$ARTIFACT_DIR/summary.json"
RESULTS_JSON="$ARTIFACT_DIR/results.json"
JUNIT_FILE="$ARTIFACT_DIR/junit.xml"
CHECK_LOG="$ARTIFACT_DIR/check.log"
mkdir -p "$ARTIFACT_DIR"

declare -a GENERIC_TESTS=()
declare -a EXT4_TESTS=()
declare -a SELECTED_TESTS=()
EFFECTIVE_MODE="$XFSTESTS_MODE"
LAST_CHECK_RC="null"

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
    local check_rc="${4:-null}"
    local safe_reason="${reason//\"/\\\"}"
    local safe_dir="${XFSTESTS_DIR//\"/\\\"}"
    local safe_guard="${XFSTESTS_REGRESSION_GUARD_JSON//\"/\\\"}"
    local safe_results="${RESULTS_JSON//\"/\\\"}"
    local safe_junit="${JUNIT_FILE//\"/\\\"}"
    local safe_selected="${SELECTED_FILE//\"/\\\"}"

    cat >"$SUMMARY_JSON" <<EOF
{
  "status": "$status",
  "mode": "$mode",
  "filter": "$XFSTESTS_FILTER",
  "dry_run": $XFSTESTS_DRY_RUN,
  "strict": $XFSTESTS_STRICT,
  "check_rc": $check_rc,
  "xfstests_dir": "$safe_dir",
  "regression_guard_json": "$safe_guard",
  "selected_file": "$safe_selected",
  "results_json": "$safe_results",
  "junit_xml": "$safe_junit",
  "generic_count": ${#GENERIC_TESTS[@]},
  "ext4_count": ${#EXT4_TESTS[@]},
  "selected_count": ${#SELECTED_TESTS[@]},
  "reason": "$safe_reason"
}
EOF
}

write_uniform_results() {
    local status="$1"
    local note="${2:-}"
    local note_safe="${note//\"/\\\"}"

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$SELECTED_FILE" "$RESULTS_JSON" "$JUNIT_FILE" "$status" "$note_safe" <<'PY'
import json
import pathlib
import sys
import xml.sax.saxutils

selected_file = pathlib.Path(sys.argv[1])
results_json = pathlib.Path(sys.argv[2])
junit_xml = pathlib.Path(sys.argv[3])
status = sys.argv[4]
note = sys.argv[5]

selected = [line.strip() for line in selected_file.read_text(encoding="utf-8").splitlines() if line.strip()]
tests = [{"id": tid, "status": status} for tid in selected]

counts = {"passed": 0, "failed": 0, "skipped": 0, "not_run": 0, "planned": 0}
if status in counts:
    counts[status] = len(selected)
else:
    counts["not_run"] = len(selected)

pass_rate = 0.0
if selected and counts["passed"] > 0:
    pass_rate = counts["passed"] / len(selected)

payload = {
    "source": "uniform",
    "status": status,
    "note": note,
    "total": len(selected),
    "passed": counts["passed"],
    "failed": counts["failed"],
    "skipped": counts["skipped"],
    "not_run": counts["not_run"],
    "planned": counts["planned"],
    "pass_rate": pass_rate,
    "tests": tests,
}
results_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with junit_xml.open("w", encoding="utf-8") as fh:
    failures = counts["failed"]
    skipped = counts["skipped"] + counts["not_run"] + counts["planned"]
    fh.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fh.write(f'<testsuite name="ffs_xfstests_e2e" tests="{len(selected)}" failures="{failures}" skipped="{skipped}">\n')
    for tid in selected:
        esc = xml.sax.saxutils.escape(tid, {'"': "&quot;", "'": "&apos;"})
        fh.write(f'  <testcase name="{esc}" time="0.000">')
        if status == "failed":
            msg = xml.sax.saxutils.escape(note or "failed", {'"': "&quot;", "'": "&apos;"})
            fh.write(f'<failure message="{msg}">{msg}</failure>')
        elif status in {"skipped", "not_run", "planned"}:
            msg = xml.sax.saxutils.escape(note or status, {'"': "&quot;", "'": "&apos;"})
            fh.write(f'<skipped message="{msg}"/>')
        fh.write("</testcase>\n")
    fh.write("</testsuite>\n")
PY
        return 0
    fi

    # Fallback without python3: write minimal JSON and omit JUnit.
    cat >"$RESULTS_JSON" <<EOF
{
  "source": "uniform",
  "status": "$status",
  "note": "$note_safe",
  "total": ${#SELECTED_TESTS[@]},
  "passed": 0,
  "failed": 0,
  "skipped": 0,
  "not_run": ${#SELECTED_TESTS[@]},
  "planned": 0,
  "pass_rate": 0.0,
  "tests": []
}
EOF
}

skip_or_fail() {
    local reason="$1"
    if [[ ! -f "$RESULTS_JSON" ]]; then
        write_uniform_results "not_run" "$reason"
    fi
    write_summary "skipped" "$EFFECTIVE_MODE" "$reason" "$LAST_CHECK_RC"
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

generate_results_from_check_log() {
    local check_rc="$1"
    LAST_CHECK_RC="$check_rc"

    if ! command -v python3 >/dev/null 2>&1; then
        e2e_log "python3 not found; writing fallback not_run result artifacts"
        write_uniform_results "not_run" "python3 unavailable; unable to parse check output"
        return 0
    fi

    python3 - "$SELECTED_FILE" "$CHECK_LOG" "$RESULTS_JSON" "$JUNIT_FILE" "$check_rc" "$XFSTESTS_DRY_RUN" <<'PY'
import json
import pathlib
import re
import sys
import xml.sax.saxutils

selected_file = pathlib.Path(sys.argv[1])
check_log = pathlib.Path(sys.argv[2])
results_json = pathlib.Path(sys.argv[3])
junit_xml = pathlib.Path(sys.argv[4])
check_rc = int(sys.argv[5])
dry_run = int(sys.argv[6])

selected = [line.strip() for line in selected_file.read_text(encoding="utf-8").splitlines() if line.strip()]
status = {tid: "not_run" for tid in selected}
rank = {"not_run": 1, "planned": 1, "skipped": 2, "passed": 3, "failed": 4}

if check_log.exists():
    for line in check_log.read_text(encoding="utf-8", errors="replace").splitlines():
        low = line.lower()
        for tid in selected:
            if tid not in line:
                continue
            candidate = None
            if "not run" in low or "notrun" in low or "skipped" in low:
                candidate = "skipped"
            elif re.search(r"\b(fail|failed|error)\b", low):
                candidate = "failed"
            elif re.search(r"\b(pass|passed|ok|success)\b", low):
                candidate = "passed"
            if candidate and rank[candidate] >= rank[status[tid]]:
                status[tid] = candidate

if check_rc == 0 and dry_run == 0:
    for tid, current in status.items():
        if current == "not_run":
            status[tid] = "passed"

tests = [{"id": tid, "status": status[tid]} for tid in selected]
counts = {"passed": 0, "failed": 0, "skipped": 0, "not_run": 0, "planned": 0}
for rec in tests:
    key = rec["status"]
    counts[key] = counts.get(key, 0) + 1

total = len(selected)
pass_rate = (counts["passed"] / total) if total else 0.0

payload = {
    "source": "check-log",
    "check_rc": check_rc,
    "dry_run": dry_run,
    "total": total,
    "passed": counts["passed"],
    "failed": counts["failed"],
    "skipped": counts["skipped"],
    "not_run": counts["not_run"],
    "planned": counts["planned"],
    "pass_rate": pass_rate,
    "tests": tests,
}
results_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with junit_xml.open("w", encoding="utf-8") as fh:
    failures = counts["failed"]
    skipped = counts["skipped"] + counts["not_run"] + counts["planned"]
    fh.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fh.write(f'<testsuite name="ffs_xfstests_e2e" tests="{total}" failures="{failures}" skipped="{skipped}">\n')
    for rec in tests:
        tid = xml.sax.saxutils.escape(rec["id"], {'"': "&quot;", "'": "&apos;"})
        test_status = rec["status"]
        fh.write(f'  <testcase name="{tid}" time="0.000">')
        if test_status == "failed":
            fh.write('<failure message="xfstests failure">xfstests failure</failure>')
        elif test_status in {"skipped", "not_run", "planned"}:
            msg = xml.sax.saxutils.escape(test_status, {'"': "&quot;", "'": "&apos;"})
            fh.write(f'<skipped message="{msg}"/>')
        fh.write("</testcase>\n")
    fh.write("</testsuite>\n")
PY
}

enforce_regression_guard() {
    if [[ "$XFSTESTS_DRY_RUN" == "1" ]]; then
        e2e_log "Skipping regression guard in dry-run mode"
        return 0
    fi

    if [[ ! -f "$XFSTESTS_REGRESSION_GUARD_JSON" ]]; then
        e2e_log "Regression guard file not found; skipping guard: $XFSTESTS_REGRESSION_GUARD_JSON"
        return 0
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        if [[ "$XFSTESTS_STRICT" == "1" ]]; then
            e2e_fail "python3 is required to enforce xfstests regression guard in strict mode"
        fi
        e2e_log "python3 not found; skipping regression guard"
        return 0
    fi

    if ! python3 - "$RESULTS_JSON" "$XFSTESTS_REGRESSION_GUARD_JSON" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
guard_path = pathlib.Path(sys.argv[2])
results = json.loads(results_path.read_text(encoding="utf-8"))
guard = json.loads(guard_path.read_text(encoding="utf-8"))

status_by_test = {rec.get("id"): rec.get("status") for rec in results.get("tests", [])}
passed = int(results.get("passed", 0))
pass_rate = float(results.get("pass_rate", 0.0))

must_pass = [t for t in guard.get("must_pass", []) if isinstance(t, str)]
min_pass_count = int(guard.get("min_pass_count", 0))
min_pass_rate = float(guard.get("min_pass_rate", 0.0))

failures = []
for tid in must_pass:
    if status_by_test.get(tid) != "passed":
        failures.append(f"must-pass test did not pass: {tid} (status={status_by_test.get(tid)})")

if passed < min_pass_count:
    failures.append(f"passed={passed} below min_pass_count={min_pass_count}")
if pass_rate < min_pass_rate:
    failures.append(f"pass_rate={pass_rate:.4f} below min_pass_rate={min_pass_rate:.4f}")

if failures:
    print("xfstests regression guard failures:", file=sys.stderr)
    for item in failures:
        print(f"  - {item}", file=sys.stderr)
    sys.exit(1)
PY
    then
        e2e_fail "xfstests regression guard failed"
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
    generate_results_from_check_log "$rc"

    if [[ $rc -ne 0 ]]; then
        if grep -qiE "not found or executable|must be run as root|Permission denied" "$CHECK_LOG"; then
            skip_or_fail "xfstests prerequisites unavailable for execution (see $CHECK_LOG)"
        fi
        e2e_log "xfstests check failed; tailing log:"
        e2e_run tail -n 120 "$CHECK_LOG" || true
        e2e_fail "xfstests check failed with exit code $rc"
    fi

    enforce_regression_guard
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
    write_uniform_results "planned" "subset materialized; execution not requested"
    write_summary "planned" "$EFFECTIVE_MODE" "subset materialized; execution not requested" "null"
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

write_summary "passed" "$EFFECTIVE_MODE" "xfstests subset check completed" "$LAST_CHECK_RC"
e2e_log "Run summary: $SUMMARY_JSON"
e2e_pass
exit 0
