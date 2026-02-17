#!/usr/bin/env bash
# ffs_fuse_production.sh - Production FUSE runtime E2E suite
#
# Coverage goals:
# - mount/unmount lifecycle correctness
# - concurrent read/write surface behavior
# - SIGTERM shutdown durability semantics
# - throughput/latency baseline capture
# - CI-safe skip behavior when FUSE is unavailable

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-ffs=trace,fuser=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export FFS_USE_RCH="${FFS_USE_RCH:-1}"
export FFS_AUTO_UNMOUNT="${FFS_AUTO_UNMOUNT:-0}"
FFS_CLI_BIN="${FFS_CLI_BIN:-$REPO_ROOT/target/release/ffs-cli}"

e2e_init "ffs_fuse_production"
e2e_print_env

CURRENT_MOUNT_PID=""
CURRENT_MOUNT_LOG=""
CURRENT_MOUNT_POINT=""
WORK_EXT4_IMAGE=""
WORK_BTRFS_IMAGE=""

JUNIT_FILE="$E2E_LOG_DIR/junit.xml"
PERF_BASELINE_JSON="$E2E_LOG_DIR/perf_baseline.json"
declare -a TEST_NAMES=()
declare -a TEST_STATUSES=()
declare -a TEST_DURATIONS_MS=()
declare -a TEST_MESSAGES=()

timestamp_ms() {
    date +%s%3N
}

xml_escape() {
    local raw="$1"
    raw="${raw//&/&amp;}"
    raw="${raw//</&lt;}"
    raw="${raw//>/&gt;}"
    raw="${raw//\"/&quot;}"
    raw="${raw//\'/&apos;}"
    printf '%s' "$raw"
}

record_test() {
    local name="$1"
    local status="$2"
    local duration_ms="$3"
    local message="${4:-}"

    TEST_NAMES+=("$name")
    TEST_STATUSES+=("$status")
    TEST_DURATIONS_MS+=("$duration_ms")
    TEST_MESSAGES+=("$message")

    e2e_log "[$(date -Iseconds)] TEST: $name STATUS: $status DURATION: ${duration_ms}ms"
    if [[ -n "$message" ]]; then
        e2e_log "  detail: $message"
    fi
}

emit_junit() {
    local tests="${#TEST_NAMES[@]}"
    local failures=0
    local skipped=0
    local i

    for i in "${!TEST_STATUSES[@]}"; do
        case "${TEST_STATUSES[$i]}" in
            fail) failures=$((failures + 1)) ;;
            skipped) skipped=$((skipped + 1)) ;;
        esac
    done

    {
        printf '<?xml version="1.0" encoding="UTF-8"?>\n'
        printf '<testsuite name="ffs_fuse_production" tests="%d" failures="%d" skipped="%d">\n' \
            "$tests" "$failures" "$skipped"
        for i in "${!TEST_NAMES[@]}"; do
            local name status duration_ms message duration_s
            name="$(xml_escape "${TEST_NAMES[$i]}")"
            status="${TEST_STATUSES[$i]}"
            duration_ms="${TEST_DURATIONS_MS[$i]}"
            message="$(xml_escape "${TEST_MESSAGES[$i]}")"
            duration_s="$(awk "BEGIN { printf \"%.3f\", ${duration_ms}/1000.0 }")"
            printf '  <testcase name="%s" time="%s">' "$name" "$duration_s"
            if [[ "$status" == "fail" ]]; then
                printf '<failure message="%s">%s</failure>' "$message" "$message"
            elif [[ "$status" == "skipped" ]]; then
                printf '<skipped message="%s"/>' "$message"
            fi
            printf '</testcase>\n'
        done
        printf '</testsuite>\n'
    } >"$JUNIT_FILE"

    e2e_log "JUnit report: $JUNIT_FILE"
}

skip_suite() {
    local reason="$1"
    record_test "suite" "skipped" 0 "$reason"
    emit_junit
    e2e_skip "$reason"
}

fail_suite() {
    local test_name="$1"
    local duration_ms="$2"
    local detail="$3"
    record_test "$test_name" "fail" "$duration_ms" "$detail"
    emit_junit
    e2e_fail "$test_name failed: $detail"
}

run_case() {
    local test_name="$1"
    shift

    local start_ms duration_ms
    start_ms="$(timestamp_ms)"
    if e2e_run "$@"; then
        duration_ms=$(( $(timestamp_ms) - start_ms ))
        record_test "$test_name" "pass" "$duration_ms"
    else
        duration_ms=$(( $(timestamp_ms) - start_ms ))
        fail_suite "$test_name" "$duration_ms" "command failed (exit=${E2E_LAST_EXIT_CODE})"
    fi
}

run_case_shell() {
    local test_name="$1"
    local shell_cmd="$2"
    run_case "$test_name" bash -lc "$shell_cmd"
}

run_cargo() {
    if [[ "$FFS_USE_RCH" == "1" ]] && command -v rch >/dev/null 2>&1; then
        e2e_assert rch exec -- cargo "$@"
    else
        e2e_assert cargo "$@"
    fi
}

log_system_state() {
    local label="$1"
    e2e_step "$label"
    if [[ -r /proc/loadavg ]]; then
        e2e_run cat /proc/loadavg || true
    fi
    if [[ -r /proc/meminfo ]]; then
        e2e_run bash -lc "grep -E 'MemTotal|MemAvailable|SwapTotal|SwapFree' /proc/meminfo" || true
    fi
    if command -v uptime >/dev/null 2>&1; then
        e2e_run uptime || true
    fi
}

ensure_mount_capability() {
    if [[ "${SKIP_MOUNT:-0}" == "1" ]]; then
        skip_suite "mount tests skipped (SKIP_MOUNT=1)"
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        skip_suite "python3 is required for concurrency and perf probes"
    fi
    if [[ ! -e /dev/fuse ]]; then
        skip_suite "/dev/fuse not available"
    fi
    if [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
        skip_suite "/dev/fuse is not readable/writable"
    fi
    if ! command -v mountpoint >/dev/null 2>&1; then
        skip_suite "mountpoint utility not found"
    fi
}

wait_for_mount_ready() {
    local mount_point="$1"
    local pid="$2"
    local timeout_seconds="${3:-20}"
    local elapsed=0

    while true; do
        if mountpoint -q "$mount_point" 2>/dev/null; then
            return 0
        fi
        if [[ -n "${CURRENT_MOUNT_LOG:-}" ]] && [[ -f "$CURRENT_MOUNT_LOG" ]]; then
            if grep -q "INIT response" "$CURRENT_MOUNT_LOG"; then
                return 0
            fi
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        sleep 0.5
        elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $((timeout_seconds * 2)) ]]; then
            return 2
        fi
    done
}

start_mount() {
    local mode="$1"
    local image="$2"
    local mount_point="$3"
    local timeout_seconds="${4:-20}"

    mkdir -p "$mount_point"
    E2E_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_LOG="$E2E_LOG_DIR/mount_${mode}_$(basename "$mount_point").log"

    local cmd=("$FFS_CLI_BIN" mount "$image" "$mount_point")
    if [[ "$mode" == "rw" ]]; then
        cmd+=(--rw)
    fi
    if [[ "${FFS_ALLOW_OTHER:-0}" == "1" ]]; then
        cmd+=(--allow-other)
    fi

    e2e_log "Starting mount command: ${cmd[*]}"
    e2e_log "Mount log: $CURRENT_MOUNT_LOG"
    "${cmd[@]}" >"$CURRENT_MOUNT_LOG" 2>&1 &
    CURRENT_MOUNT_PID=$!

    local ready_result=0
    if wait_for_mount_ready "$mount_point" "$CURRENT_MOUNT_PID" "$timeout_seconds"; then
        ready_result=0
    else
        ready_result=$?
    fi

    if [[ $ready_result -eq 0 ]]; then
        e2e_log "Mount ready at $mount_point (pid=$CURRENT_MOUNT_PID mode=$mode)"
        return 0
    fi

    local mount_rc=0
    if kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
        kill "$CURRENT_MOUNT_PID" 2>/dev/null || true
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || true
        mount_rc=124
    else
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || mount_rc=$?
    fi

    e2e_log "Mount failed (mode=$mode rc=$mount_rc). Tail follows:"
    e2e_run tail -n 120 "$CURRENT_MOUNT_LOG" || true

    if grep -qiE "allow_other only allowed if 'user_allow_other' is set" "$CURRENT_MOUNT_LOG"; then
        skip_suite "fuse3 user_allow_other is not enabled"
    fi
    if grep -qiE "Permission denied|Operation not permitted" "$CURRENT_MOUNT_LOG"; then
        skip_suite "FUSE mount not permitted in this environment"
    fi
    if [[ "$mode" == "rw" ]] && grep -qiE "read-write mount is not yet supported|not yet supported" "$CURRENT_MOUNT_LOG"; then
        skip_suite "RW mount is not supported in this build/environment"
    fi

    if [[ $ready_result -eq 2 ]]; then
        e2e_fail "Mount timed out after ${timeout_seconds}s (mode=$mode)"
    fi
    e2e_fail "Mount process exited before mount became ready (mode=$mode)"
}

stop_mount() {
    local mount_point="${1:-$CURRENT_MOUNT_POINT}"

    e2e_unmount "$mount_point"

    if [[ -n "$CURRENT_MOUNT_PID" ]] && kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
        kill "$CURRENT_MOUNT_PID" 2>/dev/null || true
        sleep 0.5
        if kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
            kill -9 "$CURRENT_MOUNT_PID" 2>/dev/null || true
        fi
    fi
    if [[ -n "$CURRENT_MOUNT_PID" ]]; then
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || true
    fi

    CURRENT_MOUNT_PID=""
    CURRENT_MOUNT_POINT=""
}

wait_for_pid_exit() {
    local pid="$1"
    local timeout_seconds="${2:-10}"
    local elapsed_ticks=0

    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.2
        elapsed_ticks=$((elapsed_ticks + 1))
        if [[ $elapsed_ticks -ge $((timeout_seconds * 5)) ]]; then
            kill -9 "$pid" 2>/dev/null || true
            break
        fi
    done
    wait "$pid" 2>/dev/null || true
}

prepare_fixtures() {
    e2e_step "Phase 1: fixture generation"

    WORK_EXT4_IMAGE="$E2E_TEMP_DIR/fuse_prod.ext4"
    e2e_create_ext4_image "$WORK_EXT4_IMAGE" 256
    e2e_assert_file "$WORK_EXT4_IMAGE"
    e2e_log "Ext4 fixture ready: $WORK_EXT4_IMAGE"

    if command -v mkfs.btrfs >/dev/null 2>&1; then
        local btrfs_candidate="$E2E_TEMP_DIR/fuse_prod.btrfs"
        if dd if=/dev/zero of="$btrfs_candidate" bs=1M count=256 status=none; then
            if mkfs.btrfs -f "$btrfs_candidate" >/dev/null 2>&1; then
                WORK_BTRFS_IMAGE="$btrfs_candidate"
                e2e_log "Btrfs fixture prepared: $WORK_BTRFS_IMAGE"
            else
                e2e_log "mkfs.btrfs failed; optional btrfs inspect smoke will be skipped"
            fi
        else
            e2e_log "Failed to allocate btrfs fixture image; optional btrfs inspect smoke skipped"
        fi
    else
        e2e_log "mkfs.btrfs not found; btrfs fixture generation skipped"
    fi
}

run_mount_lifecycle_tests() {
    local mount_rw="$E2E_TEMP_DIR/mnt_fuse_prod_rw"
    local mount_ro="$E2E_TEMP_DIR/mnt_fuse_prod_ro"

    e2e_step "Phase 2: mount/unmount lifecycle"
    run_case "mount_rw_start" start_mount rw "$WORK_EXT4_IMAGE" "$mount_rw" 20
    run_case_shell "mount_rw_probe_readme" "test -f '$mount_rw/readme.txt'"
    run_case "mount_rw_stop" stop_mount "$mount_rw"

    run_case "mount_ro_start" start_mount ro "$WORK_EXT4_IMAGE" "$mount_ro" 20
    run_case_shell "mount_ro_probe_readme" "grep -q 'FrankenFS E2E Test File' '$mount_ro/readme.txt'"
    run_case "mount_ro_stop" stop_mount "$mount_ro"
}

run_concurrent_access_tests() {
    local mount_rw="$E2E_TEMP_DIR/mnt_fuse_prod_concurrency"

    e2e_step "Phase 3: concurrent readers and mixed read/write"
    run_case "concurrency_mount_start" start_mount rw "$WORK_EXT4_IMAGE" "$mount_rw" 20

    run_case_shell "concurrency_rw_workers" "python3 - '$mount_rw' <<'PY'
import concurrent.futures
import pathlib
import sys

mnt = pathlib.Path(sys.argv[1])
seed = mnt / 'seed.txt'
seed.write_text('seed\\n', encoding='utf-8')

def reader_worker() -> None:
    for _ in range(150):
        _ = seed.read_text(encoding='utf-8')

def writer_worker(worker_id: int) -> None:
    path = mnt / f'writer-{worker_id}.txt'
    with path.open('a', encoding='utf-8') as handle:
        for idx in range(120):
            handle.write(f'{worker_id}:{idx}\\n')

with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    futures = []
    for _ in range(4):
        futures.append(pool.submit(reader_worker))
    for worker_id in range(4):
        futures.append(pool.submit(writer_worker, worker_id))
    for future in futures:
        future.result()

for worker_id in range(4):
    path = mnt / f'writer-{worker_id}.txt'
    lines = path.read_text(encoding='utf-8').strip().splitlines()
    assert len(lines) == 120, f'unexpected line count in {path}: {len(lines)}'
PY"

    run_case "concurrency_mount_stop" stop_mount "$mount_rw"
}

run_xattr_tests() {
    local mount_rw="$E2E_TEMP_DIR/mnt_fuse_prod_xattr"

    e2e_step "Phase 4: xattr surface smoke"
    if ! command -v setfattr >/dev/null 2>&1 || ! command -v getfattr >/dev/null 2>&1; then
        record_test "xattr_tools_unavailable" "skipped" 0 "setfattr/getfattr not installed"
        return
    fi

    run_case "xattr_mount_start" start_mount rw "$WORK_EXT4_IMAGE" "$mount_rw" 20
    run_case_shell "xattr_set" "setfattr -n user.fuse-prod -v runtime '$mount_rw/readme.txt'"
    run_case_shell "xattr_get" "getfattr -n user.fuse-prod --only-values '$mount_rw/readme.txt' | grep -Fxq runtime"
    run_case_shell "xattr_list" "getfattr -d '$mount_rw/readme.txt' | grep -Fq user.fuse-prod"
    run_case_shell "xattr_remove" "setfattr -x user.fuse-prod '$mount_rw/readme.txt'"
    run_case_shell "xattr_verify_removed" "! getfattr -n user.fuse-prod --only-values '$mount_rw/readme.txt' >/dev/null 2>&1"
    run_case "xattr_mount_stop" stop_mount "$mount_rw"
}

run_signal_handling_tests() {
    local mount_rw="$E2E_TEMP_DIR/mnt_fuse_prod_signal_rw"
    local mount_ro="$E2E_TEMP_DIR/mnt_fuse_prod_signal_ro"
    local baseline_file="$mount_rw/signal_baseline.txt"

    e2e_step "Phase 5: SIGTERM clean shutdown"
    run_case "signal_mount_start" start_mount rw "$WORK_EXT4_IMAGE" "$mount_rw" 20

    run_case_shell "signal_write_fsync_baseline" "python3 - '$baseline_file' <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text('baseline-data\\n', encoding='utf-8')
fd = os.open(path, os.O_RDWR)
os.fsync(fd)
os.close(fd)
PY"

    if [[ -n "$CURRENT_MOUNT_PID" ]]; then
        local start_ms duration_ms
        start_ms="$(timestamp_ms)"
        kill -TERM "$CURRENT_MOUNT_PID"
        wait_for_pid_exit "$CURRENT_MOUNT_PID" 15
        duration_ms=$(( $(timestamp_ms) - start_ms ))
        record_test "signal_sigterm_shutdown" "pass" "$duration_ms"
    else
        fail_suite "signal_sigterm_shutdown" 0 "mount pid missing before SIGTERM"
    fi

    CURRENT_MOUNT_PID=""
    run_case "signal_mount_ro_start" start_mount ro "$WORK_EXT4_IMAGE" "$mount_ro" 20
    run_case_shell "signal_verify_persisted_data" "grep -Fxq 'baseline-data' '$mount_ro/signal_baseline.txt'"
    run_case "signal_mount_ro_stop" stop_mount "$mount_ro"
}

run_performance_baseline() {
    local mount_rw="$E2E_TEMP_DIR/mnt_fuse_prod_perf"

    e2e_step "Phase 6: throughput and latency baseline"
    run_case "perf_mount_start" start_mount rw "$WORK_EXT4_IMAGE" "$mount_rw" 20

    run_case_shell "perf_measure_and_write_json" "python3 - '$mount_rw' '$PERF_BASELINE_JSON' <<'PY'
import json
import os
import pathlib
import time
import sys

mount = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])

payload_path = mount / 'perf_payload.bin'
data = b'Z' * (1024 * 1024)

start = time.perf_counter()
with payload_path.open('wb') as handle:
    for _ in range(64):
        handle.write(data)
    handle.flush()
    os.fsync(handle.fileno())
duration = max(time.perf_counter() - start, 1e-9)
throughput = 64.0 / duration

target = mount / 'readme.txt'
iterations = 2000
start = time.perf_counter()
for _ in range(iterations):
    os.stat(target)
stat_duration = max(time.perf_counter() - start, 1e-9)
stat_us = (stat_duration / iterations) * 1_000_000.0

metrics = {
    'write_size_mib': 64,
    'write_duration_s': duration,
    'write_throughput_mib_s': throughput,
    'stat_iterations': iterations,
    'stat_latency_us_per_call': stat_us,
    'timestamp': time.time(),
}

out.write_text(json.dumps(metrics, indent=2), encoding='utf-8')
print(json.dumps(metrics))

if throughput < 1.0:
    raise SystemExit(f'throughput too low: {throughput:.3f} MiB/s')
if stat_us > 10000.0:
    raise SystemExit(f'stat latency too high: {stat_us:.3f} us/call')
PY"

    run_case "perf_mount_stop" stop_mount "$mount_rw"
    e2e_assert_file "$PERF_BASELINE_JSON"
}

run_optional_btrfs_smoke() {
    if [[ -z "$WORK_BTRFS_IMAGE" ]] || [[ ! -f "$WORK_BTRFS_IMAGE" ]]; then
        record_test "btrfs_fixture_missing" "skipped" 0 "btrfs fixture not generated"
        return
    fi

    e2e_step "Phase 7: optional btrfs inspect smoke"
    run_case_shell "btrfs_inspect_json" "r='${E2E_LOG_DIR}/btrfs_inspect.json'; '$FFS_CLI_BIN' inspect '$WORK_BTRFS_IMAGE' --json > \"\$r\"; test -s \"\$r\""
}

ensure_mount_capability

e2e_step "Phase 0: build ffs-cli"
run_cargo build -p ffs-cli --release
e2e_assert_file "$FFS_CLI_BIN"

prepare_fixtures
log_system_state "System snapshot before runtime probes"
run_mount_lifecycle_tests
run_concurrent_access_tests
run_xattr_tests
run_signal_handling_tests
run_performance_baseline
run_optional_btrfs_smoke
log_system_state "System snapshot after runtime probes"

emit_junit
e2e_pass
