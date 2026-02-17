#!/usr/bin/env bash
# ffs_degradation_stress.sh - Graceful degradation stress E2E suite
#
# This suite validates degradation/backpressure behavior using:
# 1) deterministic crate tests (ffs-core + ffs-fuse)
# 2) optional host pressure probe with stress-ng
# 3) optional live mount pressure probe (opt-in)

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info,ffs::backpressure=trace,ffs::core=info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export FFS_USE_RCH="${FFS_USE_RCH:-1}"
FFS_CLI_BIN="${FFS_CLI_BIN:-$REPO_ROOT/target/release/ffs-cli}"

e2e_init "ffs_degradation_stress"
e2e_print_env

run_cargo() {
    if [[ "$FFS_USE_RCH" == "1" ]] && command -v rch >/dev/null 2>&1; then
        e2e_assert rch exec -- cargo "$@"
    else
        e2e_assert cargo "$@"
    fi
}

pressure_snapshot() {
    local label="$1"
    e2e_step "$label"
    if [[ -r /proc/loadavg ]]; then
        e2e_run cat /proc/loadavg || true
    fi
    if [[ -r /proc/meminfo ]]; then
        e2e_run bash -lc "grep -E 'MemTotal|MemAvailable|SwapTotal|SwapFree' /proc/meminfo" || true
    fi
}

run_deterministic_degradation_gates() {
    e2e_step "Phase 1: deterministic degradation/backpressure gates"
    run_cargo test -p ffs-core degradation_level_ -- --nocapture
    run_cargo test -p ffs-core fsm_ -- --nocapture
    run_cargo test -p ffs-core backpressure_gate_ -- --nocapture
    run_cargo test -p ffs-core pressure_monitor_ -- --nocapture
}

run_fuse_surface_gates() {
    e2e_step "Phase 2: FUSE surface regression gates"
    run_cargo test -p ffs-fuse -- --nocapture
}

run_host_pressure_probe() {
    local duration="${DEGRADATION_STRESS_DURATION_SECS:-20}"
    local cpu_workers="${DEGRADATION_STRESS_CPU_WORKERS:-4}"
    local vm_workers="${DEGRADATION_STRESS_VM_WORKERS:-1}"
    local vm_bytes="${DEGRADATION_STRESS_VM_BYTES:-60%}"
    local stress_log="$E2E_LOG_DIR/stress-ng.log"

    if ! command -v stress-ng >/dev/null 2>&1; then
        e2e_log "stress-ng not found; skipping host pressure probe"
        return
    fi

    pressure_snapshot "Phase 3: pressure snapshot (before stress)"
    e2e_step "Phase 3: host pressure probe with stress-ng"
    e2e_log "stress-ng --cpu $cpu_workers --vm $vm_workers --vm-bytes $vm_bytes --timeout ${duration}s"

    stress-ng \
        --cpu "$cpu_workers" \
        --vm "$vm_workers" \
        --vm-bytes "$vm_bytes" \
        --timeout "${duration}s" \
        --metrics-brief >"$stress_log" 2>&1 &
    local stress_pid=$!

    sleep 3
    pressure_snapshot "Phase 3: pressure snapshot (during stress)"

    # Re-run monitor tests while load is active.
    run_cargo test -p ffs-core pressure_monitor_ -- --nocapture

    wait "$stress_pid" || true
    e2e_run tail -n 120 "$stress_log" || true
    pressure_snapshot "Phase 3: pressure snapshot (after stress)"
}

run_optional_mount_probe() {
    local duration="${DEGRADATION_MOUNT_STRESS_DURATION_SECS:-15}"
    local cpu_workers="${DEGRADATION_MOUNT_STRESS_CPU_WORKERS:-4}"
    local mount_log="$E2E_LOG_DIR/mount_stress.log"
    local image="$E2E_TEMP_DIR/degradation_probe.ext4"
    local mount_point="$E2E_TEMP_DIR/mnt_degradation_probe"

    if [[ "${FFS_RUN_MOUNT_STRESS:-0}" != "1" ]]; then
        e2e_log "Skipping optional mount pressure probe (set FFS_RUN_MOUNT_STRESS=1 to enable)"
        return
    fi
    if [[ ! -e /dev/fuse ]] || [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
        e2e_log "Skipping mount pressure probe: /dev/fuse unavailable"
        return
    fi
    if ! command -v stress-ng >/dev/null 2>&1; then
        e2e_log "Skipping mount pressure probe: stress-ng not found"
        return
    fi
    if ! command -v mountpoint >/dev/null 2>&1; then
        e2e_log "Skipping mount pressure probe: mountpoint not found"
        return
    fi

    e2e_step "Phase 4: optional live mount pressure probe"
    e2e_create_ext4_image "$image" 64
    mkdir -p "$mount_point"

    e2e_log "Starting mount probe: $FFS_CLI_BIN mount $image $mount_point"
    "$FFS_CLI_BIN" mount "$image" "$mount_point" >"$mount_log" 2>&1 &
    local mount_pid=$!

    local ready=0
    for _ in {1..40}; do
        if mountpoint -q "$mount_point" 2>/dev/null; then
            ready=1
            break
        fi
        if ! kill -0 "$mount_pid" 2>/dev/null; then
            break
        fi
        sleep 0.5
    done

    if [[ "$ready" != "1" ]]; then
        e2e_log "Mount probe unavailable in this environment; mount log tail follows"
        e2e_run tail -n 120 "$mount_log" || true
        kill "$mount_pid" 2>/dev/null || true
        wait "$mount_pid" 2>/dev/null || true
        return
    fi

    stress-ng --cpu "$cpu_workers" --timeout "${duration}s" --metrics-brief >"$E2E_LOG_DIR/mount_stress_ng.log" 2>&1 &
    local stress_pid=$!
    sleep 2

    local read_failures=0
    for _ in {1..20}; do
        if ! e2e_run cat "$mount_point/readme.txt"; then
            read_failures=$((read_failures + 1))
        fi
        sleep 0.1
    done
    e2e_log "Mount stress probe read failures: $read_failures"

    wait "$stress_pid" || true
    e2e_unmount "$mount_point"
    kill "$mount_pid" 2>/dev/null || true
    wait "$mount_pid" 2>/dev/null || true
    e2e_run tail -n 120 "$mount_log" || true
}

e2e_step "Phase 0: build ffs-cli"
run_cargo build -p ffs-cli --release
e2e_assert_file "$FFS_CLI_BIN"

run_deterministic_degradation_gates
run_fuse_surface_gates
run_host_pressure_probe
run_optional_mount_probe

e2e_pass
