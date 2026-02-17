#!/usr/bin/env bash
# ffs_btrfs_ro_smoke.sh - btrfs read-only FUSE smoke test for FrankenFS
#
# Validates black-box btrfs RO mount behavior:
# - runtime fixture generation
# - inspect geometry logging
# - mount + basic filesystem operations
# - reliable unmount/cleanup

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

CURRENT_MOUNT_PID=""
CURRENT_MOUNT_LOG=""
CURRENT_MOUNT_POINT=""

wait_for_mount_ready() {
    local mount_point="$1"
    local pid="$2"
    local timeout_seconds="${3:-20}"
    local elapsed=0

    while ! mountpoint -q "$mount_point" 2>/dev/null; do
        sleep 0.5
        elapsed=$((elapsed + 1))

        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi

        if [[ $elapsed -ge $((timeout_seconds * 2)) ]]; then
            return 2
        fi
    done

    return 0
}

start_mount_ro() {
    local image="$1"
    local mount_point="$2"
    local timeout_seconds="${3:-20}"

    if [[ "${SKIP_MOUNT:-0}" == "1" ]]; then
        e2e_skip "mount tests skipped (SKIP_MOUNT=1)"
    fi
    if [[ ! -e /dev/fuse ]]; then
        e2e_skip "/dev/fuse not available"
    fi
    if [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
        e2e_skip "/dev/fuse not accessible"
    fi

    mkdir -p "$mount_point"
    E2E_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_LOG="$E2E_LOG_DIR/mount_ro.log"

    local cmd=(cargo run -p ffs-cli --release -- mount "$image" "$mount_point")
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
        e2e_log "Mount ready at $mount_point (pid=$CURRENT_MOUNT_PID)"
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

    e2e_log "Mount failed (rc=$mount_rc), tailing mount log:"
    e2e_run tail -n 120 "$CURRENT_MOUNT_LOG" || true

    if grep -qiE "allow_other only allowed if 'user_allow_other' is set" "$CURRENT_MOUNT_LOG"; then
        e2e_skip "FUSE present but user_allow_other is not enabled in /etc/fuse.conf"
    fi
    if grep -qiE "Permission denied|Operation not permitted|failed to open /dev/fuse" "$CURRENT_MOUNT_LOG"; then
        e2e_skip "FUSE is present but mount is not permitted in this environment"
    fi

    if [[ $ready_result -eq 2 ]]; then
        e2e_fail "Mount timed out after ${timeout_seconds}s"
    fi
    e2e_fail "Mount process exited before mount became ready"
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

detect_geometry_from_inspect() {
    local inspect_json="$1"

    local sectorsize nodesize
    sectorsize=$(grep -Eo '"sectorsize"[[:space:]]*:[[:space:]]*[0-9]+' "$inspect_json" | head -1 | grep -Eo '[0-9]+' || true)
    nodesize=$(grep -Eo '"nodesize"[[:space:]]*:[[:space:]]*[0-9]+' "$inspect_json" | head -1 | grep -Eo '[0-9]+' || true)

    [[ -z "$sectorsize" ]] && sectorsize="unknown"
    [[ -z "$nodesize" ]] && nodesize="unknown"

    e2e_log "Detected btrfs geometry: sectorsize=$sectorsize, nodesize=$nodesize"
}

e2e_init "ffs_btrfs_ro_smoke"
e2e_print_env

e2e_step "Phase 1: prerequisites"
if ! command -v mkfs.btrfs &>/dev/null; then
    e2e_skip "mkfs.btrfs not found (install btrfs-progs)"
fi
if ! command -v btrfs &>/dev/null; then
    e2e_skip "btrfs command not found (install btrfs-progs)"
fi
if [[ ! -e /dev/fuse ]]; then
    e2e_skip "/dev/fuse not available"
fi
if [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
    e2e_skip "/dev/fuse not accessible"
fi

e2e_step "Phase 2: generate btrfs reference image"
BTRFS_REF_DIR="$E2E_TEMP_DIR/btrfs-reference"
BTRFS_IMAGE="$BTRFS_REF_DIR/btrfs_reference.img"
BTRFS_FIXTURE_SCRIPT="$REPO_ROOT/scripts/fixtures/make_btrfs_reference_image.sh"

if [[ ! -x "$BTRFS_FIXTURE_SCRIPT" ]]; then
    e2e_fail "Fixture generator missing or not executable: $BTRFS_FIXTURE_SCRIPT"
fi

e2e_assert "$BTRFS_FIXTURE_SCRIPT" --output "$BTRFS_REF_DIR"
e2e_assert_file "$BTRFS_IMAGE"

e2e_step "Phase 3: inspect btrfs image"
INSPECT_JSON="$E2E_LOG_DIR/inspect_btrfs.json"
e2e_assert bash -lc "cargo run -p ffs-cli --release -- inspect '$BTRFS_IMAGE' --json > '$INSPECT_JSON'"
detect_geometry_from_inspect "$INSPECT_JSON"

e2e_step "Phase 4: mount read-only via FUSE"
MOUNT_POINT="$E2E_TEMP_DIR/mnt_btrfs_ro"
start_mount_ro "$BTRFS_IMAGE" "$MOUNT_POINT"

e2e_step "Phase 5: validate filesystem operations"
e2e_assert ls -la "$MOUNT_POINT"
e2e_assert stat "$MOUNT_POINT"
e2e_assert find "$MOUNT_POINT" -maxdepth 2 -mindepth 1

KNOWN_FILE=""
for candidate in README.txt testdir/file1.txt link_to_file1; do
    if [[ -f "$MOUNT_POINT/$candidate" ]]; then
        KNOWN_FILE="$candidate"
        break
    fi
done

if [[ -n "$KNOWN_FILE" ]]; then
    e2e_log "Found known fixture file: $KNOWN_FILE"
    e2e_assert cat "$MOUNT_POINT/$KNOWN_FILE"
else
    e2e_log "No known fixture file present in generated image; skipping file-cat check"
fi

e2e_step "Phase 6: unmount"
stop_mount "$MOUNT_POINT"
if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    e2e_fail "Failed to unmount $MOUNT_POINT"
fi

e2e_pass
