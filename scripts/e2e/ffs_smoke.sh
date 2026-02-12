#!/usr/bin/env bash
# ffs_smoke.sh - End-to-end smoke test for FrankenFS
#
# This script exercises the main user-facing workflows:
# - Build the workspace
# - Run CLI commands (inspect, scrub, parity)
# - Mount ext4 image via FUSE (if available)
# - Validate basic file operations through the mount
#
# Usage: ./scripts/e2e/ffs_smoke.sh
#
# Exit codes:
#   0 - All tests passed (or skipped)
#   1 - Test failure
#
# Environment:
#   RUST_LOG - Log level (default: info)
#   RUST_BACKTRACE - Backtrace (default: 1)
#   SKIP_MOUNT - Set to 1 to skip FUSE mount tests

# Navigate to repo root
cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

# Source shared helpers
source "$REPO_ROOT/scripts/e2e/lib.sh"

# Set Rust logging
export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

# Initialize test
e2e_init "ffs_smoke"

# Print environment
e2e_print_env

#######################################
# Phase 1: Build
#######################################
e2e_step "Phase 1: Build"

e2e_assert cargo build --workspace

#######################################
# Phase 2: Create test image
#######################################
e2e_step "Phase 2: Create Test Image"

TEST_IMAGE="$E2E_TEMP_DIR/e2e_test.ext4"
e2e_create_ext4_image "$TEST_IMAGE" 16

#######################################
# Phase 3: CLI Commands
#######################################
e2e_step "Phase 3: CLI Commands"

# Inspect
e2e_log "Testing: ffs inspect"
e2e_assert cargo run -p ffs-cli --release -- inspect "$TEST_IMAGE" --json

# Scrub
# Note: scrub returns exit code 2 if findings are detected, which is normal
# for test images. We check that it runs (doesn't crash) rather than asserting exit 0.
e2e_log ""
e2e_log "Testing: ffs scrub"
e2e_run cargo run -p ffs-cli --release -- scrub "$TEST_IMAGE" --json || true
if [[ $E2E_LAST_EXIT_CODE -eq 0 ]]; then
    e2e_log "Scrub completed: no findings"
elif [[ $E2E_LAST_EXIT_CODE -eq 2 ]]; then
    e2e_log "Scrub completed: findings detected (expected for test images)"
else
    e2e_fail "Scrub failed with unexpected exit code: $E2E_LAST_EXIT_CODE"
fi

# Parity
e2e_log ""
e2e_log "Testing: ffs parity"
e2e_assert cargo run -p ffs-cli --release -- parity --json

#######################################
# Phase 4: FUSE Mount (optional)
#######################################
e2e_step "Phase 4: FUSE Mount"

if [[ "${SKIP_MOUNT:-}" == "1" ]]; then
    e2e_log "Skipping mount tests (SKIP_MOUNT=1)"
elif [[ ! -e /dev/fuse ]]; then
    e2e_log "Skipping mount tests (/dev/fuse not available)"
elif [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
    e2e_log "Skipping mount tests (/dev/fuse not accessible)"
else
    MOUNT_POINT="$E2E_TEMP_DIR/mnt"
    mkdir -p "$MOUNT_POINT"

    e2e_log "Mounting $TEST_IMAGE to $MOUNT_POINT"

    # Start mount in background
    cargo run -p ffs-cli --release -- mount "$TEST_IMAGE" "$MOUNT_POINT" &
    MOUNT_PID=$!
    E2E_MOUNT_POINT="$MOUNT_POINT"

    # Wait for mount
    e2e_log "Waiting for mount to be ready..."
    TIMEOUT=15
    ELAPSED=0
    while ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; do
        sleep 0.5
        ELAPSED=$((ELAPSED + 1))
        if [[ $ELAPSED -ge $((TIMEOUT * 2)) ]]; then
            kill "$MOUNT_PID" 2>/dev/null || true
            e2e_fail "Mount did not become ready within ${TIMEOUT}s"
        fi
    done
    e2e_log "Mount ready (PID: $MOUNT_PID)"

    # Test file operations
    e2e_log ""
    e2e_log "Testing file operations through mount:"

    e2e_log "  ls -la $MOUNT_POINT"
    ls -la "$MOUNT_POINT" 2>&1 | while IFS= read -r line; do e2e_log "    $line"; done

    e2e_log ""
    e2e_log "  find $MOUNT_POINT -maxdepth 2 -type f"
    find "$MOUNT_POINT" -maxdepth 2 -type f 2>&1 | while IFS= read -r line; do e2e_log "    $line"; done

    e2e_log ""
    e2e_log "  cat $MOUNT_POINT/readme.txt"
    if [[ -f "$MOUNT_POINT/readme.txt" ]]; then
        cat "$MOUNT_POINT/readme.txt" 2>&1 | while IFS= read -r line; do e2e_log "    $line"; done
    else
        e2e_log "    (file not found)"
    fi

    e2e_log ""
    e2e_log "  cat $MOUNT_POINT/testdir/hello.txt"
    if [[ -f "$MOUNT_POINT/testdir/hello.txt" ]]; then
        cat "$MOUNT_POINT/testdir/hello.txt" 2>&1 | while IFS= read -r line; do e2e_log "    $line"; done
    else
        e2e_log "    (file not found)"
    fi

    # Unmount
    e2e_log ""
    e2e_log "Unmounting..."
    e2e_unmount "$MOUNT_POINT"

    # Verify unmounted
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        e2e_fail "Failed to unmount $MOUNT_POINT"
    fi
    e2e_log "Unmounted successfully"
fi

#######################################
# Done
#######################################
e2e_pass
