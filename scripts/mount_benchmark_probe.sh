#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  scripts/mount_benchmark_probe.sh --bin <ffs-cli> --image <ext4-image> --mount-root <dir> --mode <cold|warm|recovery>

Options:
  --bin <path>         Path to local ffs-cli binary
  --image <path>       Path to probe ext4 image
  --mount-root <path>  Directory where temporary mountpoints are created
  --mode <mode>        cold, warm, or recovery
  -h, --help           Show this help
USAGE
}

FFS_BIN=""
IMAGE=""
MOUNT_ROOT=""
MODE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)
            [ $# -ge 2 ] || { echo "missing value for --bin" >&2; exit 2; }
            FFS_BIN="$2"
            shift 2
            ;;
        --image)
            [ $# -ge 2 ] || { echo "missing value for --image" >&2; exit 2; }
            IMAGE="$2"
            shift 2
            ;;
        --mount-root)
            [ $# -ge 2 ] || { echo "missing value for --mount-root" >&2; exit 2; }
            MOUNT_ROOT="$2"
            shift 2
            ;;
        --mode)
            [ $# -ge 2 ] || { echo "missing value for --mode" >&2; exit 2; }
            MODE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[ -n "$FFS_BIN" ] || { echo "--bin is required" >&2; exit 2; }
[ -n "$IMAGE" ] || { echo "--image is required" >&2; exit 2; }
[ -n "$MOUNT_ROOT" ] || { echo "--mount-root is required" >&2; exit 2; }
[ -n "$MODE" ] || { echo "--mode is required" >&2; exit 2; }
[ -x "$FFS_BIN" ] || { echo "ffs-cli binary is not executable: $FFS_BIN" >&2; exit 2; }
[ -f "$IMAGE" ] || { echo "probe image does not exist: $IMAGE" >&2; exit 2; }
[ -d "$MOUNT_ROOT" ] || mkdir -p "$MOUNT_ROOT"

if ! command -v mountpoint >/dev/null 2>&1; then
    echo "mountpoint utility not available" >&2
    exit 2
fi

safe_unmount() {
    local mnt="$1"
    if ! mountpoint -q "$mnt" 2>/dev/null; then
        return 0
    fi

    if command -v fusermount3 >/dev/null 2>&1; then
        fusermount3 -u "$mnt" >/dev/null 2>&1 || true
    elif command -v fusermount >/dev/null 2>&1; then
        fusermount -u "$mnt" >/dev/null 2>&1 || true
    else
        umount "$mnt" >/dev/null 2>&1 || true
    fi

    if mountpoint -q "$mnt" 2>/dev/null; then
        umount "$mnt" >/dev/null 2>&1 || umount -l "$mnt" >/dev/null 2>&1 || true
    fi
}

single_line_text() {
    tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//'
}

mount_once() {
    local label="$1"
    local mnt="${MOUNT_ROOT}/${label}"
    local stdout_log="${MOUNT_ROOT}/${label}.stdout"
    local stderr_log="${MOUNT_ROOT}/${label}.stderr"
    local rc=0
    local ready=0
    local timed_out=0

    mkdir -p "$mnt"
    : >"$stdout_log"
    : >"$stderr_log"

    FFS_AUTO_UNMOUNT=0 "$FFS_BIN" mount "$IMAGE" "$mnt" >"$stdout_log" 2>"$stderr_log" &
    local pid=$!

    for _ in $(seq 1 200); do
        if mountpoint -q "$mnt" 2>/dev/null; then
            if stat "$mnt" >/dev/null 2>&1; then
                ready=1
            fi
            break
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 0.05
    done

    if [ "$ready" -eq 0 ] && kill -0 "$pid" 2>/dev/null; then
        timed_out=1
        kill "$pid" >/dev/null 2>&1 || true
    fi

    safe_unmount "$mnt"

    wait "$pid" || rc=$?

    if [ "$ready" -ne 1 ] || [ "$rc" -ne 0 ]; then
        local reason
        reason="$(single_line_text < "$stderr_log")"
        if [ -z "$reason" ]; then
            reason="mount probe failed"
        fi
        if [ "$timed_out" -eq 1 ]; then
            reason="${reason} (mount did not become ready within timeout)"
        fi
        echo "$reason" >&2
        return 1
    fi
}

case "$MODE" in
    cold)
        mount_once "cold"
        ;;
    warm)
        mount_once "warm_prepare"
        mount_once "warm_measure"
        ;;
    recovery)
        mount_once "recovery"
        ;;
    *)
        echo "unsupported mode: $MODE (expected cold|warm|recovery)" >&2
        exit 2
        ;;
esac
