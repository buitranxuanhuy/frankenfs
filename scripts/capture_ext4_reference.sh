#!/usr/bin/env bash
# capture_ext4_reference.sh — Generate a golden ext4 reference image + JSON.
#
# Usage:
#   scripts/capture_ext4_reference.sh [output_dir]
#
# Requires: mkfs.ext4, debugfs, dumpe2fs (e2fsprogs package)
#
# Produces:
#   <output_dir>/ext4_8mb_reference.json   — golden reference data (versioned JSON)
#   <output_dir>/ext4_8mb_reference.ext4   — the raw ext4 image (not checked in)
#
# The golden JSON captures kernel-derived metadata (superblock fields,
# directory listings, file contents) that conformance tests compare against
# ffs-ondisk parsing of the same image.
set -euo pipefail

OUTPUT_DIR="${1:-conformance/golden}"
mkdir -p "$OUTPUT_DIR"

IMAGE="$OUTPUT_DIR/ext4_8mb_reference.ext4"
GOLDEN="$OUTPUT_DIR/ext4_8mb_reference.json"
CONTENT_FILE="$(mktemp)"
trap 'rm -f "$CONTENT_FILE"' EXIT

# ── 1. Create image ──────────────────────────────────────────────
echo "Creating 8MB ext4 image..." >&2
dd if=/dev/zero of="$IMAGE" bs=1M count=8 status=none
mkfs.ext4 -L "ffs-ref" -b 4096 -q "$IMAGE" 2>/dev/null

# ── 2. Populate via debugfs ──────────────────────────────────────
echo "Populating image with test files..." >&2
printf 'hello from FrankenFS reference test\n' > "$CONTENT_FILE"

debugfs -w -R "mkdir /testdir" "$IMAGE" 2>/dev/null
debugfs -w -R "write $CONTENT_FILE /testdir/hello.txt" "$IMAGE" 2>/dev/null
debugfs -w -R "write $CONTENT_FILE /readme.txt" "$IMAGE" 2>/dev/null

# ── 3. Capture superblock via dumpe2fs ───────────────────────────
echo "Capturing superblock..." >&2
DUMPE2FS_OUT="$(dumpe2fs -h "$IMAGE" 2>/dev/null)"

parse_field() {
    echo "$DUMPE2FS_OUT" | grep "^${1}:" | head -1 | sed "s/^${1}:[[:space:]]*//"
}

BLOCK_SIZE="$(parse_field "Block size")"
BLOCKS_COUNT="$(parse_field "Block count")"
INODES_COUNT="$(parse_field "Inode count")"
VOLUME_NAME="$(parse_field "Filesystem volume name")"
FREE_BLOCKS="$(parse_field "Free blocks")"
FREE_INODES="$(parse_field "Free inodes")"

# ── 4. Capture directory listings via debugfs ────────────────────
echo "Capturing directory listings..." >&2

# Parse debugfs "ls -l" output into JSON array of {name, file_type}
capture_dir() {
    local dir="$1"
    local output
    output="$(debugfs -R "ls -l $dir" "$IMAGE" 2>/dev/null)"
    local first=true
    echo "["
    while IFS= read -r line; do
        # Lines: "  INODE  MODE (?) UID GID SIZE DATE TIME NAME"
        line="$(echo "$line" | sed 's/^[[:space:]]*//')"
        [[ -z "$line" ]] && continue
        [[ "$line" == debugfs* ]] && continue

        local inode mode name
        inode="$(echo "$line" | awk '{print $1}')"
        mode="$(echo "$line" | awk '{print $2}')"
        name="$(echo "$line" | awk '{print $NF}')"

        # Validate inode is numeric
        [[ "$inode" =~ ^[0-9]+$ ]] || continue

        # Determine file type from octal mode high bits
        # debugfs prints mode in octal: 40755=dir, 100664=regular, etc.
        local ftype="unknown"
        local mode_dec=$((8#$mode))
        local type_bits=$(( mode_dec & 8#170000 ))
        case "$type_bits" in
            $((8#040000)))  ftype="directory" ;;
            $((8#100000)))  ftype="regular" ;;
            $((8#020000)))  ftype="character" ;;
            $((8#060000)))  ftype="block" ;;
            $((8#010000)))  ftype="fifo" ;;
            $((8#140000)))  ftype="socket" ;;
            $((8#120000)))  ftype="symlink" ;;
            *)              ftype="unknown" ;;
        esac

        if [ "$first" = true ]; then first=false; else echo ","; fi
        printf '    {"name": "%s", "file_type": "%s"}' "$name" "$ftype"
    done <<< "$output"
    echo ""
    echo "  ]"
}

ROOT_ENTRIES="$(capture_dir /)"
TESTDIR_ENTRIES="$(capture_dir /testdir)"

# ── 5. Capture file contents ─────────────────────────────────────
echo "Capturing file contents..." >&2
HELLO_CONTENT="$(cat "$CONTENT_FILE" | xxd -p | tr -d '\n')"
HELLO_SIZE="$(wc -c < "$CONTENT_FILE" | tr -d ' ')"

# Convert hex string to JSON byte array
hex_to_json_array() {
    local hex="$1"
    local len=${#hex}
    local i=0
    local first=true
    echo -n "["
    while [ $i -lt $len ]; do
        local byte="${hex:$i:2}"
        local dec=$((16#$byte))
        if [ "$first" = true ]; then first=false; else echo -n ","; fi
        echo -n "$dec"
        i=$((i + 2))
    done
    echo -n "]"
}

HELLO_BYTES="$(hex_to_json_array "$HELLO_CONTENT")"

# ── 6. Emit golden JSON ─────────────────────────────────────────
echo "Writing golden JSON to $GOLDEN..." >&2
cat > "$GOLDEN" <<GOLDEN_EOF
{
  "version": 1,
  "source": "Linux e2fsprogs (mkfs.ext4 + debugfs + dumpe2fs)",
  "image_params": {
    "size_bytes": 8388608,
    "block_size": $BLOCK_SIZE,
    "volume_name": "ffs-ref"
  },
  "superblock": {
    "block_size": $BLOCK_SIZE,
    "blocks_count": $BLOCKS_COUNT,
    "inodes_count": $INODES_COUNT,
    "volume_name": "$VOLUME_NAME",
    "free_blocks_count": $FREE_BLOCKS,
    "free_inodes_count": $FREE_INODES
  },
  "directories": [
    {
      "path": "/",
      "entries": $ROOT_ENTRIES
    },
    {
      "path": "/testdir",
      "entries": $TESTDIR_ENTRIES
    }
  ],
  "files": [
    {
      "path": "/testdir/hello.txt",
      "size": $HELLO_SIZE,
      "content": $HELLO_BYTES
    },
    {
      "path": "/readme.txt",
      "size": $HELLO_SIZE,
      "content": $HELLO_BYTES
    }
  ]
}
GOLDEN_EOF

echo "Done. Golden JSON: $GOLDEN" >&2
echo "Image (not checked in): $IMAGE" >&2
