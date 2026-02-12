#!/usr/bin/env bash
# update-goldens.sh - Update golden outputs after intentional behavior changes
#
# This script regenerates all golden outputs and updates the checksums file.
# Use this when ffs-cli inspect output has intentionally changed.
#
# Usage: ./scripts/update-goldens.sh

set -euo pipefail
IFS=$'\n\t'

# Navigate to repo root
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

IMAGES_DIR="tests/fixtures/images"
GOLDEN_DIR="tests/fixtures/golden"
CHECKSUM_FILE="$GOLDEN_DIR/checksums.txt"

echo "=============================================="
echo "Golden Output Update"
echo "=============================================="
echo "Timestamp: $(date -Iseconds)"
echo ""

# Safety prompt
echo "WARNING: This will overwrite existing golden outputs!"
echo ""
if [[ -t 0 ]]; then
    read -p "Continue? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
else
    echo "(Running non-interactively, proceeding...)"
fi
echo ""

# Check for image files
image_count=$(find "$IMAGES_DIR" -name "*.img" 2>/dev/null | wc -l)
if [[ "$image_count" -eq 0 ]]; then
    echo "ERROR: No fixture images found in $IMAGES_DIR"
    echo "Run the fixture generation scripts first:"
    echo "  ./scripts/fixtures/make_ext4_fixtures.sh"
    echo "  ./scripts/fixtures/make_btrfs_fixtures.sh"
    exit 1
fi

echo "Found $image_count fixture images"
echo ""

# Build ffs-cli
echo "=== Building ffs-cli ==="
cargo build -p ffs-cli --release 2>&1 | tail -5
echo ""

# Regenerate all golden outputs
echo "=== Regenerating Golden Outputs ==="
for img in "$IMAGES_DIR"/*.img; do
    name=$(basename "$img" .img)
    golden="$GOLDEN_DIR/${name}.json"

    echo "  Generating: $name"
    cargo run -p ffs-cli --release -- inspect "$img" --json 2>/dev/null > "$golden"
done
echo ""

# Update checksums
echo "=== Updating Checksums ==="
cd "$GOLDEN_DIR"
sha256sum *.json > checksums.txt
echo "Updated checksums:"
cat checksums.txt
echo ""

# Verify
echo "=== Verification ==="
if sha256sum -c checksums.txt; then
    echo ""
    echo "=============================================="
    echo "Golden outputs updated successfully!"
    echo "=============================================="
    echo ""
    echo "Don't forget to commit the changes:"
    echo "  git add tests/fixtures/golden/"
    echo "  git commit -m 'chore: update golden outputs'"
    exit 0
else
    echo ""
    echo "ERROR: Checksum verification failed after update!"
    exit 1
fi
