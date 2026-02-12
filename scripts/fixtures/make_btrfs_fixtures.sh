#!/usr/bin/env bash
# make_btrfs_fixtures.sh - Generate btrfs golden fixture images
#
# This script creates reproducible btrfs filesystem images for conformance testing.
# Unlike ext4, btrfs requires larger minimum image sizes (256MB+).
#
# NOTE: Full content population requires sudo for mounting. Without sudo,
# images are created with valid btrfs structure but minimal content.
#
# Usage: ./scripts/fixtures/make_btrfs_fixtures.sh [--with-content]
#
# Output:
#   tests/fixtures/images/btrfs_small.img   (256 MiB)
#   tests/fixtures/images/btrfs_medium.img  (512 MiB)
#   tests/fixtures/images/btrfs_large.img   (1024 MiB)
#   tests/fixtures/golden/btrfs_*.json      (inspect output)
#   tests/fixtures/golden/checksums.txt     (updated)

set -euo pipefail
IFS=$'\n\t'

WITH_CONTENT=false
if [[ "${1:-}" == "--with-content" ]]; then
    WITH_CONTENT=true
fi

# Navigate to repo root
cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"

# Paths
IMAGES_DIR="tests/fixtures/images"
GOLDEN_DIR="tests/fixtures/golden"
LOG_FILE="${GOLDEN_DIR}/btrfs_generation.log"

# Ensure directories exist
mkdir -p "$IMAGES_DIR" "$GOLDEN_DIR"

# Start logging
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=============================================="
echo "btrfs Fixture Generation"
echo "=============================================="
echo "Start time: $(date -Iseconds)"
echo "Repository: $REPO_ROOT"
echo "With content: $WITH_CONTENT"
echo ""

# Print tool versions
echo "=== Tool Versions ==="
echo "mkfs.btrfs:"
mkfs.btrfs --version 2>&1 | head -1
echo ""
echo "btrfs:"
btrfs --version 2>&1 | head -1
echo ""
echo "dd: $(dd --version 2>&1 | head -1)"
echo "sha256sum: $(sha256sum --version 2>&1 | head -1)"
echo ""

# Function to create a btrfs image
create_image() {
    local name="$1"
    local size_mb="$2"
    local img_path="${IMAGES_DIR}/${name}.img"

    echo "=== Creating $name ($size_mb MiB) ==="
    echo ""

    # Create zero-filled image
    echo "  [1/3] Creating empty image..."
    dd if=/dev/zero of="$img_path" bs=1M count="$size_mb" status=progress 2>&1
    echo ""

    # Format as btrfs with default features
    # btrfs-progs 6.16 defaults: extref, skinny-metadata, no-holes, free-space-tree
    echo "  [2/3] Formatting as btrfs..."
    mkfs.btrfs -f -L "$name" "$img_path" 2>&1
    echo ""

    # Optionally populate with content
    if [[ "$WITH_CONTENT" == "true" ]]; then
        echo "  [3/3] Populating with test content (requires sudo)..."
        populate_image "$img_path" "$name"
    else
        echo "  [3/3] Skipping content population (use --with-content for full fixtures)"
    fi
    echo ""

    echo "  Image complete: $img_path"
    ls -lh "$img_path"
    echo ""
}

# Function to populate image with known content (requires sudo)
populate_image() {
    local img_path="$1"
    local name="$2"

    # Create mount point
    local mnt_dir
    mnt_dir=$(mktemp -d)

    cleanup() {
        sudo umount "$mnt_dir" 2>/dev/null || true
        rmdir "$mnt_dir" 2>/dev/null || true
    }
    trap cleanup RETURN

    echo "    Mounting to $mnt_dir..."
    sudo mount -o loop "$img_path" "$mnt_dir"

    # Create content structure (matching ext4 for comparison)
    echo "    Creating directory structure..."
    sudo mkdir -p "$mnt_dir/dir1/dir2"

    echo "    Creating files..."
    echo "FrankenFS Test Fixture
======================
This filesystem image was created for conformance testing.
It contains a known directory structure for validation.

Created by: scripts/fixtures/make_btrfs_fixtures.sh" | sudo tee "$mnt_dir/README.txt" > /dev/null

    # Binary file (256 bytes of deterministic pattern)
    dd if=/dev/zero bs=256 count=1 2>/dev/null | tr '\0' '\xFF' | sudo tee "$mnt_dir/dir1/file1.bin" > /dev/null

    echo "Nested text file for testing directory traversal.
Line 2
Line 3" | sudo tee "$mnt_dir/dir1/dir2/file2.txt" > /dev/null

    # Create symlink
    echo "    Creating symlink..."
    sudo ln -s dir1/file1.bin "$mnt_dir/symlink"

    # Create a subvolume (btrfs-specific feature)
    echo "    Creating subvolume..."
    sudo btrfs subvolume create "$mnt_dir/subvol1" || echo "      (subvolume creation failed, continuing)"

    # Show structure
    echo "    Content structure:"
    sudo ls -la "$mnt_dir" || true

    echo "    Unmounting..."
    sudo umount "$mnt_dir"
}

# Create three images with different sizes
# btrfs minimum size varies but 256MB is safe
echo "=== Phase 1: Creating Images ==="
echo ""

# btrfs requires minimum ~256 MiB. Use different sizes to test parsing at scale.
# Default features in btrfs-progs 6.16: extref, skinny-metadata, no-holes, free-space-tree

# Small: 256 MiB (minimum safe size)
create_image "btrfs_small" 256

# Medium: 512 MiB
create_image "btrfs_medium" 512

# Large: 1024 MiB (tests larger block groups)
create_image "btrfs_large" 1024

echo "=== Phase 2: Building FrankenFS CLI ==="
echo ""
cargo build -p ffs-cli --release 2>&1

echo ""
echo "=== Phase 3: Generating Golden Outputs ==="
echo ""

for img in "$IMAGES_DIR"/btrfs_*.img; do
    name=$(basename "$img" .img)
    golden="${GOLDEN_DIR}/${name}.json"

    echo "Generating: $golden"
    # Redirect stderr to hide cargo build output, capture only JSON
    cargo run -p ffs-cli --release -- inspect "$img" --json 2>/dev/null > "$golden"

    # Show summary
    echo "  Size: $(wc -c < "$golden") bytes"
    echo "  Preview: $(head -c 200 "$golden")..."
    echo ""
done

echo "=== Phase 4: Updating Checksums ==="
echo ""

cd "$GOLDEN_DIR"
# Regenerate checksums for all goldens (ext4 + btrfs)
sha256sum ext4_*.json btrfs_*.json 2>/dev/null > checksums.txt || sha256sum *.json > checksums.txt
echo "Checksums:"
cat checksums.txt
echo ""

echo "=== Verification ==="
echo ""
if sha256sum -c checksums.txt; then
    echo ""
    echo "All checksums verified successfully."
else
    echo ""
    echo "ERROR: Checksum verification failed!"
    exit 1
fi

echo ""
echo "=============================================="
echo "Generation Complete"
echo "=============================================="
echo "End time: $(date -Iseconds)"
echo ""
echo "Artifacts created:"
for f in "$REPO_ROOT/$IMAGES_DIR"/btrfs_*.img; do
    echo "  - $f ($(du -h "$f" | cut -f1))"
done
for f in "$REPO_ROOT/$GOLDEN_DIR"/btrfs_*.json; do
    echo "  - $f ($(wc -c < "$f") bytes)"
done
echo "  - $REPO_ROOT/$GOLDEN_DIR/checksums.txt (updated)"
echo "  - $REPO_ROOT/$GOLDEN_DIR/btrfs_generation.log"
echo ""
echo "To verify: ( cd $GOLDEN_DIR && sha256sum -c checksums.txt )"
