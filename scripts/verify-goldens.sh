#!/usr/bin/env bash
# verify-goldens.sh - Verify golden outputs match fixture images
#
# This script regenerates golden outputs from fixture images and verifies
# they match the committed checksums. Used in CI to detect regressions.
#
# Exit codes:
#   0 - All checksums match
#   1 - Checksum mismatch (regression detected)
#   2 - Missing prerequisites (images, checksums file)

set -euo pipefail
IFS=$'\n\t'

# Navigate to repo root
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

IMAGES_DIR="tests/fixtures/images"
GOLDEN_DIR="tests/fixtures/golden"
CHECKSUM_FILE="$GOLDEN_DIR/checksums.txt"

echo "=============================================="
echo "Golden Output Verification"
echo "=============================================="
echo "Timestamp: $(date -Iseconds)"
echo "Git commit: $(git rev-parse HEAD 2>/dev/null || echo 'not a git repo')"
echo "Repository: $REPO_ROOT"
echo ""

# Check prerequisites
echo "=== Checking Prerequisites ==="

if [[ ! -f "$CHECKSUM_FILE" ]]; then
    echo "ERROR: Checksum file not found: $CHECKSUM_FILE"
    echo "Run './scripts/fixtures/make_ext4_fixtures.sh' and './scripts/fixtures/make_btrfs_fixtures.sh' first."
    exit 2
fi

# Check for image files
image_count=$(find "$IMAGES_DIR" -name "*.img" 2>/dev/null | wc -l)
if [[ "$image_count" -eq 0 ]]; then
    echo "ERROR: No fixture images found in $IMAGES_DIR"
    echo "Run the fixture generation scripts first."
    exit 2
fi

echo "Found $image_count fixture images"
echo "Checksum file: $CHECKSUM_FILE"
echo ""

# Build ffs-cli
echo "=== Building ffs-cli ==="
cargo build -p ffs-cli --release 2>&1 | tail -5
echo ""

# Regenerate golden outputs
echo "=== Regenerating Golden Outputs ==="
for img in "$IMAGES_DIR"/*.img; do
    name=$(basename "$img" .img)
    golden="$GOLDEN_DIR/${name}.json"

    echo "  Processing: $name"
    cargo run -p ffs-cli --release -- inspect "$img" --json 2>/dev/null > "$golden"
done
echo ""

# Verify checksums
echo "=== Verifying Checksums ==="
cd "$GOLDEN_DIR"

if sha256sum -c checksums.txt; then
    echo ""
    echo "=============================================="
    echo "All golden outputs match!"
    echo "=============================================="
    exit 0
else
    echo ""
    echo "=============================================="
    echo "GOLDEN OUTPUT MISMATCH DETECTED"
    echo "=============================================="
    echo ""
    echo "This means the ffs-cli inspect output has changed."
    echo ""
    echo "Possible causes:"
    echo "  1. Regression introduced (fix the code)"
    echo "  2. Intentional behavior change (update goldens)"
    echo ""
    echo "To update goldens for intentional changes:"
    echo "  ./scripts/update-goldens.sh"
    echo ""
    echo "To see what changed:"
    echo "  git diff tests/fixtures/golden/"
    echo ""
    exit 1
fi
