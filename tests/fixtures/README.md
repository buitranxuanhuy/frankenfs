# FrankenFS Test Fixtures

This directory contains filesystem images and golden outputs for conformance testing.

## Directory Structure

```
tests/fixtures/
├── images/                  # Filesystem images (gitignored, regenerated)
│   ├── ext4_small.img       # 16 MiB
│   ├── ext4_medium.img      # 64 MiB
│   ├── ext4_large.img       # 128 MiB
│   ├── btrfs_small.img      # 256 MiB
│   ├── btrfs_medium.img     # 512 MiB
│   └── btrfs_large.img      # 1024 MiB
├── golden/                  # Expected outputs (committed)
│   ├── ext4_*.json          # ffs inspect output
│   ├── btrfs_*.json         # ffs inspect output
│   ├── checksums.txt        # SHA-256 verification
│   └── *.log                # Generation logs
└── README.md                # This file
```

## Regenerating Fixtures

### ext4

```bash
./scripts/fixtures/make_ext4_fixtures.sh
```

This script:
1. Creates zero-filled images of specified sizes
2. Formats with `mkfs.ext4` using specific feature flags
3. Populates with known content via `debugfs` (no sudo required)
4. Generates golden JSON outputs using `ffs inspect`
5. Creates SHA-256 checksums for verification

### btrfs

```bash
./scripts/fixtures/make_btrfs_fixtures.sh [--with-content]
```

This script:
1. Creates zero-filled images (btrfs requires minimum ~256 MiB)
2. Formats with `mkfs.btrfs` using default features
3. Optionally populates with content (requires sudo for mounting)
4. Generates golden JSON outputs using `ffs inspect`
5. Updates SHA-256 checksums

## Image Contents

### ext4 Images

Each ext4 image contains a known directory structure:

```
/
├── README.txt           # Description text
├── dir1/
│   ├── file1.bin        # 256 bytes binary (0xFF pattern)
│   └── dir2/
│       └── file2.txt    # Multi-line text file
└── symlink -> dir1/file1.bin
```

### btrfs Images

By default, btrfs images contain only the filesystem structure (no files).
Use `--with-content` (requires sudo) to populate with the same structure as ext4.

## Feature Combinations

### ext4

| Image | Size | Features |
|-------|------|----------|
| ext4_small | 16 MiB | `extent,filetype` (V1 minimum) |
| ext4_medium | 64 MiB | `extent,filetype,dir_index` |
| ext4_large | 128 MiB | `extent,filetype,dir_index,sparse_super` |

### btrfs

| Image | Size | Features |
|-------|------|----------|
| btrfs_small | 256 MiB | Default (extref, skinny-metadata, no-holes, free-space-tree) |
| btrfs_medium | 512 MiB | Default |
| btrfs_large | 1024 MiB | Default |

## Verification

To verify golden outputs match the images:

```bash
cd tests/fixtures/golden
sha256sum -c checksums.txt
```

## Updating Goldens

After intentional behavior changes:

```bash
# Regenerate everything
./scripts/fixtures/make_ext4_fixtures.sh
./scripts/fixtures/make_btrfs_fixtures.sh

# Review changes
git diff tests/fixtures/golden/

# Commit if correct
git add tests/fixtures/golden/
git commit -m "chore: update golden outputs"
```

## Requirements

- `mkfs.ext4`, `debugfs` (e2fsprogs)
- `mkfs.btrfs`, `btrfs` (btrfs-progs)
- `dd`, `sha256sum` (coreutils)
- Rust toolchain (for building ffs-cli)
- `sudo` (only for btrfs content population)

## Notes

- Images are NOT committed to git (too large). Use `.gitignore`.
- Goldens and checksums ARE committed for CI verification.
- Generation is deterministic given the same tool versions.
- Generation logs capture tool versions for reproducibility.
