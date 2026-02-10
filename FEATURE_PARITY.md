# FEATURE_PARITY

> Quantitative feature coverage tracking for FrankenFS.

## 1. Coverage Summary (Current)

| Domain | Implemented | Total Tracked | Coverage |
|--------|-------------|---------------|----------|
| ext4 metadata parsing | 6 | 19 | 31.6% |
| btrfs metadata parsing | 4 | 20 | 20.0% |
| MVCC/COW core | 4 | 14 | 28.6% |
| FUSE surface | 1 | 12 | 8.3% |
| Self-healing durability policy | 2 | 10 | 20.0% |
| Overall | 17 | 75 | 22.7% |

## 2. Tracked Capability Matrix

| Capability | Legacy Reference | Status | Notes |
|------------|------------------|--------|-------|
| ext4 superblock decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 inode core decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 extent header decode | `fs/ext4/ext4_extents.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 extent entry decode | `fs/ext4/ext4_extents.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 feature flag validation | `fs/ext4/super.c` | ✅ | Basic checks implemented |
| ext4 group descriptor decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ondisk` (`Ext4GroupDesc`) |
| ext4 journal replay parity | `fs/ext4/ext4_jbd2.c` | ❌ | Not yet implemented |
| ext4 allocator parity | `fs/ext4/mballoc.c` | ❌ | Not yet implemented |
| ext4 orphan recovery parity | `fs/ext4/orphan.c` | ❌ | Not yet implemented |
| btrfs superblock decode | `fs/btrfs/disk-io.c` | ✅ | Implemented in `ffs-btrfs` |
| btrfs btree header decode | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-btrfs` |
| btrfs leaf item metadata decode | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-btrfs` |
| btrfs geometry validation | `fs/btrfs/fs.c` | ✅ | Basic checks implemented |
| btrfs transaction parity | `fs/btrfs/transaction.c` | ❌ | Not yet implemented |
| btrfs delayed refs parity | `fs/btrfs/delayed-ref.c` | ❌ | Not yet implemented |
| btrfs scrub parity | `fs/btrfs/scrub.c` | ❌ | Not yet implemented |
| MVCC snapshot visibility | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` |
| MVCC commit sequencing | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` |
| FCW conflict detection | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` |
| version retention policy | FrankenFS spec §3 | ✅ | Current in-memory retention |
| COW block rewrite path | FrankenFS spec §3 | 🟡 | Basic version copy only |
| durability policy model | FrankenFS spec §4 | ✅ | Bayesian expected-loss selector |
| asupersync config mapping | FrankenFS spec §4 | ✅ | `RaptorQConfig` mapping implemented |
| FUSE mount runtime | FrankenFS spec §9 | ❌ | Interface scaffold only |
| CLI inspect command | FrankenFS spec §6 | ✅ | Implemented in `ffs-cli` |
| fixture conformance harness | FrankenFS spec §7 | ✅ | Implemented in `ffs-harness` |
| benchmark harness | FrankenFS spec §8 | ✅ | Criterion benchmark added |

Legend: `✅` implemented, `🟡` partial, `❌` not implemented.

## 3. Blocking Gaps to 100%

1. ext4 journal and allocator mutation behavior parity
2. btrfs transaction/delayed-ref/scrub parity
3. production FUSE mount path
4. full compatibility-mode write-path equivalence

## 4. Update Rule

Any change touching compatibility behavior MUST update this file in the same patch.
