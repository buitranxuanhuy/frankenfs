# PLAN_TO_PORT_LEGACY_FS_TO_RUST

## 1. Mission

Port legacy ext4 + btrfs behavior from `legacy_ext4_and_btrfs_code/linux-fs` into a memory-safe Rust workspace (`FrankenFS`) with:

- mount-compatible semantics for in-scope features,
- MVCC/COW internals,
- self-healing durability strategy.

## 2. Source of Truth and Inputs

- Legacy source corpus:
  - `legacy_ext4_and_btrfs_code/linux-fs/fs/ext4`
  - `legacy_ext4_and_btrfs_code/linux-fs/fs/btrfs`
- Reference architecture:
  - `/dp/frankensqlite`
  - `/dp/asupersync`
  - `/dp/frankentui`
- Canonical target spec:
  - `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md`

## 3. Clarification: `legacy_glib_code`

The repository currently contains `legacy_ext4_and_btrfs_code` and does **not** contain a separate `legacy_glib_code` path.

For this port plan, `legacy_ext4_and_btrfs_code` is treated as the active legacy corpus.

## 4. Explicit Exclusions (Current Iteration)

These are intentionally out of scope for the current implementation increment and MUST remain tracked in `FEATURE_PARITY.md`:

1. Full ext4 journaling replay equivalence (`ext4_jbd2.*` complete behavior)
2. Full btrfs transaction relocation and scrub parity
3. Complete kernel-level locking semantics parity
4. Production-ready FUSE mount daemon
5. Multi-host distributed repair transport

## 5. Phase Plan

### Phase A: Spec and Structure (current)

- Rewrite `AGENTS.md` for FrankenFS context
- Create canonical README/spec docs
- Establish workspace and crate layering

### Phase B: Metadata Conformance Base

- Implement ext4 superblock/inode/extent parsing
- Implement btrfs superblock/header/item parsing
- Add fixture-driven conformance tests

### Phase C: MVCC/COW Core

- Introduce `TxnId` + `CommitSeq` + `Snapshot`
- Implement FCW conflict checks and visibility
- Prove invariants with tests

### Phase D: Durability Policy + Integration

- Add repair-policy model and asupersync config mapping
- Add deterministic harness checks for policy behavior

### Phase E: FUSE + Runtime Integration

- Build `ffs-fuse` adapter boundary
- Incrementally add mount semantics

### Phase F: Full Parity March

- Expand parser + mutation parity against legacy matrix
- Raise feature coverage to 100% for agreed v1 scope
- Lock in benchmark and regression gates

## 6. Acceptance Criteria for This Iteration

1. Rust workspace compiles cleanly (`check`, `clippy`, `fmt`, `test`)
2. Conformance fixtures cover both ext4 and btrfs metadata parsers
3. `FEATURE_PARITY.md` exists with measurable percentages
4. Benchmark harness and command script are present

## 7. Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Legacy semantic ambiguity | High | Capture exact behavior in `EXISTING_LEGACY_FS_STRUCTURE.md` with source path references |
| Over-ambitious scope | High | Keep explicit exclusions and phased parity table |
| Performance regressions | Medium | Baseline + hotspot profiling + one-change loop |
| Concurrency bugs | High | deterministic tests + FCW invariants + explicit conflict semantics |
