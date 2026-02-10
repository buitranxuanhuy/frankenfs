# AGENTS.md — FrankenFS (ffs)

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main:master
  ```

---

## Project Identity

This repository is **FrankenFS (ffs)**: a memory-safe, clean-room Rust reimplementation of ext4 and btrfs with a higher-level architecture that combines:

1. **Mount-compatible behavior** with ext4/btrfs images
2. **MVCC + copy-on-write internals** for concurrent writers
3. **Self-healing durability** via fountain-code-based repair workflows

Primary legacy source corpus:
- `legacy_ext4_and_btrfs_code/linux-fs/fs/ext4`
- `legacy_ext4_and_btrfs_code/linux-fs/fs/btrfs`

Primary reference project:
- `/dp/frankensqlite`

Primary external crates (required):
- `/dp/asupersync`
- `/dp/frankentui`

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (nightly required — see `rust-toolchain.toml`)
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]` at crate roots + workspace lint)
- **Dependency versions:** Explicit versions for stability and reproducibility
- **Configuration:** `Cargo.toml` only

### Required Dependency Families

| Dependency | Purpose |
|------------|---------|
| `asupersync` | Async runtime, capability context (`Cx`), deterministic lab runtime, RaptorQ pipeline |
| `frankentui` / `ftui` | Terminal UX for CLI diagnostics and tooling |
| `serde` + `serde_json` | Fixtures, conformance vectors, metadata reports |
| `thiserror` | Error modeling |
| `smallvec`, `memchr` | Hot path efficiency |
| `criterion`, `proptest`, `tempfile` | Bench + property/conformance testing |

### Release Profile (size-optimized)

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

---

## Core Architecture Targets

FrankenFS must evolve toward this layered architecture:

```
Image/VFS I/O
  -> Format adapters (ext4 + btrfs parsers/encoders)
  -> MVCC/COW transaction engine
  -> Self-healing durability layer (repair symbols + decode proofs)
  -> FUSE mount surface (Linux userspace)
  -> CLI + harness + conformance + perf gates
```

### Non-Negotiable Design Rules

1. **No line-by-line translation from C.** Extract behavior, then re-implement idiomatically in Rust.
2. **No compatibility shims for bad designs.** If legacy behavior is flawed but externally observable, preserve the observable contract while fixing internals.
3. **No ambient authority.** Cancellation/deadline-sensitive operations should take `&asupersync::Cx`.
4. **Deterministic testability.** Concurrency-sensitive logic must be testable under asupersync lab runtime.
5. **Proof-first for risky logic.** Include invariants, explicit error budgets, and evidence for conflict-resolution policies.

---

## Required Spec Documents

These files are mandatory and must stay current:

1. `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` (canonical source of truth)
2. `PLAN_TO_PORT_FRANKENFS_TO_RUST.md` (scope, exclusions, sequencing)
3. `EXISTING_EXT4_BTRFS_STRUCTURE.md` (behavior extraction from legacy code)
4. `PROPOSED_ARCHITECTURE.md` (Rust crate/module architecture)
5. `FEATURE_PARITY.md` (measured parity status and gaps)

Legacy bootstrap documents (retained only for history; do not treat as canonical):
- `PLAN_TO_PORT_LEGACY_FS_TO_RUST.md`
- `EXISTING_LEGACY_FS_STRUCTURE.md`

Reference artifact copied from FrankenSQLite:
- `COMPREHENSIVE_SPEC_FOR_FRANKENSQLITE_V1.md`

Use that document as a strategy template, not as a direct filesystem specification.

---

## Code Editing Discipline

### No Script-Based Mass Code Transformations

**NEVER** run scripts that bulk rewrite code in this repo.

- Make code edits manually
- For repetitive edits, use subagents or careful targeted patches
- For subtle logic, read and reason before editing

### No File Proliferation

- Modify existing files when functionality belongs there
- Do not create `*_v2`, `*_new`, or similar variants
- New files are allowed only for genuinely new functionality

---

## Porting Doctrine (Spec-First, Conformance-First)

Follow this sequence:

1. **Extract behavior from legacy ext4/btrfs code** into `EXISTING_EXT4_BTRFS_STRUCTURE.md`
2. **Design Rust architecture** in `PROPOSED_ARCHITECTURE.md`
3. **Implement from spec** (not by copying C flow)
4. **Validate via conformance harness**
5. **Track parity numerically** in `FEATURE_PARITY.md`

### Explicit Exclusions (for now)

Anything excluded must be listed explicitly in:
- `PLAN_TO_PORT_FRANKENFS_TO_RUST.md`
- `FEATURE_PARITY.md`

Hidden exclusions are not allowed.

---

## Conformance and Benchmarking Requirements

FrankenFS must include:

1. **Fixture-based conformance tests** (goldens for ext4/btrfs metadata behavior)
2. **Legacy behavior mapping** (feature-to-source traceability)
3. **Benchmark suite** with baselines and regression detection
4. **Feature parity report** with explicit percentages and blocked items

### Benchmark Loop (mandatory)

- Baseline first (`hyperfine`)
- Profile hotspots
- Apply one optimization lever at a time
- Prove behavioral equivalence after each change
- Re-measure and record deltas

---

## Alien-Artifact Quality Bar

For high-risk subsystems (MVCC conflict logic, self-healing repair policy, distributed consistency), prefer principled models over ad-hoc thresholds:

- Bayesian evidence updates for corruption/failure rates
- Expected-loss decision rules for redundancy policies
- Anytime-valid monitoring for long-running checks
- Deterministic audit logs for explainability

If a heuristic is used, document why formal alternatives were not viable.

---

## FUSE and Compatibility Scope

FrankenFS targets Linux userspace mount paths via FUSE.

- FUSE-specific logic should remain in dedicated crate boundaries
- Format adapters should stay independent of transport/mount frontends
- Compatibility mode must preserve on-disk interpretation of ext4/btrfs images where declared supported
- Native mode innovations (MVCC/COW/self-heal) must preserve correctness and explicit conversion semantics

---

## Compiler/Lint/Test Gates (CRITICAL)

After substantive changes, you MUST run:

```bash
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

For perf/conformance work, also run:

```bash
cargo test -p ffs-harness -- --nocapture
cargo bench -p ffs-harness
```

If a gate fails, fix root causes instead of suppressing diagnostics.

---

## Suggested Working Flow for Agents

1. Read `AGENTS.md` and `README.md`
2. Update or validate spec docs before touching logic-heavy code
3. Reserve files if using MCP Agent Mail coordination
4. Implement in small, verifiable increments
5. Keep `FEATURE_PARITY.md` current in the same change set
6. Run all required checks

---

## Legacy Source Navigation

Primary legacy modules for extraction:

| Legacy Path | Domain |
|-------------|--------|
| `legacy_ext4_and_btrfs_code/linux-fs/fs/ext4/super.c` | ext4 superblock and mount behavior |
| `legacy_ext4_and_btrfs_code/linux-fs/fs/ext4/inode.c` | ext4 inode lifecycle |
| `legacy_ext4_and_btrfs_code/linux-fs/fs/ext4/extents.c` | ext4 extent tree operations |
| `legacy_ext4_and_btrfs_code/linux-fs/fs/btrfs/super.c` | btrfs superblock and mount behavior |
| `legacy_ext4_and_btrfs_code/linux-fs/fs/btrfs/ctree.c` | btrfs tree ops |
| `legacy_ext4_and_btrfs_code/linux-fs/fs/btrfs/extent-tree.c` | extent allocation/reference logic |
| `legacy_ext4_and_btrfs_code/linux-fs/fs/btrfs/transaction.c` | transaction semantics |

---

## Output Expectations

- Be direct, technical, and explicit
- Quantify parity and performance claims
- Prefer table-driven status reporting
- Clearly separate: implemented, partially implemented, not implemented

No hand-wavy “done” claims without tests, metrics, and parity evidence.

---

## Playbooks

### Session Start Ritual (Cass-Proven)

1. Read `AGENTS.md` and `README.md` fully.
2. Get oriented: run `git status --porcelain`, `bv --robot-next`, `br ready --json`.
3. Claim exactly one bead and announce it to other agents (Agent Mail thread = bead ID).
4. Make the smallest correct change set that advances parity, specs, or conformance.
5. Run gates (fmt/check/clippy/test) before claiming “done”.

### Cass Archaeology (Context Recovery)

Rules:
- Do not pipe large cass outputs to `head`/`tail` (broken pipe panics). Redirect to a file, then inspect the file.

Copy-paste workflow:

```bash
# Health + refresh (always first)
cass status --json && cass index --json

# Terrain scan: who did what, when?
cass search "*" --workspace /data/projects/frankenfs --aggregate agent,date --limit 1 --json

# Find the exact prior discussion/prompt
cass search "KEYWORD" --workspace /data/projects/frankenfs --json --fields minimal --limit 50

# Follow a hit
cass view /path/from/source_path.jsonl -n LINE -C 20
cass expand /path/from/source_path.jsonl --line LINE --context 3
cass context /path/from/source_path.jsonl --json
```

### Alien-Artifact Mode (Principled, Auditable Decisions)

Use when logic is high-risk (MVCC conflict rules, repair policy, consistency, corruption decisions).

Elicitation prompt (copy-paste):

```
Now, TRULY think even harder. Surely there is some math invented in the
last 60 years that would be relevant and helpful here? Super hard, esoteric
math that would be ultra accretive and give a ton of alpha for the specific
problems we're trying to solve here, as efficiently as possible?

REALLY RUMINATE ON THIS!!! DIG DEEP!!

STUFF THAT EVEN TERRY TAO WOULD HAVE TO CONCENTRATE SUPER HARD ON!
```

Required outputs for “alien artifact” quality work:
- Explicit invariants (what MUST remain true).
- Evidence ledger (what evidence drove what decision).
- Loss matrix / expected-loss rule for any threshold-like decision.

### Extreme Optimization Loop (One Lever, Behavior-Proven)

Rules:
- Profile first.
- One optimization lever per commit.
- Prove behavior unchanged (goldens or invariants) for every change.

```bash
# Baseline
hyperfine --warmup 3 --runs 10 'COMMAND'

# Verify unchanged behavior (example pattern)
sha256sum golden_outputs/* > golden_checksums.txt
sha256sum -c golden_checksums.txt
```

Isomorphism proof template (required for perf work):
- Ordering preserved: yes/no + why
- Tie-breaking unchanged: yes/no + why
- Floating-point identical: identical/N/A
- RNG seeds unchanged: unchanged/N/A
- Goldens verified: `sha256sum -c golden_checksums.txt` (or equivalent)

### Porting-To-Rust Essence Extraction (Spec-First)

Rules:
- Never translate C line-by-line.
- Extract behavior into spec docs first, then implement from the spec.
- Conformance harness is the arbiter, not vibes.

Minimal checklist:
1. Extract behavior into `EXISTING_EXT4_BTRFS_STRUCTURE.md` (what, not how).
2. Update `PROPOSED_ARCHITECTURE.md` (crate/module boundaries, trait contracts).
3. Implement idiomatically in Rust.
4. Add/extend fixtures + harness tests.
5. Update `FEATURE_PARITY.md` in the same change set.
