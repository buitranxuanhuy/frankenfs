# Profile Analysis (bd-3ib.1)

## Metadata

- Profile date (UTC): `2026-02-13T08:38:17Z`
- Commit: `fe476693ab708709fbb7d83d3d430953785bb6b1`
- Kernel: `Linux 6.17.0-14-generic x86_64 GNU/Linux`
- CPU: `AMD Ryzen Threadripper PRO 5995WX 64-Cores` (128 logical CPUs)
- Toolchain:
  - `cargo 1.95.0-nightly (ce69df6f7 2026-02-12)`
  - `rustc 1.95.0-nightly (47611e160 2026-02-12)`
  - `flamegraph-flamegraph 0.6.10`
  - `perf version 6.17.9`

## Scope

Target bead: `bd-3ib.1` ("Profile read path and generate flamegraph").

Attempted canonical target command:

```bash
ffs inspect conformance/golden/ext4_8mb_reference.ext4 --json
```

Current parser behavior blocks this image:

```text
unsupported feature: non-contiguous ext4 journal extents are not supported
```

Workaround used to complete profiling run:

```bash
cargo flamegraph --root -p ffs-cli --output profiles/flamegraph_cli_inspect.svg -- \
  inspect /tmp/ffs-profile-nojournal.fjnSmr.ext4 --json
```

Artifact:

- `profiles/flamegraph_cli_inspect.svg`

## Hotspots

Sample summary from `perf report --stdio -i perf.data`:

- Total samples: `18`
- Event: `cycles:P`
- Lost samples: `0`

Top symbols:

| Self % | Symbol | Shared Object | Interpretation |
|---:|---|---|---|
| 32.08% | `vma_interval_tree_remove` | kernel | ELF/object mapping lifecycle during process startup |
| 31.96% | `perf_iterate_ctx` | kernel | perf event/context overhead around exec/mmap |
| 30.98% | `srso_alias_return_thunk` | kernel | kernel return-thunk overhead in sampled startup path |
| 2.29% | `mas_preallocate` | kernel | mmap/VMA tree setup work |
| 2.11% | `_dl_map_object_deps` | `ld-linux-x86-64.so.2` | dynamic loader dependency mapping |

## Baseline Tie-In

From `baselines/baseline-20260213.md`:

- `ffs-cli inspect ext4_8mb_reference.ext4 --json` is currently skipped for the same unsupported ext4 journal-extent feature.
- Available baseline numbers are for parity/check-fixtures commands only (`~0.9–1.2 ms` range).

Consequence: inspect-path regression tracking is not yet available on canonical conformance fixtures.

## Opportunity Matrix

| Candidate | Impact | Confidence | Effort | Score (I*C/E) | Evidence |
|---|---|---|---|---:|---|
| Implement ext4 non-contiguous journal extent support in inspect open path | High | High | Medium | 3.0 | Canonical inspect is blocked in both baseline + profiling runs |
| Add a repeatable inspect profiling harness (looped workload) to raise sample count and expose Rust hot code | Medium | High | Low | 4.0 | Current profile has only 18 samples, dominated by loader/startup |
| Add FUSE read-path flamegraph once inspect fixture path is unblocked | Medium | Medium | Medium | 1.0 | Bead recommends FUSE profile; currently blocked by image support path |
| Optimize CLI cold-start overhead (link/load + startup path) after longer-run profile confirms bottleneck | Low-Medium | Low | Medium | 0.5 | Existing data is low-confidence and startup-heavy |

## Recommended First Targets

1. Unblock canonical inspect path by implementing support for non-contiguous ext4 journal extents.
2. Add a deterministic profiling harness that runs inspect repeatedly in one invocation window (to collect meaningful Rust-symbol samples).
3. Re-run flamegraph against canonical fixture and update this document with post-fix hotspot data.

## Limitations

- This run used a temporary no-journal ext4 image (`/tmp/ffs-profile-nojournal.fjnSmr.ext4`) rather than the canonical golden ext4 fixture.
- The sample count is too low for high-confidence micro-optimization decisions.
- A useful application-level hotspot map requires a longer-running inspect workload (or in-process repeated inspection).
