# Isomorphism Proof Template

> Required for any optimization PR that changes performance-sensitive code paths.
> Copy this into your PR description and fill out each field.
> See also: `scripts/verify_golden.sh`

## 1. Optimization summary

_One sentence describing what changed and why._

## 2. Golden output verification

```
scripts/verify_golden.sh
# Paste output here
```

- [ ] All checks passed (no behavioral change)
- [ ] OR: checksums updated with justification below

## 3. Behavioral equivalence checklist

| Property | Status | Notes |
|----------|--------|-------|
| **Ordering preserved** | yes / no / N/A | _Does output order match before/after?_ |
| **Tie-breaking unchanged** | yes / no / N/A | _If multiple valid orderings exist, is the same one chosen?_ |
| **Floating-point identical** | identical / N/A | _Any float computations produce bit-identical results?_ |
| **RNG seeds unchanged** | unchanged / N/A | _Deterministic seed derivation not affected?_ |
| **Fixture parity** | `ffs-harness check-fixtures` matches | |
| **Parity report** | `ffs-harness parity` unchanged / updated | |
| **Golden checksums** | `sha256sum -c` passes | |

## 4. Measurement

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| _e.g., ext4_superblock_parse_ | _53 ns_ | _48 ns_ | _-9.4%_ |

**Tool used:** `hyperfine` / `cargo bench` / `cargo flamegraph`

## 5. If golden outputs changed

_Explain why the change is correct. Reference the specific commit or code
path that produces different (but equivalent) output. If ordering changed,
explain why the new order is equally valid._
