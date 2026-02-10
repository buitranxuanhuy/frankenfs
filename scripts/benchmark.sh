#!/usr/bin/env bash
set -euo pipefail

# Baseline metadata parser latency.
hyperfine --warmup 3 --runs 10 \
  'cargo run -p ffs-harness -- parity >/dev/null' \
  'cargo run -p ffs-harness -- check-fixtures >/dev/null'

# Criterion benchmark suite.
cargo bench -p ffs-harness --bench metadata_parse
