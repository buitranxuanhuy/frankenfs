#!/usr/bin/env bash
# Benchmark comparison: S3-FIFO vs ARC cache hit rates on filesystem workloads.
#
# Produces a side-by-side comparison table with hit rates and memory overhead
# for 5 representative workloads.
#
# Usage:
#   ./scripts/bench_s3fifo_vs_arc.sh [--rch]
#
# Options:
#   --rch    Use rch (remote compilation host) for builds
#
# Output files:
#   target/bench-reports/arc_workloads.tsv
#   target/bench-reports/s3fifo_workloads.tsv
#   target/bench-reports/comparison.txt
set -euo pipefail

USE_RCH=false
for arg in "$@"; do
    case "$arg" in
        --rch) USE_RCH=true ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

CARGO_CMD="cargo"
if $USE_RCH; then
    CARGO_CMD="rch exec -- cargo"
fi

REPORT_DIR="target/bench-reports"
mkdir -p "$REPORT_DIR"

ARC_TSV="$REPORT_DIR/arc_workloads.tsv"
S3FIFO_TSV="$REPORT_DIR/s3fifo_workloads.tsv"
COMPARISON="$REPORT_DIR/comparison.txt"

echo "=== Building and running ARC workloads ==="
FFS_BLOCK_CACHE_WORKLOAD_REPORT="$ARC_TSV" \
    $CARGO_CMD bench -p ffs-block --bench arc_cache 2>/dev/null || true

echo "=== Building and running S3-FIFO workloads ==="
FFS_BLOCK_CACHE_WORKLOAD_REPORT="$S3FIFO_TSV" \
    $CARGO_CMD bench -p ffs-block --bench arc_cache --features s3fifo 2>/dev/null || true

# Verify both files exist
if [[ ! -f "$ARC_TSV" ]]; then
    echo "ERROR: ARC report not generated at $ARC_TSV" >&2
    exit 1
fi
if [[ ! -f "$S3FIFO_TSV" ]]; then
    echo "ERROR: S3-FIFO report not generated at $S3FIFO_TSV" >&2
    exit 1
fi

# Generate comparison report
{
    echo "============================================================"
    echo "  S3-FIFO vs ARC Cache Hit Rate Comparison"
    echo "  Generated: $(date -Iseconds)"
    echo "============================================================"
    echo ""

    printf "%-20s  %10s  %10s  %8s  %10s  %10s  %8s\n" \
        "Workload" "ARC Hit%" "S3F Hit%" "Winner" "ARC GhOH" "S3F GhOH" "Mem Win"
    printf "%s\n" "$(printf '%.0s-' {1..90})"

    s3fifo_wins=0
    arc_wins=0
    s3fifo_mem_wins=0

    # Read ARC results (skip header)
    declare -A arc_hit arc_ghost
    while IFS=$'\t' read -r policy workload accesses hits misses hit_rate resident capacity b1 b2 mem_oh seed; do
        [[ "$policy" == "policy" ]] && continue
        arc_hit["$workload"]="$hit_rate"
        arc_ghost["$workload"]="$mem_oh"
    done < "$ARC_TSV"

    # Read S3-FIFO results and compare
    while IFS=$'\t' read -r policy workload accesses hits misses hit_rate resident capacity b1 b2 mem_oh seed; do
        [[ "$policy" == "policy" ]] && continue

        a_hit="${arc_hit[$workload]:-0}"
        a_ghost="${arc_ghost[$workload]:-0}"

        # Compare hit rates (awk for float comparison)
        winner=$(awk "BEGIN { if ($hit_rate > $a_hit + 0.001) print \"S3-FIFO\"; else if ($a_hit > $hit_rate + 0.001) print \"ARC\"; else print \"TIE\" }")
        mem_winner=$(awk "BEGIN { if ($mem_oh < $a_ghost - 0.001) print \"S3-FIFO\"; else if ($a_ghost < $mem_oh - 0.001) print \"ARC\"; else print \"TIE\" }")

        [[ "$winner" == "S3-FIFO" ]] && ((s3fifo_wins++)) || true
        [[ "$winner" == "ARC" ]] && ((arc_wins++)) || true
        [[ "$mem_winner" == "S3-FIFO" ]] && ((s3fifo_mem_wins++)) || true

        a_pct=$(awk "BEGIN { printf \"%.4f%%\", $a_hit * 100 }")
        s_pct=$(awk "BEGIN { printf \"%.4f%%\", $hit_rate * 100 }")

        printf "%-20s  %10s  %10s  %8s  %10.4f  %10.4f  %8s\n" \
            "$workload" "$a_pct" "$s_pct" "$winner" "$a_ghost" "$mem_oh" "$mem_winner"
    done < "$S3FIFO_TSV"

    echo ""
    echo "Summary:"
    echo "  Hit rate wins:    S3-FIFO=$s3fifo_wins  ARC=$arc_wins"
    echo "  Memory overhead:  S3-FIFO lower=$s3fifo_mem_wins/5"
    echo ""

    if (( s3fifo_wins >= 3 )); then
        echo "RESULT: PASS - S3-FIFO matches or beats ARC on >= 3/5 workloads"
    else
        echo "RESULT: REVIEW - S3-FIFO wins $s3fifo_wins/5 (target: >= 3)"
    fi
} | tee "$COMPARISON"

echo ""
echo "Reports saved to:"
echo "  ARC:        $ARC_TSV"
echo "  S3-FIFO:    $S3FIFO_TSV"
echo "  Comparison: $COMPARISON"
