#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

WARMUP=3
RUNS=10
COMPARE=0
VERIFY_GOLDEN=1
DATE_TAG="$(date -u +%Y%m%d)"
REF_IMAGE="conformance/golden/ext4_8mb_reference.ext4"
P99_WARN_THRESHOLD=10
P99_FAIL_THRESHOLD=20
PERF_BASELINE_PATH="artifacts/baselines/perf_baseline.json"

usage() {
    cat <<'USAGE'
Usage:
  scripts/benchmark_record.sh [--date YYYYMMDD] [--warmup N] [--runs N] [--compare] [--skip-verify-golden] [--p99-fail-threshold N] [--out-json PATH]

Options:
  --date YYYYMMDD          Override date-tag for output paths (default: today)
  --warmup N               Hyperfine warmup runs (default: 3)
  --runs N                 Hyperfine measured runs (default: 10)
  --compare                Compare current p99 against latest prior baseline (warn >10%, fail >20%)
  --skip-verify-golden     Skip scripts/verify_golden.sh preflight
  --p99-fail-threshold N   Fail compare if p99 regression exceeds N percent (default: 20)
  --out-json PATH          Structured baseline JSON output path (default: artifacts/baselines/perf_baseline.json)
  -h, --help               Show this help
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --date)
            [ $# -ge 2 ] || { echo "missing value for --date" >&2; exit 2; }
            DATE_TAG="$2"
            shift 2
            ;;
        --warmup)
            [ $# -ge 2 ] || { echo "missing value for --warmup" >&2; exit 2; }
            WARMUP="$2"
            shift 2
            ;;
        --runs)
            [ $# -ge 2 ] || { echo "missing value for --runs" >&2; exit 2; }
            RUNS="$2"
            shift 2
            ;;
        --compare)
            COMPARE=1
            shift
            ;;
        --skip-verify-golden)
            VERIFY_GOLDEN=0
            shift
            ;;
        --p99-fail-threshold)
            [ $# -ge 2 ] || { echo "missing value for --p99-fail-threshold" >&2; exit 2; }
            P99_FAIL_THRESHOLD="$2"
            shift 2
            ;;
        --out-json)
            [ $# -ge 2 ] || { echo "missing value for --out-json" >&2; exit 2; }
            PERF_BASELINE_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

OUT_DIR="baselines/hyperfine/${DATE_TAG}"
REPORT_PATH="baselines/baseline-${DATE_TAG}.md"
if [[ "$PERF_BASELINE_PATH" == *.json ]]; then
    PERF_BASELINE_DATED_PATH="${PERF_BASELINE_PATH%.json}-${DATE_TAG}.json"
else
    PERF_BASELINE_DATED_PATH="${PERF_BASELINE_PATH}-${DATE_TAG}.json"
fi

mkdir -p "$OUT_DIR" "$(dirname "$PERF_BASELINE_PATH")"

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    TARGET_DIR="${CARGO_TARGET_DIR}"
else
    TARGET_DIR="$(cargo metadata --format-version=1 --no-deps | jq -r '.target_directory')"
fi

if [ "$VERIFY_GOLDEN" -eq 1 ]; then
    echo "=== Golden Verification Gate ==="
    scripts/verify_golden.sh
    echo ""
fi

echo "=== FrankenFS Baseline Recorder (${DATE_TAG}) ==="
echo "Output directory: ${OUT_DIR}"
echo ""

echo "Building release binaries once..."
cargo build -p ffs-cli --release --quiet
cargo build -p ffs-harness --release --quiet
echo ""

CLI_BIN="${TARGET_DIR}/release/ffs-cli"
HARNESS_BIN="${TARGET_DIR}/release/ffs-harness"

[ -x "$CLI_BIN" ] || { echo "missing executable: ${CLI_BIN}" >&2; exit 1; }
[ -x "$HARNESS_BIN" ] || { echo "missing executable: ${HARNESS_BIN}" >&2; exit 1; }

declare -a BENCH_LABELS=()
declare -a BENCH_COMMANDS=()
declare -a BENCH_FILES=()
declare -a BENCH_OPERATIONS=()
declare -a BENCH_PAYLOAD_MB=()
declare -a SKIPPED_LABELS=()

add_bench() {
    BENCH_LABELS+=("$1")
    BENCH_COMMANDS+=("$2")
    BENCH_FILES+=("$3")
    BENCH_OPERATIONS+=("$4")
    BENCH_PAYLOAD_MB+=("${5:-0}")
}

add_bench "ffs-cli parity --json" \
    "${CLI_BIN} parity --json" \
    "ffs_cli_parity.json" \
    "metadata_parity_cli" \
    "0"

add_bench "ffs-harness parity" \
    "${HARNESS_BIN} parity" \
    "ffs_harness_parity.json" \
    "metadata_parity_harness" \
    "0"

add_bench "ffs-harness check-fixtures" \
    "${HARNESS_BIN} check-fixtures" \
    "ffs_harness_check_fixtures.json" \
    "fixture_validation" \
    "0"

if [ -f "$REF_IMAGE" ]; then
    probe_stderr="${OUT_DIR}/ffs_cli_inspect_probe.stderr"
    if "$CLI_BIN" inspect "$REF_IMAGE" --json >/dev/null 2>"$probe_stderr"; then
        add_bench "ffs-cli inspect ext4_8mb_reference.ext4 --json" \
            "${CLI_BIN} inspect ${REF_IMAGE} --json" \
            "ffs_cli_inspect_ext4_8mb_reference.json" \
            "read_metadata_inspect_ext4_reference" \
            "8"
        add_bench "ffs-cli scrub ext4_8mb_reference.ext4 --json" \
            "${CLI_BIN} scrub ${REF_IMAGE} --json" \
            "ffs_cli_scrub_ext4_8mb_reference.json" \
            "read_metadata_scrub_ext4_reference" \
            "8"
    else
        probe_reason="$(tr '\n' ' ' < "$probe_stderr" | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')"
        SKIPPED_LABELS+=("ffs-cli inspect ext4_8mb_reference.ext4 --json (unsupported by current parser: ${probe_reason})")
        SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (skipped because inspect probe failed)")
    fi
else
    SKIPPED_LABELS+=("ffs-cli inspect ext4_8mb_reference.ext4 --json (missing ${REF_IMAGE})")
    SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (missing ${REF_IMAGE})")
fi

json_mean() {
    jq -r '.results[0].mean' "$1"
}

json_stddev() {
    jq -r '.results[0].stddev' "$1"
}

json_percentile() {
    local json_file="$1"
    local percentile="$2"
    jq -r --argjson p "$percentile" '
        .results[0].times as $times
        | ($times | length) as $n
        | if $n == 0 then
              0
          else
              ($times | sort) as $sorted
              | ((($n - 1) * $p) | floor) as $idx
              | $sorted[$idx]
          end
    ' "$json_file"
}

json_p50() {
    json_percentile "$1" 0.50
}

json_p95() {
    json_percentile "$1" 0.95
}

json_p99() {
    json_percentile "$1" 0.99
}

valid_number() {
    awk -v v="$1" 'BEGIN {
        if (v ~ /^-?[0-9]+([.][0-9]+)?([eE][-+]?[0-9]+)?$/) {
            exit 0;
        }
        exit 1;
    }'
}

sec_to_ms() {
    awk -v v="$1" 'BEGIN { printf "%.3f", v * 1000.0 }'
}

sec_to_us() {
    awk -v v="$1" 'BEGIN { printf "%.0f", v * 1000000.0 }'
}

ops_per_sec() {
    awk -v v="$1" 'BEGIN {
        if (v <= 0) {
            printf "0";
        } else {
            printf "%.6f", 1.0 / v;
        }
    }'
}

mb_per_sec() {
    awk -v mb="$1" -v sec="$2" 'BEGIN {
        if (mb <= 0 || sec <= 0) {
            printf "0";
        } else {
            printf "%.6f", mb / sec;
        }
    }'
}

pct_change() {
    awk -v base="$1" -v cur="$2" 'BEGIN {
        if (base == 0) {
            printf "0.00";
        } else {
            printf "%.2f", ((cur - base) / base) * 100.0;
        }
    }'
}

echo "Running hyperfine benchmarks..."
for i in "${!BENCH_LABELS[@]}"; do
    label="${BENCH_LABELS[$i]}"
    cmd="${BENCH_COMMANDS[$i]}"
    json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
    txt_file="${json_file%.json}.txt"

    echo ""
    echo "--- ${label} ---"
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --export-json "$json_file" \
        "$cmd" | tee "$txt_file"
done
echo ""

write_perf_baseline_json() {
    local tmp_measurements
    tmp_measurements="$(mktemp)"
    for i in "${!BENCH_LABELS[@]}"; do
        local json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
        local mean_s
        local p50_s
        local p95_s
        local p99_s
        local p50_us
        local p95_us
        local p99_us
        local throughput_ops_sec
        local throughput_mb_sec
        mean_s="$(json_mean "$json_file")"
        p50_s="$(json_p50 "$json_file")"
        p95_s="$(json_p95 "$json_file")"
        p99_s="$(json_p99 "$json_file")"
        p50_us="$(sec_to_us "$p50_s")"
        p95_us="$(sec_to_us "$p95_s")"
        p99_us="$(sec_to_us "$p99_s")"
        throughput_ops_sec="$(ops_per_sec "$mean_s")"
        throughput_mb_sec="$(mb_per_sec "${BENCH_PAYLOAD_MB[$i]}" "$mean_s")"

        jq -n \
            --arg operation "${BENCH_OPERATIONS[$i]}" \
            --arg metric "latency" \
            --arg command "${BENCH_COMMANDS[$i]}" \
            --arg source_json "$json_file" \
            --argjson p50_us "$p50_us" \
            --argjson p95_us "$p95_us" \
            --argjson p99_us "$p99_us" \
            --argjson throughput_ops_sec "$throughput_ops_sec" \
            --argjson throughput_mb_sec "$throughput_mb_sec" \
            '{
                operation: $operation,
                metric: $metric,
                command: $command,
                source_json: $source_json,
                p50_us: $p50_us,
                p95_us: $p95_us,
                p99_us: $p99_us,
                throughput_ops_sec: $throughput_ops_sec,
                throughput_mb_sec: $throughput_mb_sec,
                status: "measured"
            }' >> "$tmp_measurements"
    done

    local measured_json
    local measurements_json
    measured_json="$(jq -s '.' "$tmp_measurements")"
    local pending_json='[
      {
        "operation": "write_seq_4k",
        "metric": "latency",
        "command": "",
        "source_json": "",
        "p50_us": 0,
        "p95_us": 0,
        "p99_us": 0,
        "throughput_ops_sec": 0,
        "throughput_mb_sec": 0,
        "status": "pending",
        "reason": "write-path benchmark scenario not yet automated in benchmark_record.sh"
      },
      {
        "operation": "write_random_4k",
        "metric": "latency",
        "command": "",
        "source_json": "",
        "p50_us": 0,
        "p95_us": 0,
        "p99_us": 0,
        "throughput_ops_sec": 0,
        "throughput_mb_sec": 0,
        "status": "pending",
        "reason": "write-path benchmark scenario not yet automated in benchmark_record.sh"
      },
      {
        "operation": "fsync_single_write",
        "metric": "latency",
        "command": "",
        "source_json": "",
        "p50_us": 0,
        "p95_us": 0,
        "p99_us": 0,
        "throughput_ops_sec": 0,
        "throughput_mb_sec": 0,
        "status": "pending",
        "reason": "fsync benchmark scenario not yet automated in benchmark_record.sh"
      },
      {
        "operation": "fsync_batch_100",
        "metric": "latency",
        "command": "",
        "source_json": "",
        "p50_us": 0,
        "p95_us": 0,
        "p99_us": 0,
        "throughput_ops_sec": 0,
        "throughput_mb_sec": 0,
        "status": "pending",
        "reason": "fsync benchmark scenario not yet automated in benchmark_record.sh"
      },
      {
        "operation": "mount_cold",
        "metric": "latency",
        "command": "",
        "source_json": "",
        "p50_us": 0,
        "p95_us": 0,
        "p99_us": 0,
        "throughput_ops_sec": 0,
        "throughput_mb_sec": 0,
        "status": "pending",
        "reason": "mount latency scenario not yet automated in benchmark_record.sh"
      },
      {
        "operation": "mount_warm",
        "metric": "latency",
        "command": "",
        "source_json": "",
        "p50_us": 0,
        "p95_us": 0,
        "p99_us": 0,
        "throughput_ops_sec": 0,
        "throughput_mb_sec": 0,
        "status": "pending",
        "reason": "mount latency scenario not yet automated in benchmark_record.sh"
      },
      {
        "operation": "mount_recovery",
        "metric": "latency",
        "command": "",
        "source_json": "",
        "p50_us": 0,
        "p95_us": 0,
        "p99_us": 0,
        "throughput_ops_sec": 0,
        "throughput_mb_sec": 0,
        "status": "pending",
        "reason": "mount recovery scenario not yet automated in benchmark_record.sh"
      }
    ]'
    measurements_json="$(jq -n --argjson measured "$measured_json" --argjson pending "$pending_json" '$measured + $pending')"

    jq -n \
        --arg generated_at "$date_iso" \
        --arg date_tag "$DATE_TAG" \
        --arg commit "$git_sha" \
        --arg branch "$git_branch" \
        --arg cpu_model "$cpu_model" \
        --arg kernel "$kernel_ver" \
        --arg rustc "$rustc_ver" \
        --arg cargo "$cargo_ver" \
        --arg hyperfine "$hyperfine_ver" \
        --argjson warmup_runs "$WARMUP" \
        --argjson measured_runs "$RUNS" \
        --argjson p99_fail_threshold_percent "$P99_FAIL_THRESHOLD" \
        --argjson measurements "$measurements_json" \
        --argjson measured_count "$(jq 'map(select(.status == "measured")) | length' <<<"$measurements_json")" \
        --argjson pending_count "$(jq 'map(select(.status == "pending")) | length' <<<"$measurements_json")" \
        '{
            generated_at: $generated_at,
            date_tag: $date_tag,
            commit: $commit,
            branch: $branch,
            environment: {
                cpu_model: $cpu_model,
                kernel: $kernel,
                rustc: $rustc,
                cargo: $cargo,
                hyperfine: $hyperfine
            },
            warmup_runs: $warmup_runs,
            measured_runs: $measured_runs,
            p99_fail_threshold_percent: $p99_fail_threshold_percent,
            measurement_coverage: {
                measured_count: $measured_count,
                pending_count: $pending_count
            },
            measurements: $measurements
        }' > "$PERF_BASELINE_PATH"

    cp "$PERF_BASELINE_PATH" "$PERF_BASELINE_DATED_PATH"
    rm -f "$tmp_measurements"
}

cpu_model="$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
if [ -z "${cpu_model}" ]; then
    cpu_model="unknown"
fi

git_sha="$(git rev-parse HEAD)"
git_branch="$(git branch --show-current)"
rustc_ver="$(rustc --version)"
cargo_ver="$(cargo --version)"
hyperfine_ver="$(hyperfine --version)"
kernel_ver="$(uname -srmo)"
date_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
    echo "# FrankenFS Baseline — ${DATE_TAG}"
    echo ""
    echo "## Metadata"
    echo ""
    echo "- Date (UTC): \`${date_iso}\`"
    echo "- Commit: \`${git_sha}\`"
    echo "- Branch: \`${git_branch}\`"
    echo "- Host kernel: \`${kernel_ver}\`"
    echo "- CPU: \`${cpu_model}\`"
    echo "- rustc: \`${rustc_ver}\`"
    echo "- cargo: \`${cargo_ver}\`"
    echo "- hyperfine: \`${hyperfine_ver}\`"
    echo "- Warmup runs: \`${WARMUP}\`"
    echo "- Measured runs: \`${RUNS}\`"
    echo ""
    echo "## Preflight Conformance Gate"
    echo ""
    if [ "$VERIFY_GOLDEN" -eq 1 ]; then
        echo "- \`scripts/verify_golden.sh\`: **PASS**"
    else
        echo "- \`scripts/verify_golden.sh\`: SKIPPED (\`--skip-verify-golden\`)"
    fi
    echo ""
    echo "## Commands"
    echo ""
    for i in "${!BENCH_LABELS[@]}"; do
        echo "- \`${BENCH_COMMANDS[$i]}\`"
    done
    if [ "${#SKIPPED_LABELS[@]}" -gt 0 ]; then
        echo ""
        echo "### Skipped"
        echo ""
        for skipped in "${SKIPPED_LABELS[@]}"; do
            echo "- ${skipped}"
        done
    fi
    echo ""
    echo "## Hyperfine Summary"
    echo ""
    echo "| Command | Mean (ms) | Stddev (ms) | p50 (ms) | p95 (ms) | p99 (ms) | JSON |"
    echo "|---|---:|---:|---:|---:|---:|---|"
    for i in "${!BENCH_LABELS[@]}"; do
        json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
        mean_s="$(json_mean "$json_file")"
        std_s="$(json_stddev "$json_file")"
        p50_s="$(json_p50 "$json_file")"
        p95_s="$(json_p95 "$json_file")"
        p99_s="$(json_p99 "$json_file")"
        mean_ms="$(sec_to_ms "$mean_s")"
        std_ms="$(sec_to_ms "$std_s")"
        p50_ms="$(sec_to_ms "$p50_s")"
        p95_ms="$(sec_to_ms "$p95_s")"
        p99_ms="$(sec_to_ms "$p99_s")"
        echo "| ${BENCH_LABELS[$i]} | ${mean_ms} | ${std_ms} | ${p50_ms} | ${p95_ms} | ${p99_ms} | \`${json_file}\` |"
    done
} > "$REPORT_PATH"

write_perf_baseline_json

COMPARE_STATUS=0
COMPARE_SUMMARY=""
if [ "$COMPARE" -eq 1 ]; then
    if [ -d "baselines/hyperfine" ]; then
        previous_tag="$(find baselines/hyperfine -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | grep -v "^${DATE_TAG}\$" | tail -n1 || true)"
    else
        previous_tag=""
    fi

    if [ -n "$previous_tag" ]; then
        previous_dir="baselines/hyperfine/${previous_tag}"
        COMPARE_SUMMARY+="## Regression Check (vs ${previous_tag})"$'\n\n'
        COMPARE_SUMMARY+="Thresholds: warn if p99 regresses >${P99_WARN_THRESHOLD}%; fail if >${P99_FAIL_THRESHOLD}%."$'\n\n'
        COMPARE_SUMMARY+="| Command | Baseline p99 (ms) | Current p99 (ms) | Delta % | Status |"$'\n'
        COMPARE_SUMMARY+="|---|---:|---:|---:|---|"$'\n'

        for i in "${!BENCH_LABELS[@]}"; do
            cur_json="${OUT_DIR}/${BENCH_FILES[$i]}"
            prev_json="${previous_dir}/${BENCH_FILES[$i]}"
            if [ ! -f "$prev_json" ]; then
                COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | n/a | n/a | n/a | SKIP (no prior file) |"$'\n'
                continue
            fi

            cur_p99_s="$(json_p99 "$cur_json" 2>/dev/null || true)"
            prev_p99_s="$(json_p99 "$prev_json" 2>/dev/null || true)"
            if [ -z "$cur_p99_s" ] || [ -z "$prev_p99_s" ] || ! valid_number "$cur_p99_s" || ! valid_number "$prev_p99_s"; then
                COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | n/a | n/a | n/a | SKIP (invalid hyperfine JSON) |"$'\n'
                continue
            fi
            if awk -v base="$prev_p99_s" 'BEGIN { exit !(base <= 0.0) }'; then
                COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | n/a | n/a | n/a | SKIP (baseline p99 <= 0) |"$'\n'
                continue
            fi

            cur_p99_ms="$(sec_to_ms "$cur_p99_s")"
            prev_p99_ms="$(sec_to_ms "$prev_p99_s")"
            delta_pct="$(pct_change "$prev_p99_s" "$cur_p99_s")"

            status="OK"
            if awk -v d="$delta_pct" -v threshold="$P99_FAIL_THRESHOLD" 'BEGIN { exit !(d > threshold) }'; then
                status="FAIL"
                COMPARE_STATUS=1
            elif awk -v d="$delta_pct" -v threshold="$P99_WARN_THRESHOLD" 'BEGIN { exit !(d > threshold) }'; then
                status="WARN"
            fi
            COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | ${prev_p99_ms} | ${cur_p99_ms} | ${delta_pct}% | ${status} |"$'\n'
        done
    else
        COMPARE_SUMMARY+="## Regression Check"$'\n\n'
        COMPARE_SUMMARY+="No prior baseline directory found under \`baselines/hyperfine/\`; compare skipped."$'\n'
    fi

    {
        echo ""
        echo "${COMPARE_SUMMARY}"
    } >> "$REPORT_PATH"
fi

echo "Wrote baseline report: ${REPORT_PATH}"
echo "Wrote structured baseline JSON: ${PERF_BASELINE_PATH}"
echo "Wrote dated structured baseline JSON: ${PERF_BASELINE_DATED_PATH}"
echo "Wrote hyperfine exports:"
for i in "${!BENCH_LABELS[@]}"; do
    echo "  - ${OUT_DIR}/${BENCH_FILES[$i]}"
done
if [ "${#SKIPPED_LABELS[@]}" -gt 0 ]; then
    echo "Skipped commands:"
    for skipped in "${SKIPPED_LABELS[@]}"; do
        echo "  - ${skipped}"
    done
fi

if [ "$COMPARE" -eq 1 ]; then
    echo ""
    echo "Regression check summary:"
    echo "${COMPARE_SUMMARY}"
fi

exit "$COMPARE_STATUS"
