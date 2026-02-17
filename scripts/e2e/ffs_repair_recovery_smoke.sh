#!/usr/bin/env bash
# ffs_repair_recovery_smoke.sh - Deterministic corruption/recovery E2E smoke

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target-codex-ruby}"

REPAIR_E2E_TEST="${REPAIR_E2E_TEST:-e2e_survive_five_percent_random_block_corruption_with_daemon}"
REPAIR_FIXTURE_SIZE_MB="${REPAIR_FIXTURE_SIZE_MB:-16}"

have_repair_e2e_test() {
    if command -v rg >/dev/null 2>&1; then
        rg -q "fn ${REPAIR_E2E_TEST}\\(" "$REPO_ROOT/crates/ffs-repair/src/pipeline.rs"
        return $?
    fi
    grep -q "fn ${REPAIR_E2E_TEST}(" "$REPO_ROOT/crates/ffs-repair/src/pipeline.rs"
}

have_artifacts() {
    local artifact_dir="$1"
    local name
    for name in before_checksums.txt after_checksums.txt corruption_plan.json recovery_evidence.jsonl; do
        if [[ ! -f "$artifact_dir/$name" ]]; then
            return 1
        fi
    done
    return 0
}

e2e_init "ffs_repair_recovery_smoke"
e2e_print_env

e2e_step "Phase 1: prerequisites"
if ! command -v rch >/dev/null 2>&1; then
    e2e_skip "rch not found; this test requires offloaded cargo execution"
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    e2e_skip "sha256sum not found"
fi
if ! have_repair_e2e_test; then
    e2e_skip "repair pipeline test '${REPAIR_E2E_TEST}' not found; skipping until recovery pipeline is available"
fi

ARTIFACT_DIR="$E2E_LOG_DIR/repair"
mkdir -p "$ARTIFACT_DIR"

e2e_step "Phase 2: produce ext4 fixture image"
EXT4_FIXTURE="$ARTIFACT_DIR/ext4_fixture.img"
e2e_create_ext4_image "$EXT4_FIXTURE" "$REPAIR_FIXTURE_SIZE_MB"
e2e_assert_file "$EXT4_FIXTURE"
e2e_assert sha256sum "$EXT4_FIXTURE"

e2e_step "Phase 3: run deterministic corruption/recovery scenario"
export FFS_REPAIR_E2E_ARTIFACT_DIR="$ARTIFACT_DIR"
e2e_assert rch exec -- cargo test -p ffs-repair "$REPAIR_E2E_TEST" -- --nocapture

if ! have_artifacts "$ARTIFACT_DIR"; then
    if [[ "${FFS_REPAIR_LOCAL_ARTIFACT_FALLBACK:-0}" == "1" ]]; then
        e2e_log "Artifacts not present after rch run; using local fallback capture"
        e2e_assert cargo test -p ffs-repair "$REPAIR_E2E_TEST" -- --nocapture
    else
        e2e_skip "repair test passed via rch but expected artifact files were not materialized locally; rerun with FFS_REPAIR_LOCAL_ARTIFACT_FALLBACK=1 if local artifact capture is required"
    fi
fi

e2e_step "Phase 4: verify artifacts and recovery equivalence"
e2e_assert_file "$ARTIFACT_DIR/before_checksums.txt"
e2e_assert_file "$ARTIFACT_DIR/after_checksums.txt"
e2e_assert_file "$ARTIFACT_DIR/corruption_plan.json"
e2e_assert_file "$ARTIFACT_DIR/recovery_evidence.jsonl"
e2e_assert cmp "$ARTIFACT_DIR/before_checksums.txt" "$ARTIFACT_DIR/after_checksums.txt"

if command -v python3 >/dev/null 2>&1; then
    FFS_REPAIR_ARTIFACT_DIR="$ARTIFACT_DIR" e2e_assert python3 -c "import json, os, pathlib; d=pathlib.Path(os.environ['FFS_REPAIR_ARTIFACT_DIR']); plan=json.loads((d/'corruption_plan.json').read_text()); pct=int(plan['corruption_percent']); blocks=plan['corrupted_blocks']; total=int(plan['total_corrupted_blocks']); assert 1 <= pct <= 5, pct; assert total == len(blocks) and total > 0, total; assert len(set(blocks)) == len(blocks), 'duplicate corrupted blocks'; before=(d/'before_checksums.txt').read_text().strip().splitlines(); after=(d/'after_checksums.txt').read_text().strip().splitlines(); assert before and after and before == after, 'checksum mismatch'; lines=[line for line in (d/'recovery_evidence.jsonl').read_text().splitlines() if line.strip()]; assert lines, 'empty evidence ledger'; events={json.loads(line).get('event_type') for line in lines}; assert 'corruption_detected' in events, events; assert 'repair_succeeded' in events, events"
else
    e2e_log "python3 not found; skipping deep JSON validation"
fi

e2e_run wc -l "$ARTIFACT_DIR/recovery_evidence.jsonl"

e2e_pass
