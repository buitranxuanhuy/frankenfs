use ffs_mvcc::{CommitError, MvccStore};
use ffs_repair::evidence::{EvidenceEventType, TxnAbortReason, parse_evidence_ledger};
use ffs_types::BlockNumber;
use std::path::{Path, PathBuf};

fn build_store_with_ledger() -> (MvccStore, PathBuf) {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let ledger_path = std::env::temp_dir().join(format!(
        "ffs_mvcc_evidence_{pid}_{ns}.jsonl",
        pid = std::process::id(),
        ns = now_ns
    ));
    if ledger_path.exists() {
        std::fs::remove_file(&ledger_path).expect("remove stale ledger file");
    }
    let mut store = MvccStore::new();
    store
        .enable_evidence_ledger(&ledger_path)
        .expect("enable evidence ledger");
    (store, ledger_path)
}

fn load_records(path: &Path) -> Vec<ffs_repair::evidence::EvidenceRecord> {
    let data = std::fs::read(path).expect("read evidence ledger");
    parse_evidence_ledger(&data)
}

#[test]
fn commit_produces_transaction_commit_evidence() {
    let (mut store, ledger_path) = build_store_with_ledger();
    let block = BlockNumber(10);

    let mut txn = store.begin();
    txn.stage_write(block, vec![9, 9, 9]);
    let commit_seq = store.commit(txn).expect("commit succeeds");

    let records = load_records(&ledger_path);
    let commit_record = records
        .iter()
        .find(|record| record.event_type == EvidenceEventType::TransactionCommit)
        .expect("transaction_commit record present");
    let detail = commit_record
        .transaction_commit
        .as_ref()
        .expect("transaction_commit detail");
    assert_eq!(detail.commit_seq, commit_seq.0);
    assert_eq!(detail.write_set_size, 1);
}

#[test]
fn abort_produces_txn_aborted_evidence() {
    let (mut store, ledger_path) = build_store_with_ledger();
    let block = BlockNumber(12);

    let mut txn = store.begin();
    txn.record_read(block, txn.snapshot().high);
    txn.stage_write(block, vec![1]);
    store.abort(
        txn,
        TxnAbortReason::UserAbort,
        Some("manual integration-test abort".to_owned()),
    );

    let records = load_records(&ledger_path);
    let abort_record = records
        .iter()
        .find(|record| record.event_type == EvidenceEventType::TxnAborted)
        .expect("txn_aborted record present");
    let detail = abort_record
        .txn_aborted
        .as_ref()
        .expect("txn_aborted detail");
    assert_eq!(detail.reason, TxnAbortReason::UserAbort);
    assert_eq!(detail.read_set_size, 1);
    assert_eq!(detail.write_set_size, 1);
}

#[test]
fn ssi_conflict_produces_serialization_conflict_evidence() {
    let (mut store, ledger_path) = build_store_with_ledger();
    let block_a = BlockNumber(1);
    let block_b = BlockNumber(2);

    let mut seed = store.begin();
    seed.stage_write(block_a, vec![1]);
    seed.stage_write(block_b, vec![1]);
    store.commit(seed).expect("seed commit");

    let mut txn_one = store.begin();
    txn_one.record_read(block_a, store.latest_commit_seq(block_a));
    txn_one.stage_write(block_b, vec![2]);

    let mut txn_two = store.begin();
    txn_two.record_read(block_b, store.latest_commit_seq(block_b));
    txn_two.stage_write(block_a, vec![2]);

    store.commit_ssi(txn_one).expect("first writer commits");
    let second_result = store
        .commit_ssi(txn_two)
        .expect_err("ssi conflict expected");
    assert!(matches!(second_result, CommitError::SsiConflict { .. }));

    let records = load_records(&ledger_path);
    let serialization_record = records
        .iter()
        .find(|record| record.event_type == EvidenceEventType::SerializationConflict)
        .expect("serialization_conflict record present");
    let serialization_detail = serialization_record
        .serialization_conflict
        .as_ref()
        .expect("serialization detail");
    assert_eq!(
        serialization_detail.conflict_type,
        "rw_antidependency_cycle"
    );

    let abort_record = records
        .iter()
        .find(|record| record.event_type == EvidenceEventType::TxnAborted)
        .expect("txn_aborted record present");
    let abort_detail = abort_record.txn_aborted.as_ref().expect("abort detail");
    assert_eq!(abort_detail.reason, TxnAbortReason::SsiCycle);
}

#[test]
fn evidence_ledger_captures_complete_history() {
    let (mut store, ledger_path) = build_store_with_ledger();
    let block = BlockNumber(21);

    let mut committed = store.begin();
    committed.stage_write(block, vec![7]);
    store.commit(committed).expect("commit succeeds");

    let mut explicit_abort = store.begin();
    explicit_abort.stage_write(block, vec![8]);
    store.abort(explicit_abort, TxnAbortReason::UserAbort, None);

    let mut winner = store.begin();
    winner.stage_write(block, vec![9]);
    let mut loser = store.begin();
    loser.stage_write(block, vec![10]);
    store.commit(winner).expect("winner commits");
    let _ = store.commit(loser).expect_err("fcw conflict expected");

    let records = load_records(&ledger_path);
    assert!(
        records
            .iter()
            .any(|record| record.event_type == EvidenceEventType::TransactionCommit),
        "history must contain commit evidence"
    );
    assert!(
        records
            .iter()
            .any(|record| record.event_type == EvidenceEventType::TxnAborted),
        "history must contain abort evidence"
    );
}
