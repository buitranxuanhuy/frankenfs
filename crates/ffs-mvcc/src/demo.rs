use crate::{CommitError, MvccStore, Transaction};
use ffs_types::{BlockNumber, CommitSeq, Snapshot};
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotIsolationDemoResult {
    pub reader_a_first: u8,
    pub reader_a_after: u8,
    pub reader_b: u8,
    pub writer_commit_seq: CommitSeq,
    pub isolated: bool,
}

impl SnapshotIsolationDemoResult {
    #[must_use]
    pub fn output_lines(&self) -> [String; 5] {
        [
            format!("reader A sees version {}", self.reader_a_first),
            format!("writer commits version {}", self.writer_commit_seq.0),
            format!("reader A still sees version {}", self.reader_a_after),
            format!("reader B sees version {}", self.reader_b),
            format!(
                "snapshot isolation: {}",
                if self.isolated { "PASS" } else { "FAIL" }
            ),
        ]
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DemoError {
    #[error("commit failed: {0}")]
    Commit(#[from] CommitError),
    #[error(
        "no visible bytes for {reader} at block {block:?} for snapshot {snapshot_commit_seq:?}"
    )]
    MissingVisible {
        reader: &'static str,
        block: BlockNumber,
        snapshot_commit_seq: CommitSeq,
    },
}

pub fn run_snapshot_isolation_demo() -> Result<SnapshotIsolationDemoResult, DemoError> {
    let block = BlockNumber(7);
    let mut store = MvccStore::new();

    let mut seed_writer = store.begin();
    log_txn_start(&seed_writer);
    seed_writer.stage_write(block, vec![1]);
    let bootstrap_txn_id = seed_writer.id();
    let seed_write_count = seed_writer.pending_writes();
    let bootstrap_commit_seq = store.commit(seed_writer)?;
    log_txn_commit(bootstrap_txn_id.0, bootstrap_commit_seq, seed_write_count);

    let mut reader_a = store.begin();
    log_txn_start(&reader_a);
    reader_a.record_read(block, reader_a.snapshot().high);
    log_read(&reader_a, block, reader_a.snapshot().high);
    let reader_a_first = read_first_byte(&store, block, reader_a.snapshot(), "reader A")?;

    let mut writer = store.begin();
    log_txn_start(&writer);
    writer.stage_write(block, vec![2]);
    let writer_txn_id = writer.id();
    let writer_writes = writer.pending_writes();
    let writer_commit_seq = store.commit(writer)?;
    log_txn_commit(writer_txn_id.0, writer_commit_seq, writer_writes);

    let reader_a_after = read_first_byte(&store, block, reader_a.snapshot(), "reader A")?;
    log_read(&reader_a, block, reader_a.snapshot().high);
    let reader_a_stable = reader_a_first == 1 && reader_a_after == 1;
    info!(
        reader_txn = reader_a.id().0,
        expected_version = 1_u8,
        actual_version = reader_a_after,
        isolated = reader_a_stable,
        "isolation_check"
    );

    let mut reader_b = store.begin();
    log_txn_start(&reader_b);
    reader_b.record_read(block, reader_b.snapshot().high);
    log_read(&reader_b, block, reader_b.snapshot().high);
    let reader_b_value = read_first_byte(&store, block, reader_b.snapshot(), "reader B")?;
    let reader_b_matches_latest = reader_b_value == 2;
    info!(
        reader_txn = reader_b.id().0,
        expected_version = 2_u8,
        actual_version = reader_b_value,
        isolated = reader_b_matches_latest,
        "isolation_check"
    );

    let isolated = reader_a_stable && reader_b_matches_latest;
    Ok(SnapshotIsolationDemoResult {
        reader_a_first,
        reader_a_after,
        reader_b: reader_b_value,
        writer_commit_seq,
        isolated,
    })
}

fn read_first_byte(
    store: &MvccStore,
    block: BlockNumber,
    snapshot: Snapshot,
    reader: &'static str,
) -> Result<u8, DemoError> {
    let bytes = store
        .read_visible(block, snapshot)
        .ok_or(DemoError::MissingVisible {
            reader,
            block,
            snapshot_commit_seq: snapshot.high,
        })?;
    Ok(bytes.first().copied().unwrap_or_default())
}

fn log_txn_start(txn: &Transaction) {
    info!(
        txn_id = txn.id().0,
        snapshot_seq = txn.snapshot().high.0,
        "transaction_start"
    );
}

fn log_read(txn: &Transaction, block: BlockNumber, version_seen: CommitSeq) {
    debug!(
        txn_id = txn.id().0,
        block = block.0,
        version_seen = version_seen.0,
        "transaction_read"
    );
}

fn log_txn_commit(txn_id: u64, commit_seq: CommitSeq, blocks_written: usize) {
    info!(
        txn_id,
        commit_seq = commit_seq.0,
        blocks_written,
        "transaction_commit"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_isolation_demo_is_deterministic() {
        let result = run_snapshot_isolation_demo().expect("demo should succeed");
        assert_eq!(result.reader_a_first, 1);
        assert_eq!(result.reader_a_after, 1);
        assert_eq!(result.reader_b, 2);
        assert_eq!(result.writer_commit_seq, CommitSeq(2));
        assert!(result.isolated);
    }

    #[test]
    fn snapshot_isolation_demo_output_pattern() {
        let result = run_snapshot_isolation_demo().expect("demo should succeed");
        let lines = result.output_lines();
        let output = lines.as_slice().join("\n");

        assert!(output.contains("reader A sees version 1"));
        assert!(output.contains("writer commits version 2"));
        assert!(output.contains("reader A still sees version 1"));
        assert!(output.contains("reader B sees version 2"));
        assert!(output.contains("snapshot isolation: PASS"));
    }
}
