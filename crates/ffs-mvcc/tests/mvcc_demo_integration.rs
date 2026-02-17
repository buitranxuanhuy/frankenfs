use ffs_mvcc::demo::run_snapshot_isolation_demo;
use ffs_types::CommitSeq;

#[test]
fn snapshot_isolation_demo_invariant() {
    let result = run_snapshot_isolation_demo().expect("demo should succeed");

    assert_eq!(result.reader_a_first, 1);
    assert_eq!(result.reader_a_after, 1);
    assert_eq!(result.reader_b, 2);
    assert_eq!(result.writer_commit_seq, CommitSeq(2));
    assert!(result.isolated, "reader snapshots must remain isolated");
}
