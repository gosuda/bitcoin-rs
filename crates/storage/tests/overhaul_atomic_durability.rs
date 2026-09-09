//! Storage fault-injection coverage for RCV-03 and RCV-04 in
//! `docs/contracts/recovery.md`.
//!
//! A reopened batch must be entirely old or entirely new across all families.
//! Read failures fail the test; they are not evidence of an empty store.
//! These injected faults and clean reopens do not substitute for process-death
//! or power-loss testing of the complete chainstate commit protocol.

#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin_rs_storage::{
    ColumnFamily, KvStore, PersistFault, StorageError, WriteBatch, WriteCondition,
};
use std::path::Path;

const ROWS: [(ColumnFamily, &[u8]); 3] = [
    (ColumnFamily::TxConfirmed, &[0]),
    (ColumnFamily::Funding, &[1]),
    (ColumnFamily::Spending, &[2]),
];

type FamilyState = Vec<(Vec<u8>, Vec<u8>)>;

fn snapshot_all(store: &impl KvStore, rows: &[(ColumnFamily, &[u8])]) -> Vec<FamilyState> {
    rows.iter()
        .map(|(cf, _)| {
            let mut observed = store
                .iter_prefix(*cf, b"")
                .expect("open recovery iterator")
                .collect::<Result<Vec<_>, _>>()
                .expect("read every recovery row");
            observed.sort();
            observed
        })
        .collect()
}

fn expected_state(rows: &[(ColumnFamily, &[u8])], value: &[u8]) -> Vec<FamilyState> {
    rows.iter()
        .map(|(_, key)| vec![(key.to_vec(), value.to_vec())])
        .collect()
}

fn batch<S: KvStore>(store: &S, rows: &[(ColumnFamily, &[u8])], value: &[u8]) -> S::WriteBatch {
    let mut batch = store.new_batch();
    for (cf, key) in rows {
        batch.put(*cf, key, value);
    }
    batch
}

fn assert_atomic_recovery(
    observed: &[FamilyState],
    old: &[FamilyState],
    proposed: &[FamilyState],
    label: &str,
) {
    assert!(
        observed == old || observed == proposed,
        "{label}: mixed batch: observed={observed:?}, old={old:?}, proposed={proposed:?}"
    );
}

#[test]
#[should_panic(expected = "mixed batch")]
fn recovery_checker_rejects_cross_family_mixture() {
    let old = expected_state(&ROWS, b"old");
    let proposed = expected_state(&ROWS, b"new");
    let mut mixed = old.clone();
    mixed[1].clone_from(&proposed[1]);
    assert_atomic_recovery(&mixed, &old, &proposed, "checker regression");
}

#[derive(Debug)]
enum Route {
    Write,
    WriteDurable,
    WriteDurableIf,
    FlushDeferred,
}

impl Route {
    fn apply<S: KvStore>(
        &self,
        store: &S,
        batch: S::WriteBatch,
        guard_family: ColumnFamily,
    ) -> Result<(), StorageError> {
        match self {
            Self::Write => store.write(batch),
            Self::WriteDurable => store.write_durable(batch),
            Self::WriteDurableIf => store
                .write_durable_if(
                    &[WriteCondition::Absent {
                        cf: guard_family,
                        key: &[0xff],
                    }],
                    batch,
                )
                .map(|committed| assert!(committed, "the absent-key guard must match")),
            Self::FlushDeferred => store.write_deferred(batch).and_then(|()| store.flush()),
        }
    }

    fn completion_fault(&self, fault: PersistFault) -> bool {
        match self {
            Self::WriteDurable | Self::WriteDurableIf => {
                matches!(fault, PersistFault::FailSync | PersistFault::LostSync)
            }
            Self::FlushDeferred => fault == PersistFault::FailFlush,
            Self::Write => false,
        }
    }
}

const FAULTS: [PersistFault; 7] = [
    PersistFault::FailApply,
    PersistFault::LostApply,
    PersistFault::PartialApply,
    PersistFault::FailSync,
    PersistFault::LostSync,
    PersistFault::FailFlush,
    PersistFault::LostFlush,
];

#[test]
#[cfg(feature = "fjall")]
fn fjall_injected_faults_never_mix_families() {
    run_fault_matrix(
        "fjall",
        |path| bitcoin_rs_storage::FjallStore::open(path),
        &ROWS,
    );
}

#[test]
#[cfg(feature = "redb")]
fn redb_injected_faults_never_mix_families() {
    run_fault_matrix(
        "redb",
        |path| bitcoin_rs_storage::RedbStore::open(path),
        &ROWS,
    );
}

#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_injected_faults_never_mix_families() {
    run_fault_matrix(
        "rocksdb",
        |path| bitcoin_rs_storage::RocksDbStore::open(path),
        &ROWS,
    );
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_injected_faults_never_mix_families() {
    run_fault_matrix(
        "mdbx",
        |path| bitcoin_rs_storage::MdbxStore::open(path),
        &ROWS,
    );
}

#[test]
#[cfg(feature = "redb")]
fn redb_txindex_injected_faults_never_mix_families() {
    // The txindex adapter requires a fixed-width TxConfirmed key.
    let rows: [(ColumnFamily, &[u8]); 2] = [
        (ColumnFamily::UtxoMeta, b"meta"),
        (ColumnFamily::TxConfirmed, &[7; 12]),
    ];
    run_fault_matrix(
        "redb-txindex",
        |path| bitcoin_rs_storage::open_redb_tx_index_store(path),
        &rows,
    );
}

fn run_fault_matrix<S, F>(backend: &str, open: F, rows: &[(ColumnFamily, &[u8])])
where
    S: KvStore,
    F: Fn(&Path) -> Result<S, StorageError>,
{
    let old = expected_state(rows, b"old");
    let proposed = expected_state(rows, b"new");
    for route in [
        Route::Write,
        Route::WriteDurable,
        Route::WriteDurableIf,
        Route::FlushDeferred,
    ] {
        for fault in FAULTS {
            let dir = tempfile::tempdir().expect("tempdir");
            let label = format!("{backend}/{route:?}/{fault:?}");
            {
                let store = open(dir.path()).expect("open for seed");
                store
                    .write_durable(batch(&store, rows, b"old"))
                    .expect("seed write");
                assert_eq!(snapshot_all(&store, rows), old, "{label}: seed state");
            }
            let outcome = {
                let store = open(dir.path()).expect("reopen to arm");
                store.arm_persist_fault(fault);
                route.apply(&store, batch(&store, rows, b"new"), rows[0].0)
            };
            let store = open(dir.path()).expect("reopen to inspect");
            assert_atomic_recovery(&snapshot_all(&store, rows), &old, &proposed, &label);
            if route.completion_fault(fault) {
                assert!(
                    outcome.is_err(),
                    "{label}: durable route reported success on a faulted completion"
                );
            }
        }
    }
}

#[test]
#[cfg(feature = "fjall")]
fn fjall_condition_mismatch_applies_nothing_and_consumes_no_fault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::FjallStore::open(dir.path()).expect("open");
    assert_mismatch_applies_nothing_and_consumes_no_fault(&store);
}

#[test]
#[cfg(feature = "redb")]
fn redb_condition_mismatch_applies_nothing_and_consumes_no_fault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::RedbStore::open(dir.path()).expect("open");
    assert_mismatch_applies_nothing_and_consumes_no_fault(&store);
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_condition_mismatch_applies_nothing_and_consumes_no_fault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::MdbxStore::open(dir.path()).expect("open");
    assert_mismatch_applies_nothing_and_consumes_no_fault(&store);
}

#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_condition_mismatch_applies_nothing_and_consumes_no_fault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("open");
    assert_mismatch_applies_nothing_and_consumes_no_fault(&store);
}

fn assert_mismatch_applies_nothing_and_consumes_no_fault<S: KvStore>(store: &S) {
    store
        .write_durable(batch(store, &ROWS, b"old"))
        .expect("seed");
    store.arm_persist_fault(PersistFault::FailApply);
    let committed = store
        .write_durable_if(
            &[WriteCondition::Equals {
                cf: ROWS[0].0,
                key: ROWS[0].1,
                expected: b"not-the-seeded-value",
            }],
            batch(store, &ROWS, b"new"),
        )
        .expect("condition evaluation must not error");
    assert!(!committed, "condition mismatch must report Ok(false)");
    assert_eq!(snapshot_all(store, &ROWS), expected_state(&ROWS, b"old"));

    let outcome = store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ROWS[0].0,
            key: ROWS[0].1,
            expected: b"old",
        }],
        batch(store, &ROWS, b"newer"),
    );
    assert!(outcome.is_err(), "the matching call must consume FailApply");
}

#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_fail_apply_errors_on_plain_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("open");
    store.arm_persist_fault(PersistFault::FailApply);
    assert!(store.write(batch(&store, &ROWS, b"new")).is_err());
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_fail_apply_errors_on_plain_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::MdbxStore::open(dir.path()).expect("open");
    store.arm_persist_fault(PersistFault::FailApply);
    assert!(store.write(batch(&store, &ROWS, b"new")).is_err());
}

#[test]
#[cfg(feature = "fjall")]
fn fjall_snapshot_is_coherent_across_batch_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::FjallStore::open(dir.path()).expect("open");
    store
        .write_durable(batch(&store, &ROWS, b"before"))
        .expect("seed");
    let snapshot = store.snapshot().expect("snapshot");
    store
        .write(batch(&store, &ROWS, b"after"))
        .expect("commit while held");
    for (cf, key) in ROWS {
        let observed = snapshot
            .get(cf, key)
            .expect("snapshot read")
            .expect("row exists");
        assert_eq!(
            observed.as_slice(),
            b"before",
            "snapshot mixed pre- and post-batch rows"
        );
    }
}
