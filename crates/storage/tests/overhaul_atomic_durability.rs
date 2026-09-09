//! RCV-04 fault-injection coverage for the storage ladder.
//! Contract: `docs/contracts/recovery.md#rcv-04-crash-matrix`.
//! This exercises backend seams and clean reopen, not simulated power loss.
//!
//! Every fault in [`PersistFault`] is armed at each persistence boundary and
//! fired against a multi-family batch spanning three column families. After
//! the faulted call and a reopen, each family must hold either the complete
//! pre-batch or the complete post-batch state — never a cross-family mix —
//! and a durability completion (`Ok` from `write_durable`, `Ok(true)` from
//! `write_durable_if`, `Ok` from `flush`) must never precede the persisted
//! write it vouches for.

#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin_rs_storage::{ColumnFamily, KvStore, PersistFault, WriteBatch, WriteCondition};
use std::fmt;
use std::path::Path;

const FAMILIES: [ColumnFamily; 3] = [
    ColumnFamily::TxConfirmed,
    ColumnFamily::Funding,
    ColumnFamily::Spending,
];

/// One family's observed rows at a point in the fault protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FamilyState {
    rows: Vec<(Vec<u8>, Vec<u8>)>,
}

impl fmt::Display for FamilyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} rows: ", self.rows.len())?;
        for (key, value) in &self.rows {
            write!(f, "{key:02x?}->{value:02x?}, ")?;
        }
        Ok(())
    }
}

fn snapshot_all(store: &impl KvStore) -> Vec<FamilyState> {
    FAMILIES
        .iter()
        .map(|cf| {
            let rows = store
                .iter_prefix(*cf, b"")
                .expect("open family iterator")
                .collect::<Result<Vec<_>, _>>()
                .expect("read every family row");
            FamilyState { rows }
        })
        .collect()
}

/// A one-row-per-family batch tagged `label`; family index is the key.
fn multi_family_batch<S: KvStore>(store: &S, label: &[u8]) -> S::WriteBatch {
    let mut batch = store.new_batch();
    for (index, cf) in FAMILIES.iter().enumerate() {
        batch.put(*cf, &[u8::try_from(index).unwrap_or(0)], label);
    }
    batch
}

/// One write route through the ladder.
enum Route {
    Write,
    WriteDurable,
    WriteDurableIf,
    FlushDeferred,
}

impl Route {
    fn label(&self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::WriteDurable => "write_durable",
            Self::WriteDurableIf => "write_durable_if",
            Self::FlushDeferred => "write_deferred+flush",
        }
    }

    fn crosses(&self, boundary: bitcoin_rs_storage::PersistBoundary) -> bool {
        use bitcoin_rs_storage::PersistBoundary;
        match boundary {
            PersistBoundary::Apply => true,
            PersistBoundary::Sync => matches!(self, Self::WriteDurable | Self::WriteDurableIf),
            PersistBoundary::Flush => matches!(self, Self::FlushDeferred),
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

fn fault_name(fault: PersistFault) -> &'static str {
    match fault {
        PersistFault::FailApply => "FailApply",
        PersistFault::LostApply => "LostApply",
        PersistFault::PartialApply => "PartialApply",
        PersistFault::FailSync => "FailSync",
        PersistFault::LostSync => "LostSync",
        PersistFault::FailFlush => "FailFlush",
        PersistFault::LostFlush => "LostFlush",
    }
}

#[test]
#[cfg(feature = "fjall")]
fn fjall_injected_faults_never_mix_families() {
    run_fault_matrix("fjall", |path| bitcoin_rs_storage::FjallStore::open(path));
}

#[test]
#[cfg(feature = "redb")]
fn redb_injected_faults_never_mix_families() {
    run_fault_matrix("redb", |path| bitcoin_rs_storage::RedbStore::open(path));
}

#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_injected_faults_never_mix_families() {
    run_fault_matrix("rocksdb", |path| {
        bitcoin_rs_storage::RocksDbStore::open(path)
    });
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_injected_faults_never_mix_families() {
    run_fault_matrix("mdbx", |path| bitcoin_rs_storage::MdbxStore::open(path));
}

/// The txindex store serves fixed-width physical tables, so its batch uses
/// one `UtxoMeta` row (arbitrary bytes) plus one 12-byte `TxConfirmed` row; both
/// families must still recover whole.
#[test]
#[cfg(feature = "redb")]
fn redb_txindex_injected_faults_never_mix_families() {
    let routes = [
        Route::WriteDurable,
        Route::WriteDurableIf,
        Route::FlushDeferred,
    ];
    for route in &routes {
        for fault in FAULTS {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().to_path_buf();
            let label = format!("redb-txindex/{}/{})", route.label(), fault_name(fault));

            // Seed old state.
            {
                let store =
                    bitcoin_rs_storage::open_redb_tx_index_store(&path).expect("open for seed");
                let mut batch = store.new_batch();
                batch.put(ColumnFamily::UtxoMeta, b"meta", b"old");
                batch.put(ColumnFamily::TxConfirmed, &[7_u8; 12], b"old");
                store.write_durable(batch).expect("seed write");
            }

            // Arm and fire.
            let outcome = {
                let store =
                    bitcoin_rs_storage::open_redb_tx_index_store(&path).expect("reopen to arm");
                store.arm_persist_fault(fault);
                let mut batch = store.new_batch();
                batch.put(ColumnFamily::UtxoMeta, b"meta", b"new");
                batch.put(ColumnFamily::TxConfirmed, &[7_u8; 12], b"new");
                match route {
                    Route::WriteDurable => store.write_durable(batch),
                    Route::WriteDurableIf => store
                        .write_durable_if(
                            &[WriteCondition::Absent {
                                cf: ColumnFamily::UtxoMeta,
                                key: &[0xff],
                            }],
                            batch,
                        )
                        .map(|committed| assert!(committed, "seeded condition must match")),
                    Route::FlushDeferred => {
                        store.write_deferred(batch).and_then(|()| store.flush())
                    }
                    Route::Write => unreachable!("write route excluded above"),
                }
            };

            // Reopen and classify both families.
            let store =
                bitcoin_rs_storage::open_redb_tx_index_store(&path).expect("reopen to inspect");
            let meta = store
                .get(ColumnFamily::UtxoMeta, b"meta")
                .expect("read meta");
            let confirmed = store
                .get(ColumnFamily::TxConfirmed, &[7_u8; 12])
                .expect("read confirmed");
            let both_old = meta.as_deref() == Some(b"old") && confirmed.as_deref() == Some(b"old");
            let both_new = meta.as_deref() == Some(b"new") && confirmed.as_deref() == Some(b"new");
            assert!(
                both_old || both_new,
                "{label}: families recovered as a mix: meta={meta:?} confirmed={confirmed:?}"
            );

            if outcome.is_ok() {
                assert!(
                    both_new,
                    "{label}: success acknowledged an absent durable batch"
                );
            }

            let completion_fault = route.crosses(fault.boundary());
            if completion_fault {
                assert!(
                    outcome.is_err(),
                    "{label}: durable route reported success on a faulted completion"
                );
            }
        }
    }
}

/// The full route × fault matrix: seed the old state durably, arm one fault,
/// fire one route, reopen, and classify every family as entirely-old or
/// entirely-new.
fn run_fault_matrix<S, F>(backend: &str, open: F)
where
    S: KvStore,
    F: Fn(&Path) -> Result<S, bitcoin_rs_storage::StorageError> + Copy,
{
    let routes = [
        Route::Write,
        Route::WriteDurable,
        Route::WriteDurableIf,
        Route::FlushDeferred,
    ];
    for route in &routes {
        for fault in FAULTS {
            let dir = tempfile::tempdir().expect("tempdir");
            one_scenario(backend, open, dir.path(), fault, route);
        }
    }
}

fn one_scenario<S, F>(backend: &str, open: F, path: &Path, fault: PersistFault, route: &Route)
where
    S: KvStore,
    F: Fn(&Path) -> Result<S, bitcoin_rs_storage::StorageError>,
{
    let label = format!("{backend}/{}/{})", route.label(), fault_name(fault));

    // Seed the old state durably.
    let old = {
        let store = open(path).expect("open for seed");
        store
            .write_durable(multi_family_batch(&store, b"old"))
            .expect("seed write");
        snapshot_all(&store)
    };

    // Arm and fire.
    let outcome = {
        let store = open(path).expect("reopen to arm");
        store.arm_persist_fault(fault);
        let batch = multi_family_batch(&store, b"new");
        match route {
            Route::Write => store.write(batch),
            Route::WriteDurable => store.write_durable(batch),
            Route::WriteDurableIf => store
                .write_durable_if(
                    &[WriteCondition::Absent {
                        cf: FAMILIES[0],
                        key: &[0xff],
                    }],
                    batch,
                )
                .map(|committed| assert!(committed, "seeded condition must match")),
            Route::FlushDeferred => store.write_deferred(batch).and_then(|()| store.flush()),
        }
    };

    // Reopen and classify each family.
    let after = {
        let store = open(path).expect("reopen to inspect");
        snapshot_all(&store)
    };
    let expected_new: Vec<_> = old
        .iter()
        .map(|before| FamilyState {
            rows: before
                .rows
                .iter()
                .map(|(key, _)| (key.clone(), b"new".to_vec()))
                .collect(),
        })
        .collect();
    assert!(
        after == old || after == expected_new,
        "{label}: cross-family recovery is neither the whole old nor whole new batch: {after:?}"
    );
    if outcome.is_ok() && !matches!(route, Route::Write) {
        assert_eq!(
            after, expected_new,
            "{label}: success acknowledged an absent durable batch"
        );
    }

    // Completion honesty: routes that promise durability never report success
    // when the durability step faulted.
    let reported_success = outcome.is_ok();
    let completion_fault = route.crosses(fault.boundary());
    if completion_fault {
        assert!(
            !reported_success,
            "{label}: durable route reported success on a faulted completion"
        );
    }
}

/// A condition mismatch applies zero rows and consumes no armed fault.
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
        .write_durable(multi_family_batch(store, b"old"))
        .expect("seed");

    // Arm an apply fault that must never be consulted: the mismatch returns
    // before any persistence boundary.
    store.arm_persist_fault(PersistFault::FailApply);

    let committed = store
        .write_durable_if(
            &[WriteCondition::Equals {
                cf: FAMILIES[0],
                key: &[0],
                expected: b"not-the-seeded-value",
            }],
            multi_family_batch(store, b"new"),
        )
        .expect("condition evaluation must not error");
    assert!(!committed, "condition mismatch must report Ok(false)");

    for (index, cf) in FAMILIES.iter().enumerate() {
        let observed = store
            .get(*cf, &[u8::try_from(index).unwrap_or(0)])
            .expect("read")
            .expect("row exists");
        assert_eq!(
            observed,
            b"old".to_vec(),
            "family {index} observed batch effects from a mismatched conditional write"
        );
    }

    // The armed fault is still live for a later matching call.
    let outcome = store.write_durable_if(
        &[WriteCondition::Equals {
            cf: FAMILIES[0],
            key: &[0],
            expected: b"old",
        }],
        multi_family_batch(store, b"newer"),
    );
    assert!(
        outcome.is_err(),
        "the armed FailApply fault must fire on the matching conditional write"
    );
}

/// `FailApply` is contract-mandated to return `Err` with nothing applied on
/// every write path of every backend; this pins the seam wiring on the plain
/// `write` route the fault matrix deliberately excludes.
#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_fail_apply_errors_on_plain_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("open");
    store.arm_persist_fault(PersistFault::FailApply);
    assert!(
        store.write(multi_family_batch(&store, b"new")).is_err(),
        "FailApply must return Err on the plain write route"
    );
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_fail_apply_errors_on_plain_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::MdbxStore::open(dir.path()).expect("open");
    store.arm_persist_fault(PersistFault::FailApply);
    assert!(
        store.write(multi_family_batch(&store, b"new")).is_err(),
        "FailApply must return Err on the plain write route"
    );
}

/// Snapshots are coherent across a batch commit while held.
#[test]
#[cfg(feature = "fjall")]
fn fjall_snapshot_is_coherent_across_batch_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::FjallStore::open(dir.path()).expect("open");
    store
        .write_durable(multi_family_batch(&store, b"before"))
        .expect("seed");

    let snapshot = store.snapshot().expect("snapshot");
    store
        .write(multi_family_batch(&store, b"after"))
        .expect("commit while held");

    for (index, cf) in FAMILIES.iter().enumerate() {
        let observed = snapshot
            .get(*cf, &[u8::try_from(index).unwrap_or(0)])
            .expect("snapshot read")
            .expect("row exists");
        assert_eq!(
            observed,
            b"before".to_vec(),
            "snapshot mixed pre- and post-batch rows in family {index}"
        );
    }
}
