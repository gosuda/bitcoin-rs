//! Fault-injection regressions for docs/contracts/recovery.md, RCV-04.
//!
//! A reopen must recover the complete old or complete new multi-family state.
//! Reads must succeed, and lost apply/sync/flush boundaries cannot produce false
//! success receipts. These checks do not substitute for power-loss testing.

#![cfg(any(
    feature = "fjall",
    feature = "redb",
    feature = "rocksdb",
    feature = "mdbx"
))]
#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin_rs_storage::{
    ColumnFamily, KvPair, KvStore, PersistFault, StorageError, WriteBatch, WriteCondition,
};

type Image = Vec<Vec<KvPair>>;

const FAMILIES: [ColumnFamily; 3] = [
    ColumnFamily::TxConfirmed,
    ColumnFamily::Funding,
    ColumnFamily::Spending,
];
const FAULTS: [PersistFault; 7] = [
    PersistFault::FailApply,
    PersistFault::LostApply,
    PersistFault::PartialApply,
    PersistFault::FailSync,
    PersistFault::LostSync,
    PersistFault::FailFlush,
    PersistFault::LostFlush,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Write,
    Deferred,
    Durable,
    Conditional,
    Flush,
}

impl Route {
    const fn confirms_durability(self) -> bool {
        matches!(self, Self::Durable | Self::Conditional | Self::Flush)
    }

    const fn must_report_fault(self, fault: PersistFault) -> bool {
        match fault {
            PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply => true,
            PersistFault::FailSync | PersistFault::LostSync => {
                matches!(self, Self::Durable | Self::Conditional)
            }
            PersistFault::FailFlush | PersistFault::LostFlush => matches!(self, Self::Flush),
        }
    }

    fn apply<S: KvStore>(self, store: &S, families: &[ColumnFamily]) -> Result<(), StorageError> {
        let batch = batch(store, families, b"new");
        match self {
            Self::Write => store.write(batch),
            Self::Deferred => store.write_deferred(batch),
            Self::Durable => store.write_durable(batch),
            Self::Conditional => store
                .write_durable_if(
                    &[WriteCondition::Absent {
                        cf: families[0],
                        key: &[0xff; 12],
                    }],
                    batch,
                )
                .map(|committed| assert!(committed, "the known-absent guard must match")),
            Self::Flush => store.write_deferred(batch).and_then(|()| store.flush()),
        }
    }
}

fn key(index: usize) -> [u8; 12] {
    [u8::try_from(index).expect("fixture family index fits in a byte"); 12]
}

fn image(families: &[ColumnFamily], value: &[u8]) -> Image {
    (0..families.len())
        .map(|index| vec![(key(index).to_vec(), value.to_vec())])
        .collect()
}

fn batch<S: KvStore>(store: &S, families: &[ColumnFamily], value: &[u8]) -> S::WriteBatch {
    let mut batch = store.new_batch();
    for (index, cf) in families.iter().enumerate() {
        batch.put(*cf, &key(index), value);
    }
    batch
}

fn snapshot_all(store: &impl KvStore, families: &[ColumnFamily]) -> Image {
    families
        .iter()
        .map(|cf| {
            store
                .iter_prefix(*cf, b"")
                .expect("open family iterator")
                .collect::<Result<Vec<_>, _>>()
                .expect("read every family row")
        })
        .collect()
}

fn assert_atomic(observed: &Image, old: &Image, new: &Image) {
    assert!(
        observed == old || observed == new,
        "cross-family or partial state: {observed:?}"
    );
}

fn run_fault_matrix<S, F>(backend: &str, open: F, families: &[ColumnFamily])
where
    S: KvStore,
    F: Fn() -> Result<S, StorageError>,
{
    let old = image(families, b"old");
    let new = image(families, b"new");
    for route in [
        Route::Write,
        Route::Deferred,
        Route::Durable,
        Route::Conditional,
        Route::Flush,
    ] {
        for fault in FAULTS {
            let label = format!("{backend}/{route:?}/{fault:?}");
            let outcome = {
                let store = open().expect("open store");
                store
                    .write_durable(batch(&store, families, b"old"))
                    .expect("seed durably");
                assert_eq!(snapshot_all(&store, families), old);
                store.arm_persist_fault(fault);
                if route == Route::Conditional {
                    let committed = store
                        .write_durable_if(
                            &[WriteCondition::Equals {
                                cf: families[0],
                                key: &key(0),
                                expected: b"foreign",
                            }],
                            batch(&store, families, b"new"),
                        )
                        .expect("a mismatch must not consume an armed fault");
                    assert!(!committed, "{label}: mismatched guard committed");
                    assert_eq!(snapshot_all(&store, families), old);
                }
                let outcome = route.apply(&store, families);
                let visible = snapshot_all(&store, families);
                assert_atomic(&visible, &old, &new);
                if outcome.is_ok() {
                    assert_eq!(visible, new, "{label}: successful write was not visible");
                }
                if route.must_report_fault(fault) {
                    assert!(outcome.is_err(), "{label}: false success receipt");
                }
                if matches!(
                    fault,
                    PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply
                ) {
                    assert_eq!(visible, old, "{label}: failed apply changed visible state");
                }
                if route == Route::Conditional
                    && matches!(fault, PersistFault::FailFlush | PersistFault::LostFlush)
                {
                    assert!(
                        store.flush().is_err(),
                        "{label}: a condition check consumed the flush fault"
                    );
                }
                outcome
            };
            let store = open().expect("reopen store");
            let recovered = snapshot_all(&store, families);
            assert_atomic(&recovered, &old, &new);
            if outcome.is_ok() && route.confirms_durability() {
                assert_eq!(recovered, new, "{label}: confirmed durable state was lost");
            }
            if matches!(
                fault,
                PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply
            ) {
                assert_eq!(recovered, old, "{label}: aborted apply survived reopen");
            }
        }
    }
}

#[test]
#[cfg(feature = "fjall")]
fn fjall_injected_faults_never_mix_families() {
    let dir = tempfile::tempdir().expect("tempdir");
    run_fault_matrix(
        "fjall",
        || bitcoin_rs_storage::FjallStore::open(dir.path()),
        &FAMILIES,
    );
}

#[test]
#[cfg(feature = "redb")]
fn redb_injected_faults_never_mix_families() {
    let dir = tempfile::tempdir().expect("tempdir");
    run_fault_matrix(
        "redb",
        || bitcoin_rs_storage::RedbStore::open(dir.path()),
        &FAMILIES,
    );
}

#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_injected_faults_never_mix_families() {
    let dir = tempfile::tempdir().expect("tempdir");
    run_fault_matrix(
        "rocksdb",
        || bitcoin_rs_storage::RocksDbStore::open(dir.path()),
        &FAMILIES,
    );
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_injected_faults_never_mix_families() {
    let dir = tempfile::tempdir().expect("tempdir");
    run_fault_matrix(
        "mdbx",
        || bitcoin_rs_storage::MdbxStore::open(dir.path()),
        &FAMILIES,
    );
}

#[test]
#[cfg(feature = "redb")]
fn redb_txindex_injected_faults_never_mix_families() {
    let dir = tempfile::tempdir().expect("tempdir");
    run_fault_matrix(
        "redb-txindex",
        || bitcoin_rs_storage::open_redb_tx_index_store(dir.path()),
        &[ColumnFamily::UtxoMeta, ColumnFamily::TxConfirmed],
    );
}

#[test]
#[should_panic(expected = "cross-family or partial state")]
fn atomicity_assertion_rejects_cross_family_mix() {
    let old = image(&FAMILIES, b"old");
    let new = image(&FAMILIES, b"new");
    let mut mixed = old.clone();
    mixed[0].clone_from(&new[0]);
    assert_atomic(&mixed, &old, &new);
}

#[test]
#[cfg(feature = "fjall")]
fn fjall_snapshot_is_coherent_across_batch_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::FjallStore::open(dir.path()).expect("open");
    store
        .write_durable(batch(&store, &FAMILIES, b"old"))
        .expect("seed");
    let snapshot = store.snapshot().expect("snapshot");
    store
        .write(batch(&store, &FAMILIES, b"new"))
        .expect("commit while snapshot held");
    for (index, cf) in FAMILIES.iter().enumerate() {
        assert_eq!(
            snapshot.get(*cf, &key(index)).expect("snapshot read"),
            Some(b"old".to_vec())
        );
    }
    assert_eq!(snapshot_all(&store, &FAMILIES), image(&FAMILIES, b"new"));
}
