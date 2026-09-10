//! Atomic-durability proofs for the storage ladder under injected
//! persistence faults.
//!
//! This matrix exercises `docs/contracts/recovery.md` RCV-02 (ordered commit
//! and recovery fencing) and RCV-03 (prior-or-whole-proposed roots).
//!
//! Every fault in [`PersistFault`] is armed at each persistence boundary and
//! fired against a multi-family batch spanning three column families. After
//! the faulted call and a reopen, the store as a whole must hold either the
//! complete pre-batch or the complete post-batch state across every column
//! family — never a cross-family mix — and the call must report success only
//! for a silently lost completion (armed by this harness alone); an observed
//! persistence fault surfaces as `Err`, never as a durability completion.

#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvSnapshot, KvStore, PersistFault, StorageError, WriteBatch,
    WriteCondition,
};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

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
            let mut rows = Vec::new();
            if let Ok(iter) = store.iter_prefix(*cf, b"") {
                for (key, value) in iter.flatten() {
                    rows.push((key, value));
                }
            }
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
                        .map(|_| ()),
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

            let completion_fault = match route {
                Route::WriteDurable | Route::WriteDurableIf => fault == PersistFault::FailSync,
                Route::FlushDeferred => fault == PersistFault::FailFlush,
                Route::Write => false,
            };
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
/// fire one route, reopen, and classify the whole store as the complete old
/// or the complete new state across every family — never a mix.
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
                .map(|_| ()),
            Route::FlushDeferred => store.write_deferred(batch).and_then(|()| store.flush()),
        }
    };

    // Reopen and classify the whole store: every family together must hold
    // the complete pre-batch or the complete post-batch state.
    let after = {
        let store = open(path).expect("reopen to inspect");
        snapshot_all(&store)
    };
    let expected_old = sorted_families(&old);
    let expected_new = retagged_new(&expected_old);
    let observed = sorted_families(&after);
    assert!(
        observed == expected_old || observed == expected_new,
        "{label}: recovered as a mix: {observed:?} (old {expected_old:?}, new {expected_new:?})"
    );

    // Apply-boundary faults land nothing in any family: the store must hold
    // the exact pre-batch state, not merely one of the two legal states.
    if matches!(
        fault,
        PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply
    ) {
        assert_eq!(
            observed, expected_old,
            "{label}: apply-boundary fault left batch rows behind"
        );
    }

    // Outcome honesty: a durability-completing route reports success only
    // for a silently lost completion at the boundary it completes on; every
    // fault the route actually observes surfaces as `Err`.
    assert_fault_outcome(route, fault, outcome.is_ok(), &label);
}

/// Sorts each family's rows so whole-store comparisons are order-insensitive.
fn sorted_families(state: &[FamilyState]) -> Vec<FamilyState> {
    let mut sorted = state.to_vec();
    for family in &mut sorted {
        family.rows.sort();
    }
    sorted
}

/// The complete post-batch state: every seeded row re-tagged `new`.
fn retagged_new(state: &[FamilyState]) -> Vec<FamilyState> {
    state
        .iter()
        .map(|family| FamilyState {
            rows: family
                .rows
                .iter()
                .map(|(key, _)| (key.clone(), b"new".to_vec()))
                .collect(),
        })
        .collect()
}

/// Outcome honesty per route and fault: a silently lost completion at the
/// boundary the route completes on reports success, and every fault the
/// route actually observes surfaces as `Err`. A fault armed at a boundary
/// the route never crosses stays armed and is not asserted here.
fn assert_fault_outcome(route: &Route, fault: PersistFault, reported_success: bool, label: &str) {
    match route {
        Route::Write => {
            // FailApply and PartialApply are contract-mandated `Err` on the
            // plain write; `LostApply` is backend-dependent there and is
            // covered by the exact-old state check above instead.
            if matches!(fault, PersistFault::FailApply | PersistFault::PartialApply) {
                assert!(
                    !reported_success,
                    "{label}: plain write reported success on a faulted apply"
                );
            }
        }
        Route::WriteDurable | Route::WriteDurableIf => match fault {
            PersistFault::LostSync => assert!(
                reported_success,
                "{label}: durable route reported failure on a silently lost sync"
            ),
            PersistFault::FailApply
            | PersistFault::LostApply
            | PersistFault::PartialApply
            | PersistFault::FailSync => assert!(
                !reported_success,
                "{label}: durable route reported success despite an observed fault"
            ),
            // Flush-boundary faults stay armed: the single-commit durable
            // routes never call `flush`.
            PersistFault::FailFlush | PersistFault::LostFlush => {}
        },
        Route::FlushDeferred => match fault {
            PersistFault::LostFlush => assert!(
                reported_success,
                "{label}: flush reported failure on a silently lost flush"
            ),
            PersistFault::FailApply | PersistFault::PartialApply | PersistFault::FailFlush => {
                assert!(
                    !reported_success,
                    "{label}: deferred+flush route reported success despite an observed fault"
                );
            }
            // `LostApply` is backend-dependent on the deferred route, and
            // sync-boundary faults stay armed: `write_deferred` defers the
            // sync to `flush`.
            PersistFault::LostApply | PersistFault::FailSync | PersistFault::LostSync => {}
        },
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

/// A deliberately broken backend for the matrix's own rejection proof: an
/// armed write (`arm_persist_fault`) commits only the first family of the
/// batch and silently drops the rest — exactly the cross-family mix the
/// contract forbids. Unarmed writes commit every family, so the seed state
/// spans all three families and the defect fires only where the matrix
/// injects a fault.
type OneFamilyRows = BTreeMap<(u8, Vec<u8>), Vec<u8>>;

/// Shared, defect-latched rows for every `OneFamilyStore` opened on the same
/// path, so the matrix's seed/fire/reopen protocol observes one database.
type SharedOneFamilyRows = Arc<parking_lot::Mutex<OneFamilyShared>>;

struct OneFamilyShared {
    rows: OneFamilyRows,
    defect_armed: bool,
}

fn shared_one_family_rows(path: &Path) -> SharedOneFamilyRows {
    static REGISTRY: LazyLock<parking_lot::Mutex<BTreeMap<PathBuf, SharedOneFamilyRows>>> =
        LazyLock::new(|| parking_lot::Mutex::new(BTreeMap::new()));
    REGISTRY
        .lock()
        .entry(path.to_path_buf())
        .or_insert_with(|| {
            Arc::new(parking_lot::Mutex::new(OneFamilyShared {
                rows: OneFamilyRows::new(),
                defect_armed: false,
            }))
        })
        .clone()
}

struct OneFamilyStore {
    rows: SharedOneFamilyRows,
}

impl OneFamilyStore {
    fn open(path: &Path) -> Self {
        Self {
            rows: shared_one_family_rows(path),
        }
    }
}

enum OneFamilyOp {
    Put {
        cf: ColumnFamily,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        cf: ColumnFamily,
        key: Vec<u8>,
    },
    DeleteRange {
        cf: ColumnFamily,
        start: Vec<u8>,
        end: Vec<u8>,
    },
}

/// The stable one-byte key the strawman stores rows under: a family's row
/// key is its `repr(u8)` discriminant, reconstructed losslessly.
fn family_index(cf: ColumnFamily) -> u8 {
    u8::try_from(cf.index()).unwrap_or(0)
}

impl OneFamilyOp {
    fn cf(&self) -> ColumnFamily {
        match self {
            Self::Put { cf, .. } | Self::Delete { cf, .. } | Self::DeleteRange { cf, .. } => *cf,
        }
    }
}

#[derive(Default)]
struct OneFamilyBatch {
    ops: Vec<OneFamilyOp>,
}

impl WriteBatch for OneFamilyBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.ops.push(OneFamilyOp::Put {
            cf,
            key: key.to_vec(),
            value: value.to_vec(),
        });
    }

    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.ops.push(OneFamilyOp::Delete {
            cf,
            key: key.to_vec(),
        });
    }

    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]) {
        self.ops.push(OneFamilyOp::DeleteRange {
            cf,
            start: start.to_vec(),
            end: end.to_vec(),
        });
    }
}

/// Deliberate defect under test: an armed commit lands only the batch's
/// first family; the rest silently drops, leaving the store cross-family
/// mixed. Unarmed commits land every family.
fn apply_one_family_ops(rows: &mut OneFamilyShared, ops: Vec<OneFamilyOp>) {
    let defect_armed = rows.defect_armed;
    rows.defect_armed = false;
    let Some(committed) = ops.first().map(OneFamilyOp::cf) else {
        return;
    };
    for op in ops.into_iter().filter(|op| !defect_armed || op.cf() == committed) {
        let cf = family_index(op.cf());
        match op {
            OneFamilyOp::Put { key, value, .. } => {
                rows.rows.insert((cf, key), value);
            }
            OneFamilyOp::Delete { key, .. } => {
                rows.rows.remove(&(cf, key));
            }
            OneFamilyOp::DeleteRange { start, end, .. } => {
                let doomed: Vec<Vec<u8>> = rows
                    .rows
                    .keys()
                    .filter(|(row_cf, key)| *row_cf == cf && *key >= start && *key < end)
                    .map(|(_, key)| key.clone())
                    .collect();
                for key in doomed {
                    rows.rows.remove(&(cf, key));
                }
            }
        }
    }
}

impl KvStore for OneFamilyStore {
    type WriteBatch = OneFamilyBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .rows
            .lock()
            .rows
            .get(&(family_index(cf), key.to_vec()))
            .cloned())
    }

    #[expect(
        clippy::needless_collect,
        reason = "the collect drops the lock guard before the owned iterator returns"
    )]
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let rows: Vec<(Vec<u8>, Vec<u8>)> = self
            .rows
            .lock()
            .rows
            .iter()
            .filter(|((row_cf, key), _)| *row_cf == family_index(cf) && key.starts_with(prefix))
            .map(|((_, key), value)| (key.clone(), value.clone()))
            .collect();
        Ok(Box::new(rows.into_iter().map(Ok)))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        OneFamilyBatch::default()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        apply_one_family_ops(&mut self.rows.lock(), batch.ops);
        Ok(())
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        for condition in conditions {
            let (cf, key) = condition.location();
            let current = self.get(cf, key)?;
            if !condition.matches(current.as_deref()) {
                return Ok(false);
            }
        }
        self.write(batch)?;
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        // The rows live in memory; nothing can lag behind durability.
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(OneFamilySnapshot {
            rows: self.rows.lock().rows.clone(),
        }))
    }

    fn arm_persist_fault(&self, _fault: PersistFault) {
        // Latches the one-family defect for the next commit: the strawman
        // never consults fault identities, it just breaks once.
        self.rows.lock().defect_armed = true;
    }
}

struct OneFamilySnapshot {
    rows: OneFamilyRows,
}

impl KvSnapshot for OneFamilySnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.rows.get(&(family_index(cf), key.to_vec())).cloned())
    }

    #[expect(
        clippy::needless_collect,
        reason = "the returned box owns its rows; materializing keeps the two impls uniform"
    )]
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let rows: Vec<(Vec<u8>, Vec<u8>)> = self
            .rows
            .iter()
            .filter(|((row_cf, key), _)| *row_cf == family_index(cf) && key.starts_with(prefix))
            .map(|((_, key), value)| (key.clone(), value.clone()))
            .collect();
        Ok(Box::new(rows.into_iter().map(Ok)))
    }
}

/// The matrix rejects a backend that commits only one family of a batch: the
/// whole-store classification must panic on the cross-family mix that
/// per-family checks alone would pass.
#[test]
#[should_panic(expected = "recovered as a mix")]
fn one_family_store_matrix_rejects_cross_family_mix() {
    let dir = tempfile::tempdir().expect("tempdir");
    one_scenario(
        "one-family",
        |path| Ok(OneFamilyStore::open(path)),
        dir.path(),
        PersistFault::LostSync,
        &Route::WriteDurable,
    );
}
