#![cfg_attr(
    any(feature = "fjall", feature = "redb", feature = "rocksdb"),
    expect(clippy::expect_used, reason = "test assertions")
)]
#![cfg(any(feature = "fjall", feature = "redb", feature = "rocksdb"))]

use bitcoin_rs_storage::{
    BatchOp, BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, PersistFault,
    PrefixScan, PrefixScanLimit, StorageError, WriteCondition,
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

fn multi_family_batch<S: KvStore>(store: &S, label: &[u8]) -> BufferedWriteBatch {
    let mut batch = store.new_batch();
    for (index, cf) in FAMILIES.iter().enumerate() {
        batch.put(*cf, &[u8::try_from(index).unwrap_or(0)], label);
    }
    batch
}

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

            {
                let store =
                    bitcoin_rs_storage::open_redb_tx_index_store(&path).expect("open for seed");
                let mut batch = store.new_batch();
                batch.put(ColumnFamily::UtxoMeta, b"meta", b"old");
                batch.put(ColumnFamily::TxConfirmed, &[7_u8; 12], b"old");
                store.write_durable(batch).expect("seed write");
            }

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
    let dir = tempfile::tempdir().expect("tempdir");
    assert_later_durable_receipt_covers_deferred(backend, open, dir.path());
}

fn assert_later_durable_receipt_covers_deferred<S, F>(backend: &str, open: F, path: &Path)
where
    S: KvStore,
    F: Fn(&Path) -> Result<S, StorageError> + Copy,
{
    let rows: [(ColumnFamily, &[u8]); 2] = [
        (ColumnFamily::TxConfirmed, b"receipt/deferred"),
        (ColumnFamily::Funding, b"receipt/durable"),
    ];
    for guarded in [false, true] {
        let label = if guarded {
            format!("{backend}/guarded-receipt")
        } else {
            format!("{backend}/durable-receipt")
        };
        {
            let store = open(path).expect("open for deferred receipt seed");
            let mut seed = store.new_batch();
            for (cf, key) in rows {
                seed.put(cf, key, b"old");
            }
            store
                .write_durable(seed)
                .expect("seed deferred receipt state");
            let mut deferred = store.new_batch();
            deferred.put(rows[0].0, rows[0].1, b"deferred");
            store.write_deferred(deferred).expect("deferred write");
            if guarded {
                let mut receipt = store.new_batch();
                receipt.put(rows[1].0, rows[1].1, b"receipt");
                let committed = store
                    .write_durable_if(
                        &[WriteCondition::Equals {
                            cf: rows[1].0,
                            key: rows[1].1,
                            expected: b"old",
                        }],
                        receipt,
                    )
                    .expect("guarded durable receipt");
                assert!(committed, "{label}: guard unexpectedly mismatched");
            } else {
                let mut receipt = store.new_batch();
                receipt.put(rows[1].0, rows[1].1, b"receipt");
                store.write_durable(receipt).expect("durable receipt");
            }
        }

        let store = open(path).expect("reopen after durable receipt");
        assert_eq!(
            store
                .get(rows[0].0, rows[0].1)
                .expect("read earlier deferred row")
                .as_deref(),
            Some(&b"deferred"[..]),
            "{label}: earlier deferred write did not survive reopen"
        );
        assert_eq!(
            store
                .get(rows[1].0, rows[1].1)
                .expect("read receipt row")
                .as_deref(),
            Some(&b"receipt"[..]),
            "{label}: durable receipt row did not survive reopen"
        );
    }
}

fn one_scenario<S, F>(backend: &str, open: F, path: &Path, fault: PersistFault, route: &Route)
where
    S: KvStore,
    F: Fn(&Path) -> Result<S, bitcoin_rs_storage::StorageError>,
{
    let label = format!("{backend}/{}/{})", route.label(), fault_name(fault));

    let old = {
        let store = open(path).expect("open for seed");
        store
            .write_durable(multi_family_batch(&store, b"old"))
            .expect("seed write");
        snapshot_all(&store)
    };

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

    if matches!(
        fault,
        PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply
    ) {
        assert_eq!(
            observed, expected_old,
            "{label}: apply-boundary fault left batch rows behind"
        );
    }

    assert_fault_outcome(route, fault, outcome.is_ok(), &label);
}

fn sorted_families(state: &[FamilyState]) -> Vec<FamilyState> {
    let mut sorted = state.to_vec();
    for family in &mut sorted {
        family.rows.sort();
    }
    sorted
}

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

fn assert_fault_outcome(route: &Route, fault: PersistFault, reported_success: bool, label: &str) {
    match route {
        Route::Write => {
            if matches!(fault, PersistFault::FailApply | PersistFault::PartialApply) {
                assert!(
                    !reported_success,
                    "{label}: plain write reported success on a faulted apply"
                );
            }
        }
        Route::WriteDurable | Route::WriteDurableIf => match fault {
            PersistFault::FailApply
            | PersistFault::LostApply
            | PersistFault::PartialApply
            | PersistFault::FailSync
            | PersistFault::LostSync => assert!(
                !reported_success,
                "{label}: durable route reported success despite an observed fault"
            ),
            PersistFault::FailFlush | PersistFault::LostFlush => {}
        },
        Route::FlushDeferred => match fault {
            PersistFault::FailApply
            | PersistFault::LostApply
            | PersistFault::PartialApply
            | PersistFault::FailFlush
            | PersistFault::LostFlush => assert!(
                !reported_success,
                "{label}: deferred+flush route reported success despite an observed fault"
            ),
            PersistFault::FailSync | PersistFault::LostSync => {}
        },
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

type OneFamilyRows = BTreeMap<(u8, Vec<u8>), Vec<u8>>;

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

fn family_index(cf: ColumnFamily) -> u8 {
    u8::try_from(cf.index()).unwrap_or(0)
}

fn op_cf(op: &BatchOp) -> ColumnFamily {
    match op {
        BatchOp::Put { cf, .. } | BatchOp::Delete { cf, .. } | BatchOp::DeleteRange { cf, .. } => {
            *cf
        }
    }
}

fn apply_one_family_ops(rows: &mut OneFamilyShared, ops: Vec<BatchOp>) {
    let defect_armed = rows.defect_armed;
    rows.defect_armed = false;
    let Some(committed) = ops.first().map(op_cf) else {
        return;
    };
    for op in ops
        .into_iter()
        .filter(|op| !defect_armed || op_cf(op) == committed)
    {
        let cf = family_index(op_cf(&op));
        match op {
            BatchOp::Put { key, value, .. } => {
                rows.rows.insert((cf, key), value.into());
            }
            BatchOp::Delete { key, .. } => {
                rows.rows.remove(&(cf, key));
            }
            BatchOp::DeleteRange { start, end, .. } => {
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

fn scan_one_family_from(
    rows: &OneFamilyRows,
    cf: ColumnFamily,
    prefix: &[u8],
    start: &[u8],
    limit: PrefixScanLimit,
) -> PrefixScan {
    let family = family_index(cf);
    let mut taken = Vec::new();
    let mut bytes = 0usize;
    for ((row_cf, key), value) in rows.range((family, std::cmp::max(start, prefix).to_vec())..) {
        if *row_cf != family || !key.starts_with(prefix) {
            break;
        }
        let next_bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
        if taken.len() >= limit.max_rows || (!taken.is_empty() && next_bytes > limit.max_bytes) {
            return PrefixScan {
                rows: taken,
                complete: false,
            };
        }
        bytes = next_bytes;
        taken.push((key.clone(), value.clone()));
    }
    PrefixScan {
        rows: taken,
        complete: true,
    }
}

impl KvStore for OneFamilyStore {
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

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        Ok(scan_one_family_from(
            &self.rows.lock().rows,
            cf,
            prefix,
            start,
            limit,
        ))
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        BufferedWriteBatch::default()
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        apply_one_family_ops(&mut self.rows.lock(), batch.into_ops());
        Ok(())
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
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
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(OneFamilySnapshot {
            rows: self.rows.lock().rows.clone(),
        }))
    }

    fn arm_persist_fault(&self, _fault: PersistFault) {
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

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        Ok(scan_one_family_from(&self.rows, cf, prefix, start, limit))
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
