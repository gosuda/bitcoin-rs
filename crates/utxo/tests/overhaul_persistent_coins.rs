//! Scenario tests for incrementally persisted grouped coin records (T10).
//!
//! These pin the persisted coin layer: connect and disconnect retain exact
//! full keys with lossless scripts and values, colliding accelerators never
//! alias two records, eviction reloads byte-identical records (spending one
//! output of an evicted record never truncates its siblings), ephemeral
//! same-block outputs persist nothing while undo stays exact, and the byte
//! ledger counts resident tables plus retained versions.

#![expect(clippy::expect_used, reason = "test assertions")]

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition,
};
use bitcoin_rs_utxo::set::{
    BlockChanges, CoinDurability, PersistentUtxoError, PersistentUtxoSet, UtxoAdd,
};

type Row = ((ColumnFamily, Vec<u8>), Vec<u8>);

fn txid(index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txid_with_prefix(prefix: u64, index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&prefix.to_le_bytes());
    bytes[28..].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn outpoint(txid: Hash256, vout: u32) -> OutPoint {
    OutPoint::new(txid.into(), vout)
}

fn txout(value: u64, script: &[u8]) -> TxOut {
    TxOut {
        value,
        script_pubkey: script.to_vec(),
    }
}

fn block(changes: Vec<UtxoAdd>, removes: Vec<OutPoint>) -> BlockChanges {
    let mut block = BlockChanges::default();
    for add in changes {
        block.add(add);
    }
    for outpoint in removes {
        block.remove(outpoint);
    }
    block
}

/// The exact undo for a funding change set: the outputs the block created
/// are removed; nothing is restored (the block spent nothing).
fn undo_of(adds: &[UtxoAdd]) -> bitcoin_rs_utxo::set::UndoBatch {
    let mut undo = bitcoin_rs_utxo::set::UndoBatch::default();
    for add in adds {
        undo.remove(add.outpoint);
    }
    undo
}

fn two_output_add(txid: Hash256, script_a: &[u8], script_b: &[u8]) -> Vec<UtxoAdd> {
    vec![
        UtxoAdd::new(outpoint(txid, 0), txout(100, script_a), false, 10),
        UtxoAdd::new(outpoint(txid, 1), txout(200, script_b), false, 10),
    ]
}

#[derive(Default)]
struct StoreFaults {
    fail_read: AtomicBool,
    fail_write: AtomicBool,
    fail_after_write: AtomicBool,
    reject_cas: AtomicBool,
    fail_flush: AtomicBool,
    reads: AtomicUsize,
    read_gate:
        parking_lot::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}

#[derive(Clone, Default)]
struct MemoryStore {
    rows: Arc<parking_lot::RwLock<Vec<Row>>>,
    faults: Arc<StoreFaults>,
}

fn injected() -> StorageError {
    StorageError::InvalidOperation("injected coin storage failure")
}

impl KvStore for MemoryStore {
    type WriteBatch = MemoryBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.faults.reads.fetch_add(1, Ordering::SeqCst);
        if self.faults.fail_read.swap(false, Ordering::SeqCst) {
            return Err(injected());
        }
        let value = self
            .rows
            .read()
            .iter()
            .find(|((row_cf, row_key), _value)| *row_cf == cf && row_key == key)
            .map(|(_row, value)| value.clone());
        let gate = self.faults.read_gate.lock().take();
        if let Some((entered, release)) = gate {
            entered.send(()).expect("announce suspended read");
            release.recv().expect("release suspended read");
        }
        Ok(value)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let mut rows = self
            .rows
            .read()
            .iter()
            .filter(|((row_cf, key), _value)| *row_cf == cf && key.starts_with(prefix))
            .map(|((_row_cf, key), value)| Ok((key.clone(), value.clone())))
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| match (left, right) {
            (Ok((left_key, _)), Ok((right_key, _))) => left_key.cmp(right_key),
            _ => core::cmp::Ordering::Equal,
        });
        Ok(Box::new(rows.into_iter()))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        MemoryBatch::default()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        if self.faults.fail_write.swap(false, Ordering::SeqCst) {
            return Err(injected());
        }
        let mut rows = self.rows.write();
        apply_ops(&mut rows, batch.ops.into_iter());
        if self.faults.fail_after_write.swap(false, Ordering::SeqCst) {
            return Err(injected());
        }
        Ok(())
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        if self.faults.fail_write.swap(false, Ordering::SeqCst) {
            return Err(injected());
        }
        if self.faults.reject_cas.swap(false, Ordering::SeqCst) {
            return Ok(false);
        }
        let mut rows = self.rows.write();
        let matched = conditions.iter().all(|condition| {
            let (cf, key) = condition.location();
            condition.matches(
                rows.iter()
                    .find(|((row_cf, row_key), _value)| *row_cf == cf && row_key == key)
                    .map(|(_row, value)| value.as_slice()),
            )
        });
        if !matched {
            return Ok(false);
        }
        apply_ops(&mut rows, batch.ops.into_iter());
        if self.faults.fail_after_write.swap(false, Ordering::SeqCst) {
            return Err(injected());
        }
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        if self.faults.fail_flush.swap(false, Ordering::SeqCst) {
            return Err(injected());
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Err(StorageError::InvalidOperation(
            "memory snapshots unsupported",
        ))
    }

    fn arm_persist_fault(&self, _fault: bitcoin_rs_storage::PersistFault) {
        // In-memory double: no persistence boundary exists to fault.
    }
}

#[derive(Default)]
struct MemoryBatch {
    ops: Vec<MemoryOp>,
}

enum MemoryOp {
    Put(ColumnFamily, Vec<u8>, Vec<u8>),
    Delete(ColumnFamily, Vec<u8>),
    DeleteRange(ColumnFamily, Vec<u8>, Vec<u8>),
}

impl WriteBatch for MemoryBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.ops
            .push(MemoryOp::Put(cf, key.to_vec(), value.to_vec()));
    }

    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.ops.push(MemoryOp::Delete(cf, key.to_vec()));
    }

    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]) {
        self.ops
            .push(MemoryOp::DeleteRange(cf, start.to_vec(), end.to_vec()));
    }
}

fn apply_ops(rows: &mut Vec<Row>, ops: std::vec::IntoIter<MemoryOp>) {
    for op in ops {
        match op {
            MemoryOp::Put(cf, key, value) => {
                if let Some((_row, existing_value)) = rows
                    .iter_mut()
                    .find(|((row_cf, row_key), _value)| *row_cf == cf && row_key == &key)
                {
                    *existing_value = value;
                } else {
                    rows.push(((cf, key), value));
                }
            }
            MemoryOp::Delete(cf, key) => {
                rows.retain(|((row_cf, row_key), _value)| *row_cf != cf || row_key != &key);
            }
            MemoryOp::DeleteRange(cf, start, end) => {
                rows.retain(|((row_cf, key), _value)| {
                    *row_cf != cf
                        || key.as_slice() < start.as_slice()
                        || key.as_slice() >= end.as_slice()
                });
            }
        }
    }
}

/// Connect then disconnect one block: exact keys survive, scripts and
/// values stay lossless, and the store row returns with the block.
#[test]
fn connect_and_disconnect_retain_exact_keys_losslessly() {
    let set = PersistentUtxoSet::new(MemoryStore::default());
    let script_a = [0x51, 0x52, 0x53];
    let script_b = [0x00_u8; 77]; // large distinct script
    let a = txid(1);
    let changes = block(two_output_add(a, &script_a, &script_b), vec![]);
    let hash = Hash256::from_le_bytes(&[1; 32]);
    set.connect_block(&changes, &hash, CoinDurability::Durable)
        .expect("connect");

    let stored_a = set.ledger().expect("ledger").resident.records;
    assert_eq!(stored_a, 1, "one grouped record");
    let got_a = set.get(&outpoint(a, 0)).expect("lookup").expect("output 0");
    assert_eq!(got_a.script_pubkey, script_a);
    assert_eq!(got_a.value, 100);
    let got_b = set.get(&outpoint(a, 1)).expect("lookup").expect("output 1");
    assert_eq!(got_b.script_pubkey, script_b);
    assert_eq!(got_b.value, 200);

    // Undo restores both halves exactly.
    let adds = two_output_add(a, &script_a, &script_b);
    let undo = undo_of(&adds);
    set.undo_block(&undo, CoinDurability::Durable)
        .expect("undo");
    assert!(set.get(&outpoint(a, 0)).expect("lookup").is_none());
    assert!(set.get(&outpoint(a, 1)).expect("lookup").is_none());
    assert_eq!(
        set.ledger().expect("ledger").stored_rows,
        0,
        "row removed with the block"
    );
}

/// Two txids sharing the accelerator prefix never alias: both records stay
/// distinct by their full 256-bit identities.
#[test]
fn colliding_accelerators_never_alias_records() {
    let set = PersistentUtxoSet::new(MemoryStore::default());
    let a = txid_with_prefix(0xDEAD_BEEF, 1);
    let b = txid_with_prefix(0xDEAD_BEEF, 2);
    let hash = Hash256::from_le_bytes(&[2; 32]);
    set.connect_block(
        &block(two_output_add(a, &[0xAA], &[0xAB]), vec![]),
        &hash,
        CoinDurability::Durable,
    )
    .expect("connect a");
    set.connect_block(
        &block(two_output_add(b, &[0xBA], &[0xBB]), vec![]),
        &hash,
        CoinDurability::Durable,
    )
    .expect("connect b");

    assert_eq!(
        set.get(&outpoint(a, 0))
            .expect("lookup")
            .expect("a:0")
            .script_pubkey,
        [0xAA]
    );
    assert_eq!(
        set.get(&outpoint(b, 0))
            .expect("lookup")
            .expect("b:0")
            .script_pubkey,
        [0xBA]
    );
    assert_eq!(
        set.ledger().expect("ledger").stored_rows,
        2,
        "two distinct rows"
    );
}

/// The critical eviction scenario: spend one output of a record the cache
/// evicted; the sibling output survives connect byte-identically and undo
/// restores both halves. Without the reload-before-snapshot rule the
/// persisted row would be silently truncated to the spending block's view.
#[test]
fn evicted_record_survives_partial_spend_byte_identically() {
    let base = PersistentUtxoSet::new(MemoryStore::default());
    let mut set = base;
    let a = txid(7);
    let script_a = [0x51; 33];
    let script_b = [0x52; 66];
    let hash = Hash256::from_le_bytes(&[3; 32]);
    set.connect_block(
        &block(two_output_add(a, &script_a, &script_b), vec![]),
        &hash,
        CoinDurability::Durable,
    )
    .expect("connect funding block");

    // Force whole-record eviction: budget below the resident footprint.
    set.set_resident_budget(1);
    set.connect_block(&block(vec![], vec![]), &hash, CoinDurability::Durable)
        .expect("no-op connect triggers eviction");
    assert_eq!(
        set.ledger().expect("ledger").resident.records,
        0,
        "record evicted from the cache"
    );
    assert_eq!(
        set.ledger().expect("ledger").stored_rows,
        1,
        "record durable in the store"
    );

    // Spend output 0 in a later block: reload-before-snapshot must recover
    // the full record so the after-image keeps output 1.
    set.connect_block(
        &block(vec![], vec![outpoint(a, 0)]),
        &hash,
        CoinDurability::Durable,
    )
    .expect("connect spending block");
    let sibling = set
        .get(&outpoint(a, 1))
        .expect("lookup")
        .expect("sibling output survived");
    assert_eq!(sibling.script_pubkey, script_b);
    assert_eq!(sibling.value, 200);
    assert!(
        set.get(&outpoint(a, 0)).expect("lookup").is_none(),
        "spent output gone"
    );

    // Undo the spending block: both outputs return.
    let mut undo = bitcoin_rs_utxo::set::UndoBatch::default();
    undo.restore(UtxoAdd::new(
        outpoint(a, 0),
        txout(100, &script_a),
        false,
        10,
    ));
    set.undo_block(&undo, CoinDurability::Durable)
        .expect("undo");
    assert_eq!(
        set.get(&outpoint(a, 0))
            .expect("lookup")
            .expect("restored 0")
            .script_pubkey,
        script_a
    );
    assert_eq!(
        set.get(&outpoint(a, 1))
            .expect("lookup")
            .expect("restored 1")
            .script_pubkey,
        script_b
    );
}

/// An output created and spent in the same block persists nothing (no live
/// row appears in the store) while the undo batch still restores it.
#[test]
fn ephemeral_same_block_output_persists_nothing() {
    let set = PersistentUtxoSet::new(MemoryStore::default());
    let a = txid(9);
    let hash = Hash256::from_le_bytes(&[4; 32]);
    let add = UtxoAdd::new(outpoint(a, 0), txout(50, &[0x51]), false, 10);
    let changes = block(vec![add.clone()], vec![outpoint(a, 0)]);
    set.connect_block(&changes, &hash, CoinDurability::Durable)
        .expect("connect ephemeral block");
    assert_eq!(
        set.ledger().expect("ledger").stored_rows,
        0,
        "no live row ever persisted"
    );
    assert!(
        set.get(&outpoint(a, 0)).expect("lookup").is_none(),
        "ephemeral output never live"
    );

    // Undoing the block cancels symmetrically: the creation and the spend
    // both reverse, so the output stays absent - the undo batch keeps both
    // halves as history without resurrecting a canceled output.
    let mut undo = bitcoin_rs_utxo::set::UndoBatch::default();
    undo.restore(add);
    undo.remove(outpoint(a, 0));
    set.undo_block(&undo, CoinDurability::Durable)
        .expect("undo ephemeral block");
    assert!(
        set.get(&outpoint(a, 0)).expect("lookup").is_none(),
        "canceled output stays absent after undo"
    );
}

/// The ledger counts resident tables and the retained before-image versions
/// a deferred durable window owes the store, and `flush` drains them.
#[test]
fn ledger_counts_tables_and_retained_versions() {
    let set = PersistentUtxoSet::new(MemoryStore::default());
    let a = txid(11);
    let hash = Hash256::from_le_bytes(&[5; 32]);
    set.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &hash,
        CoinDurability::Deferred,
    )
    .expect("deferred connect");
    let ledger = set.ledger().expect("ledger");
    assert_eq!(ledger.stored_rows, 1, "row visible after deferred write");
    assert!(
        ledger.retained_before_image_bytes == 0,
        "creating a fresh record retains an empty before-image"
    );
    assert_eq!(ledger.resident.records, 1, "record resident");

    // A mutation under Deferred retains the prior version's bytes.
    set.connect_block(
        &block(vec![], vec![outpoint(a, 0)]),
        &hash,
        CoinDurability::Deferred,
    )
    .expect("deferred spend");
    let ledger = set.ledger().expect("ledger");
    assert!(
        ledger.retained_before_image_bytes > 0,
        "the durable window owes the prior version"
    );
    set.flush().expect("flush completes durability");
    let ledger = set.ledger().expect("ledger");
    assert_eq!(
        ledger.retained_before_image_bytes, 0,
        "flush drains the retained versions"
    );
}

/// A guarded durable write against a foreign stored row is a typed
/// mismatch, never a silent success.
#[test]
fn corrupt_stored_row_is_rejected_before_any_mutation() {
    let store = MemoryStore::default();
    let a = txid(13);
    let hash = Hash256::from_le_bytes(&[6; 32]);

    // Foreign row: a already stored under its full-txid key.
    let mut foreign = store.new_batch();
    let txid_conv = bitcoin_rs_primitives::Txid::from(a);
    let key = txid_conv.0.as_byte_array();
    foreign.put(ColumnFamily::CoinRecords, key, b"foreign");
    store.write(foreign).expect("seed foreign row");

    let set = PersistentUtxoSet::new(store);
    let error = set
        .connect_block(
            &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
            &hash,
            CoinDurability::CasGuarded,
        )
        .expect_err("guarded connect must fail");
    assert!(
        matches!(error, PersistentUtxoError::CorruptStoredRecord(_)),
        "expected typed corruption, got {error:?}"
    );
}

/// T10: lookup failures and corrupt full-key identities are not missing coins.
#[test]
fn reload_reports_io_and_full_txid_corruption_without_refilling() {
    let store = MemoryStore::default();
    let mut set = PersistentUtxoSet::new(store.clone());
    let a = txid_with_prefix(5, 1);
    let b = txid_with_prefix(5, 2);
    set.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &Hash256::default(),
        CoinDurability::Durable,
    )
    .expect("seed");
    let bytes = store
        .get(
            ColumnFamily::CoinRecords,
            bitcoin_rs_primitives::Txid::from(a).0.as_byte_array(),
        )
        .expect("read")
        .expect("row");
    let mut batch = store.new_batch();
    batch.put(
        ColumnFamily::CoinRecords,
        bitcoin_rs_primitives::Txid::from(b).0.as_byte_array(),
        &bytes,
    );
    store.write(batch).expect("seed miskeyed bytes");
    set.set_resident_budget(1);
    store.faults.fail_read.store(true, Ordering::SeqCst);
    assert!(matches!(
        set.get(&outpoint(a, 0)),
        Err(PersistentUtxoError::Storage(_))
    ));
    assert!(matches!(
        set.get(&outpoint(b, 0)),
        Err(PersistentUtxoError::CorruptStoredRecord(_))
    ));
    assert_eq!(set.ledger().expect("ledger").resident.records, 0);
    for mode in [
        CoinDurability::Deferred,
        CoinDurability::Durable,
        CoinDurability::CasGuarded,
    ] {
        assert!(matches!(
            set.connect_block(
                &block(vec![], vec![outpoint(b, 0)]),
                &Hash256::default(),
                mode
            ),
            Err(PersistentUtxoError::CorruptStoredRecord(_))
        ));
    }
    assert_eq!(
        set.get(&outpoint(a, 0))
            .expect("healthy row")
            .expect("coin")
            .value,
        100
    );
}

/// T10: no cache reads or writes escape an unresolved backend outcome.
#[test]
fn storage_failure_closes_cache_until_explicit_backend_recovery() {
    for applied in [false, true] {
        let store = MemoryStore::default();
        let set = PersistentUtxoSet::new(store.clone());
        let a = txid(33);
        let adds = block(two_output_add(a, &[0x51], &[0x52]), vec![]);
        if applied {
            store.faults.fail_after_write.store(true, Ordering::SeqCst);
        } else {
            store.faults.fail_write.store(true, Ordering::SeqCst);
        }
        assert!(matches!(
            set.connect_block(&adds, &Hash256::default(), CoinDurability::Durable),
            Err(PersistentUtxoError::Storage(_))
        ));
        assert!(matches!(
            set.get(&outpoint(a, 0)),
            Err(PersistentUtxoError::RecoveryRequired)
        ));
        assert!(matches!(
            set.connect_block(&adds, &Hash256::default(), CoinDurability::Durable),
            Err(PersistentUtxoError::RecoveryRequired)
        ));
        assert!(matches!(
            set.flush(),
            Err(PersistentUtxoError::RecoveryRequired)
        ));
        let store = set.into_store();
        store
            .flush()
            .expect("resolve this memory backend's completion");
        let recovered = PersistentUtxoSet::new(store);
        assert_eq!(
            recovered
                .get(&outpoint(a, 0))
                .expect("recovered lookup")
                .is_some(),
            applied
        );
    }
}

/// T10: a CAS refusal neither publishes proposed coins nor prevents a clean retry.
#[test]
fn cas_refusal_leaves_old_coins_and_retry_applies_once() {
    let store = MemoryStore::default();
    let set = PersistentUtxoSet::new(store.clone());
    let a = txid(34);
    let hash = Hash256::default();
    set.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &hash,
        CoinDurability::Durable,
    )
    .expect("seed");
    let spend = block(vec![], vec![outpoint(a, 0)]);
    store.faults.reject_cas.store(true, Ordering::SeqCst);
    assert!(matches!(
        set.connect_block(&spend, &hash, CoinDurability::CasGuarded),
        Err(PersistentUtxoError::ConditionMismatch(_))
    ));
    assert!(set.get(&outpoint(a, 0)).expect("lookup").is_some());
    set.connect_block(&spend, &hash, CoinDurability::CasGuarded)
        .expect("retry");
    assert!(set.get(&outpoint(a, 0)).expect("lookup").is_none());
    assert!(set.get(&outpoint(a, 1)).expect("lookup").is_some());
}

/// T10: validation failure cannot publish a partially mutated shard set.
#[test]
fn invalid_mutation_keeps_store_and_cache_unchanged() {
    let store = MemoryStore::default();
    let set = PersistentUtxoSet::new(store);
    let a = txid(35);
    let hash = Hash256::default();
    set.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &hash,
        CoinDurability::Durable,
    )
    .expect("seed");
    let invalid = block(
        vec![UtxoAdd::new(
            outpoint(txid(36), 0),
            txout(1, &vec![0x51; 65_536]),
            false,
            1,
        )],
        vec![outpoint(a, 0)],
    );
    assert!(matches!(
        set.connect_block(&invalid, &hash, CoinDurability::Durable),
        Err(PersistentUtxoError::Utxo(_))
    ));
    assert!(set.get(&outpoint(a, 0)).expect("old output").is_some());
    assert_eq!(set.ledger().expect("ledger").stored_rows, 1);
}

/// T10: cache misses are bounded and an absent vout of a resident txid needs no I/O.
#[test]
fn reads_obey_budget_and_resident_missing_vouts_do_not_reload() {
    let store = MemoryStore::default();
    let mut set = PersistentUtxoSet::new(store.clone());
    let a = txid(37);
    set.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &Hash256::default(),
        CoinDurability::Durable,
    )
    .expect("seed");
    let reads = store.faults.reads.load(Ordering::SeqCst);
    assert!(set.get(&outpoint(a, 99)).expect("missing vout").is_none());
    assert_eq!(store.faults.reads.load(Ordering::SeqCst), reads);
    set.set_resident_budget(1);
    for vout in [0, 1, 0, 1] {
        assert!(
            set.get(&outpoint(a, vout))
                .expect("reloaded coin")
                .is_some()
        );
        assert_eq!(set.ledger().expect("ledger").resident.records, 0);
    }
}

/// T10: flush releases previously skipped eviction candidates; failure closes the owner.
#[test]
fn flush_evicts_deferred_pins_and_failure_closes_reads() {
    let store = MemoryStore::default();
    let mut set = PersistentUtxoSet::new(store.clone());
    set.set_resident_budget(1);
    let a = txid(38);
    set.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &Hash256::default(),
        CoinDurability::Deferred,
    )
    .expect("deferred seed");
    assert_eq!(set.ledger().expect("ledger").resident.records, 1);
    set.flush().expect("flush");
    assert_eq!(set.ledger().expect("ledger").resident.records, 0);
    store.faults.fail_flush.store(true, Ordering::SeqCst);
    assert!(matches!(set.flush(), Err(PersistentUtxoError::Storage(_))));
    assert!(matches!(
        set.get(&outpoint(a, 0)),
        Err(PersistentUtxoError::RecoveryRequired)
    ));
}

/// T10: a suspended refill cannot publish stale coins over a concurrent spend.
#[test]
fn refill_and_spend_share_one_transition_lock() {
    use std::sync::mpsc;
    use std::time::Duration;
    let store = MemoryStore::default();
    let mut set = PersistentUtxoSet::new(store.clone());
    let a = txid(39);
    set.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &Hash256::default(),
        CoinDurability::Durable,
    )
    .expect("seed");
    set.set_resident_budget(1);
    let set = Arc::new(set);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    *store.faults.read_gate.lock() = Some((entered_tx, release_rx));
    let reader_set = Arc::clone(&set);
    let reader = std::thread::spawn(move || reader_set.get(&outpoint(a, 0)));
    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("refill suspended");
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let writer_set = Arc::clone(&set);
    let writer = std::thread::spawn(move || {
        started_tx.send(()).expect("writer started");
        let result = writer_set.connect_block(
            &block(vec![], vec![outpoint(a, 0)]),
            &Hash256::default(),
            CoinDurability::Durable,
        );
        done_tx.send(()).expect("writer finished");
        result
    });
    started_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("writer attempted");
    let premature = done_rx.recv_timeout(Duration::from_millis(50));
    release_tx
        .send(())
        .expect("release refill even if assertion will fail");
    reader.join().expect("reader join").expect("read");
    writer.join().expect("writer join").expect("spend");
    assert!(matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)));
    assert!(
        set.get(&outpoint(a, 0))
            .expect("post-spend lookup")
            .is_none()
    );
    assert!(set.get(&outpoint(a, 1)).expect("sibling lookup").is_some());
}
