//! Scenario tests for incrementally persisted grouped coin records (T10) and `RCV-04A`.
//!
//! These pin the persisted coin layer: connect and disconnect retain exact
//! full keys with lossless scripts and values, colliding accelerators never
//! alias two records, eviction reloads byte-identical records (spending one
//! output of an evicted record never truncates its siblings), ephemeral
//! same-block outputs persist nothing while undo stays exact, the byte
//! ledger counts resident tables plus retained versions, and persistent
//! transition regressions follow `docs/contracts/recovery.md::RCV-04A`.

#![expect(clippy::expect_used, reason = "test assertions")]

use std::{
    sync::{
        Arc, Barrier, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition,
};
use bitcoin_rs_utxo::set::{
    BlockChanges, CoinDurability, PersistentUtxoError, PersistentUtxoSet, UtxoAdd,
    UtxoChangeEvents, UtxoChangeListener, UtxoInserted, UtxoRemoved, UtxoSet,
};

const DEADLOCK_TIMEOUT: Duration = Duration::from_secs(5);

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

fn one_output_add(txid: Hash256) -> Vec<UtxoAdd> {
    vec![UtxoAdd::new(
        outpoint(txid, 0),
        txout(100, &[0x51]),
        false,
        1,
    )]
}

fn two_output_add(txid: Hash256, script_a: &[u8], script_b: &[u8]) -> Vec<UtxoAdd> {
    vec![
        UtxoAdd::new(outpoint(txid, 0), txout(100, script_a), false, 10),
        UtxoAdd::new(outpoint(txid, 1), txout(200, script_b), false, 10),
    ]
}

#[derive(Clone)]
struct FlushGate {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[derive(Clone, Default)]
struct MemoryStore {
    rows: Arc<parking_lot::RwLock<Vec<Row>>>,
    fault: Arc<parking_lot::Mutex<Option<Fault>>>,
    next_flush: Arc<parking_lot::Mutex<Option<FlushGate>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Read,
    IterOpen,
    IterRow,
    BeforeWrite,
    AfterWrite,
    RejectCas,
    Flush,
}

impl MemoryStore {
    fn arm(&self, fault: Fault) {
        *self.fault.lock() = Some(fault);
    }

    fn block_next_flush(&self) -> FlushGate {
        let gate = FlushGate {
            entered: Arc::new(Barrier::new(2)),
            release: Arc::new(Barrier::new(2)),
        };
        *self.next_flush.lock() = Some(gate.clone());
        gate
    }

    fn take(&self, fault: Fault) -> bool {
        let mut slot = self.fault.lock();
        if *slot == Some(fault) {
            slot.take();
            true
        } else {
            false
        }
    }

    fn fail(&self, fault: Fault) -> Result<(), StorageError> {
        if self.take(fault) {
            Err(StorageError::InvalidOperation("injected store failure"))
        } else {
            Ok(())
        }
    }
}

impl KvStore for MemoryStore {
    type WriteBatch = MemoryBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.fail(Fault::Read)?;
        Ok(self
            .rows
            .read()
            .iter()
            .find(|((row_cf, row_key), _value)| *row_cf == cf && row_key == key)
            .map(|(_row, value)| value.clone()))
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.fail(Fault::IterOpen)?;
        if self.take(Fault::IterRow) {
            return Ok(Box::new(std::iter::once(Err(
                StorageError::InvalidOperation("injected row failure"),
            ))));
        }
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
        self.fail(Fault::BeforeWrite)?;
        apply_ops(&mut self.rows.write(), batch.ops.into_iter());
        self.fail(Fault::AfterWrite)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        if self.take(Fault::RejectCas) {
            return Ok(false);
        }
        self.fail(Fault::BeforeWrite)?;
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
        self.fail(Fault::AfterWrite)?;
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.fail(Fault::Flush)?;
        let gate = self.next_flush.lock().take();
        if let Some(gate) = gate {
            gate.entered.wait();
            gate.release.wait();
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
    let set = PersistentUtxoSet::new(UtxoSet::new(), MemoryStore::default());
    let script_a = [0x51, 0x52, 0x53];
    let script_b = [0x00_u8; 77]; // large distinct script
    let a = txid(1);
    let changes = block(two_output_add(a, &script_a, &script_b), vec![]);
    let hash = Hash256::from_le_bytes(&[1; 32]);
    set.connect_block(&changes, &hash, CoinDurability::Durable)
        .expect("connect");

    let stored_a = set.ledger().expect("read coin ledger").resident.records;
    assert_eq!(stored_a, 1, "one grouped record");
    let got_a = set
        .get(&outpoint(a, 0))
        .expect("read coin")
        .expect("output 0");
    assert_eq!(got_a.script_pubkey, script_a);
    assert_eq!(got_a.value, 100);
    let got_b = set
        .get(&outpoint(a, 1))
        .expect("read coin")
        .expect("output 1");
    assert_eq!(got_b.script_pubkey, script_b);
    assert_eq!(got_b.value, 200);

    // Undo restores both halves exactly.
    let adds = two_output_add(a, &script_a, &script_b);
    let undo = undo_of(&adds);
    set.undo_block(&undo, CoinDurability::Durable)
        .expect("undo");
    assert!(set.get(&outpoint(a, 0)).expect("read coin").is_none());
    assert!(set.get(&outpoint(a, 1)).expect("read coin").is_none());
    assert_eq!(
        set.ledger().expect("read coin ledger").stored_rows,
        0,
        "row removed with the block"
    );
}

/// Two txids sharing the accelerator prefix never alias: both records stay
/// distinct by their full 256-bit identities.
#[test]
fn colliding_accelerators_never_alias_records() {
    let set = PersistentUtxoSet::new(UtxoSet::new(), MemoryStore::default());
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
            .expect("read coin")
            .expect("a:0")
            .script_pubkey,
        [0xAA]
    );
    assert_eq!(
        set.get(&outpoint(b, 0))
            .expect("read coin")
            .expect("b:0")
            .script_pubkey,
        [0xBA]
    );
    assert_eq!(
        set.ledger().expect("read coin ledger").stored_rows,
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
    let base = PersistentUtxoSet::new(UtxoSet::new(), MemoryStore::default());
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
        set.ledger().expect("read coin ledger").resident.records,
        0,
        "record evicted from the cache"
    );
    assert_eq!(
        set.ledger().expect("read coin ledger").stored_rows,
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
        .expect("read coin")
        .expect("sibling output survived");
    assert_eq!(sibling.script_pubkey, script_b);
    assert_eq!(sibling.value, 200);
    assert!(
        set.get(&outpoint(a, 0)).expect("read coin").is_none(),
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
            .expect("read coin")
            .expect("restored 0")
            .script_pubkey,
        script_a
    );
    assert_eq!(
        set.get(&outpoint(a, 1))
            .expect("read coin")
            .expect("restored 1")
            .script_pubkey,
        script_b
    );
}

/// An output created and spent in the same block persists nothing (no live
/// row appears in the store) while the undo batch still restores it.
#[test]
fn ephemeral_same_block_output_persists_nothing() {
    let set = PersistentUtxoSet::new(UtxoSet::new(), MemoryStore::default());
    let a = txid(9);
    let hash = Hash256::from_le_bytes(&[4; 32]);
    let add = UtxoAdd::new(outpoint(a, 0), txout(50, &[0x51]), false, 10);
    let changes = block(vec![add.clone()], vec![outpoint(a, 0)]);
    set.connect_block(&changes, &hash, CoinDurability::Durable)
        .expect("connect ephemeral block");
    assert_eq!(
        set.ledger().expect("read coin ledger").stored_rows,
        0,
        "no live row ever persisted"
    );
    assert!(
        set.get(&outpoint(a, 0)).expect("read coin").is_none(),
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
        set.get(&outpoint(a, 0)).expect("read coin").is_none(),
        "canceled output stays absent after undo"
    );
}

/// The ledger counts resident tables and the retained before-image versions
/// a deferred durable window owes the store, and `flush` drains them.
#[test]
fn ledger_counts_tables_and_retained_versions() {
    let set = PersistentUtxoSet::new(UtxoSet::new(), MemoryStore::default());
    let a = txid(11);
    let hash = Hash256::from_le_bytes(&[5; 32]);
    set.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &hash,
        CoinDurability::Deferred,
    )
    .expect("deferred connect");
    let ledger = set.ledger().expect("read coin ledger");
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
    let ledger = set.ledger().expect("read coin ledger");
    assert!(
        ledger.retained_before_image_bytes > 0,
        "the durable window owes the prior version"
    );
    set.flush().expect("flush completes durability");
    let ledger = set.ledger().expect("read coin ledger");
    assert_eq!(
        ledger.retained_before_image_bytes, 0,
        "flush drains the retained versions"
    );
}

/// Malformed stored bytes fail before mutation, including guarded writes.
#[test]
fn malformed_stored_row_is_a_typed_corruption_error() {
    let store = MemoryStore::default();
    let a = txid(13);
    let hash = Hash256::from_le_bytes(&[6; 32]);

    // Foreign row: a already stored under its full-txid key.
    let mut foreign = store.new_batch();
    let txid_conv = bitcoin_rs_primitives::Txid::from(a);
    let key = txid_conv.0.as_byte_array();
    foreign.put(ColumnFamily::CoinRecords, key, b"foreign");
    store.write(foreign).expect("seed foreign row");

    let set = PersistentUtxoSet::new(UtxoSet::new(), store);
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

fn coin_row(store: &MemoryStore, txid: Hash256) -> Option<Vec<u8>> {
    store
        .get(ColumnFamily::CoinRecords, txid.as_byte_array())
        .expect("read raw coin row")
}

fn put_row(store: &MemoryStore, txid: Hash256, bytes: &[u8]) {
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::CoinRecords, txid.as_byte_array(), bytes);
    store.write(batch).expect("seed raw coin row");
}

#[test]
fn read_and_iterator_failures_are_not_absence_or_partial_ledgers() {
    let store = MemoryStore::default();
    let set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    store.arm(Fault::Read);
    assert!(matches!(
        set.get(&outpoint(txid(20), 0)),
        Err(PersistentUtxoError::Storage(_))
    ));
    assert!(
        set.get(&outpoint(txid(20), 0))
            .expect("retry read")
            .is_none()
    );
    for fault in [Fault::IterOpen, Fault::IterRow] {
        store.arm(fault);
        assert!(matches!(set.ledger(), Err(PersistentUtxoError::Storage(_))));
    }
    assert_eq!(set.ledger().expect("retry scan").stored_rows, 0);
}

#[test]
fn corrupt_rows_cannot_be_read_spent_or_overwritten() {
    for mode in [
        CoinDurability::Deferred,
        CoinDurability::Durable,
        CoinDurability::CasGuarded,
    ] {
        let store = MemoryStore::default();
        let a = txid(21);
        put_row(&store, a, b"corrupt");
        let set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
        assert!(matches!(
            set.get(&outpoint(a, 0)),
            Err(PersistentUtxoError::CorruptStoredRecord(_))
        ));
        for changes in [
            block(vec![], vec![outpoint(a, 0)]),
            block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        ] {
            assert!(matches!(
                set.connect_block(&changes, &a, mode),
                Err(PersistentUtxoError::CorruptStoredRecord(_))
            ));
            assert_eq!(coin_row(&store, a).as_deref(), Some(b"corrupt".as_slice()));
            assert_eq!(
                set.ledger()
                    .expect("pre-mutation rejection remains readable")
                    .resident
                    .records,
                0
            );
        }
    }
}

#[test]
fn stored_full_identity_must_match_even_when_accelerators_collide() {
    let store = MemoryStore::default();
    let a = txid_with_prefix(7, 1);
    let b = txid_with_prefix(7, 2);
    let writer = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    writer
        .connect_block(
            &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
            &a,
            CoinDurability::Durable,
        )
        .expect("seed");
    let bytes = coin_row(&store, a).expect("encoded row");
    put_row(&store, b, &bytes);
    let set = PersistentUtxoSet::new(UtxoSet::new(), store);
    assert!(
        matches!(set.get(&outpoint(b, 0)), Err(PersistentUtxoError::CorruptStoredRecord(id)) if id == b.into())
    );
    assert_eq!(set.ledger().expect("no corrupt refill").resident.records, 0);
    assert_eq!(
        set.get(&outpoint(a, 0))
            .expect("valid identity")
            .expect("live output")
            .value,
        100
    );
}

#[test]
fn failed_mutations_quarantine_all_public_operations() {
    for mode in [
        CoinDurability::Deferred,
        CoinDurability::Durable,
        CoinDurability::CasGuarded,
    ] {
        for fault in [Fault::BeforeWrite, Fault::AfterWrite, Fault::RejectCas] {
            if fault == Fault::RejectCas && mode != CoinDurability::CasGuarded {
                continue;
            }
            let store = MemoryStore::default();
            let set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
            let a = txid(22);
            let changes = block(two_output_add(a, &[0x51], &[0x52]), vec![]);
            store.arm(fault);
            let result = set.connect_block(&changes, &a, mode);
            if fault == Fault::RejectCas {
                assert!(matches!(
                    result,
                    Err(PersistentUtxoError::ConditionMismatch)
                ));
            } else {
                assert!(matches!(result, Err(PersistentUtxoError::Storage(_))));
            }
            assert_eq!(coin_row(&store, a).is_some(), fault == Fault::AfterWrite);
            assert!(matches!(
                set.get(&outpoint(a, 0)),
                Err(PersistentUtxoError::RecoveryRequired)
            ));
            assert!(matches!(
                set.ledger(),
                Err(PersistentUtxoError::RecoveryRequired)
            ));
            assert!(matches!(
                set.flush(),
                Err(PersistentUtxoError::RecoveryRequired)
            ));
            assert!(matches!(
                set.connect_block(&changes, &a, mode),
                Err(PersistentUtxoError::RecoveryRequired)
            ));
            assert!(matches!(
                set.undo_block(&undo_of(&two_output_add(a, &[0x51], &[0x52])), mode),
                Err(PersistentUtxoError::RecoveryRequired)
            ));
        }
    }
}

#[test]
fn refills_and_successful_flushes_reapply_the_resident_budget() {
    let store = MemoryStore::default();
    let mut set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    let a = txid(23);
    set.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &a,
        CoinDurability::Durable,
    )
    .expect("seed");
    set.set_resident_budget(1);
    set.connect_block(
        &block(vec![], vec![outpoint(a, 0)]),
        &a,
        CoinDurability::Deferred,
    )
    .expect("deferred spend");
    set.connect_block(&BlockChanges::default(), &a, CoinDurability::CasGuarded)
        .expect("no-op eviction pass");
    assert_eq!(
        set.ledger()
            .expect("dirty record is pinned")
            .resident
            .records,
        1
    );
    store.arm(Fault::Flush);
    assert!(set.flush().is_err());
    assert_eq!(
        set.ledger()
            .expect("failed flush retains pins")
            .resident
            .records,
        1
    );
    set.flush().expect("retry flush");
    assert_eq!(
        set.ledger()
            .expect("unpinned record is evicted")
            .resident
            .records,
        0
    );
    for _ in 0..3 {
        assert_eq!(
            set.get(&outpoint(a, 1))
                .expect("reload")
                .expect("sibling")
                .value,
            200
        );
        assert_eq!(
            set.ledger().expect("read respects budget").resident.records,
            0
        );
    }
}

#[test]
fn missing_vout_in_a_resident_record_does_not_refill() {
    let store = MemoryStore::default();
    let mut set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    let a = txid(24);
    set.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &a,
        CoinDurability::Durable,
    )
    .expect("seed");
    store.arm(Fault::Read);
    assert!(
        set.get(&outpoint(a, 2))
            .expect("no store read for missing sibling")
            .is_none()
    );
    set.set_resident_budget(1);
    set.flush().expect("evict clean record");
    assert!(matches!(
        set.get(&outpoint(a, 0)),
        Err(PersistentUtxoError::Storage(_))
    ));
}

#[test]
fn concurrent_partial_spends_preserve_siblings_and_store_cache_agreement() {
    let store = MemoryStore::default();
    let mut set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    let a = txid(25);
    let adds = (0..32)
        .map(|vout| UtxoAdd::new(outpoint(a, vout), txout(100, &[0x51]), false, 10))
        .collect();
    set.connect_block(&block(adds, vec![]), &a, CoinDurability::Durable)
        .expect("seed");
    set.set_resident_budget(1);
    set.flush().expect("evict");
    let barrier = Barrier::new(9);
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let set = &set;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                for vout in (worker..24).step_by(8) {
                    set.connect_block(
                        &block(vec![], vec![outpoint(a, vout)]),
                        &a,
                        CoinDurability::CasGuarded,
                    )
                    .expect("serialized partial spend");
                    assert!(
                        set.get(&outpoint(a, 31))
                            .expect("concurrent refill")
                            .is_some()
                    );
                }
            });
        }
        barrier.wait();
    });
    let reopened = PersistentUtxoSet::new(UtxoSet::new(), store);
    for vout in 0..32 {
        let output = set.get(&outpoint(a, vout)).expect("cache read");
        assert_eq!(output.is_some(), vout >= 24);
        assert_eq!(
            output,
            reopened.get(&outpoint(a, vout)).expect("store read")
        );
    }
}

#[test]
fn real_durable_write_releases_earlier_deferred_pins() {
    for mode in [CoinDurability::Durable, CoinDurability::CasGuarded] {
        let store = MemoryStore::default();
        let set = PersistentUtxoSet::new(UtxoSet::new(), store);
        let a = txid(26);
        let b = txid(27);

        set.connect_block(&block(one_output_add(a), vec![]), &a, CoinDurability::Durable)
            .expect("seed first record");
        set.connect_block(
            &block(vec![], vec![outpoint(a, 0)]),
            &a,
            CoinDurability::Deferred,
        )
        .expect("defer first-record spend");
        assert!(
            set.ledger()
                .expect("deferred ledger")
                .retained_before_image_bytes
                > 0,
            "deferred overwrite must retain its before-image"
        );

        set.connect_block(&block(one_output_add(b), vec![]), &b, mode)
            .expect("real durability boundary on second record");
        assert_eq!(
            set.ledger()
                .expect("durable ledger")
                .retained_before_image_bytes,
            0,
            "a real durable write must complete every earlier deferred write"
        );
    }
}

struct ReentrantListener {
    target: Arc<OnceLock<Weak<PersistentUtxoSet<MemoryStore>>>>,
    called: Arc<AtomicBool>,
    rejected: Arc<AtomicBool>,
}

impl ReentrantListener {
    fn probe(&self, op: &OutPoint) {
        let set = self
            .target
            .get()
            .and_then(Weak::upgrade)
            .expect("persistent set installed");
        let hash = txid(999);
        let rejected = matches!(
            set.get(op),
            Err(PersistentUtxoError::ReentrantOperation)
        ) && matches!(
            set.ledger(),
            Err(PersistentUtxoError::ReentrantOperation)
        ) && matches!(
            set.flush(),
            Err(PersistentUtxoError::ReentrantOperation)
        ) && matches!(
            set.connect_block(
                &BlockChanges::default(),
                &hash,
                CoinDurability::Durable,
            ),
            Err(PersistentUtxoError::ReentrantOperation)
        ) && matches!(
            set.undo_block(
                &bitcoin_rs_utxo::set::UndoBatch::default(),
                CoinDurability::Durable,
            ),
            Err(PersistentUtxoError::ReentrantOperation)
        );
        self.rejected.store(rejected, Ordering::SeqCst);
        self.called.store(true, Ordering::SeqCst);
    }
}

impl UtxoChangeListener for ReentrantListener {
    fn on_insert_coins(&self, insertions: &[UtxoInserted<'_>]) {
        if let Some(first) = insertions.first() {
            self.probe(first.op);
        }
    }

    fn on_remove_coins(&self, _removals: &[UtxoRemoved]) {}

    fn on_committed_event_batches(&self, _batches: &[UtxoChangeEvents<'_>]) {}
}

#[test]
fn blocked_flush_does_not_block_resident_reads() {
    let store = MemoryStore::default();
    let set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    let a = txid(28);
    set.connect_block(&block(one_output_add(a), vec![]), &a, CoinDurability::Durable)
        .expect("seed persisted resident coin");

    let gate = store.block_next_flush();
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| set.flush().expect("blocked flush completes"));
        gate.entered.wait();

        scope.spawn(|| {
            tx.send(set.get(&outpoint(a, 0)))
                .expect("send resident read");
        });

        // RCV-04A: this is a deadlock detector, not a latency requirement.
        let read_while_blocked = rx.recv_timeout(DEADLOCK_TIMEOUT);
        gate.release.wait();
        let output = read_while_blocked
            .expect("resident read waited for backing-store flush")
            .expect("resident read succeeds")
            .expect("resident output");
        assert_eq!(output.value, 100);
    });
}

#[test]
fn listener_reentry_is_rejected_instead_of_deadlocking() {
    let target = Arc::new(OnceLock::new());
    let called = Arc::new(AtomicBool::new(false));
    let rejected = Arc::new(AtomicBool::new(false));
    let store = MemoryStore::default();

    let mut raw = UtxoSet::new();
    raw.set_listener(Box::new(ReentrantListener {
        target: Arc::clone(&target),
        called: Arc::clone(&called),
        rejected: Arc::clone(&rejected),
    }));

    let set = Arc::new(PersistentUtxoSet::new(raw, store.clone()));
    assert!(target.set(Arc::downgrade(&set)).is_ok());
    store.arm(Fault::BeforeWrite);

    let worker_set = Arc::clone(&set);
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let a = txid(29);
        tx.send(worker_set.connect_block(
            &block(one_output_add(a), vec![]),
            &a,
            CoinDurability::Durable,
        ))
        .expect("send outer mutation result");
    });

    // RCV-04A: the timeout converts a regression back to self-deadlock into a test failure.
    let result = rx
        .recv_timeout(DEADLOCK_TIMEOUT)
        .expect("listener reentry deadlocked the outer mutation");
    handle.join().expect("outer mutation thread");
    assert!(matches!(result, Err(PersistentUtxoError::Storage(_))));
    assert!(called.load(Ordering::SeqCst), "listener was invoked");
    assert!(
        rejected.load(Ordering::SeqCst),
        "reentrant persistent operations must fail fast"
    );
}
