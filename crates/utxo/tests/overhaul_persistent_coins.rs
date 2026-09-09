//! Scenario tests for incrementally persisted grouped coin records (T10).
//!
//! These pin the persisted coin layer: connect and disconnect retain exact
//! full keys with lossless scripts and values, colliding accelerators never
//! alias two records, eviction reloads byte-identical records (spending one
//! output of an evicted record never truncates its siblings), ephemeral
//! same-block outputs persist nothing while undo stays exact, and the byte
//! ledger counts resident tables plus retained versions.

#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition,
};
use bitcoin_rs_utxo::set::{
    BlockChanges, CoinDurability, PersistentUtxoError, PersistentUtxoSet, UtxoAdd, UtxoSet,
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
struct MemoryStore {
    rows: parking_lot::RwLock<Vec<Row>>,
}

impl KvStore for MemoryStore {
    type WriteBatch = MemoryBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
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
        let mut rows = self.rows.write();
        apply_ops(&mut rows, batch.ops.into_iter());
        Ok(())
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
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
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
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

    let stored_a = set.ledger().resident.records;
    assert_eq!(stored_a, 1, "one grouped record");
    let got_a = set.get(&outpoint(a, 0)).expect("output 0");
    assert_eq!(got_a.script_pubkey, script_a);
    assert_eq!(got_a.value, 100);
    let got_b = set.get(&outpoint(a, 1)).expect("output 1");
    assert_eq!(got_b.script_pubkey, script_b);
    assert_eq!(got_b.value, 200);

    // Undo restores both halves exactly.
    let adds = two_output_add(a, &script_a, &script_b);
    let undo = undo_of(&adds);
    set.undo_block(&undo, CoinDurability::Durable)
        .expect("undo");
    assert!(set.get(&outpoint(a, 0)).is_none());
    assert!(set.get(&outpoint(a, 1)).is_none());
    assert_eq!(set.ledger().stored_rows, 0, "row removed with the block");
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

    assert_eq!(set.get(&outpoint(a, 0)).expect("a:0").script_pubkey, [0xAA]);
    assert_eq!(set.get(&outpoint(b, 0)).expect("b:0").script_pubkey, [0xBA]);
    assert_eq!(set.ledger().stored_rows, 2, "two distinct rows");
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
        set.ledger().resident.records,
        0,
        "record evicted from the cache"
    );
    assert_eq!(set.ledger().stored_rows, 1, "record durable in the store");

    // Spend output 0 in a later block: reload-before-snapshot must recover
    // the full record so the after-image keeps output 1.
    set.connect_block(
        &block(vec![], vec![outpoint(a, 0)]),
        &hash,
        CoinDurability::Durable,
    )
    .expect("connect spending block");
    let sibling = set.get(&outpoint(a, 1)).expect("sibling output survived");
    assert_eq!(sibling.script_pubkey, script_b);
    assert_eq!(sibling.value, 200);
    assert!(set.get(&outpoint(a, 0)).is_none(), "spent output gone");

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
        set.get(&outpoint(a, 0)).expect("restored 0").script_pubkey,
        script_a
    );
    assert_eq!(
        set.get(&outpoint(a, 1)).expect("restored 1").script_pubkey,
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
    assert_eq!(set.ledger().stored_rows, 0, "no live row ever persisted");
    assert!(
        set.get(&outpoint(a, 0)).is_none(),
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
        set.get(&outpoint(a, 0)).is_none(),
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
    let ledger = set.ledger();
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
    let ledger = set.ledger();
    assert!(
        ledger.retained_before_image_bytes > 0,
        "the durable window owes the prior version"
    );
    set.flush().expect("flush completes durability");
    let ledger = set.ledger();
    assert_eq!(
        ledger.retained_before_image_bytes, 0,
        "flush drains the retained versions"
    );
}

/// A guarded durable write against a foreign stored row is a typed
/// mismatch, never a silent success.
#[test]
fn guarded_write_mismatch_is_a_typed_error() {
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
        matches!(error, PersistentUtxoError::ConditionMismatch(_)),
        "expected a typed condition mismatch, got {error:?}"
    );
}
