#!/usr/bin/env python3
"""Persistent-coin review edits; the helper stays off the PR branch."""
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()

def edit(path, before, after):
    target = root / path
    source = target.read_text()
    assert source.count(before) == 1, (path, before[:100])
    target.write_text(source.replace(before, after, 1))

def checked(path, sha):
    data = (root / path).read_bytes()
    actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    assert actual == sha, f'{path} advanced concurrently: {actual}; re-review before replacing'
    return data.decode()

# Rust 2024 impl-Trait capture: pass an owned path into the test factory.
edit('crates/storage/tests/overhaul_atomic_durability.rs',
     'bitcoin_rs_storage::open_redb_tx_index_store(path)',
     'bitcoin_rs_storage::open_redb_tx_index_store(path.to_path_buf())')

path = 'crates/utxo/src/set.rs'
source = checked(path, '8444c99a5e7cf09e8c161d5ab215fba06ee4f92e')
marker = '/// Durability mode for one persisted connect or disconnect.'
assert source.count(marker) == 1
source = source[:source.index(marker)].rstrip() + '\n'
source = source.replace('use bitcoin_rs_storage::WriteBatch as _;\n', '''mod persistent;
pub use persistent::{CoinDurability, CoinLedger, PersistentUtxoError, PersistentUtxoSet};
''')
(root / path).write_text(source)

edit('crates/utxo/src/shard.rs',
     'find_record(&table, key, txid).map(|record| record.encoded_bytes().to_vec())',
     'find_record(&table, key, txid)\n            .filter(|record| !record.is_empty())\n            .map(|record| record.encoded_bytes().to_vec())')

module = root / 'crates/utxo/src/set/persistent.rs'
assert not module.exists()
module.parent.mkdir(parents=True, exist_ok=True)
module.write_text(r'''//! Incremental grouped-coin persistence. See RCV-04 in docs/contracts/recovery.md.

use std::collections::VecDeque;

use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
use bitcoin_rs_storage::{ColumnFamily::CoinRecords, KvStore, StorageError, WriteBatch as _, WriteCondition};
use hashbrown::{HashMap, HashSet};
use parking_lot::{Mutex, MutexGuard};
use thiserror::Error;

use super::{BlockChanges, UndoBatch, UtxoError, UtxoMemoryReport, UtxoSet};
use crate::{UtxoKey, record::UtxoRecord, shard::Shard};

/// Durability required for changed coin rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinDurability {
    /// Visible on return; call [`PersistentUtxoSet::flush`] for crash durability.
    Deferred,
    /// Changed rows are durable on return.
    Durable,
    /// Durably replace rows only when all stored before-images still match.
    CasGuarded,
}

/// Failures are never reported as an absent coin or a successful durable write.
#[derive(Debug, Error)]
pub enum PersistentUtxoError {
    /// A mutation failed and may have changed some shards. The instance is quarantined.
    #[error("utxo mutation failed: {0}")]
    Utxo(#[from] UtxoError),
    /// A backing-store operation failed. Failed mutations quarantine the instance;
    /// read failures and unsuccessful flushes can be retried.
    #[error("coin storage operation failed: {0}")]
    Storage(#[from] StorageError),
    /// At least one before-image differed. The backend does not identify which row.
    #[error("guarded coin write found a mismatched stored row")]
    ConditionMismatch,
    /// A stored row is malformed, empty, or carries a different full transaction id.
    #[error("stored coin record failed validation for txid {0}")]
    CorruptStoredRecord(Txid),
    /// A previous mutation failed. Discard this instance and recover externally.
    #[error("coin state requires recovery after a failed mutation")]
    RecoveryRequired,
}

/// Cache accounting and pending preimage payloads; not a recovery journal or RSS total.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoinLedger {
    /// Resident shard-table accounting.
    pub resident: UtxoMemoryReport,
    /// Latest pending before-image payload per changed transaction id.
    pub retained_before_image_bytes: usize,
    /// Number of stored coin rows; a failed scan returns an error instead.
    pub stored_rows: usize,
}

#[derive(Default)]
struct State {
    resident_order: VecDeque<Hash256>,
    retained_before_images: HashMap<Hash256, Option<Vec<u8>>>,
    faulted: bool,
}

struct Change {
    txid: Hash256,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
}

/// A serialized cache and incremental writer for grouped coin rows.
///
/// Reload, mutation, persistence, and cache bookkeeping form one operation.
/// The protocol mutex precedes shard locks; no shard lock spans store I/O.
/// All coin-row writes must go through this instance. CAS detects mismatched
/// writes, but does not make an independently modified backing store a coherent cache.
///
/// A failed mutation may leave memory ahead of storage. The instance then rejects
/// all reads, writes, and flushes with [`PersistentUtxoError::RecoveryRequired`].
/// It does not roll back, reopen, or publish a recovered chain state. The caller
/// must discard it and perform the node's recovery procedure before constructing
/// a replacement. This boundary does not implement the gated durable-root owner.
pub struct PersistentUtxoSet<S: KvStore> {
    set: UtxoSet,
    store: S,
    resident_budget_bytes: usize,
    state: Mutex<State>,
}

impl<S: KvStore> PersistentUtxoSet<S> {
    /// Takes ownership of a cache consistent with `store`. An empty cache reloads
    /// rows lazily. Existing listeners observe in-memory mutations, not durability,
    /// and must not re-enter this wrapper.
    pub fn new(set: UtxoSet, store: S) -> Self {
        let mut seen = HashSet::new();
        let mut state = State::default();
        set.with_stable_view(|view| {
            view.for_each_all(|outpoint, _script| {
                let txid = Hash256::from(outpoint.txid);
                if seen.insert(txid) {
                    state.resident_order.push_back(txid);
                }
            });
        });
        Self { set, store, resident_budget_bytes: 0, state: Mutex::new(state) }
    }

    /// Sets a best-effort resident budget, applied on reads, mutations, and flush.
    /// Zero disables eviction. Pending writes and irreducible table overhead can
    /// exceed the budget; dirty records remain eligible after a successful flush.
    pub fn set_resident_budget(&mut self, bytes: usize) {
        self.resident_budget_bytes = bytes;
    }

    /// Connects a block and persists only changed rows. A no-op does not flush
    /// earlier deferred writes, regardless of the chosen mode.
    pub fn connect_block(&self, changes: &BlockChanges, block_hash: &Hash256, mode: CoinDurability) -> Result<(), PersistentUtxoError> {
        self.mutate(Self::affected_txids(changes.adds.iter().map(|add| add.outpoint.txid), &changes.removes),
                    mode, |set| set.commit_block(changes, block_hash))
    }

    /// Disconnects a block using the same serialized persistence boundary.
    pub fn undo_block(&self, undo: &UndoBatch, mode: CoinDurability) -> Result<(), PersistentUtxoError> {
        self.mutate(Self::affected_txids(undo.restores.iter().map(|add| add.outpoint.txid), &undo.removes),
                    mode, |set| set.undo_block(undo))
    }

    /// Confirms all deferred writes before releasing their pins. A failed flush
    /// retains every pin and can be retried; it cannot recover a failed mutation.
    pub fn flush(&self) -> Result<(), PersistentUtxoError> {
        let mut state = self.lock_healthy()?;
        self.store.flush()?;
        state.retained_before_images.clear();
        self.evict_over_budget(&mut state);
        Ok(())
    }

    /// Returns a live output, genuine absence, or a typed storage/corruption error.
    /// A missing vout in a resident record does not trigger a redundant refill.
    pub fn get(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, PersistentUtxoError> {
        let mut state = self.lock_healthy()?;
        let txid = Hash256::from(outpoint.txid);
        let mut output = self.set.get(outpoint);
        if output.is_none() && self.record_bytes(&txid).is_none() {
            self.reload_record(&txid, &mut state)?;
            output = self.set.get(outpoint);
        }
        self.evict_over_budget(&mut state);
        Ok(output)
    }

    /// Reads a complete byte ledger. Iterator and row-read failures propagate.
    pub fn ledger(&self) -> Result<CoinLedger, PersistentUtxoError> {
        let state = self.lock_healthy()?;
        let stored_rows = self.store.iter_prefix(CoinRecords, b"")?
            .try_fold(0_usize, |count, row| row.map(|_| count + 1))?;
        Ok(CoinLedger {
            resident: self.set.memory_report(),
            retained_before_image_bytes: state.retained_before_images.values()
                .map(|image| image.as_ref().map_or(0, Vec::len)).sum(),
            stored_rows,
        })
    }

    fn lock_healthy(&self) -> Result<MutexGuard<'_, State>, PersistentUtxoError> {
        let state = self.state.lock();
        if state.faulted { return Err(PersistentUtxoError::RecoveryRequired); }
        Ok(state)
    }

    fn affected_txids(adds: impl Iterator<Item = Txid>, removes: &[OutPoint]) -> Vec<Hash256> {
        let mut seen = HashSet::new();
        adds.chain(removes.iter().map(|op| op.txid)).map(Hash256::from)
            .filter(|txid| seen.insert(*txid)).collect()
    }

    fn mutate(&self, affected: Vec<Hash256>, mode: CoinDurability,
              apply: impl FnOnce(&UtxoSet) -> Result<(), UtxoError>) -> Result<(), PersistentUtxoError> {
        let mut state = self.lock_healthy()?;
        let mut changes = Vec::with_capacity(affected.len());
        for txid in affected {
            if self.record_bytes(&txid).is_none() { self.reload_record(&txid, &mut state)?; }
            changes.push(Change { txid, before: self.record_bytes(&txid), after: None });
        }
        // Quarantine before crossing the mutation boundary, including a caught
        // panic or a partial shard failure. Only complete success clears it.
        state.faulted = true;
        apply(&self.set)?;
        for change in &mut changes { change.after = self.record_bytes(&change.txid); }
        changes.retain(|change| change.before != change.after);
        self.persist_changed(&changes, mode)?;
        for change in changes {
            if mode == CoinDurability::Deferred {
                state.retained_before_images.insert(change.txid, change.before);
            } else {
                state.retained_before_images.remove(&change.txid);
            }
            state.resident_order.retain(|txid| *txid != change.txid);
            if change.after.is_some() {
                state.resident_order.push_back(change.txid);
            } else {
                let (shard, key) = self.shard(&change.txid);
                shard.remove_resident_record(key, change.txid);
            }
        }
        self.evict_over_budget(&mut state);
        state.faulted = false;
        Ok(())
    }

    fn persist_changed(&self, changes: &[Change], mode: CoinDurability) -> Result<(), PersistentUtxoError> {
        if changes.is_empty() { return Ok(()); }
        let mut batch = self.store.new_batch();
        for change in changes {
            let key = change.txid.as_byte_array();
            match &change.after {
                Some(bytes) => batch.put(CoinRecords, key, bytes),
                None => batch.delete(CoinRecords, key),
            }
        }
        match mode {
            CoinDurability::Deferred => self.store.write_deferred(batch)?,
            CoinDurability::Durable => self.store.write_durable(batch)?,
            CoinDurability::CasGuarded => {
                let conditions: Vec<_> = changes.iter().map(|change| {
                    let key = change.txid.as_byte_array();
                    match &change.before {
                        Some(expected) => WriteCondition::Equals { cf: CoinRecords, key, expected },
                        None => WriteCondition::Absent { cf: CoinRecords, key },
                    }
                }).collect();
                if !self.store.write_durable_if(&conditions, batch)? {
                    return Err(PersistentUtxoError::ConditionMismatch);
                }
            }
        }
        Ok(())
    }

    fn shard(&self, txid: &Hash256) -> (&Shard, UtxoKey) {
        let key = UtxoKey::from_txid(&Txid::from(*txid));
        (&self.set.shards[usize::from(key.shard())], key)
    }

    fn record_bytes(&self, txid: &Hash256) -> Option<Vec<u8>> {
        let (shard, key) = self.shard(txid);
        shard.record_bytes(key, *txid)
    }

    fn reload_record(&self, txid: &Hash256, state: &mut State) -> Result<(), PersistentUtxoError> {
        let Some(bytes) = self.store.get(CoinRecords, txid.as_byte_array())? else { return Ok(()); };
        let record = UtxoRecord::from_stored_bytes(&bytes)
            .map_err(|_| PersistentUtxoError::CorruptStoredRecord((*txid).into()))?;
        if record.txid() != *txid || record.is_empty() {
            return Err(PersistentUtxoError::CorruptStoredRecord((*txid).into()));
        }
        let (shard, key) = self.shard(txid);
        shard.insert_encoded_record(key, record);
        state.resident_order.retain(|seen| seen != txid);
        state.resident_order.push_back(*txid);
        Ok(())
    }

    fn evict_over_budget(&self, state: &mut State) {
        if self.resident_budget_bytes == 0 { return; }
        // Inspect each queued record once. Retained records rotate rather than
        // disappearing from the eviction queue forever.
        for _ in 0..state.resident_order.len() {
            if self.set.memory_report().accounted_bytes() <= self.resident_budget_bytes { break; }
            let Some(txid) = state.resident_order.pop_front() else { break; };
            if state.retained_before_images.contains_key(&txid) {
                state.resident_order.push_back(txid);
            } else {
                let (shard, key) = self.shard(&txid);
                shard.remove_resident_record(key, txid);
            }
        }
    }
}
''')

path = 'crates/utxo/tests/overhaul_persistent_coins.rs'
source = checked(path, '5e679711285161a2b71c945d4246ac97f11863db')
source = source.replace('set.ledger()', 'set.ledger().expect("read coin ledger")')
# Match balanced call parentheses, including nested outpoint helpers.
start = 0
while True:
    begin = source.find('set.get(', start)
    if begin < 0: break
    end = begin + len('set.get(')
    depth = 1
    while depth:
        depth += (source[end] == '(') - (source[end] == ')')
        end += 1
    source = source[:end] + '.expect("read coin")' + source[end:]
    start = end + len('.expect("read coin")')
source = source.replace('fn guarded_write_mismatch_is_a_typed_error()', 'fn malformed_stored_row_is_a_typed_corruption_error()')
source = source.replace('PersistentUtxoError::ConditionMismatch(_)', 'PersistentUtxoError::CorruptStoredRecord(_)')
source = source.replace('expected a typed condition mismatch', 'expected typed corruption')
source = source.replace('/// A guarded durable write against a foreign stored row is a typed\n/// mismatch, never a silent success.',
                        '/// Malformed stored bytes fail before mutation, including guarded writes.')
source = source.replace('#[derive(Default)]\nstruct MemoryStore {\n    rows: parking_lot::RwLock<Vec<Row>>,\n}', '''#[derive(Clone, Default)]
struct MemoryStore {
    rows: std::sync::Arc<parking_lot::RwLock<Vec<Row>>>,
    fault: std::sync::Arc<parking_lot::Mutex<Option<Fault>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault { Read, IterOpen, IterRow, BeforeWrite, AfterWrite, RejectCas, Flush }

impl MemoryStore {
    fn arm(&self, fault: Fault) { *self.fault.lock() = Some(fault); }

    fn take(&self, fault: Fault) -> bool {
        let mut slot = self.fault.lock();
        if *slot == Some(fault) { slot.take(); true } else { false }
    }

    fn fail(&self, fault: Fault) -> Result<(), StorageError> {
        if self.take(fault) { Err(StorageError::InvalidOperation("injected store failure")) } else { Ok(()) }
    }
}''')
source = source.replace('''        Ok(self
            .rows''', '''        self.fail(Fault::Read)?;
        Ok(self
            .rows''', 1)
source = source.replace('''        let mut rows = self
            .rows
            .read()''', '''        self.fail(Fault::IterOpen)?;
        if self.take(Fault::IterRow) {
            return Ok(Box::new(std::iter::once(Err(StorageError::InvalidOperation("injected row failure")))));
        }
        let mut rows = self
            .rows
            .read()''', 1)
source = source.replace('''    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let mut rows = self.rows.write();
        apply_ops(&mut rows, batch.ops.into_iter());
        Ok(())
    }''', '''    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.fail(Fault::BeforeWrite)?;
        apply_ops(&mut self.rows.write(), batch.ops.into_iter());
        self.fail(Fault::AfterWrite)
    }''')
source = source.replace('''    ) -> Result<bool, StorageError> {
        let mut rows = self.rows.write();''', '''    ) -> Result<bool, StorageError> {
        if self.take(Fault::RejectCas) { return Ok(false); }
        self.fail(Fault::BeforeWrite)?;
        let mut rows = self.rows.write();''', 1)
source = source.replace('''        apply_ops(&mut rows, batch.ops.into_iter());
        Ok(true)''', '''        apply_ops(&mut rows, batch.ops.into_iter());
        self.fail(Fault::AfterWrite)?;
        Ok(true)''', 1)
source = source.replace('''    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }''', '''    fn flush(&self) -> Result<(), StorageError> {
        self.fail(Fault::Flush)
    }''', 1)
source += r'''

fn coin_row(store: &MemoryStore, txid: Hash256) -> Option<Vec<u8>> {
    store.get(ColumnFamily::CoinRecords, txid.as_byte_array()).expect("read raw coin row")
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
    assert!(matches!(set.get(&outpoint(txid(20), 0)), Err(PersistentUtxoError::Storage(_))));
    assert!(set.get(&outpoint(txid(20), 0)).expect("retry read").is_none());
    for fault in [Fault::IterOpen, Fault::IterRow] {
        store.arm(fault);
        assert!(matches!(set.ledger(), Err(PersistentUtxoError::Storage(_))));
    }
    assert_eq!(set.ledger().expect("retry scan").stored_rows, 0);
}

#[test]
fn corrupt_rows_cannot_be_read_spent_or_overwritten() {
    for mode in [CoinDurability::Deferred, CoinDurability::Durable, CoinDurability::CasGuarded] {
        let store = MemoryStore::default();
        let a = txid(21);
        put_row(&store, a, b"corrupt");
        let set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
        assert!(matches!(set.get(&outpoint(a, 0)), Err(PersistentUtxoError::CorruptStoredRecord(_))));
        for changes in [block(vec![], vec![outpoint(a, 0)]), block(two_output_add(a, &[0x51], &[0x52]), vec![])] {
            assert!(matches!(set.connect_block(&changes, &a, mode), Err(PersistentUtxoError::CorruptStoredRecord(_))));
            assert_eq!(coin_row(&store, a).as_deref(), Some(b"corrupt".as_slice()));
            assert_eq!(set.ledger().expect("pre-mutation rejection remains readable").resident.records, 0);
        }
    }
}

#[test]
fn stored_full_identity_must_match_even_when_accelerators_collide() {
    let store = MemoryStore::default();
    let a = txid_with_prefix(7, 1);
    let b = txid_with_prefix(7, 2);
    let writer = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    writer.connect_block(&block(two_output_add(a, &[0x51], &[0x52]), vec![]), &a, CoinDurability::Durable).expect("seed");
    let bytes = coin_row(&store, a).expect("encoded row");
    put_row(&store, b, &bytes);
    let set = PersistentUtxoSet::new(UtxoSet::new(), store);
    assert!(matches!(set.get(&outpoint(b, 0)), Err(PersistentUtxoError::CorruptStoredRecord(id)) if id == b.into()));
    assert_eq!(set.ledger().expect("no corrupt refill").resident.records, 0);
    assert_eq!(set.get(&outpoint(a, 0)).expect("valid identity").expect("live output").value, 100);
}

#[test]
fn failed_mutations_quarantine_all_public_operations() {
    for mode in [CoinDurability::Deferred, CoinDurability::Durable, CoinDurability::CasGuarded] {
        for fault in [Fault::BeforeWrite, Fault::AfterWrite, Fault::RejectCas] {
            if fault == Fault::RejectCas && mode != CoinDurability::CasGuarded { continue; }
            let store = MemoryStore::default();
            let set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
            let a = txid(22);
            let changes = block(two_output_add(a, &[0x51], &[0x52]), vec![]);
            store.arm(fault);
            let result = set.connect_block(&changes, &a, mode);
            if fault == Fault::RejectCas {
                assert!(matches!(result, Err(PersistentUtxoError::ConditionMismatch)));
            } else {
                assert!(matches!(result, Err(PersistentUtxoError::Storage(_))));
            }
            assert_eq!(coin_row(&store, a).is_some(), fault == Fault::AfterWrite);
            assert!(matches!(set.get(&outpoint(a, 0)), Err(PersistentUtxoError::RecoveryRequired)));
            assert!(matches!(set.ledger(), Err(PersistentUtxoError::RecoveryRequired)));
            assert!(matches!(set.flush(), Err(PersistentUtxoError::RecoveryRequired)));
            assert!(matches!(set.connect_block(&changes, &a, mode), Err(PersistentUtxoError::RecoveryRequired)));
            assert!(matches!(set.undo_block(&undo_of(&two_output_add(a, &[0x51], &[0x52])), mode), Err(PersistentUtxoError::RecoveryRequired)));
        }
    }
}

#[test]
fn refills_and_successful_flushes_reapply_the_resident_budget() {
    let store = MemoryStore::default();
    let mut set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    let a = txid(23);
    set.connect_block(&block(two_output_add(a, &[0x51], &[0x52]), vec![]), &a, CoinDurability::Durable).expect("seed");
    set.set_resident_budget(1);
    set.connect_block(&block(vec![], vec![outpoint(a, 0)]), &a, CoinDurability::Deferred).expect("deferred spend");
    set.connect_block(&BlockChanges::default(), &a, CoinDurability::CasGuarded).expect("no-op eviction pass");
    assert_eq!(set.ledger().expect("dirty record is pinned").resident.records, 1);
    store.arm(Fault::Flush);
    assert!(set.flush().is_err());
    assert_eq!(set.ledger().expect("failed flush retains pins").resident.records, 1);
    set.flush().expect("retry flush");
    assert_eq!(set.ledger().expect("unpinned record is evicted").resident.records, 0);
    for _ in 0..3 {
        assert_eq!(set.get(&outpoint(a, 1)).expect("reload").expect("sibling").value, 200);
        assert_eq!(set.ledger().expect("read respects budget").resident.records, 0);
    }
}

#[test]
fn missing_vout_in_a_resident_record_does_not_refill() {
    let store = MemoryStore::default();
    let mut set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    let a = txid(24);
    set.connect_block(&block(two_output_add(a, &[0x51], &[0x52]), vec![]), &a, CoinDurability::Durable).expect("seed");
    store.arm(Fault::Read);
    assert!(set.get(&outpoint(a, 2)).expect("no store read for missing sibling").is_none());
    set.set_resident_budget(1);
    set.flush().expect("evict clean record");
    assert!(matches!(set.get(&outpoint(a, 0)), Err(PersistentUtxoError::Storage(_))));
}

#[test]
fn concurrent_partial_spends_preserve_siblings_and_store_cache_agreement() {
    let store = MemoryStore::default();
    let mut set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    let a = txid(25);
    let adds = (0..32).map(|vout| UtxoAdd::new(outpoint(a, vout), txout(100, &[0x51]), false, 10)).collect();
    set.connect_block(&block(adds, vec![]), &a, CoinDurability::Durable).expect("seed");
    set.set_resident_budget(1);
    set.flush().expect("evict");
    let barrier = std::sync::Barrier::new(9);
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let set = &set;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                for vout in (worker..24).step_by(8) {
                    set.connect_block(&block(vec![], vec![outpoint(a, vout)]), &a, CoinDurability::CasGuarded).expect("serialized partial spend");
                    assert!(set.get(&outpoint(a, 31)).expect("concurrent refill").is_some());
                }
            });
        }
        barrier.wait();
    });
    let reopened = PersistentUtxoSet::new(UtxoSet::new(), store);
    for vout in 0..32 {
        let output = set.get(&outpoint(a, vout)).expect("cache read");
        assert_eq!(output.is_some(), vout >= 24);
        assert_eq!(output, reopened.get(&outpoint(a, vout)).expect("store read"));
    }
}
'''
(root / path).write_text(source)

# Stop rather than leave other callers compiling against the old fallible API.
known = {'crates/utxo/src/set.rs', 'crates/utxo/src/set/persistent.rs', path}
callers = {str(p.relative_to(root)) for p in (root / 'crates').rglob('*.rs') if 'PersistentUtxoSet' in p.read_text()}
assert callers <= known, f'Additional callers require migration: {callers - known}'
print('Persistent-coin module, fallible callers, and failure/cache/concurrency regressions prepared')
