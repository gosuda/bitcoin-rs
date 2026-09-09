//! Incremental grouped-coin persistence. See RCV-04 in docs/contracts/recovery.md.

use std::{collections::VecDeque, thread::ThreadId};

use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
use bitcoin_rs_storage::{
    ColumnFamily::CoinRecords, KvStore, StorageError, WriteBatch as _, WriteCondition,
};
use hashbrown::{HashMap, HashSet};
use parking_lot::{Condvar, Mutex, MutexGuard};
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
    /// A callback tried to start an operation that would wait on its own transition.
    #[error("coin operation cannot re-enter an active persistent transition")]
    ReentrantOperation,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransitionKind {
    Mutation,
    Storage,
}

#[derive(Clone, Copy, Debug)]
struct InFlight {
    owner: ThreadId,
    generation: u64,
    kind: TransitionKind,
}

#[derive(Default)]
struct State {
    resident_order: VecDeque<Hash256>,
    retained_before_images: HashMap<Hash256, Option<Vec<u8>>>,
    faulted: bool,
    generation: u64,
    in_flight: Option<InFlight>,
}

struct Change {
    txid: Hash256,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
}

struct Transition<'a, S: KvStore> {
    set: &'a PersistentUtxoSet<S>,
    owner: ThreadId,
    generation: u64,
}

impl<S: KvStore> Drop for Transition<'_, S> {
    fn drop(&mut self) {
        let mut state = self.set.state.lock();
        let owns_transition = state.in_flight.is_some_and(|active| {
            active.owner == self.owner && active.generation == self.generation
        });
        debug_assert!(owns_transition, "persistent transition generation changed");
        if owns_transition {
            state.in_flight = None;
        }
        drop(state);
        self.set.idle.notify_all();
    }
}

/// A serialized cache and incremental writer for grouped coin rows.
///
/// An in-flight generation serializes refill, mutation, persistence, and flush
/// without keeping the metadata mutex across backing-store I/O or callbacks.
/// The metadata mutex precedes shard locks; no shard lock spans store I/O.
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
    idle: Condvar,
}

impl<S: KvStore> PersistentUtxoSet<S> {
    /// Takes ownership of a cache consistent with `store`. An empty cache reloads
    /// rows lazily. Existing listeners observe in-memory mutations, not durability.
    /// Reentrant persistent operations fail instead of waiting on their own callback.
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
        Self {
            set,
            store,
            resident_budget_bytes: 0,
            state: Mutex::new(state),
            idle: Condvar::new(),
        }
    }

    /// Sets a best-effort resident budget, applied on reads, mutations, and flush.
    /// Zero disables eviction. Pending writes and irreducible table overhead can
    /// exceed the budget; dirty records remain eligible after a successful flush.
    pub fn set_resident_budget(&mut self, bytes: usize) {
        self.resident_budget_bytes = bytes;
    }

    /// Connects a block and persists only changed rows. A no-op does not flush
    /// earlier deferred writes, regardless of the chosen mode.
    pub fn connect_block(
        &self,
        changes: &BlockChanges,
        block_hash: &Hash256,
        mode: CoinDurability,
    ) -> Result<(), PersistentUtxoError> {
        self.mutate(
            Self::affected_txids(
                changes.adds.iter().map(|add| add.outpoint.txid),
                &changes.removes,
            ),
            mode,
            |set| set.commit_block(changes, block_hash),
        )
    }

    /// Disconnects a block using the same serialized persistence boundary.
    pub fn undo_block(
        &self,
        undo: &UndoBatch,
        mode: CoinDurability,
    ) -> Result<(), PersistentUtxoError> {
        self.mutate(
            Self::affected_txids(
                undo.restores.iter().map(|add| add.outpoint.txid),
                &undo.removes,
            ),
            mode,
            |set| set.undo_block(undo),
        )
    }

    /// Confirms all deferred writes before releasing their pins. A failed flush
    /// retains every pin and can be retried; it cannot recover a failed mutation.
    pub fn flush(&self) -> Result<(), PersistentUtxoError> {
        let transition = self.begin_transition(TransitionKind::Storage)?;
        self.store.flush()?;
        let mut state = self.transition_state(&transition);
        state.retained_before_images.clear();
        self.evict_over_budget(&mut state);
        Ok(())
    }

    /// Returns a live output, genuine absence, or a typed storage/corruption error.
    /// A missing vout in a resident record does not trigger a redundant refill.
    pub fn get(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, PersistentUtxoError> {
        let owner = std::thread::current().id();
        let txid = Hash256::from(outpoint.txid);

        loop {
            let mut state = self.state.lock();
            if let Some(active) = state.in_flight {
                if active.kind == TransitionKind::Mutation {
                    if active.owner == owner {
                        return Err(PersistentUtxoError::ReentrantOperation);
                    }
                    self.idle.wait(&mut state);
                    continue;
                }
            }
            if state.faulted {
                return Err(PersistentUtxoError::RecoveryRequired);
            }

            let output = self.set.get(outpoint);
            if output.is_some() || self.record_bytes(&txid).is_some() {
                self.evict_over_budget(&mut state);
                return Ok(output);
            }
            drop(state);

            let transition = self.begin_transition(TransitionKind::Storage)?;
            {
                let mut state = self.transition_state(&transition);
                let output = self.set.get(outpoint);
                if output.is_some() || self.record_bytes(&txid).is_some() {
                    self.evict_over_budget(&mut state);
                    return Ok(output);
                }
            }

            let record = self.load_record(&txid)?;
            let mut state = self.transition_state(&transition);
            if let Some(record) = record {
                self.install_record(&txid, record, &mut state);
            }
            let output = self.set.get(outpoint);
            self.evict_over_budget(&mut state);
            return Ok(output);
        }
    }

    /// Reads a complete byte ledger. Iterator and row-read failures propagate.
    pub fn ledger(&self) -> Result<CoinLedger, PersistentUtxoError> {
        let transition = self.begin_transition(TransitionKind::Storage)?;
        let stored_rows = self
            .store
            .iter_prefix(CoinRecords, b"")?
            .try_fold(0_usize, |count, row| row.map(|_| count + 1))?;
        let state = self.transition_state(&transition);
        Ok(CoinLedger {
            resident: self.set.memory_report(),
            retained_before_image_bytes: state
                .retained_before_images
                .values()
                .map(|image| image.as_ref().map_or(0, Vec::len))
                .sum(),
            stored_rows,
        })
    }

    fn begin_transition(
        &self,
        kind: TransitionKind,
    ) -> Result<Transition<'_, S>, PersistentUtxoError> {
        let owner = std::thread::current().id();
        let mut state = self.state.lock();
        loop {
            if let Some(active) = state.in_flight {
                if active.owner == owner {
                    return Err(PersistentUtxoError::ReentrantOperation);
                }
                self.idle.wait(&mut state);
                continue;
            }
            if state.faulted {
                return Err(PersistentUtxoError::RecoveryRequired);
            }
            state.generation = state.generation.wrapping_add(1);
            let generation = state.generation;
            state.in_flight = Some(InFlight {
                owner,
                generation,
                kind,
            });
            return Ok(Transition {
                set: self,
                owner,
                generation,
            });
        }
    }

    fn transition_state<'a>(
        &'a self,
        transition: &Transition<'_, S>,
    ) -> MutexGuard<'a, State> {
        let state = self.state.lock();
        debug_assert!(std::ptr::eq(self, transition.set));
        debug_assert!(state.in_flight.is_some_and(|active| {
            active.owner == transition.owner && active.generation == transition.generation
        }));
        state
    }

    fn affected_txids(adds: impl Iterator<Item = Txid>, removes: &[OutPoint]) -> Vec<Hash256> {
        let mut seen = HashSet::new();
        adds.chain(removes.iter().map(|op| op.txid))
            .map(Hash256::from)
            .filter(|txid| seen.insert(*txid))
            .collect()
    }

    fn mutate(
        &self,
        affected: Vec<Hash256>,
        mode: CoinDurability,
        apply: impl FnOnce(&UtxoSet) -> Result<(), UtxoError>,
    ) -> Result<(), PersistentUtxoError> {
        let transition = self.begin_transition(TransitionKind::Mutation)?;
        let mut changes = Vec::with_capacity(affected.len());
        for txid in affected {
            self.ensure_resident(&txid, &transition)?;
            changes.push(Change {
                txid,
                before: self.record_bytes(&txid),
                after: None,
            });
        }

        // Quarantine before crossing the mutation boundary, including a caught
        // panic or a partial shard failure. Only complete success clears it.
        self.transition_state(&transition).faulted = true;
        apply(&self.set)?;
        for change in &mut changes {
            change.after = self.record_bytes(&change.txid);
        }
        changes.retain(|change| change.before != change.after);

        let completed_durability = self.persist_changed(&changes, mode)?;
        let mut state = self.transition_state(&transition);
        if completed_durability {
            // A successful durable write also completes every earlier deferred
            // write, so none of their before-images remain pinned.
            state.retained_before_images.clear();
        }
        for change in changes {
            if mode == CoinDurability::Deferred {
                state
                    .retained_before_images
                    .insert(change.txid, change.before);
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

    fn persist_changed(
        &self,
        changes: &[Change],
        mode: CoinDurability,
    ) -> Result<bool, PersistentUtxoError> {
        if changes.is_empty() {
            return Ok(false);
        }
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
                let conditions: Vec<_> = changes
                    .iter()
                    .map(|change| {
                        let key = change.txid.as_byte_array();
                        match &change.before {
                            Some(expected) => WriteCondition::Equals {
                                cf: CoinRecords,
                                key,
                                expected,
                            },
                            None => WriteCondition::Absent {
                                cf: CoinRecords,
                                key,
                            },
                        }
                    })
                    .collect();
                if !self.store.write_durable_if(&conditions, batch)? {
                    return Err(PersistentUtxoError::ConditionMismatch);
                }
            }
        }
        Ok(mode != CoinDurability::Deferred)
    }

    fn shard(&self, txid: &Hash256) -> (&Shard, UtxoKey) {
        let key = UtxoKey::from_txid(&Txid::from(*txid));
        (&self.set.shards[usize::from(key.shard())], key)
    }

    fn record_bytes(&self, txid: &Hash256) -> Option<Vec<u8>> {
        let (shard, key) = self.shard(txid);
        shard.record_bytes(key, *txid)
    }

    fn ensure_resident(
        &self,
        txid: &Hash256,
        transition: &Transition<'_, S>,
    ) -> Result<(), PersistentUtxoError> {
        {
            let _state = self.transition_state(transition);
            if self.record_bytes(txid).is_some() {
                return Ok(());
            }
        }

        let record = self.load_record(txid)?;
        if let Some(record) = record {
            let mut state = self.transition_state(transition);
            if self.record_bytes(txid).is_none() {
                self.install_record(txid, record, &mut state);
            }
        }
        Ok(())
    }

    fn load_record(&self, txid: &Hash256) -> Result<Option<UtxoRecord>, PersistentUtxoError> {
        let Some(bytes) = self.store.get(CoinRecords, txid.as_byte_array())? else {
            return Ok(None);
        };
        let record = UtxoRecord::from_stored_bytes(&bytes)
            .map_err(|_| PersistentUtxoError::CorruptStoredRecord((*txid).into()))?;
        if record.txid() != *txid || record.is_empty() {
            return Err(PersistentUtxoError::CorruptStoredRecord((*txid).into()));
        }
        Ok(Some(record))
    }

    fn install_record(&self, txid: &Hash256, record: UtxoRecord, state: &mut State) {
        let (shard, key) = self.shard(txid);
        shard.insert_encoded_record(key, record);
        state.resident_order.retain(|seen| seen != txid);
        state.resident_order.push_back(*txid);
    }

    fn evict_over_budget(&self, state: &mut State) {
        if self.resident_budget_bytes == 0 {
            return;
        }
        // Inspect each queued record once. Retained records rotate rather than
        // disappearing from the eviction queue forever.
        for _ in 0..state.resident_order.len() {
            if self.set.memory_report().accounted_bytes() <= self.resident_budget_bytes {
                break;
            }
            let Some(txid) = state.resident_order.pop_front() else {
                break;
            };
            if state.retained_before_images.contains_key(&txid) {
                state.resident_order.push_back(txid);
            } else {
                let (shard, key) = self.shard(&txid);
                shard.remove_resident_record(key, txid);
            }
        }
    }
}
