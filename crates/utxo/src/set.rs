use std::{
    io,
    mem::{self, MaybeUninit},
};

use bitcoin::ScriptBuf;
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use rayon::prelude::*;
use smallvec::SmallVec;
use thiserror::Error;

use crate::{UtxoKey, record::OwnedUtxoOut, shard::Shard};

const PARALLEL_NO_LISTENER_SHARD_THRESHOLD: usize = 3;
const PARALLEL_LISTENER_SHARD_THRESHOLD: usize = 16;
const TXID_RUN_GROUPING_MAX_SHARDS: usize = 8;

/// Errors returned by UTXO mutation and snapshot operations.
#[derive(Debug, Error)]
pub enum UtxoError {
    /// A legacy snapshot v2 bitmap only represents vouts `0..64`.
    #[error("snapshot v2 vout {vout} exceeds bitmap range 0..64")]
    VoutOutOfRange {
        /// Invalid vout.
        vout: u32,
    },
    /// A script does not fit the snapshot and record `u16` length field.
    #[error("script_pubkey is too large for a u16 length: {len} bytes")]
    ScriptTooLarge {
        /// Script length in bytes.
        len: usize,
    },
    /// The shard script slab exceeded the record `u32` offset field.
    #[error("script arena offset exceeded u32 range at {len} bytes")]
    ArenaOffsetOverflow {
        /// Current script slab byte length.
        len: usize,
    },
    /// Internal record offsets no longer point into the shard script slab.
    #[error("UTXO record points outside its shard script arena")]
    CorruptArena,
    /// Snapshot I/O failed.
    #[error("snapshot I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Snapshot magic did not match `UTXO`.
    #[error("invalid snapshot magic {actual:#010x}")]
    InvalidSnapshotMagic {
        /// Observed magic.
        actual: u32,
    },
    /// Snapshot version is not supported by this crate.
    #[error("unsupported snapshot version {version}")]
    UnsupportedSnapshotVersion {
        /// Observed version.
        version: u32,
    },
    /// Snapshot record count does not fit the local platform.
    #[error("snapshot record count {count} does not fit usize")]
    SnapshotRecordCountTooLarge {
        /// Record count from the header.
        count: u64,
    },
    /// Snapshot output count does not fit the record header.
    #[error("snapshot record has too many live outputs: {count}")]
    SnapshotOutputCountTooLarge {
        /// Live output count in one transaction-level record.
        count: usize,
    },
    /// Snapshot vout count does not match the bitmap.
    #[error("snapshot record vout count {vout_count} does not match bitmap {bitmap:#018x}")]
    SnapshotVoutCountMismatch {
        /// Vout bitmap from the record.
        bitmap: u64,
        /// Vout count from the record.
        vout_count: u8,
    },
    /// Snapshot vout is not present in the legacy record bitmap.
    #[error("snapshot v2 vout {vout} is not present in bitmap {bitmap:#018x}")]
    SnapshotVoutBitmapMismatch {
        /// Vout bitmap from the record.
        bitmap: u64,
        /// Output index from the record body.
        vout: u32,
    },
    /// Snapshot record serialized the same vout more than once.
    #[error("snapshot record duplicates vout {vout}")]
    SnapshotDuplicateVout {
        /// Duplicated output index.
        vout: u32,
    },
    /// Snapshot shard byte does not match the key's first byte.
    #[error("snapshot shard {shard} does not match key shard {key_shard}")]
    SnapshotShardMismatch {
        /// Shard index serialized in the record.
        shard: u8,
        /// Shard implied by the key prefix.
        key_shard: u8,
    },
    /// Snapshot full txid does not match the stored key prefix.
    #[error("snapshot txid prefix does not match record key prefix")]
    SnapshotTxidPrefixMismatch,
}

/// Receives UTXO mutations committed to durable shard state.
pub trait UtxoChangeListener {
    /// Called after an output has been inserted into its shard.
    fn on_insert(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool);

    /// Called after a same-transaction run of outputs has been inserted.
    fn on_insert_coins(&self, insertions: &[UtxoInserted<'_>]) {
        for insertion in insertions {
            self.on_insert(
                insertion.op,
                insertion.txout,
                insertion.height,
                insertion.coinbase,
            );
        }
    }

    /// Called after an output has been removed from its shard.
    fn on_remove(&self, op: &OutPoint, txout: &TxOut, height: u32);

    /// Called after an output has been removed, with the coinbase flag retained.
    fn on_remove_coin(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        let _ = coinbase;
        self.on_remove(op, txout, height);
    }

    /// Called after a same-transaction run of outputs has been removed.
    fn on_remove_coins(&self, removals: &[UtxoRemoved]) {
        for removal in removals {
            self.on_remove_coin(
                &removal.op,
                &removal.txout,
                removal.height,
                removal.coinbase,
            );
        }
    }

    #[doc(hidden)]
    /// Applies committed shard event batches when this listener's final state is event-order
    /// independent.
    fn on_committed_event_batches(&self, batches: &[UtxoChangeEvents<'_>]) -> bool {
        let _ = batches;
        false
    }

    #[doc(hidden)]
    /// Returns true when this listener accepts coalesced committed event batches.
    fn coalesces_committed_events(&self) -> bool {
        false
    }

    /// Returns the current `MuHash3072` snapshot trailer, when this listener tracks one.
    fn muhash3072(&self) -> Option<[u8; 384]> {
        None
    }
}

/// One inserted UTXO event delivered to a change listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoInserted<'a> {
    /// Outpoint that was inserted.
    pub op: &'a OutPoint,
    /// Inserted transaction output.
    pub txout: &'a TxOut,
    /// Height at which the inserted output was created.
    pub height: u32,
    /// Whether the inserted output came from a coinbase transaction.
    pub coinbase: bool,
}

impl<'a> UtxoInserted<'a> {
    /// Constructs one inserted UTXO event.
    #[must_use]
    pub const fn new(op: &'a OutPoint, txout: &'a TxOut, height: u32, coinbase: bool) -> Self {
        Self {
            op,
            txout,
            height,
            coinbase,
        }
    }
}

/// One removed UTXO event delivered to a change listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoRemoved {
    /// Outpoint that was removed.
    pub op: OutPoint,
    /// Removed transaction output.
    pub txout: TxOut,
    /// Height at which the removed output was created.
    pub height: u32,
    /// Whether the removed output came from a coinbase transaction.
    pub coinbase: bool,
}

impl UtxoRemoved {
    /// Constructs one removed UTXO event.
    #[must_use]
    pub const fn new(op: OutPoint, txout: TxOut, height: u32, coinbase: bool) -> Self {
        Self {
            op,
            txout,
            height,
            coinbase,
        }
    }
}

enum UtxoChangeEvent<'a> {
    InsertBatch(SmallVec<[UtxoInserted<'a>; 8]>),
    RemoveBatch(SmallVec<[UtxoRemoved; 2]>),
    RemoveCoin(UtxoRemoved),
}

#[derive(Default)]
#[doc(hidden)]
pub struct UtxoChangeEvents<'a> {
    events: Vec<UtxoChangeEvent<'a>>,
    operation_count: usize,
    coalesced_insert_capacity: usize,
    coalesced_remove_capacity: usize,
}

#[doc(hidden)]
/// Read-only view over one committed UTXO event.
#[derive(Clone, Copy)]
pub enum UtxoCommittedEvent<'batch, 'coin> {
    /// Batch of inserted UTXOs.
    InsertBatch(&'batch [UtxoInserted<'coin>]),
    /// Batch of removed UTXOs.
    RemoveBatch(&'batch [UtxoRemoved]),
    /// Single removed UTXO emitted at an overwrite boundary.
    RemoveCoin(&'batch UtxoRemoved),
}

impl<'a> UtxoChangeEvents<'a> {
    pub(crate) fn with_coalesced_capacity(insertions: usize, removals: usize) -> Self {
        Self {
            events: Vec::with_capacity(usize::from(insertions > 0) + usize::from(removals > 0)),
            operation_count: 0,
            coalesced_insert_capacity: insertions,
            coalesced_remove_capacity: removals,
        }
    }

    pub(crate) fn push_insert_batch(&mut self, insertions: SmallVec<[UtxoInserted<'a>; 8]>) {
        if !insertions.is_empty() {
            self.operation_count = self.operation_count.saturating_add(insertions.len());
            self.events.push(UtxoChangeEvent::InsertBatch(insertions));
        }
    }

    pub(crate) fn push_insert_batch_coalesced(
        &mut self,
        insertions: SmallVec<[UtxoInserted<'a>; 8]>,
    ) {
        if insertions.is_empty() {
            return;
        }
        self.operation_count = self.operation_count.saturating_add(insertions.len());
        if let Some(UtxoChangeEvent::InsertBatch(existing)) = self.events.last_mut() {
            existing.extend(insertions);
        } else {
            let mut insertions = insertions;
            reserve_smallvec(&mut insertions, self.coalesced_insert_capacity);
            self.events.push(UtxoChangeEvent::InsertBatch(insertions));
        }
    }

    pub(crate) fn push_insert_coin_coalesced(&mut self, insertion: UtxoInserted<'a>) {
        self.operation_count = self.operation_count.saturating_add(1);
        if let Some(UtxoChangeEvent::InsertBatch(existing)) = self.events.last_mut() {
            existing.push(insertion);
        } else {
            let mut insertions = SmallVec::<[UtxoInserted<'a>; 8]>::new();
            reserve_smallvec(&mut insertions, self.coalesced_insert_capacity);
            insertions.push(insertion);
            self.events.push(UtxoChangeEvent::InsertBatch(insertions));
        }
    }

    pub(crate) fn push_remove_batch(&mut self, removals: SmallVec<[UtxoRemoved; 2]>) {
        self.operation_count = self.operation_count.saturating_add(removals.len());
        self.events.push(UtxoChangeEvent::RemoveBatch(removals));
    }

    pub(crate) fn push_remove_batch_coalesced(&mut self, removals: SmallVec<[UtxoRemoved; 2]>) {
        if removals.is_empty() {
            return;
        }
        self.operation_count = self.operation_count.saturating_add(removals.len());
        if let Some(UtxoChangeEvent::RemoveBatch(existing)) = self.events.last_mut() {
            existing.extend(removals);
        } else {
            let mut removals = removals;
            reserve_smallvec(&mut removals, self.coalesced_remove_capacity);
            self.events.push(UtxoChangeEvent::RemoveBatch(removals));
        }
    }

    pub(crate) fn push_remove_coin(&mut self, removal: UtxoRemoved) {
        self.operation_count = self.operation_count.saturating_add(1);
        self.events.push(UtxoChangeEvent::RemoveCoin(removal));
    }

    /// Visits committed events in the same order the fallback listener replay uses.
    pub fn for_each(&self, mut visit: impl FnMut(UtxoCommittedEvent<'_, 'a>)) {
        for event in &self.events {
            match event {
                UtxoChangeEvent::InsertBatch(insertions) => {
                    visit(UtxoCommittedEvent::InsertBatch(insertions));
                }
                UtxoChangeEvent::RemoveBatch(removals) => {
                    visit(UtxoCommittedEvent::RemoveBatch(removals));
                }
                UtxoChangeEvent::RemoveCoin(removal) => {
                    visit(UtxoCommittedEvent::RemoveCoin(removal));
                }
            }
        }
    }

    /// Returns the number of output-level mutations represented by these events.
    #[must_use]
    pub fn operation_count(&self) -> usize {
        self.operation_count
    }

    /// Visits committed events split into bounded chunks.
    pub fn for_each_chunk<'batch>(
        &'batch self,
        chunk_size: usize,
        mut visit: impl FnMut(UtxoCommittedEvent<'batch, 'a>),
    ) {
        let chunk_size = chunk_size.max(1);
        for event in &self.events {
            match event {
                UtxoChangeEvent::InsertBatch(insertions) => {
                    for chunk in insertions.chunks(chunk_size) {
                        visit(UtxoCommittedEvent::InsertBatch(chunk));
                    }
                }
                UtxoChangeEvent::RemoveBatch(removals) => {
                    for chunk in removals.chunks(chunk_size) {
                        visit(UtxoCommittedEvent::RemoveBatch(chunk));
                    }
                }
                UtxoChangeEvent::RemoveCoin(removal) => {
                    visit(UtxoCommittedEvent::RemoveCoin(removal));
                }
            }
        }
    }

    fn replay(&self, listener: &(dyn UtxoChangeListener + Send + Sync)) {
        for event in &self.events {
            match event {
                UtxoChangeEvent::InsertBatch(insertions) => listener.on_insert_coins(insertions),
                UtxoChangeEvent::RemoveBatch(removals) => listener.on_remove_coins(removals),
                UtxoChangeEvent::RemoveCoin(removal) => listener.on_remove_coin(
                    &removal.op,
                    &removal.txout,
                    removal.height,
                    removal.coinbase,
                ),
            }
        }
    }
}

fn reserve_smallvec<A>(items: &mut SmallVec<A>, capacity: usize)
where
    A: smallvec::Array,
{
    if capacity > items.capacity() {
        items.reserve_exact(capacity - items.len());
    }
}

/// One UTXO output to add to the set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoAdd {
    /// Outpoint being created.
    pub outpoint: OutPoint,
    /// Output payload.
    pub txout: TxOut,
    /// Whether the creating transaction is coinbase.
    pub coinbase: bool,
    /// Creating block height.
    pub height: u32,
}

impl UtxoAdd {
    /// Constructs an add operation.
    #[must_use]
    pub const fn new(outpoint: OutPoint, txout: TxOut, coinbase: bool, height: u32) -> Self {
        Self {
            outpoint,
            txout,
            coinbase,
            height,
        }
    }
}

/// One borrowed UTXO output to add to the set.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BorrowedUtxoAdd<'a> {
    /// Outpoint being created.
    pub outpoint: OutPoint,
    /// Output payload borrowed from the connected block.
    pub txout: &'a TxOut,
    /// Whether the creating transaction is coinbase.
    pub coinbase: bool,
    /// Creating block height.
    pub height: u32,
}

impl<'a> BorrowedUtxoAdd<'a> {
    /// Constructs a borrowed add operation.
    #[must_use]
    pub const fn new(outpoint: OutPoint, txout: &'a TxOut, coinbase: bool, height: u32) -> Self {
        Self {
            outpoint,
            txout,
            coinbase,
            height,
        }
    }
}

pub(crate) trait UtxoAddView {
    fn outpoint(&self) -> &OutPoint;
    fn txout(&self) -> &TxOut;
    fn coinbase(&self) -> bool;
    fn height(&self) -> u32;

    fn payload(&self) -> BuildPayload<'_> {
        BuildPayload {
            outpoint: self.outpoint(),
            vout: self.outpoint().vout,
            txout: self.txout(),
            coinbase: self.coinbase(),
            height: self.height(),
        }
    }
}

impl UtxoAddView for UtxoAdd {
    fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    fn txout(&self) -> &TxOut {
        &self.txout
    }

    fn coinbase(&self) -> bool {
        self.coinbase
    }

    fn height(&self) -> u32 {
        self.height
    }
}

impl UtxoAddView for BorrowedUtxoAdd<'_> {
    fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    fn txout(&self) -> &TxOut {
        self.txout
    }

    fn coinbase(&self) -> bool {
        self.coinbase
    }

    fn height(&self) -> u32 {
        self.height
    }
}

/// One live output found by a UTXO script scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedUtxo {
    /// Outpoint that identifies the live output.
    pub outpoint: OutPoint,
    /// Output payload stored in the UTXO set.
    pub txout: TxOut,
    /// Whether the creating transaction was coinbase.
    pub coinbase: bool,
    /// Creating block height.
    pub height: u32,
}

/// Result of scanning a stable UTXO-set view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UtxoScan {
    /// Number of live outputs visited during the scan.
    pub txouts: usize,
    /// Live outputs whose script matched the scan set.
    pub unspents: Vec<ScannedUtxo>,
}

/// UTXO mutations produced by one connected block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockChanges {
    adds: Vec<UtxoAdd>,
    removes: Vec<OutPoint>,
}

impl BlockChanges {
    /// Creates an empty change set with storage reserved for known operation counts.
    #[must_use]
    pub fn with_capacity(adds: usize, removes: usize) -> Self {
        Self {
            adds: Vec::with_capacity(adds),
            removes: Vec::with_capacity(removes),
        }
    }

    /// Appends an output creation.
    pub fn add(&mut self, add: UtxoAdd) {
        self.adds.push(add);
    }

    /// Appends an output spend.
    pub fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    /// Returns true when there are no additions or removals.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.adds.is_empty() && self.removes.is_empty()
    }

    /// Returns the number of add operations.
    #[must_use]
    pub const fn add_count(&self) -> usize {
        self.adds.len()
    }

    /// Returns the number of remove operations.
    #[must_use]
    pub const fn remove_count(&self) -> usize {
        self.removes.len()
    }
}

/// Borrowed UTXO mutations produced by one connected block.
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BorrowedBlockChanges<'a> {
    adds: Vec<BorrowedUtxoAdd<'a>>,
    removes: Vec<OutPoint>,
}

impl<'a> BorrowedBlockChanges<'a> {
    /// Creates an empty borrowed change set with storage reserved for known operation counts.
    #[must_use]
    pub fn with_capacity(adds: usize, removes: usize) -> Self {
        Self {
            adds: Vec::with_capacity(adds),
            removes: Vec::with_capacity(removes),
        }
    }

    /// Appends an output creation.
    pub fn add(&mut self, add: BorrowedUtxoAdd<'a>) {
        self.adds.push(add);
    }

    /// Appends an output spend.
    pub fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    /// Returns true when there are no additions or removals.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.adds.is_empty() && self.removes.is_empty()
    }

    /// Returns the number of add operations.
    #[must_use]
    pub const fn add_count(&self) -> usize {
        self.adds.len()
    }

    /// Returns the number of remove operations.
    #[must_use]
    pub const fn remove_count(&self) -> usize {
        self.removes.len()
    }
}

/// Inverse mutations needed to disconnect one block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UndoBatch {
    restores: Vec<UtxoAdd>,
    removes: Vec<OutPoint>,
}

impl UndoBatch {
    /// Restores an output spent by the disconnected block.
    pub fn restore(&mut self, add: UtxoAdd) {
        self.restores.push(add);
    }

    /// Removes an output created by the disconnected block.
    pub fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    /// Returns true when the undo batch is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.restores.is_empty() && self.removes.is_empty()
    }
}

#[derive(Copy, Clone)]
pub(crate) struct BuildPayload<'a> {
    pub(crate) outpoint: &'a OutPoint,
    pub(crate) vout: u32,
    pub(crate) txout: &'a TxOut,
    pub(crate) coinbase: bool,
    pub(crate) height: u32,
}

#[derive(Copy, Clone)]
pub(crate) struct SpendPayload<'a> {
    pub(crate) op: &'a OutPoint,
    pub(crate) key: UtxoKey,
    pub(crate) vout: u32,
    pub(crate) txid: Hash256,
}

/// In-memory 256-shard UTXO set.
pub struct UtxoSet {
    pub(crate) shards: [Shard; UtxoKey::SHARD_COUNT],
    pub(crate) last_defragged_shard: Mutex<u8>,
    stable_view_lock: RwLock<()>,
    listener: Option<Box<dyn UtxoChangeListener + Send + Sync>>,
}

/// Read guard for a stable whole-set UTXO view.
pub struct UtxoSetView<'a> {
    set: &'a UtxoSet,
    _guard: RwLockReadGuard<'a, ()>,
}

impl UtxoSetView<'_> {
    /// Returns the number of live outpoint entries in this stable view.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.shards.iter().map(Shard::output_count).sum()
    }

    /// Returns true when this stable view has no live outpoint entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of transaction-level records in this stable view.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.set.shards.iter().map(Shard::record_count).sum()
    }

    /// Returns each shard's script-slab high-water mark in this stable view.
    #[must_use]
    pub fn arena_high_water_by_shard(&self) -> [usize; UtxoKey::SHARD_COUNT] {
        core::array::from_fn(|idx| self.set.shards[idx].arena_high_water())
    }

    /// Computes Bitcoin Core's `hash_serialized_3` commitment for this stable view.
    pub fn hash_serialized_3(&self) -> Result<Hash256, UtxoError> {
        crate::snapshot::hash_serialized_3_stable(self)
    }

    /// Scans every live output for exact scriptPubKey matches.
    pub fn scan_script_pubkeys(&self, scripts: &[ScriptBuf]) -> Result<UtxoScan, UtxoError> {
        let mut scan = UtxoScan::default();
        for shard in &self.set.shards {
            shard.scan_script_pubkeys(scripts, &mut scan)?;
        }
        Ok(scan)
    }

    pub(crate) const fn shard(&self, idx: usize) -> &Shard {
        &self.set.shards[idx]
    }

    pub(crate) fn listener_muhash3072(&self) -> Option<[u8; 384]> {
        self.set
            .listener
            .as_deref()
            .and_then(UtxoChangeListener::muhash3072)
    }
}

impl UtxoSet {
    /// Creates an empty UTXO set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shards: [(); UtxoKey::SHARD_COUNT].map(|()| Shard::new()),
            last_defragged_shard: Mutex::new(0),
            stable_view_lock: RwLock::new(()),
            listener: None,
        }
    }

    /// Installs a listener for subsequently committed UTXO changes.
    pub fn set_listener(&mut self, listener: Box<dyn UtxoChangeListener + Send + Sync>) {
        self.listener = Some(listener);
    }

    /// Runs `read` while commits are blocked, yielding a stable whole-set view.
    pub fn with_stable_view<R>(&self, read: impl FnOnce(&UtxoSetView<'_>) -> R) -> R {
        let guard = self.stable_view_lock.read();
        let view = UtxoSetView {
            set: self,
            _guard: guard,
        };
        read(&view)
    }

    /// Applies all UTXO changes for a connected block.
    pub fn commit_block(
        &self,
        changes: &BlockChanges,
        block_hash: &Hash256,
    ) -> Result<(), UtxoError> {
        tracing::trace!(%block_hash, adds = changes.adds.len(), removes = changes.removes.len(), "commit utxo block");
        self.commit_adds_and_removes(&changes.adds, &changes.removes)
    }

    /// Applies borrowed UTXO changes for a connected block.
    #[doc(hidden)]
    pub fn commit_borrowed_block(
        &self,
        changes: &BorrowedBlockChanges<'_>,
        block_hash: &Hash256,
    ) -> Result<(), UtxoError> {
        tracing::trace!(%block_hash, adds = changes.adds.len(), removes = changes.removes.len(), "commit borrowed utxo block");
        self.commit_adds_and_removes(&changes.adds, &changes.removes)
    }

    /// Returns an owned transaction output if the outpoint is live.
    #[must_use]
    pub fn get(&self, op: &OutPoint) -> Option<TxOut> {
        let key = UtxoKey::from_txid(&op.txid);
        self.shards[usize::from(key.shard())].get(&key, &op.txid, op.vout)
    }

    /// Returns the full live-output entry (txout + coinbase + height)
    /// if `op` is live in the set.
    #[must_use]
    pub fn get_entry(&self, op: &OutPoint) -> Option<crate::shard::LiveOutput> {
        let key = UtxoKey::from_txid(&op.txid);
        self.shards[usize::from(key.shard())].get_entry(&key, &op.txid, op.vout)
    }

    /// Returns live-output metadata without materializing script bytes.
    #[must_use]
    pub fn get_meta(&self, op: &OutPoint) -> Option<crate::shard::LiveOutputMeta> {
        let key = UtxoKey::from_txid(&op.txid);
        self.shards[usize::from(key.shard())].get_meta(&key, &op.txid, op.vout)
    }

    /// Scans a stable whole-set view for exact scriptPubKey matches.
    pub fn scan_script_pubkeys(&self, scripts: &[ScriptBuf]) -> Result<UtxoScan, UtxoError> {
        self.with_stable_view(|view| view.scan_script_pubkeys(scripts))
    }

    /// Returns true when any output of `txid` is live in the set.
    ///
    /// This is the transaction-level BIP30 predicate: a duplicate txid is
    /// forbidden while any earlier output for that txid remains unspent.
    #[must_use]
    pub fn has_live_outputs_for_txid(&self, txid: &Hash256) -> bool {
        let key = UtxoKey::from_txid(txid);
        self.shards[usize::from(key.shard())].has_live_outputs_for_txid(&key, txid)
    }

    /// Reverses one connected block using its undo data.
    pub fn undo_block(&self, undo: &UndoBatch) -> Result<(), UtxoError> {
        self.commit_adds_and_removes(&undo.restores, &undo.removes)
    }

    /// Returns the number of live outpoint entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.with_stable_view(stable_view_len)
    }

    /// Returns true when the set has no live outpoint entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of transaction-level records.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.with_stable_view(stable_view_record_count)
    }

    /// Returns each shard's script-slab high-water mark.
    #[must_use]
    pub fn arena_high_water_by_shard(&self) -> [usize; UtxoKey::SHARD_COUNT] {
        self.with_stable_view(stable_view_arena_high_water_by_shard)
    }

    pub(crate) fn insert_snapshot_record(
        &self,
        key: UtxoKey,
        txid: Hash256,
        outputs: &[OwnedUtxoOut],
    ) -> Result<(), UtxoError> {
        self.shards[usize::from(key.shard())].insert_owned_record(key, txid, outputs)
    }

    fn commit_adds_and_removes<A: UtxoAddView>(
        &self,
        adds: &[A],
        removes: &[OutPoint],
    ) -> Result<(), UtxoError> {
        let mut add_counts = [0_usize; UtxoKey::SHARD_COUNT];
        let mut remove_counts = [0_usize; UtxoKey::SHARD_COUNT];

        for add in adds {
            validate_add(add)?;
            let key = UtxoKey::from_txid(&add.outpoint().txid);
            let shard_idx = usize::from(key.shard());
            add_counts[shard_idx] = add_counts[shard_idx].saturating_add(1);
        }
        for remove in removes {
            let key = UtxoKey::from_txid(&remove.txid);
            let shard_idx = usize::from(key.shard());
            remove_counts[shard_idx] = remove_counts[shard_idx].saturating_add(1);
        }
        let (active_shards, active_shard_count) = active_shards(&add_counts, &remove_counts);
        if active_shard_count == 0 {
            return Ok(());
        }
        if active_shard_count == 1 {
            return self.commit_single_shard(adds, removes, active_shards[0]);
        }

        let listener = self.listener.as_deref();
        let group_txid_runs =
            listener.is_none() && active_shard_count <= TXID_RUN_GROUPING_MAX_SHARDS;
        let buckets =
            ShardCommitBuckets::new(adds, removes, &add_counts, &remove_counts, group_txid_runs);

        let _stable_commit = self.stable_view_lock.write();

        if let Some(listener) = listener {
            return self.commit_multi_shard_with_listener(
                &active_shards,
                active_shard_count,
                &buckets,
                listener,
            );
        }

        if active_shard_count < PARALLEL_NO_LISTENER_SHARD_THRESHOLD {
            for &shard_idx in &active_shards[..active_shard_count] {
                let shard_adds = buckets.adds(shard_idx);
                let shard_removes = buckets.removes(shard_idx);
                self.shards[shard_idx].commit_batch(shard_adds, shard_removes, None)?;
            }
            return Ok(());
        }

        let errors = Mutex::new(Vec::new());
        let target_tasks = rayon::current_num_threads().saturating_mul(2).max(1);
        let shards_per_task = active_shard_count.div_ceil(target_tasks).max(1);
        let buckets = &buckets;
        let shards = &self.shards;
        rayon::scope(|scope| {
            for shard_chunk in active_shards[..active_shard_count].chunks(shards_per_task) {
                let errors = &errors;
                scope.spawn(move |_| {
                    for &shard_idx in shard_chunk {
                        let shard_adds = buckets.adds(shard_idx);
                        let shard_removes = buckets.removes(shard_idx);
                        let shard = &shards[shard_idx];
                        if let Err(error) = shard.commit_batch(shard_adds, shard_removes, listener)
                        {
                            errors.lock().push(error);
                        }
                    }
                });
            }
        });

        let mut errors = errors.into_inner();
        if let Some(error) = errors.pop() {
            Err(error)
        } else {
            Ok(())
        }
    }

    fn commit_multi_shard_with_listener(
        &self,
        active_shards: &[usize; UtxoKey::SHARD_COUNT],
        active_shard_count: usize,
        buckets: &ShardCommitBuckets<'_>,
        listener: &(dyn UtxoChangeListener + Send + Sync),
    ) -> Result<(), UtxoError> {
        let coalesce_events = listener.coalesces_committed_events();
        if active_shard_count < PARALLEL_LISTENER_SHARD_THRESHOLD {
            if coalesce_events {
                return self.commit_serial_coalesced_event_batches(
                    active_shards,
                    active_shard_count,
                    buckets,
                    listener,
                );
            }
            for &shard_idx in &active_shards[..active_shard_count] {
                let shard_adds = buckets.adds(shard_idx);
                let shard_removes = buckets.removes(shard_idx);
                self.shards[shard_idx].commit_batch(shard_adds, shard_removes, Some(listener))?;
            }
            return Ok(());
        }

        for &shard_idx in &active_shards[..active_shard_count] {
            self.shards[shard_idx].validate_script_capacity(buckets.adds(shard_idx))?;
        }

        let errors = Mutex::new(Vec::new());
        let shard_events: Vec<_> = active_shards[..active_shard_count]
            .par_iter()
            .map(|&shard_idx| {
                let shard_adds = buckets.adds(shard_idx);
                let shard_removes = buckets.removes(shard_idx);
                let shard = &self.shards[shard_idx];
                let (shard_events, result) =
                    shard.commit_batch_collect_events(shard_adds, shard_removes, coalesce_events);
                if let Err(error) = result {
                    errors.lock().push(error);
                }
                shard_events
            })
            .collect();
        if !listener.on_committed_event_batches(&shard_events) {
            for shard_events in &shard_events {
                shard_events.replay(listener);
            }
        }

        let mut errors = errors.into_inner();
        if let Some(error) = errors.pop() {
            return Err(error);
        }

        Ok(())
    }

    fn commit_serial_coalesced_event_batches(
        &self,
        active_shards: &[usize; UtxoKey::SHARD_COUNT],
        active_shard_count: usize,
        buckets: &ShardCommitBuckets<'_>,
        listener: &(dyn UtxoChangeListener + Send + Sync),
    ) -> Result<(), UtxoError> {
        for &shard_idx in &active_shards[..active_shard_count] {
            self.shards[shard_idx].validate_script_capacity(buckets.adds(shard_idx))?;
        }

        let mut error = None;
        let mut shard_events = Vec::with_capacity(active_shard_count);
        for &shard_idx in &active_shards[..active_shard_count] {
            let shard_adds = buckets.adds(shard_idx);
            let shard_removes = buckets.removes(shard_idx);
            let (events, result) =
                self.shards[shard_idx].commit_batch_collect_events(shard_adds, shard_removes, true);
            if let Err(shard_error) = result {
                error = Some(shard_error);
            }
            shard_events.push(events);
        }
        if !listener.on_committed_event_batches(&shard_events) {
            for shard_events in &shard_events {
                shard_events.replay(listener);
            }
        }

        if let Some(error) = error {
            return Err(error);
        }
        Ok(())
    }

    fn commit_single_shard<A: UtxoAddView>(
        &self,
        adds: &[A],
        removes: &[OutPoint],
        shard_idx: usize,
    ) -> Result<(), UtxoError> {
        let _stable_commit = self.stable_view_lock.write();
        let Some(listener) = self.listener.as_deref() else {
            return self.shards[shard_idx].commit_single_shard_batch(adds, removes, shard_idx);
        };

        self.shards[shard_idx]
            .commit_single_shard_batch_with_listener(adds, removes, shard_idx, listener)
    }
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_add(add: &impl UtxoAddView) -> Result<(), UtxoError> {
    let script_len = add.txout().script_pubkey.as_bytes().len();
    let _fits =
        u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
    Ok(())
}

type AddPayload<'a> = (UtxoKey, Hash256, BuildPayload<'a>);

struct ShardCommitBuckets<'a> {
    adds: ShardBucketSide<AddPayload<'a>>,
    removes: ShardBucketSide<SpendPayload<'a>>,
}

enum BucketShape {
    Empty,
    Single(usize),
    Scattered,
}

struct ShardBucketSide<T> {
    payloads: Vec<T>,
    ranges: [(usize, usize); UtxoKey::SHARD_COUNT],
    shape: BucketShape,
}

impl<T> ShardBucketSide<T> {
    fn empty() -> Self {
        Self {
            payloads: Vec::new(),
            ranges: empty_ranges(),
            shape: BucketShape::Empty,
        }
    }

    fn direct(shard_idx: usize, payloads: Vec<T>) -> Self {
        Self {
            payloads,
            ranges: empty_ranges(),
            shape: BucketShape::Single(shard_idx),
        }
    }

    fn scattered(ranges: &[(usize, usize); UtxoKey::SHARD_COUNT], payloads: Vec<T>) -> Self {
        Self {
            payloads,
            ranges: *ranges,
            shape: BucketShape::Scattered,
        }
    }
}

impl<'a> ShardCommitBuckets<'a> {
    fn new<A: UtxoAddView>(
        adds: &'a [A],
        removes: &'a [OutPoint],
        add_counts: &[usize; UtxoKey::SHARD_COUNT],
        remove_counts: &[usize; UtxoKey::SHARD_COUNT],
        group_txid_runs: bool,
    ) -> Self {
        let mut buckets = Self {
            adds: build_add_side(adds, add_counts),
            removes: build_remove_side(removes, remove_counts),
        };
        if group_txid_runs {
            buckets.group_txid_runs();
        }
        buckets
    }

    fn adds(&self, shard_idx: usize) -> &[(UtxoKey, Hash256, BuildPayload<'a>)] {
        self.adds.get(shard_idx)
    }

    fn removes(&self, shard_idx: usize) -> &[SpendPayload<'a>] {
        self.removes.get(shard_idx)
    }

    fn group_txid_runs(&mut self) {
        group_add_txid_runs(&mut self.adds);
        group_remove_txid_runs(&mut self.removes);
    }
}

impl<T> ShardBucketSide<T> {
    fn get(&self, shard_idx: usize) -> &[T] {
        match self.shape {
            BucketShape::Empty => &[],
            BucketShape::Single(active_shard) => {
                if active_shard == shard_idx {
                    &self.payloads
                } else {
                    &[]
                }
            }
            BucketShape::Scattered => {
                let (start, end) = self.ranges[shard_idx];
                &self.payloads[start..end]
            }
        }
    }
}

fn build_add_side<'a, A: UtxoAddView>(
    adds: &'a [A],
    counts: &[usize; UtxoKey::SHARD_COUNT],
) -> ShardBucketSide<AddPayload<'a>> {
    match bucket_shape(counts) {
        BucketShape::Empty => ShardBucketSide::empty(),
        BucketShape::Single(shard_idx) => {
            ShardBucketSide::direct(shard_idx, direct_adds(adds, shard_idx))
        }
        BucketShape::Scattered => {
            let (ranges, payloads) = scattered_adds(adds, counts);
            ShardBucketSide::scattered(&ranges, payloads)
        }
    }
}

fn build_remove_side<'a>(
    removes: &'a [OutPoint],
    counts: &[usize; UtxoKey::SHARD_COUNT],
) -> ShardBucketSide<SpendPayload<'a>> {
    match bucket_shape(counts) {
        BucketShape::Empty => ShardBucketSide::empty(),
        BucketShape::Single(shard_idx) => {
            ShardBucketSide::direct(shard_idx, direct_removes(removes, shard_idx))
        }
        BucketShape::Scattered => {
            let (ranges, payloads) = scattered_removes(removes, counts);
            ShardBucketSide::scattered(&ranges, payloads)
        }
    }
}

fn group_add_txid_runs(side: &mut ShardBucketSide<AddPayload<'_>>) {
    side.group_payloads_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
}

fn group_remove_txid_runs(side: &mut ShardBucketSide<SpendPayload<'_>>) {
    side.group_payloads_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.txid.cmp(&right.txid))
    });
}

impl<T> ShardBucketSide<T> {
    fn group_payloads_by(&mut self, mut compare: impl FnMut(&T, &T) -> core::cmp::Ordering) {
        match self.shape {
            BucketShape::Empty => {}
            BucketShape::Single(_shard_idx) => {
                self.payloads.sort_by(compare);
            }
            BucketShape::Scattered => {
                for (start, end) in self.ranges {
                    if end.saturating_sub(start) > 1 {
                        self.payloads[start..end].sort_by(&mut compare);
                    }
                }
            }
        }
    }
}

fn bucket_shape(counts: &[usize; UtxoKey::SHARD_COUNT]) -> BucketShape {
    let mut active = None;
    for (shard_idx, &count) in counts.iter().enumerate() {
        if count == 0 {
            continue;
        }
        if active.replace(shard_idx).is_some() {
            return BucketShape::Scattered;
        }
    }
    active.map_or(BucketShape::Empty, BucketShape::Single)
}

fn direct_adds<A: UtxoAddView>(adds: &[A], shard_idx: usize) -> Vec<AddPayload<'_>> {
    let mut payloads = Vec::with_capacity(adds.len());
    for add in adds {
        let key = UtxoKey::from_txid(&add.outpoint().txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        payloads.push((key, add.outpoint().txid, add.payload()));
    }
    payloads
}

fn direct_removes(removes: &[OutPoint], shard_idx: usize) -> Vec<SpendPayload<'_>> {
    let mut payloads = Vec::with_capacity(removes.len());
    for remove in removes {
        let key = UtxoKey::from_txid(&remove.txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        payloads.push(spend_payload(remove, key));
    }
    payloads
}

fn scattered_adds<'a, A: UtxoAddView>(
    adds: &'a [A],
    counts: &[usize; UtxoKey::SHARD_COUNT],
) -> ([(usize, usize); UtxoKey::SHARD_COUNT], Vec<AddPayload<'a>>) {
    let (ranges, mut cursors) = shard_ranges(counts);
    let mut slots = uninit_slots(adds.len());
    for add in adds {
        let key = UtxoKey::from_txid(&add.outpoint().txid);
        let shard_idx = usize::from(key.shard());
        let cursor = &mut cursors[shard_idx];
        slots[*cursor].write((key, add.outpoint().txid, add.payload()));
        *cursor = cursor.saturating_add(1);
    }
    debug_assert_eq!(cursors, range_ends(&ranges));
    (ranges, initialized_slots(slots))
}

fn scattered_removes<'a>(
    removes: &'a [OutPoint],
    counts: &[usize; UtxoKey::SHARD_COUNT],
) -> (
    [(usize, usize); UtxoKey::SHARD_COUNT],
    Vec<SpendPayload<'a>>,
) {
    let (ranges, mut cursors) = shard_ranges(counts);
    let mut slots = uninit_slots(removes.len());
    for remove in removes {
        let key = UtxoKey::from_txid(&remove.txid);
        let shard_idx = usize::from(key.shard());
        let cursor = &mut cursors[shard_idx];
        slots[*cursor].write(spend_payload(remove, key));
        *cursor = cursor.saturating_add(1);
    }
    debug_assert_eq!(cursors, range_ends(&ranges));
    (ranges, initialized_slots(slots))
}

fn spend_payload(remove: &OutPoint, key: UtxoKey) -> SpendPayload<'_> {
    SpendPayload {
        op: remove,
        key,
        vout: remove.vout,
        txid: remove.txid,
    }
}

const fn empty_ranges() -> [(usize, usize); UtxoKey::SHARD_COUNT] {
    [(0_usize, 0_usize); UtxoKey::SHARD_COUNT]
}

fn shard_ranges(
    counts: &[usize; UtxoKey::SHARD_COUNT],
) -> (
    [(usize, usize); UtxoKey::SHARD_COUNT],
    [usize; UtxoKey::SHARD_COUNT],
) {
    let mut ranges = [(0_usize, 0_usize); UtxoKey::SHARD_COUNT];
    let mut start = 0_usize;
    for shard_idx in 0..UtxoKey::SHARD_COUNT {
        let end = start.saturating_add(counts[shard_idx]);
        ranges[shard_idx] = (start, end);
        start = end;
    }
    let cursors = ranges.map(|(start, _end)| start);
    (ranges, cursors)
}

fn range_ends(ranges: &[(usize, usize); UtxoKey::SHARD_COUNT]) -> [usize; UtxoKey::SHARD_COUNT] {
    ranges.map(|(_start, end)| end)
}

fn uninit_slots<T>(len: usize) -> Vec<MaybeUninit<T>> {
    let mut slots = Vec::with_capacity(len);
    slots.resize_with(len, MaybeUninit::uninit);
    slots
}

fn initialized_slots<T>(mut slots: Vec<MaybeUninit<T>>) -> Vec<T> {
    let ptr = slots.as_mut_ptr().cast::<T>();
    let len = slots.len();
    let capacity = slots.capacity();
    mem::forget(slots);
    // SAFETY: `ShardCommitBuckets::new` writes exactly one initialized value
    // into each slot before calling this helper. `MaybeUninit<T>` has the same
    // layout as `T`, and ownership of the original allocation is transferred to
    // the returned `Vec<T>` with the same length and capacity.
    unsafe { Vec::from_raw_parts(ptr, len, capacity) }
}

fn active_shards(
    add_counts: &[usize; UtxoKey::SHARD_COUNT],
    remove_counts: &[usize; UtxoKey::SHARD_COUNT],
) -> ([usize; UtxoKey::SHARD_COUNT], usize) {
    let mut active = [0_usize; UtxoKey::SHARD_COUNT];
    let mut len = 0_usize;
    for shard_idx in 0..UtxoKey::SHARD_COUNT {
        if add_counts[shard_idx] == 0 && remove_counts[shard_idx] == 0 {
            continue;
        }
        active[len] = shard_idx;
        len = len.saturating_add(1);
    }
    (active, len)
}

fn stable_view_len(view: &UtxoSetView<'_>) -> usize {
    view.len()
}

fn stable_view_record_count(view: &UtxoSetView<'_>) -> usize {
    view.record_count()
}

fn stable_view_arena_high_water_by_shard(view: &UtxoSetView<'_>) -> [usize; UtxoKey::SHARD_COUNT] {
    view.arena_high_water_by_shard()
}
