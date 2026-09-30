use std::sync::Arc;
use std::{borrow::Borrow, io, time::Instant};

use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use rayon::prelude::*;
use smallvec::SmallVec;
use thiserror::Error;

use crate::contract::{BlockChanges, UndoBatch, UtxoAdd};
use crate::listener::{UtxoChangeEvents, UtxoChangeListener};
use crate::{UtxoKey, record::OwnedUtxoOut, shard::Shard};

/// Below this many combined add+remove operations, a multi-shard no-listener
/// commit runs serially: a `rayon` scope plus per-shard task dispatch costs
/// more than the handful of hash-table ops a small block touches. Larger
/// blocks still fan out across shards.
const PARALLEL_NO_LISTENER_OP_THRESHOLD: usize = 2048;
/// Lowered from 16: listener event collection overhead is modest
/// compared to the shard commit work itself.
const PARALLEL_LISTENER_SHARD_THRESHOLD: usize = 8;
const TXID_RUN_GROUPING_MAX_SHARDS: usize = 8;

/// Errors returned by UTXO mutation and snapshot operations.
#[derive(Debug, Error)]
pub enum UtxoError {
    /// A script does not fit the snapshot and record `u16` length field.
    #[error("script_pubkey is too large for a u16 length: {len} bytes")]
    ScriptTooLarge {
        /// Script length in bytes.
        len: usize,
    },
    /// One encoded record could not fit in the local address space.
    #[error("encoded UTXO record exceeds addressable size at {len} bytes")]
    RecordTooLarge {
        /// Encoded record byte length.
        len: usize,
    },
    /// Encoded UTXO record bytes are truncated, trailing, or noncanonical.
    #[error("invalid encoded UTXO record")]
    CorruptRecord,
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
    /// Strict snapshot records did not produce the declared number of records.
    #[error("strict snapshot record count mismatch: declared {declared}, actual {actual}")]
    SnapshotRecordCountMismatch {
        /// Record count declared by the snapshot header.
        declared: u64,
        /// Number of records actually retained after insertion.
        actual: usize,
    },
    /// Snapshot output count does not fit the record header.
    #[error("snapshot record has too many live outputs: {count}")]
    SnapshotOutputCountTooLarge {
        /// Live output count in one transaction-level record.
        count: usize,
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
    /// An output value exceeds the largest amount any UTXO can hold.
    ///
    /// Unreachable through consensus, which caps the money supply. It exists so
    /// a corrupt or synthetic value fails loudly instead of overflowing the
    /// amount compression.
    #[error("output value {value} exceeds the maximum money supply")]
    AmountOutOfRange {
        /// Offending value in satoshis.
        value: u64,
    },
}

/// One live UTXO coin as contract consumers observe it.
///
/// The single coin shape for lookups, window overlays, and scans: it replaces
/// the separate live-output, metadata-only, and scanned-coin records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoCoin {
    /// Outpoint that identifies the live coin.
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
    /// Number of live coins visited during the scan.
    pub txouts: usize,
    /// Live coins whose script matched the scan set.
    pub unspents: Vec<UtxoCoin>,
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
    stable_view_lock: RwLock<()>,
    listener: Option<Box<dyn UtxoChangeListener + Send + Sync>>,
}

/// Byte-level accounting of what a UTXO set holds in memory.
///
/// Every field is what the set can account for itself: the exact requested
/// bytes of every boxed record payload and the estimated hash-table backing.
/// What it cannot see — allocator size-class rounding, fragmentation, and
/// allocator metadata — is exactly the residual against process RSS, which is
/// the point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UtxoMemoryReport {
    /// Transaction-level records held.
    pub records: usize,
    /// Live outputs across those records.
    pub outputs: usize,
    /// Sum of every record's complete boxed payload.
    pub record_payload_bytes: usize,
    /// Estimated hash-table backing store across all shards.
    pub table_bytes: usize,
}

impl UtxoMemoryReport {
    /// Everything the set can attribute: record payload bytes plus estimated
    /// table storage.
    #[must_use]
    pub const fn accounted_bytes(&self) -> usize {
        self.record_payload_bytes.saturating_add(self.table_bytes)
    }
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

    /// Accounts for what this set holds in memory, shard by shard.
    ///
    /// Exists to attribute process RSS rather than to guess at it. The set is
    /// fully memory-resident with no eviction tier, and the published
    /// 13.83 GiB at height 645,804 is far above what the record encoding alone
    /// predicts, so the gap between `record_payload_bytes + table_bytes` and
    /// actual RSS is the number that decides whether an encoding change is worth
    /// making at all.
    ///
    /// Walks every record in every shard: O(records), for measurement only.
    #[must_use]
    pub fn memory_report(&self) -> UtxoMemoryReport {
        let mut report = UtxoMemoryReport::default();
        for shard in &self.set.shards {
            report.records += shard.record_count();
            report.outputs += shard.output_count();
            report.record_payload_bytes += shard.record_payload_bytes();
            report.table_bytes += shard.table_bytes();
        }
        report
    }

    /// Computes Bitcoin Core's `hash_serialized_3` commitment for this stable view.
    pub fn hash_serialized_3(&self) -> Result<Hash256, UtxoError> {
        crate::snapshot::hash_serialized_3_stable(self)
    }

    /// Scans every live output for exact scriptPubKey matches.
    pub fn scan_script_pubkeys(&self, scripts: &[Vec<u8>]) -> Result<UtxoScan, UtxoError> {
        let mut scan = UtxoScan::default();
        for shard in &self.set.shards {
            shard.scan_script_pubkeys(scripts, &mut scan);
        }
        Ok(scan)
    }

    /// Visits every live output without materializing the complete set.
    pub fn for_each_all(&self, mut f: impl FnMut(&OutPoint, &[u8])) {
        for shard in &self.set.shards {
            shard.for_each_all(&mut f);
        }
    }

    /// Returns the full live-output entry for `op` in this stable view.
    #[must_use]
    pub fn get_entry(&self, op: &OutPoint) -> Option<UtxoCoin> {
        let key = UtxoKey::from_txid(&op.txid);
        self.set.shards[usize::from(key.shard())].get_entry(key, &op.txid.into(), op.vout)
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
    /// Byte-level memory report over a stable view (measurement only).
    #[must_use]
    pub fn memory_report(&self) -> UtxoMemoryReport {
        #[expect(clippy::redundant_closure_for_method_calls, reason = "HRTB lifetime")]
        self.with_stable_view(|view| view.memory_report())
    }

    /// Creates an empty UTXO set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shards: [(); UtxoKey::SHARD_COUNT].map(|()| Shard::new()),
            stable_view_lock: RwLock::new(()),
            listener: None,
        }
    }

    /// Attaches the coinstats listener for subsequently committed UTXO changes.
    ///
    /// The set keeps one listener slot and the node keeps one listener: the
    /// [`CoinStatsListener`](crate::stats::CoinStatsListener) whose `MuHash` and
    /// accounting track every commit. Replay and recovery attach the same one.
    pub fn track_coin_stats(&mut self, listener: crate::stats::CoinStatsListener) {
        self.listener = Some(Box::new(listener));
    }

    /// Runs `read` while commits are blocked, yielding a stable whole-set view.
    pub fn with_stable_view<R>(&self, read: impl FnOnce(&UtxoSetView<'_>) -> R) -> R {
        read(&self.lock_stable_view())
    }

    /// Locks a stable whole-set view until the returned guard is dropped.
    ///
    /// Commits take the matching write lock. Acquire any chain-transition
    /// authority first when both are needed, matching block apply.
    #[must_use]
    pub fn lock_stable_view(&self) -> UtxoSetView<'_> {
        UtxoSetView {
            set: self,
            _guard: self.stable_view_lock.read(),
        }
    }

    /// Applies all UTXO changes for a connected block.
    ///
    /// Crate-visible on purpose: the public commit entry is the contract's
    /// [`commit_block_changes`](crate::contract::commit_block_changes), so
    /// every cross-crate mutation goes through `utxo::contract`.
    pub(crate) fn commit_block<T: Borrow<TxOut>>(
        &self,
        changes: &BlockChanges<T>,
        block_hash: &Hash256,
    ) -> Result<(), UtxoError> {
        tracing::trace!(
            %block_hash,
            adds = changes.add_count(),
            removes = changes.remove_count(),
            "commit utxo block"
        );
        self.commit_adds_and_removes(changes.adds_slice(), changes.removes_slice())
    }

    /// Returns an owned transaction output if the outpoint is live.
    #[must_use]
    pub fn get(&self, op: &OutPoint) -> Option<TxOut> {
        let key = UtxoKey::from_txid(&op.txid);
        self.shards[usize::from(key.shard())].get(key, &op.txid.into(), op.vout)
    }

    /// Returns the full live-output entry (txout + coinbase + height)
    /// if `op` is live in the set.
    #[must_use]
    pub fn get_entry(&self, op: &OutPoint) -> Option<UtxoCoin> {
        let key = UtxoKey::from_txid(&op.txid);
        self.shards[usize::from(key.shard())].get_entry(key, &op.txid.into(), op.vout)
    }

    /// Scans a stable whole-set view for exact scriptPubKey matches.
    pub fn scan_script_pubkeys(&self, scripts: &[Vec<u8>]) -> Result<UtxoScan, UtxoError> {
        self.with_stable_view(|view| view.scan_script_pubkeys(scripts))
    }

    /// Returns true when any output of `txid` is live in the set.
    ///
    /// This is the transaction-level BIP30 predicate: a duplicate txid is
    /// forbidden while any earlier output for that txid remains unspent.
    #[must_use]
    pub fn has_live_outputs_for_txid(&self, txid: &Hash256) -> bool {
        let key = UtxoKey::from_txid(&Txid::from(*txid));
        self.shards[usize::from(key.shard())].has_live_outputs_for_txid(key, txid)
    }

    /// Reverses one connected block using its undo data.
    ///
    /// The raw inverse of [`Self::commit_block`], without any durability
    /// ordering. Crate-visible on purpose: everything outside this crate
    /// disconnects through
    /// [`contract::rollback_block`](crate::contract::rollback_block), which
    /// runs this under the durable disconnect marker and the coinstats rewind.
    pub(crate) fn undo_block(&self, undo: &UndoBatch) -> Result<(), UtxoError> {
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

    pub(crate) fn insert_snapshot_record(
        &self,
        key: UtxoKey,
        txid: Hash256,
        outputs: &[OwnedUtxoOut],
    ) -> Result<(), UtxoError> {
        self.shards[usize::from(key.shard())].insert_owned_record(key, txid, outputs)
    }

    fn commit_adds_and_removes<T: Borrow<TxOut>>(
        &self,
        adds: &[UtxoAdd<T>],
        removes: &[OutPoint],
    ) -> Result<(), UtxoError> {
        let mut add_counts = [0_usize; UtxoKey::SHARD_COUNT];
        let mut remove_counts = [0_usize; UtxoKey::SHARD_COUNT];

        for add in adds {
            validate_add(add)?;
            let key = UtxoKey::from_txid(&add.outpoint.txid);
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

        let total_ops = adds.len().saturating_add(removes.len());
        if total_ops < PARALLEL_NO_LISTENER_OP_THRESHOLD {
            for &shard_idx in &active_shards[..active_shard_count] {
                let shard_adds = buckets.adds(shard_idx);
                let shard_removes = buckets.removes(shard_idx);
                self.shards[shard_idx].commit_batch(shard_adds, shard_removes)?;
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
                        if let Err(error) = shard.commit_batch(shard_adds, shard_removes) {
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
        if active_shard_count < PARALLEL_LISTENER_SHARD_THRESHOLD {
            return self.commit_serial_event_batches(
                active_shards,
                active_shard_count,
                buckets,
                listener,
            );
        }

        let errors = Mutex::new(Vec::new());
        let shard_events: Vec<_> = active_shards[..active_shard_count]
            .par_iter()
            .map(|&shard_idx| {
                let shard_adds = buckets.adds(shard_idx);
                let shard_removes = buckets.removes(shard_idx);
                let shard = &self.shards[shard_idx];
                let (shard_events, result) =
                    shard.commit_batch_collect_events(shard_adds, shard_removes);
                if let Err(error) = result {
                    errors.lock().push(error);
                }
                shard_events
            })
            .collect();

        let listener_started = Instant::now();
        listener.on_committed_event_batches(&shard_events);
        metrics::histogram!("node.utxo.listener.event_batches_seconds")
            .record(listener_started.elapsed().as_secs_f64());

        let mut errors = errors.into_inner();
        if let Some(error) = errors.pop() {
            return Err(error);
        }

        Ok(())
    }

    fn commit_serial_event_batches(
        &self,
        active_shards: &[usize; UtxoKey::SHARD_COUNT],
        active_shard_count: usize,
        buckets: &ShardCommitBuckets<'_>,
        listener: &(dyn UtxoChangeListener + Send + Sync),
    ) -> Result<(), UtxoError> {
        let mut error = None;
        let mut shard_events =
            SmallVec::<[UtxoChangeEvents<'_>; PARALLEL_LISTENER_SHARD_THRESHOLD]>::new();
        for &shard_idx in &active_shards[..active_shard_count] {
            let shard_adds = buckets.adds(shard_idx);
            let shard_removes = buckets.removes(shard_idx);
            let (events, result) =
                self.shards[shard_idx].commit_batch_collect_events(shard_adds, shard_removes);
            if let Err(shard_error) = result {
                error = Some(shard_error);
            }
            shard_events.push(events);
        }

        let listener_started = Instant::now();
        listener.on_committed_event_batches(&shard_events);
        metrics::histogram!("node.utxo.listener.event_batches_seconds")
            .record(listener_started.elapsed().as_secs_f64());

        if let Some(error) = error {
            return Err(error);
        }
        Ok(())
    }

    fn commit_single_shard<T: Borrow<TxOut>>(
        &self,
        adds: &[UtxoAdd<T>],
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

/// Read-only capability over the authoritative [`UtxoSet`].
///
/// The set itself is never handed out: [`crate::contract`] mutates through
/// `&UtxoSet`, so a consumer that held the set would hold the mutation path
/// too. This type exposes the reads an admission preview, a live index query,
/// or a mining candidate needs, and nothing that can change a coin.
#[derive(Clone)]
pub struct UtxoReader {
    set: Arc<UtxoSet>,
}

impl UtxoReader {
    /// Wraps the owner's set into a read capability.
    #[must_use]
    pub fn new(set: Arc<UtxoSet>) -> Self {
        Self { set }
    }

    /// Looks up one live output.
    #[must_use]
    pub fn get(&self, op: &OutPoint) -> Option<TxOut> {
        self.set.get(op)
    }

    /// Looks up one live output with its confirmation metadata.
    #[must_use]
    pub fn get_entry(&self, op: &OutPoint) -> Option<UtxoCoin> {
        self.set.get_entry(op)
    }

    /// Reports whether `txid` still owns at least one live output.
    #[must_use]
    pub fn has_live_outputs_for_txid(&self, txid: &Hash256) -> bool {
        self.set.has_live_outputs_for_txid(txid)
    }

    /// Scans a stable whole-set view for exact `scriptPubKey` matches.
    pub fn scan_script_pubkeys(&self, scripts: &[Vec<u8>]) -> Result<UtxoScan, UtxoError> {
        self.set.scan_script_pubkeys(scripts)
    }

    /// Runs `read` against a stable whole-set view, blocking commits meanwhile.
    ///
    /// The view borrows the owner's set for the closure only: the set itself
    /// never escapes, so the closure still carries no mutation path.
    pub fn with_stable_view<R>(&self, read: impl FnOnce(&UtxoSetView<'_>) -> R) -> R {
        self.set.with_stable_view(read)
    }

    /// Locks a stable whole-set view until the returned guard is dropped.
    ///
    /// Commits take the matching write lock, so a caller that must hold one
    /// coherent set across a multi-step scan takes this instead of calling
    /// [`Self::get`] repeatedly. Acquire any chain-transition authority first
    /// when both are needed, matching block apply.
    #[must_use]
    pub fn lock_stable_view(&self) -> UtxoSetView<'_> {
        self.set.lock_stable_view()
    }

    /// Reveals the owner's set so a fixture can commit through `crate::contract`.
    ///
    /// Not present in production builds: a production reader must never reach
    /// the set, because `contract::commit_block_changes` takes `&UtxoSet` as
    /// its mutation surface.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn fixture_set(&self) -> Arc<UtxoSet> {
        Arc::clone(&self.set)
    }
}

fn validate_add<T: Borrow<TxOut>>(add: &UtxoAdd<T>) -> Result<(), UtxoError> {
    let script_len = add.txout.borrow().script_pubkey.len();
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
    fn new<T: Borrow<TxOut>>(
        adds: &'a [UtxoAdd<T>],
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

fn build_add_side<'a, T: Borrow<TxOut>>(
    adds: &'a [UtxoAdd<T>],
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

fn direct_adds<T: Borrow<TxOut>>(adds: &[UtxoAdd<T>], shard_idx: usize) -> Vec<AddPayload<'_>> {
    let mut payloads = Vec::with_capacity(adds.len());
    for add in adds {
        let key = UtxoKey::from_txid(&add.outpoint.txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        payloads.push((key, add.outpoint.txid.into(), add.payload()));
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

fn scattered_adds<'a, T: Borrow<TxOut>>(
    adds: &'a [UtxoAdd<T>],
    counts: &[usize; UtxoKey::SHARD_COUNT],
) -> ([(usize, usize); UtxoKey::SHARD_COUNT], Vec<AddPayload<'a>>) {
    let (ranges, mut cursors) = shard_ranges(counts);
    let mut slots = std::iter::repeat_with(|| None)
        .take(adds.len())
        .collect::<Vec<Option<AddPayload<'a>>>>();
    for add in adds {
        let key = UtxoKey::from_txid(&add.outpoint.txid);
        let shard_idx = usize::from(key.shard());
        let cursor = &mut cursors[shard_idx];
        slots[*cursor] = Some((key, add.outpoint.txid.into(), add.payload()));
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
    let mut slots = std::iter::repeat_with(|| None)
        .take(removes.len())
        .collect::<Vec<Option<SpendPayload<'a>>>>();
    for remove in removes {
        let key = UtxoKey::from_txid(&remove.txid);
        let shard_idx = usize::from(key.shard());
        let cursor = &mut cursors[shard_idx];
        slots[*cursor] = Some(spend_payload(remove, key));
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
        txid: remove.txid.into(),
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

fn initialized_slots<T>(slots: Vec<Option<T>>) -> Vec<T> {
    slots
        .into_iter()
        .map(|slot| match slot {
            Some(value) => value,
            // `shard_ranges` sizes each shard's range from the per-shard
            // counts, and every add/remove writes its payload into the slot
            // at its shard's running cursor; a missing slot means the bucket
            // counts disagreed with the input length, which is an
            // unrecoverable internal corrupt state.
            None => panic!("shard bucket counts allocate every slot"),
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::Amount;

    /// The report accounts the exact boxed record payload plus the estimated
    /// table backing: with records resident, `accounted_bytes()` must equal
    /// that sum and every component must be positive.
    #[test]
    fn memory_report_accounts_payload_plus_table_bytes() -> Result<(), UtxoError> {
        let set = UtxoSet::new();
        let mut changes = BlockChanges::default();
        let txid = Hash256::from_le_bytes(&[0x11; 32]);
        for vout in 0..3_u32 {
            changes.add(UtxoAdd::new(
                OutPoint::new(Txid::from(txid), vout),
                TxOut {
                    value: Amount::from_sat(1_000 + u64::from(vout)),
                    script_pubkey: vec![0x51].into(),
                },
                false,
                1,
            ));
        }
        set.commit_block(&changes, &Hash256::from_le_bytes(&[0x22; 32]))?;

        let report = set.memory_report();
        assert_eq!(report.records, 1);
        assert_eq!(report.outputs, 3);
        assert!(report.record_payload_bytes > 0);
        assert!(report.table_bytes > 0);
        assert_eq!(
            report.accounted_bytes(),
            report
                .record_payload_bytes
                .saturating_add(report.table_bytes)
        );
        Ok(())
    }
}
