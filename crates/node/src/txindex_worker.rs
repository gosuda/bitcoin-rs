//! Asynchronous, durable, node-owned transaction index runtime.
//!
//! The node creates and owns exactly one `TxIndexRuntime` when `txindex` is
//! enabled. The runtime holds a process-local revision counter and a bounded
//! nonblocking wake channel; `ApplyHandles` clones it and wakes the worker
//! after every committed `applied_tip.store`. The single writer may atomically
//! publish a complete formerly authoritative prefix while the applied chain
//! advances or reorganizes; exact query gating refuses that temporary lag and
//! the next worker pass repairs it. A snapshot-gated query engine serves
//! `bitcoin_rs_rpc::TxIndexQuery` and the Electrum `ConfirmedHistoryReader`
//! without raw index mutex paths.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::{Block, OutPoint, Transaction, Txid};
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_electrum::methods::{
    ConfirmedHistoryReader, ConfirmedHistorySnapshot, ElectrumError, HistoryRecord,
    TxIndexInfo as ElectrumTxIndexInfo,
};
use bitcoin_rs_index::{
    HashPrefixRow, IndexError, IndexReader, IndexWatermark, IndexWriter, PreparedBatch,
    PreparedBatchLimits, PreparedBlock, ScriptHash, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
    types::{TxPosition, TxPositionValue},
};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{BlockBodySource, TxIndexInfo, TxIndexQuery, TxQueryError};
use bitcoin_rs_storage::{PrefixScanLimit, StorageError};
use compact_str::CompactString;
use crossbeam_channel::{Receiver, Sender};
use parking_lot::{Mutex, RwLock};

use crate::apply::PruneBodyStore;
use crate::block_source::NodeBlockSource;

/// Bounded scan limits used by the query engine.
///
/// These are query-side safety limits, not the writer batch limits.
const QUERY_SCAN_ROW_LIMIT: usize = 1_000_000;
const QUERY_SCAN_BYTE_LIMIT: usize = 64 << 20;
const QUERY_SCAN_COUNT_LIMIT: usize = 4_096;
const QUERY_BODY_READ_LIMIT: usize = 4_096;
const MAX_SERIALIZED_BLOCK_BYTES: usize = 4_000_000;

/// Writer-side batch limits.
///
/// Capped by actual retained row count and encoded bytes to keep each forward
/// commit bounded.
const BATCH_BYTE_LIMIT: usize = 256 << 20;

#[cfg(feature = "rocksdb")]
pub(crate) const ROCKSDB_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 1_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

#[cfg(any(feature = "fjall", feature = "mdbx", test))]
pub(crate) const DEFAULT_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 1_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

#[cfg(feature = "redb")]
pub(crate) const REDB_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 16_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

const IDENTITY_CHUNK_BLOCKS: u32 = 65_536;
const POSITION_PREFETCH_BLOCKS: usize = 65_536;
const REVISION_QUIET_PERIOD: Duration = Duration::from_millis(100);
const FORWARD_BATCH_DELAY: Duration = Duration::from_millis(100);

/// Shared wake/revision/health state owned by `NodeState` and referenced by
/// `ApplyHandles`, the worker thread, and the query engine.
#[derive(Debug)]
pub struct TxIndexRuntime {
    revision: AtomicU64,
    shutdown: AtomicBool,
    failed: AtomicBool,
    wake_tx: Sender<()>,
    failure_message: RwLock<Option<CompactString>>,
}

impl TxIndexRuntime {
    /// Creates a runtime attached to `wake_tx`.
    #[must_use]
    pub fn new(wake_tx: Sender<()>) -> Self {
        Self {
            revision: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            wake_tx,
            failure_message: RwLock::new(None),
        }
    }

    /// Called immediately after a committed `applied_tip.store`.
    ///
    /// Increments the revision with `Release` ordering and `try_send`s one
    /// wake.  Coalesced or lost wakes are harmless: the worker reconciles
    /// against current authoritative state each loop.
    pub fn wake(&self) {
        self.revision.fetch_add(1, Ordering::Release);
        let _ = self.wake_tx.try_send(());
    }

    /// Marks the worker as failed with an explanatory message.
    pub fn publish_failed(&self, message: impl Into<CompactString>) {
        *self.failure_message.write() = Some(message.into());
        self.failed.store(true, Ordering::Release);
    }

    /// Returns the current revision.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    /// Returns true once a failure or shutdown has been published.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire)
    }

    /// Initiates graceful shutdown.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.wake_tx.try_send(());
    }

    /// Returns the published failure message, if any.
    #[must_use]
    pub fn failure_message(&self) -> Option<CompactString> {
        self.failure_message.read().clone()
    }
}

/// Handle used to spawn and join the supervised reconciliation worker.
pub(crate) struct TxIndexWorker {
    runtime: Arc<TxIndexRuntime>,
    join_handle: Option<JoinHandle<()>>,
}

impl TxIndexWorker {
    /// Spawns a worker that owns `writer` and reconciles the durable watermark
    /// to the applied tip stored in `handles`.
    ///
    /// `wake_rx` must be the receiver paired with the `Sender` used to construct
    /// `runtime`.
    pub(crate) fn spawn(
        runtime: Arc<TxIndexRuntime>,
        writer: Arc<dyn TxIndexWriter>,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        body_store: Option<Arc<dyn PruneBodyStore>>,
        batch_limits: PreparedBatchLimits,
        wake_rx: Receiver<()>,
    ) -> std::io::Result<Self> {
        let worker = Worker {
            runtime: Arc::clone(&runtime),
            writer,
            applied_tip,
            block_tree,
            body_store,
            batch_limits,
            wake_rx,
            quiet_period: REVISION_QUIET_PERIOD,
            batch_delay: FORWARD_BATCH_DELAY,
        };
        let runtime_for_error = Arc::clone(&runtime);
        let join_handle = thread::Builder::new()
            .name("bitcoin-rs-txindex".to_owned())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker.run()));
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::error!(%error, "txindex worker failed");
                        runtime_for_error.publish_failed(error.to_string());
                    }
                    Err(payload) => {
                        let message = payload
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("txindex worker panicked");
                        tracing::error!(%message, "txindex worker panicked");
                        runtime_for_error.publish_failed(message);
                    }
                }
            })?;
        Ok(Self {
            runtime,
            join_handle: Some(join_handle),
        })
    }

    /// Requests shutdown and joins the worker thread.
    pub(crate) fn join(mut self) {
        self.runtime.request_shutdown();
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for TxIndexWorker {
    fn drop(&mut self) {
        self.runtime.request_shutdown();
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Erased prepared-index writer used by the worker and stored in `NodeState`.
pub(crate) trait TxIndexWriter: Send + Sync {
    fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError>;
    fn prepare_block(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError>;
    fn commit_forward(&self, batch: PreparedBatch) -> Result<IndexWatermark, IndexError>;
    fn commit_rollback_one(
        &self,
        prev: Option<IndexWatermark>,
        body: &[u8],
    ) -> Result<(), IndexError>;
}

impl<S> TxIndexWriter for Mutex<IndexWriter<S>>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.lock().watermark()
    }

    fn prepare_block(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.lock().prepare_block(height, hash, body)
    }

    fn commit_forward(&self, batch: PreparedBatch) -> Result<IndexWatermark, IndexError> {
        self.lock().commit_forward(batch)
    }

    fn commit_rollback_one(
        &self,
        prev: Option<IndexWatermark>,
        body: &[u8],
    ) -> Result<(), IndexError> {
        self.lock().commit_rollback_one(prev, body)
    }
}

struct Worker {
    runtime: Arc<TxIndexRuntime>,
    writer: Arc<dyn TxIndexWriter>,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    body_store: Option<Arc<dyn PruneBodyStore>>,
    batch_limits: PreparedBatchLimits,
    wake_rx: Receiver<()>,
    quiet_period: Duration,
    batch_delay: Duration,
}

/// Uncommitted contiguous rows based on one unchanged durable watermark.
struct PendingForward {
    durable: Option<IndexWatermark>,
    batch: PreparedBatch,
    deadline: Instant,
}

impl PendingForward {
    fn endpoint(&self) -> IndexWatermark {
        let Some(watermark) = self.batch.watermark() else {
            unreachable!("pending forward batch is nonempty");
        };
        watermark
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchWait {
    Woken,
    Deadline,
    Stopped,
}

fn wait_for_revision_quiet(
    runtime: &TxIndexRuntime,
    wake_rx: &Receiver<()>,
    quiet_period: Duration,
    mut seen_revision: u64,
) -> Option<u64> {
    loop {
        if runtime.should_stop() {
            return None;
        }
        match wake_rx.recv_timeout(quiet_period) {
            Ok(()) => seen_revision = runtime.revision(),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                let current = runtime.revision();
                if current == seen_revision {
                    return Some(current);
                }
                seen_revision = current;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return None,
        }
    }
}
/// Waits for a wake hint or the pending batch's original deadline.
fn wait_for_batch_deadline(
    runtime: &TxIndexRuntime,
    wake_rx: &Receiver<()>,
    deadline: Instant,
) -> BatchWait {
    if runtime.should_stop() {
        return BatchWait::Stopped;
    }
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return BatchWait::Deadline;
    };
    if remaining.is_zero() {
        return BatchWait::Deadline;
    }
    match wake_rx.recv_timeout(remaining) {
        Ok(()) if runtime.should_stop() => BatchWait::Stopped,
        Ok(()) => BatchWait::Woken,
        Err(crossbeam_channel::RecvTimeoutError::Timeout) if runtime.should_stop() => {
            BatchWait::Stopped
        }
        Err(crossbeam_channel::RecvTimeoutError::Timeout) => BatchWait::Deadline,
        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => BatchWait::Stopped,
    }
}

/// Identity of one block on the active chain, captured under a short tree lock.
#[derive(Clone, Copy, Debug)]
struct BlockIdentity {
    height: u32,
    hash: [u8; 32],
    parent_hash: [u8; 32],
}

impl Worker {
    fn run(self) -> Result<(), TxIndexWorkerError> {
        let mut quiet_armed = false;
        let mut pending = None;
        loop {
            if self.runtime.should_stop() {
                break;
            }
            if quiet_armed {
                quiet_armed = false;
                if wait_for_revision_quiet(
                    &self.runtime,
                    &self.wake_rx,
                    self.quiet_period,
                    self.runtime.revision(),
                )
                .is_none()
                {
                    break;
                }
            }

            let revision_before = self.runtime.revision();
            let action = match self.reconcile_once(&mut pending) {
                Ok(action) => action,
                Err(TxIndexWorkerError::Stopped) => break,
                Err(error) => return Err(error),
            };
            if self.runtime.should_stop() {
                break;
            }

            match action {
                ReconcileAction::Progressed => continue,
                ReconcileAction::CaughtUp => {
                    // A wake can be coalesced or consumed while this pass runs.
                    // The revision is authoritative: never sleep after it moved.
                    if self.runtime.revision() != revision_before {
                        continue;
                    }
                    match self.wake_rx.recv_timeout(Duration::from_secs(1)) {
                        Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }
                }
                ReconcileAction::Buffered => {
                    let Some(deadline) = pending.as_ref().map(|state| state.deadline) else {
                        unreachable!("buffered action has a pending batch");
                    };
                    match wait_for_batch_deadline(&self.runtime, &self.wake_rx, deadline) {
                        BatchWait::Woken => continue,
                        BatchWait::Deadline => {
                            if !self.commit_pending(&mut pending)? {
                                break;
                            }
                        }
                        BatchWait::Stopped => break,
                    }
                }
                ReconcileAction::Stalled => {
                    // Missing bodies and stopped writes retry only after one
                    // revision lull; forward progress never waits.
                    quiet_armed = true;
                }
            }
        }
        Ok(())
    }

    /// Reconciles the durable watermark to the current applied tip in one pass.
    ///
    /// All `BlockTree` data needed for the pass is copied under a short read
    /// lock before any body I/O or index commit.  Body loads, prepares, and
    /// commits happen with the lock released.
    fn reconcile_once(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        let (target, watermark) = self.capture_target_watermark()?;

        if let Some(state) = pending.as_ref() {
            if state.durable != watermark {
                return Err(TxIndexWorkerError::PendingDurableChanged);
            }
            let endpoint = state.endpoint();
            let Some(target) = target.as_deref() else {
                return if self.commit_pending(pending)? {
                    Ok(ReconcileAction::Progressed)
                } else {
                    Ok(ReconcileAction::Stalled)
                };
            };

            if endpoint.height == target.height && endpoint.hash == target.hash.to_le_bytes() {
                if Instant::now() < state.deadline {
                    return Ok(ReconcileAction::Buffered);
                }
                return if self.commit_pending(pending)? {
                    Ok(ReconcileAction::CaughtUp)
                } else {
                    Ok(ReconcileAction::Stalled)
                };
            }
            if endpoint.height < target.height
                && self.watermark_is_on_target_chain(endpoint, target)
            {
                if Instant::now() >= state.deadline {
                    return if self.commit_pending(pending)? {
                        Ok(ReconcileAction::Progressed)
                    } else {
                        Ok(ReconcileAction::Stalled)
                    };
                }
                return self.catch_up_to(target, watermark, pending);
            }

            return if self.commit_pending(pending)? {
                Ok(ReconcileAction::Progressed)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        }

        let Some(watermark) = watermark else {
            let Some(target) = target else {
                return Ok(ReconcileAction::CaughtUp);
            };
            return self.catch_up_to(&target, None, pending);
        };

        let Some(target) = target else {
            return match self.rollback_to_none(watermark) {
                Ok(()) => Ok(ReconcileAction::CaughtUp),
                Err(TxIndexWorkerError::MissingBody { .. }) => Ok(ReconcileAction::Stalled),
                Err(error) => Err(error),
            };
        };

        if !self.watermark_is_on_target_chain(watermark, &target) {
            let new_watermark = match self.rollback_to_target(watermark, &target) {
                Ok(watermark) => watermark,
                Err(TxIndexWorkerError::MissingBody { .. }) => {
                    return Ok(ReconcileAction::Stalled);
                }
                Err(error) => return Err(error),
            };
            return self.catch_up_to(&target, new_watermark, pending);
        }

        if watermark.height == target.height {
            return Ok(ReconcileAction::CaughtUp);
        }

        self.catch_up_to(&target, Some(watermark), pending)
    }

    fn capture_target_watermark(
        &self,
    ) -> Result<(Option<Arc<TipSnapshot>>, Option<IndexWatermark>), TxIndexWorkerError> {
        let target = self.applied_tip.load_full();
        let watermark = self.writer.watermark().map_err(TxIndexWorkerError::Index)?;
        Ok((target, watermark))
    }

    fn watermark_is_on_target_chain(
        &self,
        watermark: IndexWatermark,
        target: &TipSnapshot,
    ) -> bool {
        let tree = self.block_tree.read();
        let watermark_hash = Hash256::from_le_bytes(&watermark.hash);
        let Some(watermark_node) = tree.lookup(watermark_hash) else {
            return false;
        };
        tree.node_at_height_from(target.tip_id, watermark.height)
            .is_some_and(|id| id == watermark_node)
    }

    /// Copies one bounded chunk of active-chain identities under one short
    /// read lock.
    fn collect_target_chain(
        &self,
        target: &TipSnapshot,
        start_height: u32,
        end_height: u32,
    ) -> Result<Vec<BlockIdentity>, TxIndexWorkerError> {
        let tree = self.block_tree.read();
        let capacity = usize::try_from(end_height.saturating_sub(start_height).saturating_add(1))
            .unwrap_or(usize::MAX);
        let mut identities = Vec::with_capacity(capacity);
        for height in start_height..=end_height {
            let node_id = tree
                .node_at_height_from(target.tip_id, height)
                .ok_or(TxIndexWorkerError::MissingTargetChain { height })?;
            let node = tree
                .node(node_id)
                .map_err(|_| TxIndexWorkerError::MissingTargetChain { height })?;
            let parent_hash = if height == 0 {
                [0_u8; 32]
            } else {
                let parent_id = tree
                    .parent_id(node_id)
                    .map_err(|_| TxIndexWorkerError::MissingTargetChain { height })?
                    .ok_or(TxIndexWorkerError::MissingTargetChain { height })?;
                let parent = tree
                    .node(parent_id)
                    .map_err(|_| TxIndexWorkerError::MissingTargetChain { height })?;
                *parent.hash.as_byte_array()
            };
            identities.push(BlockIdentity {
                height,
                hash: *node.hash.as_byte_array(),
                parent_hash,
            });
        }
        Ok(identities)
    }

    fn catch_up_to(
        &self,
        target: &TipSnapshot,
        watermark: Option<IndexWatermark>,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        if self.runtime.should_stop() {
            return Ok(ReconcileAction::Stalled);
        }

        let mut state = pending.take().unwrap_or_else(|| PendingForward {
            durable: watermark,
            batch: PreparedBatch::new(self.batch_limits),
            deadline: Instant::now() + self.batch_delay,
        });
        if state.durable != watermark {
            return Err(TxIndexWorkerError::PendingDurableChanged);
        }
        let start_height = state.batch.watermark().map_or_else(
            || watermark.map_or(0, |w| w.height.saturating_add(1)),
            |endpoint| endpoint.height.saturating_add(1),
        );
        if start_height > target.height {
            return if self.sync_and_commit(state.batch)?.is_some() {
                Ok(ReconcileAction::CaughtUp)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        }

        let chunk_end = start_height
            .saturating_add(IDENTITY_CHUNK_BLOCKS - 1)
            .min(target.height);
        let identities = self.collect_target_chain(target, start_height, chunk_end)?;
        if self.runtime.should_stop() {
            return Ok(ReconcileAction::Stalled);
        }
        let Some(body_store) = self.body_store.as_ref() else {
            return Err(TxIndexWorkerError::NoBodyStore);
        };
        let mut body_reader = body_store.reader().map_err(TxIndexWorkerError::Storage)?;
        let mut requests = Vec::with_capacity(POSITION_PREFETCH_BLOCKS);
        for identities in identities.chunks(POSITION_PREFETCH_BLOCKS) {
            if self.runtime.should_stop() {
                return Ok(ReconcileAction::Stalled);
            }
            requests.clear();
            requests.extend(
                identities
                    .iter()
                    .map(|identity| (identity.height, Hash256::from_le_bytes(&identity.hash))),
            );
            body_reader
                .prefetch_positions(&requests)
                .map_err(TxIndexWorkerError::Storage)?;

            for identity in identities {
                if self.runtime.should_stop() {
                    return Ok(ReconcileAction::Stalled);
                }

                let hash = Hash256::from_le_bytes(&identity.hash);
                let Some(body) = body_reader
                    .load_block_body(identity.height, hash)
                    .map_err(TxIndexWorkerError::Storage)?
                else {
                    if !state.batch.is_empty() {
                        *pending = Some(state);
                    }
                    return Ok(ReconcileAction::Stalled);
                };

                let prepared = self
                    .writer
                    .prepare_block(identity.height, identity.hash, &body)
                    .map_err(TxIndexWorkerError::Index)?;
                drop(body);
                if self.runtime.should_stop() {
                    return Ok(ReconcileAction::Stalled);
                }
                if identity.height > 0 && prepared.parent_hash != identity.parent_hash {
                    return Err(TxIndexWorkerError::MissingTargetChain {
                        height: identity.height,
                    });
                }

                if state.batch.try_push(prepared).is_err() {
                    return if self.sync_and_commit(state.batch)?.is_some() {
                        Ok(ReconcileAction::Progressed)
                    } else {
                        Ok(ReconcileAction::Stalled)
                    };
                }
                if state.batch.is_full() {
                    return if self.sync_and_commit(state.batch)?.is_some() {
                        Ok(ReconcileAction::Progressed)
                    } else {
                        Ok(ReconcileAction::Stalled)
                    };
                }
            }
        }

        self.finish_catch_up(state, chunk_end, target, pending)
    }

    fn finish_catch_up(
        &self,
        state: PendingForward,
        chunk_end: u32,
        target: &TipSnapshot,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        if chunk_end < target.height {
            *pending = Some(state);
            return Ok(ReconcileAction::Progressed);
        }

        let endpoint = state.endpoint();
        let latest = self.applied_tip.load_full();
        if latest.as_deref().is_some_and(|tip| {
            endpoint.height < tip.height && self.watermark_is_on_target_chain(endpoint, tip)
        }) {
            *pending = Some(state);
            return Ok(ReconcileAction::Progressed);
        }

        if latest.as_deref().is_some_and(|tip| {
            endpoint.height == tip.height && endpoint.hash == tip.hash.to_le_bytes()
        }) {
            *pending = Some(state);
            return Ok(ReconcileAction::Buffered);
        }

        if self.sync_and_commit(state.batch)?.is_some() {
            Ok(ReconcileAction::Progressed)
        } else {
            Ok(ReconcileAction::Stalled)
        }
    }
    /// Rolls the index back until the watermark is an ancestor of `target` or
    /// `None`.
    fn rollback_to_target(
        &self,
        mut watermark: IndexWatermark,
        target: &TipSnapshot,
    ) -> Result<Option<IndexWatermark>, TxIndexWorkerError> {
        while !self.watermark_is_on_target_chain(watermark, target) {
            if self.runtime.should_stop() {
                return Err(TxIndexWorkerError::Stopped);
            }
            let new_watermark = self.rollback_one(watermark)?;
            watermark = match new_watermark {
                Some(watermark) => watermark,
                None => return Ok(None),
            };
        }
        Ok(Some(watermark))
    }

    /// Rolls the index back to `None`.
    fn rollback_to_none(&self, mut watermark: IndexWatermark) -> Result<(), TxIndexWorkerError> {
        loop {
            if self.runtime.should_stop() {
                return Err(TxIndexWorkerError::Stopped);
            }
            match self.rollback_one(watermark)? {
                Some(next) => watermark = next,
                None => return Ok(()),
            }
        }
    }

    /// Rolls back one complete block from the single-writer index.
    fn rollback_one(
        &self,
        watermark: IndexWatermark,
    ) -> Result<Option<IndexWatermark>, TxIndexWorkerError> {
        let watermark_hash = Hash256::from_le_bytes(&watermark.hash);
        let body = self.load_body(watermark.height, watermark_hash)?;

        let prev = if watermark.height == 0 {
            None
        } else {
            let prepared = self
                .writer
                .prepare_block(watermark.height, watermark.hash, &body)
                .map_err(TxIndexWorkerError::Index)?;
            Some(IndexWatermark {
                height: watermark.height.saturating_sub(1),
                hash: prepared.parent_hash,
            })
        };

        if self.runtime.should_stop() {
            return Err(TxIndexWorkerError::Stopped);
        }
        self.writer
            .commit_rollback_one(prev, &body)
            .map_err(TxIndexWorkerError::Index)?;
        Ok(prev)
    }

    fn load_body(&self, height: u32, hash: Hash256) -> Result<Vec<u8>, TxIndexWorkerError> {
        let Some(store) = self.body_store.as_ref() else {
            return Err(TxIndexWorkerError::NoBodyStore);
        };
        store
            .load_block_body(height, hash)
            .map_err(TxIndexWorkerError::Storage)?
            .ok_or(TxIndexWorkerError::MissingBody { height, hash })
    }

    fn sync_and_commit(
        &self,
        batch: PreparedBatch,
    ) -> Result<Option<IndexWatermark>, TxIndexWorkerError> {
        if batch.is_empty() {
            return Ok(None);
        }
        if let Some(store) = self.body_store.as_ref() {
            store.sync().map_err(TxIndexWorkerError::Storage)?;
        }
        if self.runtime.should_stop() {
            return Ok(None);
        }

        let watermark = self
            .writer
            .commit_forward(batch)
            .map_err(TxIndexWorkerError::Index)?;
        Ok(Some(watermark))
    }

    fn commit_pending(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<bool, TxIndexWorkerError> {
        let Some(state) = pending.take() else {
            unreachable!("commit_pending has a pending batch");
        };
        Ok(self.sync_and_commit(state.batch)?.is_some())
    }
}

enum ReconcileAction {
    Progressed,
    Buffered,
    CaughtUp,
    Stalled,
}

#[derive(Debug, thiserror::Error)]
enum TxIndexWorkerError {
    #[error("txindex worker stopped")]
    Stopped,
    #[error("txindex durable watermark changed while a forward batch was pending")]
    PendingDurableChanged,
    #[error("txindex storage error: {0}")]
    Storage(#[source] bitcoin_rs_storage::StorageError),
    #[error("txindex index error: {0}")]
    Index(#[from] IndexError),
    #[error("txindex worker: missing body at height {height}, hash {hash}")]
    MissingBody { height: u32, hash: Hash256 },
    #[error("txindex worker: body store missing")]
    NoBodyStore,
    #[error("txindex worker: target chain node missing at height {height}")]
    MissingTargetChain { height: u32 },
}

/// Aggregate work budget shared by every operation in one public query.
struct QueryBudget {
    remaining_rows: usize,
    remaining_bytes: usize,
    remaining_scans: usize,
    remaining_body_reads: usize,
}

impl QueryBudget {
    const fn new() -> Self {
        Self {
            remaining_rows: QUERY_SCAN_ROW_LIMIT,
            remaining_bytes: QUERY_SCAN_BYTE_LIMIT,
            remaining_scans: QUERY_SCAN_COUNT_LIMIT,
            remaining_body_reads: QUERY_BODY_READ_LIMIT,
        }
    }

    fn next_scan_limit(&mut self) -> Result<PrefixScanLimit, TxQueryError> {
        if self.remaining_scans == 0 || self.remaining_rows == 0 || self.remaining_bytes == 0 {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exhausted".into(),
            ));
        }
        self.remaining_scans -= 1;
        Ok(PrefixScanLimit {
            max_rows: self.remaining_rows,
            max_bytes: self.remaining_bytes,
        })
    }

    fn accept_scan(&mut self, scan: TxIndexScan) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        if !scan.complete {
            return Err(TxQueryError::Unavailable(
                "txindex prefix scan truncated".into(),
            ));
        }
        if scan.rows.len() > self.remaining_rows || scan.encoded_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exceeded".into(),
            ));
        }
        self.remaining_rows -= scan.rows.len();
        self.remaining_bytes -= scan.encoded_bytes;
        Ok(scan.rows)
    }

    fn reserve_body_read(&mut self, max_bytes: usize) -> Result<(), TxQueryError> {
        if self.remaining_body_reads == 0 || max_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query body budget exhausted".into(),
            ));
        }
        self.remaining_body_reads -= 1;
        Ok(())
    }

    fn charge_body_bytes(&mut self, bytes: usize) -> Result<(), TxQueryError> {
        if bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query body budget exceeded".into(),
            ));
        }
        self.remaining_bytes -= bytes;
        Ok(())
    }
}

/// Node-owned, snapshot-gated transaction-index query engine.
///
/// Implements `bitcoin_rs_rpc::TxIndexQuery` and `bitcoin_rs_electrum`'s
/// `ConfirmedHistoryReader` as the only public read paths for the transaction
/// index. Every query runs against one typed point-in-time snapshot, captures
/// health/shutdown/revision/tip before and after work, and returns typed
/// `Retry`/`Unavailable` when the answer cannot be proven.
#[derive(Clone)]
pub(crate) struct TxIndexQueryEngine {
    runtime: Arc<TxIndexRuntime>,
    reader: Arc<dyn IndexReader>,
    block_source: NodeBlockSource,
    block_tree: Arc<RwLock<BlockTree>>,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    body_source: Option<Arc<dyn BlockBodySource>>,
}

impl core::fmt::Debug for TxIndexQueryEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxIndexQueryEngine").finish_non_exhaustive()
    }
}

impl TxIndexQueryEngine {
    /// Builds a query engine over the shared reader and authoritative block source.
    #[must_use]
    pub(crate) fn new(
        runtime: Arc<TxIndexRuntime>,
        reader: Arc<dyn IndexReader>,
        block_source: NodeBlockSource,
        block_tree: Arc<RwLock<BlockTree>>,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
        body_source: Option<Arc<dyn BlockBodySource>>,
    ) -> Self {
        Self {
            runtime,
            reader,
            block_source,
            block_tree,
            applied_tip,
            body_source,
        }
    }

    fn query_health(&self) -> Result<(), TxQueryError> {
        if self.runtime.failed.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable(
                self.runtime
                    .failure_message()
                    .unwrap_or_else(|| "txindex worker failed".into()),
            ));
        }
        if self.runtime.shutdown.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable("txindex worker stopped".into()));
        }
        Ok(())
    }

    fn with_snapshot<F, T>(&self, f: F) -> Result<T, TxQueryError>
    where
        F: for<'s> FnOnce(
            &'s dyn TxIndexSnapshot,
            &TipSnapshot,
            &mut QueryBudget,
        ) -> Result<T, TxQueryError>,
    {
        self.query_health()?;

        let tip_before = self
            .applied_tip
            .load()
            .as_ref()
            .cloned()
            .ok_or(TxQueryError::Retry)?;
        let revision_before = self.runtime.revision();

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;

        // Ensure the index watermark is exactly at the applied tip we are
        // answering for, otherwise the snapshot is stale.
        let watermark = snapshot
            .watermark()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
        let Some(watermark) = watermark else {
            return Err(TxQueryError::Retry);
        };
        if watermark.height != tip_before.height
            || watermark.hash != *tip_before.hash.as_byte_array()
        {
            return Err(TxQueryError::Retry);
        }

        let mut budget = QueryBudget::new();
        let result = f(snapshot.as_ref(), &tip_before, &mut budget);

        self.query_health()?;
        let tip_after = self.applied_tip.load();
        let revision_after = self.runtime.revision();
        if revision_before != revision_after
            || tip_after
                .as_ref()
                .is_none_or(|tip| tip.height != tip_before.height || tip.hash != tip_before.hash)
        {
            return Err(TxQueryError::Retry);
        }

        result
    }

    fn resolve_hash_at_height(
        &self,
        height: u32,
        tip: &TipSnapshot,
    ) -> Result<Hash256, TxQueryError> {
        let tree = self.block_tree.read();
        Self::hash_at_height(&tree, tip.tip_id, height).ok_or(TxQueryError::Retry)
    }

    fn hash_at_height(
        tree: &BlockTree,
        tip_id: bitcoin_rs_chain::NodeId,
        height: u32,
    ) -> Option<Hash256> {
        let node_id = tree.node_at_height_from(tip_id, height)?;
        tree.node(node_id).ok().map(|n| n.hash)
    }

    fn resolve_block(
        &self,
        budget: &mut QueryBudget,
        height: u32,
        hash: Hash256,
    ) -> Result<Block, TxQueryError> {
        budget.reserve_body_read(MAX_SERIALIZED_BLOCK_BYTES)?;
        let bytes = self.resolve_block_body_bytes(height, hash)?;
        budget.charge_body_bytes(bytes.len())?;
        Self::verify_block(&bytes, height, hash)
    }

    fn resolve_block_body_bytes(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<Vec<u8>, TxQueryError> {
        if let Some(body_source) = self.body_source.as_ref() {
            if let Some(bytes) = body_source.block_body(height, hash) {
                return Ok(bytes);
            }
        }
        self.block_source
            .block_body_bytes_for(height, hash)
            .ok_or_else(|| {
                TxQueryError::Unavailable(
                    format!("block body missing for txindex query at height {height}").into(),
                )
            })
    }

    fn verify_block(bytes: &[u8], height: u32, hash: Hash256) -> Result<Block, TxQueryError> {
        let block = deserialize::<Block>(bytes).map_err(|_| {
            TxQueryError::Storage(format!("corrupt serialized block at height {height}").into())
        })?;
        let decoded = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        if decoded != hash {
            return Err(TxQueryError::Storage(
                format!("block identity mismatch at height {height}").into(),
            ));
        }
        Ok(block)
    }

    fn validated_positions(value: &[u8]) -> Option<&[TxPosition]> {
        let positions = TxPositionValue::decode(value)?;
        let mut previous: Option<TxPosition> = None;
        for &position in positions {
            let end = position.end()?;
            if position.byte_len() == 0
                || usize::try_from(end).ok()? > MAX_SERIALIZED_BLOCK_BYTES
                || previous.is_some_and(|prior| {
                    position.offset() <= prior.offset()
                        || position.offset() < prior.end().unwrap_or(u32::MAX)
                })
            {
                return None;
            }
            previous = Some(position);
        }
        Some(positions)
    }

    fn resolve_positioned_transaction(
        &self,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        height: u32,
        position: TxPosition,
    ) -> Result<Option<Transaction>, TxQueryError> {
        let hash = self.resolve_hash_at_height(height, tip)?;
        let Some(body_source) = self.body_source.as_ref() else {
            return Ok(None);
        };
        let byte_len = usize::try_from(position.byte_len())
            .map_err(|_| TxQueryError::Storage("transaction position length overflow".into()))?;
        budget.reserve_body_read(byte_len)?;
        let Some(bytes) =
            body_source.block_body_range(height, hash, position.offset(), position.byte_len())
        else {
            return Ok(None);
        };
        budget.charge_body_bytes(bytes.len())?;
        if bytes.len() != byte_len {
            return Ok(None);
        }
        Ok(deserialize::<Transaction>(&bytes).ok())
    }

    fn transaction_from_full_block(
        &self,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        height: u32,
        txid: &Txid,
    ) -> Result<Option<Transaction>, TxQueryError> {
        let hash = self.resolve_hash_at_height(height, tip)?;
        let block = self.resolve_block(budget, height, hash)?;
        Ok(block
            .txdata
            .into_iter()
            .find(|transaction| transaction.compute_txid() == *txid))
    }

    fn transaction_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        txid: &Txid,
    ) -> Result<Option<Transaction>, TxQueryError> {
        Ok(self
            .locate_transaction_for(snapshot, tip, budget, txid)?
            .map(|(_, transaction)| transaction))
    }

    /// Resolves both the confirming height and the transaction itself.
    ///
    /// `transaction_for` and `transaction_height_for` are the same walk, so they
    /// share it rather than keeping two copies of the row/position/full-block
    /// fallback ladder. The height caller pays for the deserialization it does
    /// not use, which is the price of not answering with an unverified row: a
    /// row surviving from a reorged block would otherwise name a height whose
    /// block never held the transaction.
    fn locate_transaction_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        txid: &Txid,
    ) -> Result<Option<(u32, Transaction)>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .transaction_rows(txid, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        let rows = budget.accept_scan(scan)?;
        if rows.is_empty() {
            return Ok(None);
        }

        for row in rows {
            let height = row.row.height();
            let Some(positions) = Self::validated_positions(&row.value) else {
                if let Some(transaction) =
                    self.transaction_from_full_block(tip, budget, height, txid)?
                {
                    return Ok(Some((height, transaction)));
                }
                continue;
            };
            let position = positions[0];
            match self.resolve_positioned_transaction(tip, budget, height, position)? {
                Some(transaction) if transaction.compute_txid() == *txid => {
                    return Ok(Some((height, transaction)));
                }
                _ => {
                    if let Some(transaction) =
                        self.transaction_from_full_block(tip, budget, height, txid)?
                    {
                        return Ok(Some((height, transaction)));
                    }
                }
            }
        }
        Ok(None)
    }

    fn outpoint_value_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Option<u64>, TxQueryError> {
        let tx = self.transaction_for(snapshot, tip, budget, &outpoint.txid)?;
        let Some(tx) = tx else {
            return Ok(None);
        };
        let vout = usize::try_from(outpoint.vout)
            .map_err(|_| TxQueryError::Storage("outpoint vout overflow".into()))?;
        Ok(tx.output.get(vout).map(|o| o.value.to_sat()))
    }

    fn scan_funding_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .funding_rows(scripthash, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        budget.accept_scan(scan)
    }

    fn scan_spending_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Vec<HashPrefixRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .spending_rows(outpoint, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        Ok(budget
            .accept_scan(scan)?
            .into_iter()
            .map(|row| row.row)
            .collect())
    }

    fn collect_funding_outputs(
        transaction: &Transaction,
        height: u32,
        scripthash: ScriptHash,
        outputs: &mut Vec<(Txid, u32, u64, u32)>,
    ) -> Result<bool, TxQueryError> {
        let txid = transaction.compute_txid();
        let before = outputs.len();
        for (vout_idx, output) in transaction.output.iter().enumerate() {
            if ScriptHash::new(&output.script_pubkey) != scripthash {
                continue;
            }
            let vout = u32::try_from(vout_idx)
                .map_err(|_| TxQueryError::Storage("vout overflow".into()))?;
            outputs.push((txid, vout, output.value.to_sat(), height));
        }
        Ok(outputs.len() != before)
    }

    fn funding_outputs_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<(Txid, u32, u64, u32)>, TxQueryError> {
        let rows = Self::scan_funding_rows(snapshot, budget, scripthash)?;
        let mut outputs = Vec::new();
        for row in rows {
            let height = row.row.height();
            let Some(positions) = Self::validated_positions(&row.value) else {
                let hash = self.resolve_hash_at_height(height, tip)?;
                let block = self.resolve_block(budget, height, hash)?;
                for transaction in &block.txdata {
                    Self::collect_funding_outputs(transaction, height, scripthash, &mut outputs)?;
                }
                continue;
            };

            let row_start = outputs.len();
            let mut complete = true;
            for &position in positions {
                let Some(transaction) =
                    self.resolve_positioned_transaction(tip, budget, height, position)?
                else {
                    complete = false;
                    break;
                };
                if !Self::collect_funding_outputs(&transaction, height, scripthash, &mut outputs)? {
                    complete = false;
                    break;
                }
            }
            if complete {
                continue;
            }

            outputs.truncate(row_start);
            let hash = self.resolve_hash_at_height(height, tip)?;
            let block = self.resolve_block(budget, height, hash)?;
            for transaction in &block.txdata {
                Self::collect_funding_outputs(transaction, height, scripthash, &mut outputs)?;
            }
        }
        Ok(outputs)
    }

    fn confirmed_history_snapshot_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<ConfirmedHistorySnapshot, TxQueryError> {
        let funding_outputs = self.funding_outputs_for(snapshot, tip, budget, scripthash)?;

        let mut history = Vec::new();
        let mut unspent = Vec::new();
        for &(txid, vout, value, height) in &funding_outputs {
            history.push(HistoryRecord {
                txid,
                height: i64::from(height),
                value,
                vout,
                spent: false,
            });
        }

        // Resolve every funding record, retaining it as unspent only when no
        // indexed candidate contains a transaction that actually spends it.
        for (txid, vout, value, height) in funding_outputs {
            let outpoint = OutPoint { txid, vout };
            let spend_rows = Self::scan_spending_rows(snapshot, budget, &outpoint)?;
            let mut spent = false;

            let mut last_spend_height: Option<u32> = None;
            let mut cached_spend_block: Option<Block> = None;
            for row in spend_rows {
                let spend_height = row.height();
                if last_spend_height != Some(spend_height) {
                    let hash = self.resolve_hash_at_height(spend_height, tip)?;
                    cached_spend_block = Some(self.resolve_block(budget, spend_height, hash)?);
                    last_spend_height = Some(spend_height);
                }
                let block = cached_spend_block.as_ref().ok_or_else(|| {
                    TxQueryError::Unavailable("missing block during history query".into())
                })?;
                for tx in &block.txdata {
                    if tx
                        .input
                        .iter()
                        .any(|input| input.previous_output == outpoint)
                    {
                        spent = true;
                        history.push(HistoryRecord {
                            txid: tx.compute_txid(),
                            height: i64::from(spend_height),
                            value: 0,
                            vout: 0,
                            spent: true,
                        });
                        break;
                    }
                }
            }

            if !spent {
                unspent.push(HistoryRecord {
                    txid,
                    height: i64::from(height),
                    value,
                    vout,
                    spent: false,
                });
            }
        }

        history.sort_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
                .then_with(|| a.value.cmp(&b.value))
        });
        history.dedup_by(|a, b| a.txid == b.txid && a.height == b.height && a.vout == b.vout);
        unspent.sort_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
        });
        unspent.dedup_by(|a, b| a.txid == b.txid && a.height == b.height && a.vout == b.vout);

        Ok(ConfirmedHistorySnapshot { history, unspent })
    }

    fn unspent_outputs_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<HistoryRecord>, TxQueryError> {
        let funding_outputs = self.funding_outputs_for(snapshot, tip, budget, scripthash)?;
        let mut records = Vec::new();
        for (txid, vout, value, height) in funding_outputs {
            let outpoint = OutPoint { txid, vout };
            let spend_rows = Self::scan_spending_rows(snapshot, budget, &outpoint)?;
            let mut spent = false;
            let mut last_spend_height = None;
            let mut cached_spend_block = None;
            for row in spend_rows {
                let spend_height = row.height();
                if last_spend_height != Some(spend_height) {
                    let hash = self.resolve_hash_at_height(spend_height, tip)?;
                    cached_spend_block = Some(self.resolve_block(budget, spend_height, hash)?);
                    last_spend_height = Some(spend_height);
                }
                let block = cached_spend_block.as_ref().ok_or_else(|| {
                    TxQueryError::Unavailable("missing block during unspent query".into())
                })?;
                if block.txdata.iter().any(|transaction| {
                    transaction
                        .input
                        .iter()
                        .any(|input| input.previous_output == outpoint)
                }) {
                    spent = true;
                    break;
                }
            }
            if !spent {
                records.push(HistoryRecord {
                    txid,
                    height: i64::from(height),
                    value,
                    vout,
                    spent: false,
                });
            }
        }

        records.sort_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
        });
        records.dedup_by(|a, b| a.txid == b.txid && a.height == b.height && a.vout == b.vout);
        Ok(records)
    }

    fn index_info_internal(&self) -> Result<TxIndexInfo, TxQueryError> {
        self.query_health()?;

        let tip_before = self
            .applied_tip
            .load()
            .as_ref()
            .cloned()
            .ok_or(TxQueryError::Retry)?;
        let revision_before = self.runtime.revision();

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
        let watermark = snapshot
            .watermark()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;

        // Synced means the durable index watermark is exactly at the published
        // applied chainstate tip.
        let synced = watermark.as_ref().is_some_and(|watermark| {
            watermark.height == tip_before.height
                && watermark.hash == *tip_before.hash.as_byte_array()
        });
        let best_block_height = watermark.map_or(0, |w| w.height);

        self.query_health()?;
        let tip_after = self.applied_tip.load();
        let revision_after = self.runtime.revision();

        if revision_before != revision_after
            || tip_after
                .as_ref()
                .is_none_or(|tip| tip.height != tip_before.height || tip.hash != tip_before.hash)
        {
            return Err(TxQueryError::Retry);
        }

        Ok(TxIndexInfo {
            synced,
            best_block_height,
        })
    }
}

impl TxIndexQuery for TxIndexQueryEngine {
    fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, TxQueryError> {
        self.with_snapshot(|snapshot, tip, budget| {
            self.transaction_for(snapshot, tip, budget, txid)
        })
    }

    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        self.with_snapshot(|snapshot, tip, budget| {
            self.outpoint_value_for(snapshot, tip, budget, outpoint)
        })
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        self.with_snapshot(|snapshot, tip, budget| {
            Ok(self
                .locate_transaction_for(snapshot, tip, budget, txid)?
                .map(|(height, _)| height))
        })
    }

    fn index_info(&self) -> Result<TxIndexInfo, TxQueryError> {
        self.index_info_internal()
    }
}

impl ConfirmedHistoryReader for TxIndexQueryEngine {
    fn confirmed_history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ConfirmedHistorySnapshot, ElectrumError> {
        self.with_snapshot(|snapshot, tip, budget| {
            self.confirmed_history_snapshot_for(snapshot, tip, budget, scripthash)
        })
        .map_err(tx_query_error_to_electrum)
    }

    fn unspent_outputs(&self, scripthash: ScriptHash) -> Result<Vec<HistoryRecord>, ElectrumError> {
        self.with_snapshot(|snapshot, tip, budget| {
            self.unspent_outputs_for(snapshot, tip, budget, scripthash)
        })
        .map_err(tx_query_error_to_electrum)
    }

    fn transaction_hex(&self, txid: &Txid) -> Result<String, ElectrumError> {
        let tx = self
            .transaction(txid)
            .map_err(tx_query_error_to_electrum)?
            .ok_or(ElectrumError::NotFound("transaction not found"))?;
        Ok(serialize(&tx).to_lower_hex_string())
    }

    fn outpoint_value(&self, op: &OutPoint) -> Result<Option<u64>, ElectrumError> {
        TxIndexQuery::outpoint_value(self, op).map_err(tx_query_error_to_electrum)
    }

    fn index_info(&self) -> Result<ElectrumTxIndexInfo, ElectrumError> {
        let info = TxIndexQuery::index_info(self).map_err(tx_query_error_to_electrum)?;
        Ok(ElectrumTxIndexInfo {
            synced: info.synced,
            best_block_height: info.best_block_height,
        })
    }
}

fn tx_query_error_to_electrum(error: TxQueryError) -> ElectrumError {
    match error {
        TxQueryError::Retry => {
            ElectrumError::Unavailable("transaction index changed during query; retry".into())
        }
        TxQueryError::Unavailable(reason) => ElectrumError::Unavailable(reason),
        TxQueryError::Storage(reason) => {
            ElectrumError::Storage(StorageError::Backend(reason.to_string()))
        }
    }
}

#[cfg(all(test, feature = "fjall"))]
mod body_reader_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin::Network;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin_rs_chain::NodeStatus;

    use super::*;
    use crate::apply::{PruneBodyReader, PruneBodyStore};

    struct SessionBodyStore {
        height: u32,
        hash: Hash256,
        body: Vec<u8>,
        readers: AtomicUsize,
        prefetches: AtomicUsize,
        session_loads: AtomicUsize,
        direct_loads: AtomicUsize,
    }

    struct SessionBodyReader<'a> {
        store: &'a SessionBodyStore,
        pending: Option<(u32, Hash256)>,
    }

    impl PruneBodyReader for SessionBodyReader<'_> {
        fn prefetch_positions(&mut self, requests: &[(u32, Hash256)]) -> Result<(), StorageError> {
            let [request] = requests else {
                return Err(StorageError::InvalidOperation(
                    "session test expects one prefetched position",
                ));
            };
            if self.pending.replace(*request).is_some() {
                return Err(StorageError::InvalidOperation(
                    "session test position was not consumed",
                ));
            }
            self.store.prefetches.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn load_block_body(
            &mut self,
            height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            if self.pending.take() != Some((height, hash)) {
                return Err(StorageError::InvalidOperation(
                    "session body loaded without matching prefetch",
                ));
            }
            self.store.session_loads.fetch_add(1, Ordering::AcqRel);
            Ok((height == self.store.height && hash == self.store.hash)
                .then(|| self.store.body.clone()))
        }
    }

    impl PruneBodyStore for SessionBodyStore {
        fn persist_block_body(
            &self,
            _height: u32,
            _hash: Hash256,
            _body: &[u8],
        ) -> Result<(), StorageError> {
            Ok(())
        }

        fn load_block_body(
            &self,
            _height: u32,
            _hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            self.direct_loads.fetch_add(1, Ordering::AcqRel);
            Err(StorageError::InvalidOperation(
                "direct body load must not be used",
            ))
        }

        fn reader(&self) -> Result<Box<dyn PruneBodyReader + '_>, StorageError> {
            self.readers.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(SessionBodyReader {
                store: self,
                pending: None,
            }))
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[test]
    fn catch_up_uses_one_body_reader_session() -> Result<(), Box<dyn std::error::Error>> {
        let block = genesis_block(Network::Regtest);
        let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let mut tree = BlockTree::new();
        let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let node = tree.node(tip_id)?;
        let tip = TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        };

        let tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(tip.clone())));
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
        let runtime = Arc::new(TxIndexRuntime::new(wake_tx));
        let data_dir = tempfile::tempdir()?;
        let index_store = Arc::new(bitcoin_rs_storage::FjallStore::open(data_dir.path())?);
        let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
            bitcoin_rs_index::IndexWriter::open(index_store)?,
        ));
        let body_store = Arc::new(SessionBodyStore {
            height: tip.height,
            hash,
            body: bitcoin::consensus::serialize(&block),
            readers: AtomicUsize::new(0),
            prefetches: AtomicUsize::new(0),
            session_loads: AtomicUsize::new(0),
            direct_loads: AtomicUsize::new(0),
        });
        let worker = Worker {
            runtime,
            writer,
            applied_tip,
            block_tree: tree,
            body_store: Some(body_store.clone()),
            batch_limits: DEFAULT_BATCH_LIMITS,
            wake_rx,
            quiet_period: Duration::ZERO,
            batch_delay: Duration::ZERO,
        };
        let mut pending = None;

        assert!(matches!(
            worker.catch_up_to(&tip, None, &mut pending)?,
            ReconcileAction::Buffered
        ));
        assert_eq!(body_store.readers.load(Ordering::Acquire), 1);
        assert_eq!(body_store.prefetches.load(Ordering::Acquire), 1);
        assert_eq!(body_store.session_loads.load(Ordering::Acquire), 1);
        assert_eq!(body_store.direct_loads.load(Ordering::Acquire), 0);
        Ok(())
    }
}

#[cfg(test)]
#[path = "txindex_worker_query_tests.rs"]
mod query_tests;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "txindex_worker_catchup_tests.rs"]
mod catchup_tests;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "txindex_worker_reconcile_tests.rs"]
mod reconcile_tests;
