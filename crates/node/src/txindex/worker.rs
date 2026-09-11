//! Durable watermark reconciliation, rollback, and cursor commit ownership.

mod commit;
mod reconcile;

use super::{
    runtime::TxIndexRuntime, scheduling::BatchWait, scheduling::wait_for_batch_deadline,
    scheduling::wait_for_revision_quiet,
};
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_index::{
    IndexCapabilities, IndexError, IndexWatermark, IndexWatermarks, IndexWriteFence, PreparedBatch,
    PreparedBatchLimits, writer::TxIndexWriter,
};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use crossbeam_channel::Receiver;
use parking_lot::{Mutex, RwLock};
use std::{sync::Arc, time::Duration, time::Instant};

/// Writer-side batch limits.
///
/// Capped by actual retained row count and encoded bytes to keep each forward
/// commit bounded.
const BATCH_BYTE_LIMIT: usize = 256 << 20;

pub(crate) const ROCKSDB_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 1_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

pub(crate) const DEFAULT_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 1_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

pub(crate) const REDB_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 16_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

/// Default fork depth at which a stale txindex watermark routes to a
/// selective reset + rebuild instead of a per-block rewind.
///
/// Grounded in three measured runs of per-block forward-ingest versus rollback
/// cost (see `docs/benchmarks/index-rollback-rebuild-cutover.md`): the default
/// routes the 834k-block stale-branch incident shape to a rebuild while organic
/// reorgs (tens of blocks) keep rewinding block by block.
pub(crate) const DEFAULT_ROLLBACK_REBUILD_CUTOVER: u32 = 100_000;

pub(super) const REVISION_QUIET_PERIOD: Duration = Duration::from_millis(100);

pub(super) const FORWARD_BATCH_DELAY: Duration = Duration::from_millis(100);

pub(super) struct Worker {
    pub(super) runtime: Arc<TxIndexRuntime>,
    pub(super) writer: Arc<dyn TxIndexWriter>,
    pub(super) applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    pub(super) block_tree: Arc<RwLock<BlockTree>>,
    pub(super) body_store: Option<Arc<dyn BlockBodyStore>>,
    pub(super) batch_limits: PreparedBatchLimits,
    pub(super) enabled: IndexCapabilities,
    pub(super) chain_events: Arc<crate::state::ChainEventPublisher>,
    /// Sink for the index-ahead rollback evidence (`chain-rollback-event`
    /// marker plus `getblockchaininfo` warning).
    pub(super) reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
    pub(super) wake_rx: Receiver<()>,
    pub(super) quiet_period: Duration,
    pub(super) batch_delay: Duration,
    /// Fork depth at which a stale watermark routes to a selective reset
    /// and rebuild instead of a per-block rewind. `u32::MAX` means rewind
    /// at any depth (pre-cutover behavior).
    pub(super) rollback_rebuild_cutover: u32,
    /// Authoritative UTXO source for live-view seeding.
    pub(super) utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    /// Chain transition authority shared with apply and RPC reads.
    pub(super) chain_transition: Option<Arc<Mutex<()>>>,
}

/// Uncommitted contiguous rows based on one unchanged durable watermark.
pub(super) struct PendingForward {
    pub(super) fence: IndexWriteFence,
    pub(super) watermarks: IndexWatermarks,
    pub(super) capabilities: IndexCapabilities,
    pub(super) durable: Option<IndexWatermark>,
    pub(super) batch: PreparedBatch,
    pub(super) deadline: Instant,
}

impl PendingForward {
    pub(super) fn endpoint(&self) -> IndexWatermark {
        let Some(watermark) = self.batch.watermark() else {
            unreachable!("pending forward batch is nonempty");
        };
        watermark
    }
}

fn index_ahead_capability_label(capabilities: IndexCapabilities) -> Option<String> {
    let mut names = Vec::new();
    if capabilities.tx_lookup {
        names.push("tx_lookup");
    }
    if capabilities.script_history {
        names.push("script_history");
    }
    if capabilities.script_live {
        names.push("script_live");
    }
    (!names.is_empty()).then(|| names.join(","))
}

enum CursorCommit {
    Settled,
    ResetRejected,
    NotAligned,
}

#[derive(Debug)]
pub(super) enum ReconcileAction {
    Progressed,
    Buffered,
    CaughtUp,
    Stalled,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum TxIndexWorkerError {
    #[error("txindex worker stopped")]
    Stopped,
    #[error("txindex durable watermark changed while a forward batch was pending")]
    PendingDurableChanged,
    #[error("txindex storage error: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(
        "txindex store open timed out after {secs}s — the storage engine recovery may be stuck"
    )]
    OpenTimeout { secs: u64 },
    #[error("txindex index error: {0}")]
    Index(#[from] IndexError),
    #[error("txindex worker: missing body at height {height}, hash {hash}")]
    MissingBody { height: u32, hash: Hash256 },
    #[error("txindex worker: body store missing")]
    NoBodyStore,
    #[error("txindex worker: authoritative UTXO view missing for ScriptLive")]
    MissingUtxo,
    #[error("txindex worker: chain transition authority missing for ScriptLive")]
    MissingChainTransition,
    #[error("txindex worker: undo record missing or unreadable at height {height}, hash {hash}")]
    UndoUnavailable { height: u32, hash: Hash256 },
    #[error("txindex worker: target chain node missing at height {height}")]
    MissingTargetChain { height: u32 },
    #[error("txindex worker: rollback evidence marker not written: {0}")]
    RollbackEvidence(#[source] crate::recovery_evidence::EvidenceError),
}

impl TxIndexWorkerError {
    fn requires_capability_rebuild(&self) -> bool {
        matches!(
            self,
            Self::MissingBody { .. } | Self::Index(IndexError::MissingWatermarkIdentity { .. })
        )
    }
}

impl Worker {
    pub(super) fn run(self) -> Result<(), TxIndexWorkerError> {
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
                Err(TxIndexWorkerError::Index(
                    IndexError::ResetInProgress | IndexError::StaleIndexState,
                )) => {
                    pending = None;
                    ReconcileAction::Stalled
                }
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
                    match self.persist_chain_cursor()? {
                        CursorCommit::Settled => {}
                        CursorCommit::ResetRejected | CursorCommit::NotAligned => {
                            quiet_armed = true;
                            continue;
                        }
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
                                // `commit_pending` already took the pending
                                // forward; `Ok(false)` means a retryable
                                // reset rejection, not a permanent failure.
                                // Exit only on shutdown; otherwise let the
                                // quiet wait throttle the retry.
                                if self.runtime.should_stop() {
                                    break;
                                }
                                quiet_armed = true;
                                continue;
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
}
