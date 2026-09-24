//! Authoritative chainstate mutation: connect, disconnect, and window apply.
//!
//! Ownership, admission, and the `Chainstate` / `ChainTransition` boundary
//! are specified by `ARCH-07` in `docs/contracts/architecture.md`. Chainstate
//! publishes the tip and returns a concrete connect or disconnect outcome.
//! Higher layers consume those outcomes after the authoritative commit.

pub use crate::error::{ApplyError, DisconnectError};
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainTxCount;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::TxOut;
use bitcoin_rs_primitives::Txid;
pub use bitcoin_rs_storage::DisconnectPhase;
use bitcoin_rs_storage::DurableHeadStore;
use bitcoin_rs_storage::InMemoryUndoStore;
pub use bitcoin_rs_storage::KvUndoStore;
pub use bitcoin_rs_storage::UndoStore;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_utxo::LiveOutput;
use bitcoin_rs_utxo::LiveOutputMeta;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::connect::SpentOutputLookup;
use bitcoin_rs_utxo::is_coinbase_tx;
use connect::apply_block_admitted;
use connect::apply_committed_block_admitted;
use disconnect::disconnect_block_admitted;
pub use durable::reconcile_at_boot;
use hashbrown::HashMap;
use parking_lot::Mutex;
use parking_lot::MutexGuard;
use parking_lot::RwLock;
use parking_lot::RwLockReadGuard;
use parking_lot::RwLockWriteGuard;
use scratch::ApplyScratchCapacities;
use scratch::SameBlockSpentSet;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
pub use window::DURABLE_HEAD_GROUP_BLOCKS;
pub use window::DURABLE_HEAD_GROUP_MAX_BYTES;
use window::PublishMode;
use window::apply_window_admitted;

mod connect;
mod disconnect;
mod durable;
mod prepare;
mod publication;
mod window;
pub use prepare::bytes_are_block;
pub use window::classify_apply_error;

mod checkpoint;
pub use checkpoint::CheckpointError;
pub use checkpoint::headers::HeaderCheckpointError;
/// Typed chainstate mutation failures.
pub mod error;
pub mod events;
pub mod journal;
mod maintenance;
pub mod recovery;
pub mod reorg;
mod scratch;

/// Historical script-verification policy owned by authoritative chainstate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ValidationMode {
    /// Every script executes; assume-valid settings are ignored.
    Full,
    /// Skip scripts through a pinned assume-valid anchor.
    #[default]
    AssumeValid,
    /// Skip scripts below the best header tip.
    Fast,
}

impl ValidationMode {
    /// Parses a configuration spelling, case-insensitively.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "full" => Some(Self::Full),
            "assume-valid" | "assume_valid" | "assumevalid" => Some(Self::AssumeValid),
            "fast" => Some(Self::Fast),
            _ => None,
        }
    }
}

/// Chainstate journal durability and retention policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainstateJournalConfig {
    /// Whether journal recovery is enabled.
    pub enabled: bool,
    /// Maximum blocks between durability boundaries.
    pub blocks: u32,
    /// Maximum seconds between durability boundaries.
    pub seconds: u64,
    /// Active segment rotation threshold in MiB.
    pub rotate_mib: u64,
    /// Total journal retention bound in MiB.
    pub max_journal_mib: u64,
    /// Maximum blocks the applied tip may lead the durable head.
    pub max_lag_blocks: u32,
    /// Maximum seconds the applied tip may lead the durable head.
    pub max_lag_seconds: u64,
}

impl Default for ChainstateJournalConfig {
    fn default() -> Self {
        let policy = bitcoin_rs_storage::chainstate_journal::JournalPolicy::default();
        Self {
            enabled: true,
            blocks: policy.batch_blocks,
            seconds: policy.batch_seconds.as_secs(),
            rotate_mib: policy.rotate_mib,
            max_journal_mib: policy.max_journal_mib,
            max_lag_blocks: policy.max_lag_blocks,
            max_lag_seconds: policy.max_lag_seconds.as_secs(),
        }
    }
}

/// Inputs required to open a chainstate journal writer.
#[derive(Clone, Copy)]
pub struct JournalBootstrap {
    /// Whether to open an existing journal instead of initializing one.
    pub open_existing: bool,
    /// Full-checkpoint generation the journal extends.
    pub base_generation: u64,
    /// Durable base height.
    pub height: u32,
    /// Durable base block hash.
    pub block_hash: [u8; 32],
    /// Parent hash of the durable base.
    pub prev_hash: [u8; 32],
    /// Cumulative transaction count through the durable base.
    pub chain_tx_count: u64,
    /// Journal policy.
    pub config: ChainstateJournalConfig,
}

const LOCAL_OVERLAY_TXID_SET_THRESHOLD: usize = 8;

/// Admission barrier shared by every cloned apply handle.
pub(crate) struct ApplyAdmission {
    closed: AtomicBool,
    barrier: RwLock<()>,
}

impl ApplyAdmission {
    pub(crate) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            barrier: RwLock::new(()),
        }
    }

    fn ensure_open(&self) -> Result<(), ApplyError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(ApplyError::Shutdown);
        }
        Ok(())
    }

    fn enter(&self) -> Result<RwLockReadGuard<'_, ()>, ApplyError> {
        self.ensure_open()?;
        let permit = self.barrier.read();
        if let Err(error) = self.ensure_open() {
            drop(permit);
            return Err(error);
        }
        Ok(permit)
    }

    pub(crate) fn close(&self) -> RwLockWriteGuard<'_, ()> {
        self.closed.store(true, Ordering::Release);
        self.barrier.write()
    }

    /// Temporarily pauses new chain transitions while the returned guard lives.
    pub(crate) fn pause(&self) -> RwLockWriteGuard<'_, ()> {
        self.barrier.write()
    }

    /// Closes admission without taking the barrier.
    ///
    /// [`Self::close`] hands back the write guard because shutdown holds it
    /// while it drains. A torn chainstate has nothing to drain and no owner to
    /// hold a guard: it needs the flag set and every later `enter` refused,
    /// including the one that would otherwise apply the next block.
    pub(crate) fn close_permanently(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// Admission plus the chain-transition lock.
///
/// Field order releases the transition lock before the admission permit.
struct TransitionGuard<'a> {
    _transition: MutexGuard<'a, ()>,
    _admission: RwLockReadGuard<'a, ()>,
}

fn begin_chain_transition<'a>(
    admission: &'a ApplyAdmission,
    chain_transition: &'a Mutex<()>,
) -> core::result::Result<TransitionGuard<'a>, ApplyError> {
    let admission_guard = admission.enter()?;
    let transition = chain_transition.lock();
    admission.ensure_open()?;
    Ok(TransitionGuard {
        _transition: transition,
        _admission: admission_guard,
    })
}

/// Proof that this chainstate's admission and transition lock are both held.
///
/// The issuing [`Chainstate`] is captured in the token. Promotion consumes the
/// token, so a lock from one service cannot authorize mutation of another.
pub struct TransitionLock<'a> {
    chainstate: &'a Chainstate,
    guard: TransitionGuard<'a>,
}

impl<'a> TransitionLock<'a> {
    /// Promotes this owner-bound lock into the authoritative mutation capability.
    #[must_use]
    pub fn into_transition(self) -> ChainTransition<'a> {
        ChainTransition {
            chainstate: self.chainstate,
            _lock: self.guard,
        }
    }
}

/// Chain-mutation authority required by destructive block-body pruning.
#[derive(Clone)]
pub struct PruneAuthority {
    admission: Arc<ApplyAdmission>,
    chain_transition: Arc<Mutex<()>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
}

impl PruneAuthority {
    /// Acquires exclusive chain-mutation authority for one pruning pass.
    pub fn begin(&self) -> core::result::Result<PruneGuard<'_>, ApplyError> {
        Ok(PruneGuard {
            _transition: begin_chain_transition(&self.admission, &self.chain_transition)?,
            applied_tip: &self.applied_tip,
        })
    }
}

/// Proof that pruning owns chain mutation and may read the authoritative tip.
pub struct PruneGuard<'a> {
    _transition: TransitionGuard<'a>,
    applied_tip: &'a ArcSwapOption<TipSnapshot>,
}

impl PruneGuard<'_> {
    #[must_use]
    /// Returns the authoritative applied-tip height while pruning owns the transition.
    pub fn applied_tip_height(&self) -> Option<u32> {
        self.applied_tip.load().as_ref().map(|tip| tip.height)
    }
}

/// Hash-pinned assume-valid trust gate (Bitcoin Core `-assumevalid` semantics).
///
/// Historical script verification may be skipped only while the active header
/// chain is verified to contain the pinned anchor block. The gate starts
/// trusted when no anchor applies (no pin configured) and starts untrusted
/// when an anchor is pinned; [`AssumeValidGate::evaluate`] re-evaluates trust
/// against the block tree whenever a new inbound headers batch is accepted.
#[derive(Debug)]
pub struct AssumeValidGate {
    /// Pinned `(height, hash)` anchor, or `None` when no pin applies.
    anchor: Option<(u32, Hash256)>,
    /// Whether the active chain is currently verified to contain the anchor.
    trusted: AtomicBool,
    /// Whether the diverged-chain warning has already been emitted.
    warned: AtomicBool,
}

impl AssumeValidGate {
    /// Builds the gate for `network` gated on `configured_height`.
    ///
    /// The network's pinned anchor applies only when `configured_height` equals
    /// the anchor height (the production default). Any other value — `0` (full
    /// verification opt-in) or a custom height-only shortcut — leaves the gate
    /// unpinned and therefore always trusted.
    #[must_use]
    pub fn new(network: Network, configured_height: u32) -> Self {
        let anchor = network
            .assume_valid_anchor()
            .filter(|(height, _)| *height == configured_height);
        Self {
            trusted: AtomicBool::new(anchor.is_none()),
            warned: AtomicBool::new(false),
            anchor,
        }
    }

    /// Builds a gate directly from an optional pinned anchor.
    #[must_use]
    pub fn with_anchor(anchor: Option<(u32, Hash256)>) -> Self {
        Self {
            trusted: AtomicBool::new(anchor.is_none()),
            warned: AtomicBool::new(false),
            anchor,
        }
    }

    /// Returns whether historical script verification may currently be skipped.
    #[must_use]
    pub fn trusted(&self) -> bool {
        self.trusted.load(Ordering::Relaxed)
    }

    /// Re-evaluates trust against `tree`'s active chain.
    ///
    /// Trusted only when the active tip is at or above the pinned height and
    /// the node at the pinned height on the active chain carries the pinned
    /// hash. Emits a one-time warning when a chain at/past the anchor height
    /// lacks the anchor block; such a chain is never trusted.
    pub fn evaluate(&self, tree: &BlockTree) {
        let Some((pinned_height, pinned_hash)) = self.anchor else {
            return;
        };
        let Some(tip) = tree.tip() else {
            self.trusted.store(false, Ordering::Relaxed);
            return;
        };
        if tip.height < pinned_height {
            self.trusted.store(false, Ordering::Relaxed);
            return;
        }
        let trusted = tree
            .node_at_height_from(tip.tip_id, pinned_height)
            .is_some_and(|id| tree.lookup(pinned_hash) == Some(id));
        if !trusted && !self.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                pinned_height,
                pinned_hash = %pinned_hash,
                "active chain lacks the assume-valid anchor block; verifying every script",
            );
        }
        self.trusted.store(trusted, Ordering::Relaxed);
    }
}

/// Where a block being applied came from. Decides whether its scripts execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockProvenance {
    /// Untrusted input (peer delivery, submitblock, file import): scripts run
    /// unless the assume-valid gate covers the height.
    Network,
    /// A body this node validated and persisted under its recovery marker
    /// before the crash; its scripts already ran here.
    LocalReplay,
}

/// Committed connect. Derived consumers read this after the tip is published.
#[derive(Clone, Debug)]
pub struct ConnectOutcome {
    /// New applied tip.
    pub tip: TipSnapshot,
    /// The durable-head commit id that certified this block before it
    /// published. Windows share one id across a committed group prefix.
    pub commit_id: u64,
    /// Height of the connected block.
    pub height: u32,
    /// Hash of the connected block.
    pub hash: Hash256,
    /// Transaction ids in block order.
    pub txids: Vec<Txid>,
    /// Canonical block bytes when a derived consumer asked for them, else empty.
    pub block_bytes: bytes::Bytes,
    /// Per-transaction wire bytes when a derived consumer asked for `rawtx`.
    pub raw_txs: Option<Vec<Vec<u8>>>,
}

/// Committed disconnect. Derived consumers read this after the tip is published.
#[derive(Clone, Debug)]
pub struct DisconnectOutcome {
    /// Applied tip after the rollback (the parent).
    pub parent_tip: TipSnapshot,
    /// Hash of the disconnected block.
    pub hash: Hash256,
    /// Creating txids of coins the undo restored, for orphan re-evaluation.
    pub restored_parents: Vec<Txid>,
}

/// Connect intent. See `ARCH-07` in `docs/contracts/architecture.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplyIntent {
    Commit,
    /// See `ARCH-07` in `docs/contracts/architecture.md`.
    Propose,
}

/// Outcome of [`apply_block_admitted`] once intent is known.
enum ApplyFinish {
    /// Commit path: the new applied tip, already published.
    Committed(ConnectOutcome),
    /// See `ARCH-07` in `docs/contracts/architecture.md`.
    Proposed,
}

/// Coherent read of the header tip and the applied tip.
///
/// Produced by [`Chainstate::snapshot`]. Each tip is one cell, and an applied
/// tip carries its own certified cumulative transaction count, so one load
/// supplies both. Header tip is a separate cell and may legitimately be ahead
/// of the applied chain. The snapshot cannot mutate chainstate.
#[derive(Clone, Debug)]
pub struct ChainstateSnapshot {
    /// Best-work header tip, if the tree has one.
    pub header: Option<TipSnapshot>,
    /// Authoritative applied tip, if any block has committed.
    pub applied: Option<TipSnapshot>,
    /// Cumulative transaction count of the applied chain.
    ///
    /// Derived from `applied`, never stored beside it independently.
    pub chain_tx_count: ChainTxCount,
}

/// In-process facade for authoritative applied-chain mutation.
///
/// See `ARCH-07` in `docs/contracts/architecture.md`. Construction and
/// lifecycle stay in `node`. Mutation goes through [`Self::begin_transition`].
#[derive(Clone)]
pub struct Chainstate {
    pub(crate) network: Network,
    pub(crate) chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(crate) applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(crate) block_tree: Arc<RwLock<BlockTree>>,
    pub(crate) utxo: Arc<UtxoSet>,
    pub(crate) coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    pub(crate) chain_events: Arc<crate::events::ChainEventPublisher>,
    pub(crate) block_body_store: Option<Arc<dyn BlockBodyStore>>,
    pub(crate) undo_store: Arc<dyn UndoStore>,
    /// Owner of the durable-head row: the chain's durable commit point,
    /// advanced by one atomic batch per committed connect or disconnect
    /// before the tip publishes (`RCV-02`).
    pub(crate) durable_head: Arc<dyn DurableHeadStore>,
    pub(crate) admission: Arc<ApplyAdmission>,
    pub(crate) shutdown: Arc<AtomicBool>,
    /// Serializes whole chain transitions against each other.
    ///
    /// Distinct from `admission`, which is a shutdown barrier: `enter` takes a
    /// READ guard, so any number of applies hold it at once and it excludes
    /// nothing but a checkpoint close. A transition reads the applied tip,
    /// decides what follows it, mutates chain-owned state, and publishes the
    /// result. Two such operations interleaved can both validate against the
    /// same tip and then invalidate each other's retention or publication
    /// decisions. This lock spans connects, windows, disconnects, and pruning.
    pub(crate) chain_transition: Arc<parking_lot::Mutex<()>>,
    pub(crate) assume_valid_height: u32,
    pub(crate) assume_valid_gate: Arc<AssumeValidGate>,
    pub(crate) validation_mode: ValidationMode,
    /// Chainstate-journal writer, when the journal is enabled (issue #230).
    ///
    /// `None` = journal off: the apply path emits nothing and behaves exactly
    /// as a checkpoint-only node. The writer is single-owner (the apply path);
    /// the `Mutex` only makes the shared handle exclusive.
    pub(crate) journal: Option<bitcoin_rs_storage::chainstate_journal::SharedJournalWriter>,
    /// Publishes checkpoints to settle rolled-back disconnect debt after a
    /// non-fatal reorg. `None` in unit-test handle sets that never reorg.
    pub(crate) checkpoint_publisher: Option<Arc<crate::checkpoint::publisher::CheckpointPublisher>>,
    /// Capture per-transaction wire bytes for a derived `rawtx` consumer.
    pub(crate) capture_rawtx: bool,
    /// Serialize the full block for a derived consumer (body store, index, rawblock).
    pub(crate) capture_block_bytes: bool,
    /// Retention authority shared with the pruning pass: chain transitions
    /// and required readers pin old-branch bodies here so pruning cannot
    /// delete data an active transition still re-reads (#655, `RCV-08`).
    pub(crate) retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
}

/// Construction inputs for one authoritative chainstate service.
///
/// Every field is an owned lower-layer capability. Process composition belongs
/// to the node crate; mutation ownership starts here.
pub struct ChainstateParts {
    /// Consensus network.
    pub network: Network,
    /// Best-work header-tip publication cell.
    pub chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Authoritative applied-tip publication cell.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Shared header/block tree.
    pub block_tree: Arc<RwLock<BlockTree>>,
    /// Authoritative UTXO set.
    pub utxo: Arc<UtxoSet>,
    /// Coin-statistics listener attached to the UTXO set.
    pub coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    /// Applied-chain event publisher.
    pub chain_events: Arc<crate::events::ChainEventPublisher>,
    /// Durable canonical block-body store, when configured.
    pub block_body_store: Option<Arc<dyn BlockBodyStore>>,
    /// Durable undo store.
    pub undo_store: Arc<dyn UndoStore>,
    /// Durable applied-head store.
    pub durable_head: Arc<dyn DurableHeadStore>,
    /// Process shutdown signal.
    pub shutdown: Arc<AtomicBool>,
    /// Highest assume-valid height.
    pub assume_valid_height: u32,
    /// Historical script-verification policy.
    pub validation_mode: ValidationMode,
    /// Chainstate journal writer, when journal recovery is enabled.
    pub journal: Option<bitcoin_rs_storage::chainstate_journal::SharedJournalWriter>,
    /// Whether connects retain raw transaction bytes for node-owned consumers.
    pub capture_rawtx: bool,
    /// Whether connects retain canonical block bytes for node-owned consumers.
    pub capture_block_bytes: bool,
}

/// Held while new chain mutations are blocked.
pub struct AdmissionGuard<'a> {
    _guard: RwLockWriteGuard<'a, ()>,
}

/// One admitted chain mutation.
///
/// Owns admission and the exclusive authoritative-chain transition lock.
/// Connect, window-connect, and disconnect run only through this type.
/// # Persistence
///
/// Every connect follows the ordered durable protocol (`RCV-02` in
/// `docs/contracts/recovery.md`): reserve, append, sync, one atomic durable
/// batch, publish. The durable batch — head row, undo record, and body
/// locator under one `write_durable_if` receipt — is the commit point; the
/// tip publishes strictly after it, so a follower-visible block is already
/// durable (`INV-04`), and a crash recovers the old or the new committed
/// head, never a mix. The chainstate journal is derived from the durable
/// head, not a second authority, and the next clean checkpoint is a
/// maintenance export.
///
/// Disconnect arms a durable `DisconnectMarker` before the UTXO undo and
/// advances the same durable head atomically with the `RolledBack` marker.
/// `DisconnectError::Refused` means nothing was mutated.
/// `DisconnectError::Fatal` means a partial undo: do not retry, poison
/// admission, and shut down. A crash during rollback is recovered from the
/// marker, not by retrying the disconnect.
///
/// Window apply commits a bounded verified prefix per durable batch. A
/// failure leaves the committed prefix in place; the failing block stays
/// retryable unless the failure was fatal (`UtxoCommit`, durable-head
/// commit), in which case recovery owns reconciliation.
///
pub struct ChainTransition<'a> {
    chainstate: &'a Chainstate,
    _lock: TransitionGuard<'a>,
}

impl<'a> ChainTransition<'a> {
    fn settle_apply<T>(
        &self,
        result: core::result::Result<T, ApplyError>,
    ) -> core::result::Result<T, ApplyError> {
        if result
            .as_ref()
            .is_err_and(|error| classify_apply_error(error) == WindowApplyDisposition::Fatal)
        {
            self.chainstate.fail_closed_for_recovery();
        }
        result
    }

    /// Connects `block` as the next applied tip.
    ///
    /// `serialized` is `Some` when the caller holds the block's wire bytes,
    /// which skips re-serialization and validates those bytes; `None` keeps
    /// serialization lazy. Both arms share one commit and publication order.
    ///
    /// PRE: the caller holds admission and the chain-transition guard, and
    /// present bytes encode `block`.
    ///
    /// POST: `Ok` is a durable commit followed by publication; an error keeps
    /// the existing refusal and recovery semantics.
    ///
    /// INVARIANT: `None` and `Some` commit and publish in the same order.
    pub fn connect(
        &self,
        block: &Block,
        serialized: Option<bytes::Bytes>,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        self.settle_apply(apply_committed_block_admitted(
            self.chainstate,
            block,
            serialized,
            None,
            BlockProvenance::Network,
            PublishMode::Now,
        ))
    }

    /// Re-applies a body this node already validated and persisted before a crash.
    ///
    /// Scripts do not run again (`BlockProvenance::LocalReplay`). Persistence
    /// otherwise matches [`Self::connect`].
    pub fn replay_local(
        &self,
        block: &Block,
        serialized: bytes::Bytes,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        self.settle_apply(apply_committed_block_admitted(
            self.chainstate,
            block,
            Some(serialized),
            None,
            BlockProvenance::LocalReplay,
            PublishMode::Now,
        ))
    }

    /// Disconnects `block`, which must be the current applied tip.
    ///
    /// See the type-level persistence notes for marker arming, the commit
    /// point, and `Refused` versus `Fatal`.
    pub fn disconnect(
        &self,
        block: &Block,
    ) -> core::result::Result<DisconnectOutcome, crate::DisconnectError> {
        let result = disconnect_block_admitted(self.chainstate, block);
        if matches!(
            result,
            Err(crate::DisconnectError::Fatal { .. } | crate::DisconnectError::MarkerStuck { .. })
        ) {
            self.chainstate.fail_closed_for_recovery();
        }
        result
    }

    /// Applies consecutive blocks under this one transition.
    ///
    /// Commits one at a time and in order. A failure leaves the committed
    /// prefix in place, matching per-block apply. See the type-level
    /// persistence notes for permanent versus operational retry.
    #[allow(clippy::result_large_err)]
    pub fn connect_window(
        &self,
        blocks: &[&Block],
        serialized: &[bytes::Bytes],
    ) -> core::result::Result<Vec<ConnectOutcome>, WindowApplyError> {
        let mut result = apply_window_admitted(self.chainstate, blocks, serialized);
        if let Err(error) = &mut result
            && (error.disposition == WindowApplyDisposition::Fatal
                || classify_apply_error(&error.source) == WindowApplyDisposition::Fatal)
        {
            error.disposition = WindowApplyDisposition::Fatal;
            self.chainstate.fail_closed_for_recovery();
        }
        result
    }

    /// Returns the chainstate service owning this transition.
    pub fn chainstate(&self) -> &'a Chainstate {
        self.chainstate
    }
}

impl Chainstate {
    /// Creates the production service from lower-layer capabilities.
    #[must_use]
    pub fn from_parts(parts: ChainstateParts) -> Self {
        let assume_valid_gate = Arc::new(AssumeValidGate::new(
            parts.network,
            parts.assume_valid_height,
        ));
        assume_valid_gate.evaluate(&parts.block_tree.read());
        Self {
            network: parts.network,
            chain_tip: parts.chain_tip,
            applied_tip: parts.applied_tip,
            block_tree: parts.block_tree,
            utxo: parts.utxo,
            coin_stats: parts.coin_stats,
            chain_events: parts.chain_events,
            block_body_store: parts.block_body_store,
            undo_store: parts.undo_store,
            durable_head: parts.durable_head,
            admission: Arc::new(ApplyAdmission::new()),
            shutdown: parts.shutdown,
            chain_transition: Arc::new(Mutex::new(())),
            assume_valid_height: parts.assume_valid_height,
            assume_valid_gate,
            validation_mode: parts.validation_mode,
            journal: parts.journal,
            checkpoint_publisher: None,
            capture_rawtx: parts.capture_rawtx,
            capture_block_bytes: parts.capture_block_bytes,
            retention: Arc::new(bitcoin_rs_storage::RetentionRegistry::new()),
        }
    }

    /// Permanently closes chain mutation and asks the process to shut down.
    ///
    /// Call only when the current chainstate may require restart-time recovery;
    /// retrying or continuing to serve a mutable process state is unsafe.
    pub fn fail_closed_for_recovery(&self) {
        self.admission.close_permanently();
        self.shutdown.store(true, Ordering::Release);
    }

    /// Permanently closes mutation admission and waits for in-flight mutations.
    ///
    /// Dropping the returned guard releases only the exclusive drain lock;
    /// admission remains closed. Use this for orderly shutdown, not a scoped
    /// maintenance pause.
    #[must_use]
    pub fn close(&self) -> AdmissionGuard<'_> {
        self.shutdown.store(true, Ordering::Release);
        AdmissionGuard {
            _guard: self.admission.close(),
        }
    }

    /// Returns the consensus network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Returns the best-work header-tip cell.
    #[must_use]
    pub fn chain_tip(&self) -> &ArcSwapOption<TipSnapshot> {
        &self.chain_tip
    }

    /// Clones the best-work header-tip handle for node-owned readers.
    #[must_use]
    pub fn chain_tip_handle(&self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.chain_tip)
    }

    /// Returns the authoritative applied-tip cell.
    #[must_use]
    pub fn applied_tip(&self) -> &ArcSwapOption<TipSnapshot> {
        &self.applied_tip
    }

    /// Returns the shared applied-tip handle for node-owned readers.
    #[must_use]
    pub fn applied_tip_handle(&self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.applied_tip)
    }

    /// Returns the shared block tree.
    #[must_use]
    pub fn block_tree(&self) -> &RwLock<BlockTree> {
        &self.block_tree
    }

    /// Clones the shared block-tree handle for node-owned readers.
    #[must_use]
    pub fn block_tree_handle(&self) -> Arc<RwLock<BlockTree>> {
        Arc::clone(&self.block_tree)
    }

    /// Returns the authoritative UTXO set.
    #[must_use]
    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    /// Clones the authoritative UTXO handle for node-owned readers.
    #[must_use]
    pub fn utxo_handle(&self) -> Arc<UtxoSet> {
        Arc::clone(&self.utxo)
    }

    /// Clones the coin-statistics listener handle.
    #[must_use]
    pub fn coin_stats_handle(&self) -> Arc<bitcoin_rs_utxo::stats::CoinStatsListener> {
        Arc::clone(&self.coin_stats)
    }

    /// Clones the authoritative chain-event publisher.
    pub fn chain_events_handle(&self) -> Arc<crate::events::ChainEventPublisher> {
        Arc::clone(&self.chain_events)
    }

    /// Returns the current coherent applied-chain event snapshot.
    #[must_use]
    pub fn chain_snapshot(&self) -> crate::events::ChainSnapshot {
        self.chain_events.snapshot()
    }

    /// Returns the durable block-body store when configured.
    #[must_use]
    pub fn block_body_store(&self) -> Option<&Arc<dyn BlockBodyStore>> {
        self.block_body_store.as_ref()
    }

    /// Clones the durable block-body store when configured.
    #[must_use]
    pub fn block_body_store_handle(&self) -> Option<Arc<dyn BlockBodyStore>> {
        self.block_body_store.clone()
    }

    /// Clones the process shutdown signal.
    #[must_use]
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Clones the pruning retention registry.
    #[must_use]
    pub fn retention_handle(&self) -> Arc<bitcoin_rs_storage::RetentionRegistry> {
        Arc::clone(&self.retention)
    }

    /// Returns the read barrier used by lower-layer live-view consumers.
    ///
    /// Locking this mutex prevents an authoritative transition from starting;
    /// it does not grant mutation capability.
    #[must_use]
    pub fn transition_barrier(&self) -> Arc<Mutex<()>> {
        Arc::clone(&self.chain_transition)
    }

    /// Sets which committed wire payloads must be retained for node-owned followers.
    pub fn set_capture_flags(&mut self, rawtx: bool, block_bytes: bool) {
        self.capture_rawtx = rawtx;
        self.capture_block_bytes = block_bytes;
    }

    /// Re-evaluates the assume-valid anchor against the current active header chain.
    pub fn reevaluate_assume_valid(&self) {
        self.assume_valid_gate.evaluate(&self.block_tree.read());
    }

    /// Re-evaluates the assume-valid anchor against an already locked tree.
    pub fn reevaluate_assume_valid_with(&self, tree: &BlockTree) {
        self.assume_valid_gate.evaluate(tree);
    }

    /// `Fast` trusts a block only when it is the node at `height` on the
    /// best header tip's own chain, so a block on a competing branch never
    /// borrows that trust. The tip is read from the tree under the same read
    /// guard as the ancestry walk, and every header-tip writer holds the
    /// chain-transition lock, so the answer stays true through the caller's
    /// commit.
    pub(crate) fn scripts_verified_upstream(
        &self,
        provenance: BlockProvenance,
        height: u32,
        hash: Hash256,
    ) -> bool {
        match provenance {
            BlockProvenance::LocalReplay => true,
            BlockProvenance::Network => match self.validation_mode {
                ValidationMode::Full => false,
                ValidationMode::AssumeValid => {
                    self.assume_valid_height > 0
                        && height <= self.assume_valid_height
                        && self.assume_valid_gate.trusted()
                }
                ValidationMode::Fast => {
                    let tree = self.block_tree.read();
                    let Some(header_tip) = tree.tip() else {
                        return false;
                    };
                    height < header_tip.height
                        && tree
                            .node_at_height_from(header_tip.tip_id, height)
                            .is_some_and(|id| tree.lookup(hash) == Some(id))
                }
            },
        }
    }

    /// Returns pruning authority coupled to this chainstate transition lock.
    pub fn prune_authority(&self) -> PruneAuthority {
        PruneAuthority {
            admission: Arc::clone(&self.admission),
            chain_transition: Arc::clone(&self.chain_transition),
            applied_tip: Arc::clone(&self.applied_tip),
        }
    }

    /// Admission plus the exclusive transition lock, without mempool generation.
    ///
    /// Used for read-consistent planning that may abort without mutating
    /// (reorg replans, `validate_block`, pruning) and for header admission,
    /// which moves the header tip without touching chainstate. Mutation requires
    /// [`Self::begin_transition`] or promotion through
    /// [`TransitionLock::into_transition`].
    pub fn lock_transition(&self) -> core::result::Result<TransitionLock<'_>, ApplyError> {
        let guard = begin_chain_transition(&self.admission, &self.chain_transition)?;
        Ok(TransitionLock {
            chainstate: self,
            guard,
        })
    }

    /// Begins an admitted authoritative-chain mutation.
    ///
    /// The returned capability holds admission and the exclusive transition
    /// lock until it is dropped. A clean refusal releases those locks normally;
    /// fatal mutation failures retain their documented recovery semantics.
    /// Mempool generation settlement is node-owned and is not part of this
    /// chainstate capability.
    pub fn begin_transition(&self) -> core::result::Result<ChainTransition<'_>, ApplyError> {
        Ok(self.lock_transition()?.into_transition())
    }

    /// Builds a chainstate facade for tests and composition that do not go
    /// through `NodeState::open`.
    ///
    /// Derived consumers are not attached. Capture flags default off; set them
    /// with [`Self::capturing`] when a caller will dispatch `rawtx` or block
    /// bytes after the commit.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        network: Network,
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        utxo: Arc<UtxoSet>,
        coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
        chain_events: Arc<crate::events::ChainEventPublisher>,
    ) -> Self {
        Self {
            network,
            chain_tip,
            applied_tip,
            block_tree,
            utxo,
            coin_stats,
            chain_events,
            block_body_store: None,
            undo_store: Arc::new(InMemoryUndoStore::default()),
            durable_head: Arc::new(bitcoin_rs_storage::InMemoryDurableHeadStore::new()),
            admission: Arc::new(ApplyAdmission::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            chain_transition: Arc::new(parking_lot::Mutex::new(())),
            assume_valid_height: 0,
            assume_valid_gate: Arc::new(AssumeValidGate::with_anchor(None)),
            validation_mode: ValidationMode::AssumeValid,
            journal: None,
            checkpoint_publisher: None,
            capture_rawtx: false,
            capture_block_bytes: false,
            retention: Arc::new(bitcoin_rs_storage::RetentionRegistry::new()),
        }
    }

    /// Captures derived payloads on later connects: per-tx wire bytes and/or
    /// the canonical block serialization.
    #[must_use]
    pub fn capturing(mut self, rawtx: bool, block_bytes: bool) -> Self {
        self.capture_rawtx = rawtx;
        self.capture_block_bytes = block_bytes;
        self
    }

    /// Copies the published header tip and the published applied tip.
    ///
    /// Does not take the transition lock. Each tip is one cell, and an applied
    /// tip carries its own certified count, so one load per cell cannot
    /// observe a tip and a count from different publications. Header tip is a
    /// separate cell and may be ahead of the applied chain.
    #[must_use]
    pub fn snapshot(&self) -> ChainstateSnapshot {
        let applied = self.applied_tip.load_full().as_deref().cloned();
        let chain_tx_count = applied
            .as_ref()
            .map_or(ChainTxCount::UNKNOWN, |tip| tip.chain_tx_count);
        ChainstateSnapshot {
            header: self.chain_tip.load_full().as_deref().cloned(),
            applied,
            chain_tx_count,
        }
    }

    /// Publishes a checkpoint to settle rolled-back disconnect debt.
    ///
    /// Returns `Ok(true)` when a checkpoint was written, `Ok(false)` when
    /// there was no debt or no publisher. A publication failure leaves the
    /// `RolledBack` marker in place.
    pub fn settle_disconnect_debt(&self) -> core::result::Result<bool, CheckpointError> {
        match &self.checkpoint_publisher {
            Some(publisher) => publisher.settle_disconnect_debt(),
            None => Ok(false),
        }
    }

    /// Installs the checkpoint publisher used by maintenance and disconnect settlement.
    pub fn configure_checkpointing(
        &mut self,
        data_dir: &std::path::Path,
        durable_tip_height: Arc<std::sync::atomic::AtomicU32>,
    ) -> anyhow::Result<()> {
        let checkpoint_data_dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(data_dir)
            .map_err(anyhow::Error::new)?;
        let block_body_store = self
            .block_body_store
            .clone()
            .ok_or_else(|| anyhow::anyhow!("checkpointing requires a block body store"))?;
        self.checkpoint_publisher = Some(Arc::new(
            crate::checkpoint::publisher::CheckpointPublisher {
                admission: Arc::clone(&self.admission),
                undo_store: Arc::clone(&self.undo_store),
                durable_head: Arc::clone(&self.durable_head),
                block_body_store,
                applied_tip: Arc::clone(&self.applied_tip),
                checkpoint_data_dir,
                network: self.network,
                genesis_hash: self.network.genesis_block_hash(),
                block_tree: Arc::clone(&self.block_tree),
                utxo: Arc::clone(&self.utxo),
                coin_stats: Arc::clone(&self.coin_stats),
                journal: self.journal.clone(),
                data_dir: data_dir.to_path_buf(),
                chain_events: Arc::clone(&self.chain_events),
                durable_tip_height,
            },
        ));
        Ok(())
    }

    /// Publishes one full maintenance checkpoint.
    pub fn publish_checkpoint(&self) -> core::result::Result<Option<u64>, CheckpointError> {
        let Some(publisher) = &self.checkpoint_publisher else {
            return Ok(None);
        };
        match publisher.publish()? {
            crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => Ok(None),
            crate::checkpoint::CheckpointWrite::Published { generation } => Ok(Some(generation)),
        }
    }

    /// Admits a transition, connects `block`, then releases the transition lock.
    /// A refusal releases the same chainstate locks; retry semantics come from
    /// [`ChainTransition::connect`], whose `serialized` rules this method
    /// inherits: `Some` reuses the caller's wire bytes, `None` serializes
    /// lazily, and both share one commit and publication order.
    ///
    /// PRE: present bytes encode `block`.
    ///
    /// POST: `Ok` is a durable commit followed by publication.
    ///
    /// INVARIANT: derived consumers are not invoked. Production paths with
    /// followers must dispatch while the chain transition is still held
    /// (`ARCH-07`); node-owned followers consume the returned outcome outside
    /// this crate.
    pub fn apply_block(
        &self,
        block: &Block,
        serialized: Option<bytes::Bytes>,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        let transition = self.begin_transition()?;
        let result = transition.connect(block, serialized);
        drop(transition);
        result
    }

    /// Admits a transition, replays a locally persisted body, then releases the
    /// transition lock.
    ///
    /// Persistence matches [`ChainTransition::replay_local`].
    pub fn replay_local_block(
        &self,
        block: &Block,
        serialized: bytes::Bytes,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        let transition = self.begin_transition()?;
        let result = transition.replay_local(block, serialized);
        drop(transition);
        result
    }

    /// Admits a transition, disconnects `block`, then releases the transition
    /// lock. Refusal and fatal-recovery semantics are defined by
    /// [`ChainTransition::disconnect`].
    ///
    /// Persistence matches [`ChainTransition::disconnect`]. An admission
    /// failure is `DisconnectError::Refused`. Derived consumers are not
    /// invoked; node-owned followers consume the returned outcome.
    pub fn disconnect_block(
        &self,
        block: &Block,
    ) -> core::result::Result<DisconnectOutcome, crate::DisconnectError> {
        let transition = self
            .begin_transition()
            .map_err(|error| crate::DisconnectError::Refused(Box::new(error)))?;
        let result = transition.disconnect(block);
        drop(transition);
        result
    }

    /// Admits a transition, applies consecutive blocks, then releases the
    /// transition lock. Persistence matches [`ChainTransition::connect_window`].
    #[allow(clippy::result_large_err)]
    pub fn apply_window(
        &self,
        blocks: &[&Block],
        serialized: &[bytes::Bytes],
    ) -> core::result::Result<Vec<ConnectOutcome>, WindowApplyError> {
        if blocks.len() != serialized.len() {
            return Err(WindowApplyError {
                applied: 0,
                committed: Vec::new(),
                source: ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Kernel(
                    format!(
                        "window has {} blocks but {} serialized bodies",
                        blocks.len(),
                        serialized.len()
                    ),
                )),
                disposition: WindowApplyDisposition::Operational,
                invalidated: Box::default(),
            });
        }
        let transition = self.begin_transition().map_err(|source| WindowApplyError {
            applied: 0,
            committed: Vec::new(),
            source,
            disposition: WindowApplyDisposition::Operational,
            invalidated: Box::default(),
        })?;
        match transition.connect_window(blocks, serialized) {
            Ok(committed) => {
                drop(transition);
                Ok(committed)
            }
            Err(error) => {
                drop(transition);
                Err(error)
            }
        }
    }

    /// See `ARCH-07` in `docs/contracts/architecture.md`.
    pub fn validate_block(&self, block: &Block) -> core::result::Result<(), ApplyError> {
        let _lock = self.lock_transition()?;
        match apply_block_admitted(
            self,
            block,
            None,
            None,
            BlockProvenance::Network,
            ApplyIntent::Propose,
            PublishMode::Now,
        )? {
            ApplyFinish::Proposed => Ok(()),
            ApplyFinish::Committed(_) => {
                unreachable!("propose intent does not persist")
            }
        }
    }
}

/// Everything a disconnect can refuse, decided before anything is mutated.
///
/// Split out because the ordering matters more than the code: if a check can
/// live here it must, since a refusal from this function costs nothing while a
/// refusal after the first write leaves a partly disconnected chain. Anything
/// added to `disconnect_block` that can fail belongs here unless it physically
/// cannot run this early.
struct DisconnectPlan {
    /// Parent tip with the cumulative count its tree node carries, which the
    /// disconnect commits and publishes unchanged.
    parent_tip: TipSnapshot,
    parent_prev_hash: Hash256,
    undo: bitcoin_rs_utxo::UndoBatch,
    height: u32,
    tx_count_delta: u64,
}

/// How many consecutive blocks share one script-verification dispatch.
///
/// The window amortises dispatch, it does not add parallelism. A mainnet block
/// early in the chain carries about 19 input checks, so fanning those across 32
/// workers costs more in wakeups than the work itself: measured over blocks
/// `0..150_000`, per-block dispatch left 29s of checks running serially in blocks
/// below the parallel threshold and wasted a further 11s above it. Sixty-four
/// blocks turns roughly 21,000 dispatches into 330.
///
/// Bounded by memory: the window holds every block's parsed kernel block and
/// resolved prevouts at once, which costs far more than the block bytes.
/// Measured over `0..150_000`, pinned to 32 cores, medians of interleaved runs:
///
///   window     wall     CPU     peak RSS
///       64    66.2s   596.3s      397 MB
///      128    75.8s   525.6s      409 MB
///      256    69.8s   471.5s      436 MB
///     1024    51.8s   388.7s      572 MB
///     4096    47.2s   377.1s     1205 MB
///
/// CPU falls by a third from 64 to 1024 because the cost being removed is rayon
/// dispatch and spin, not verification. RSS is what stops it: 4096 doubles the
/// resident set for a few more seconds.
///
/// This is a COUNT cap, and count alone is the wrong bound. Early-chain blocks
/// average about 4.6 KB, so 1024 of them is 5 MB of block data; at the tip they
/// are 2 MB, so the same 1024 would hold 2 GB. [`SCRIPT_BATCH_MAX_BYTES`] is the
/// other half, and the window is whichever bound hits first.
///
/// Peer sync does not reach 1024 today. `RECEIVED_BLOCK_BUDGET` caps staging at
/// 256 blocks, so the windows it forms are at most that, worth 471s CPU against
/// 596s at 64 — a real gain, and not the 389s the replay driver reaches.
/// Raising the staging cap further is not a constant change: the staller-arming
/// invariant ties the staged byte budget to the staged count at
/// `MAX_SERIALIZED_BLOCK_SIZE`, so a 1024-block stage would demand a 2 GB bound.
pub const SCRIPT_BATCH_WINDOW: usize = 1024;

/// How many bytes of block data one window may hold.
///
/// The count cap above is sized for small early-chain blocks. This is what
/// keeps the same constant safe at the tip, where a block is roughly 2 MB and
/// the count would otherwise let a window hold gigabytes. Whichever cap binds
/// first ends the window, so the batch is large exactly where blocks are small
/// and dispatch dominates, and small where blocks are large and it does not.
pub const SCRIPT_BATCH_MAX_BYTES: usize = 64 << 20;

/// Returns how many of `sizes` fit in one window.
///
/// At least one block always fits, even one larger than the byte cap on its
/// own: refusing it would stall the chain on an oversized block rather than
/// verify it.
pub fn window_len(sizes: impl IntoIterator<Item = usize>) -> usize {
    let mut count = 0_usize;
    let mut bytes = 0_usize;
    for size in sizes {
        if count == SCRIPT_BATCH_WINDOW {
            break;
        }
        let next = bytes.saturating_add(size);
        if count > 0 && next > SCRIPT_BATCH_MAX_BYTES {
            break;
        }
        bytes = next;
        count = count.saturating_add(1);
    }
    count
}

/// A window that failed partway, and how many of its blocks committed first.
///
/// The count is what a caller needs to recover: it must record the hashes that
/// landed, retry only the one that failed, and put the rest back. A bare
/// `ApplyError` cannot say where the window stopped.
#[derive(Debug)]
pub struct WindowApplyError {
    /// Blocks that committed before the failure.
    pub applied: usize,
    /// Outcomes for the committed prefix, in apply order.
    pub committed: Vec<ConnectOutcome>,
    /// What stopped the block at index `applied`.
    pub source: ApplyError,
    /// How the caller must treat this failure: `Permanent` failures poisoned
    /// the failed block's header subtree while the chain transition was still
    /// held; `BodyMutated` discards only the delivered body; `Operational`
    /// failures poisoned nothing; `Fatal` means mutation or durable-head
    /// state may be torn, so recovery must run before another mutation.
    pub disposition: WindowApplyDisposition,
    /// Hashes marked invalid under the held transition when `disposition` is
    /// [`WindowApplyDisposition::Permanent`]: the failed block and every
    /// descendant, in deterministic slab order. Empty otherwise.
    pub invalidated: Box<[Hash256]>,
}

impl core::fmt::Display for WindowApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "window failed after applying {} block(s): {}",
            self.applied, self.source
        )
    }
}

impl std::error::Error for WindowApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl WindowApplyError {
    /// Failure kind the caller should act on.
    #[must_use]
    pub const fn disposition(&self) -> WindowApplyDisposition {
        self.disposition
    }

    /// Hashes invalidated for a `Permanent` failure, empty otherwise.
    #[must_use]
    pub fn invalidated(&self) -> &[Hash256] {
        &self.invalidated
    }
}

/// Whether a window failure invalidates the header branch, only its delivered
/// body, or neither.
///
/// The caller must not re-classify the source error: the node and reorg paths
/// share one classifier, and this disposition is its decision at failure time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowApplyDisposition {
    /// The failed block and its descendants can never be valid. Their header
    /// subtrees were invalidated under the window's chain transition; purge
    /// every returned hash from staged/download state without retrying.
    Permanent,
    /// The delivered body is mutated or not bound to its header. Discard this
    /// body and retry the same header/hash from another source; do not poison
    /// the header or its descendants.
    BodyMutated,
    /// Transient failure (storage, UTXO commit, shutdown). Nothing was
    /// invalidated; the failed block and its tail stay retryable.
    Operational,
    /// Mutation or durable-head state may already have changed without a
    /// reliable commit receipt. Do not retry in-process; recovery must
    /// re-establish authoritative chainstate first. Nothing about the blocks is
    /// necessarily invalid, so no header subtree is purged.
    Fatal,
}

/// Chain context that determines the ordered transaction checks for one block.
///
/// A window captures this before it applies any block. The commit path derives
/// it again from the live chain and accepts a proof only when every field still
/// agrees.
#[derive(Debug, Eq, PartialEq)]
struct BlockValidationContext {
    hash: Hash256,
    parent: Hash256,
    height: u32,
    flags: bitcoin_rs_script::VerifyFlags,
    locktime_cutoff: u32,
}

/// Chain facts BIP68 evaluates against: the validation context fixing the
/// block's height, the parent median-time-past, the softfork state at
/// connect, and the applied tip the prevout ancestry hangs from.
#[derive(Clone, Copy)]
struct Bip68Context<'a> {
    validation: &'a BlockValidationContext,
    median_time_past: u32,
    softfork_state: bitcoin_rs_chain::SoftforkState,
    previous_tip_id: Option<bitcoin_rs_chain::node::NodeId>,
}

/// Evidence that every ordered transaction pre-check, input script, and
/// transaction post-check passed for this exact prepared block state.
///
/// The proof is private, single-use, and owns the prepared state it certifies.
/// It is constructed only after the whole window verifier succeeds, so callers
/// cannot pair a block's verdict with foreign resolved prevouts.
struct BlockValidationProof<'b> {
    prepared: PreparedApply<'b>,
    context: BlockValidationContext,
}

/// Prepared state returned by a successful window attempt.
///
/// Assume-valid is not proof. A skipped block must re-enter the ordinary
/// transaction path at commit so it reads the trust gate in its current state.
enum ProvenApply<'b> {
    Proven(BlockValidationProof<'b>),
    AssumeValidSkipped(PreparedApply<'b>),
}

/// Everything a block's application needs that depends only on the block and
/// the outputs it spends, not on the chain state the commit will mutate.
///
/// Split out because a window of consecutive blocks can produce all of these
/// at once, against one ordered overlay, and share a single script dispatch.
/// The measured duplication that made an earlier batching attempt a wash was
/// exactly the kernel parse and the prevout resolution below being done twice.
struct PreparedApply<'b> {
    kernel_block: bitcoin_rs_consensus::kernel::KernelBlock,
    /// Parse-once transaction state: identities computed once in
    /// [`parse_block_for_apply`], witness IDs on demand, and the prevout
    /// matrix installed once right before script verification.
    view: bitcoin_rs_consensus::BlockView<'b>,
    tx_plan: BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
}

/// Parses a block and resolves the outputs it spends.
///
/// `source` is where prevouts come from. Today that is always the committed
/// UTXO set; a window passes an overlay so a block can see outputs an earlier
/// block in the same window created.
///
/// Runs no consensus rule and mutates nothing, which is what lets a window
/// prepare several blocks before committing any of them.
/// A sink that compares what is written to it against `expected`.
///
/// Used to check preserved bytes against a block without serialising the block
/// into a second buffer: nothing is allocated and the first differing byte ends
/// the walk.
struct ByteEquality<'a> {
    expected: &'a [u8],
    offset: usize,
    equal: bool,
}

impl bitcoin_rs_primitives::Sink for ByteEquality<'_> {
    fn write_all(&mut self, buf: &[u8]) {
        if self.equal {
            match self
                .expected
                .get(self.offset..self.offset.saturating_add(buf.len()))
            {
                Some(window) if window == buf => {}
                _ => self.equal = false,
            }
        }
        self.offset = self.offset.saturating_add(buf.len());
    }
}

struct BlockTxPlan {
    only_coinbase: bool,
    needs_local_utxo_overlay: bool,
    overlay_capacity: usize,
    witness_presence: WitnessPresence,
    has_bip68_sequence_locks: bool,
    created_output_count: usize,
    spent_input_count: usize,
    same_block_spent: Option<SameBlockSpentSet>,
    same_block_spent_input_count: usize,
}

impl BlockTxPlan {
    /// Outpoints this block both creates and spends, empty when it has none.
    ///
    /// The overlay nets these out exactly as `build_block_changes` does: such an
    /// output never reaches the committed set, so a view carrying it would
    /// resolve a later spend the real set would refuse.
    fn same_block_spent_set(&self) -> &SameBlockSpentSet {
        static NONE: std::sync::LazyLock<SameBlockSpentSet> =
            std::sync::LazyLock::new(SameBlockSpentSet::new);
        self.same_block_spent.as_ref().unwrap_or(&NONE)
    }

    fn into_scratch_parts(
        self,
        txids: Vec<Txid>,
    ) -> (
        Vec<Txid>,
        ApplyScratchCapacities,
        Option<SameBlockSpentSet>,
        usize,
    ) {
        (
            txids,
            ApplyScratchCapacities {
                created_outputs: self.created_output_count,
                spent_inputs: self.spent_input_count,
            },
            self.same_block_spent,
            self.same_block_spent_input_count,
        )
    }
}

#[derive(Clone, Copy)]
enum WitnessPresence {
    Absent,
    Present,
}

impl WitnessPresence {
    const fn from_bool(has_witness: bool) -> Self {
        if has_witness {
            Self::Present
        } else {
            Self::Absent
        }
    }

    const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

/// All external (already-committed) prevouts for one block, resolved in a single
/// parallel pass so `script_verify`, `coinbase_maturity`, and `bip68` reuse one
/// lookup table instead of hitting the `UtxoSet` repeatedly.
struct ResolvedUtxoView {
    external: HashMap<OutPoint, LiveOutput>,
}

impl ResolvedUtxoView {
    /// Resolves a block's external prevouts from any source of live outputs.
    ///
    /// Generic so a window can substitute an overlay carrying the outputs its
    /// earlier blocks created. Every caller outside a window passes the
    /// committed set.
    fn resolve<S: bitcoin_rs_utxo::OutputSource + ?Sized>(
        utxo: &S,
        block: &Block,
        tx_plan: &BlockTxPlan,
    ) -> Self {
        let same_block = tx_plan.same_block_spent.as_ref();
        let candidates = block
            .txs
            .iter()
            .filter(|tx| !is_coinbase_tx(tx))
            .flat_map(|tx| &tx.inputs)
            .filter(|input| same_block.is_none_or(|set| !set.contains(&input.previous_output)))
            .map(|input| input.previous_output);
        // Serial on purpose. A UTXO lookup is a sharded hashmap hit of order
        // 500 ns, so a rayon fan-out costs more than the work it distributes.
        // Measured on mainnet 0..150_000, 3x medians pinned to `taskset -c
        // 0-31`, parallel and serial interleaved: `into_par_iter` 143.8s vs
        // serial 134.7s, and serial won every round. Apply alone goes 116.2s
        // to 103.6s. Parallelize a stage only when per-item work exceeds the
        // dispatch, as the script checks do at ~100 us per input.
        Self {
            external: candidates
                .filter_map(|outpoint| utxo.get_entry(&outpoint).map(|entry| (outpoint, entry)))
                .collect(),
        }
    }
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.external.get(outpoint).map(|entry| entry.txout.clone())
    }

    /// Full resolved entry for a spent outpoint, including creation metadata.
    fn entry(&self, outpoint: &OutPoint) -> Option<&LiveOutput> {
        self.external.get(outpoint)
    }

    fn lookup_meta(&self, outpoint: &OutPoint) -> Option<LiveOutputMeta> {
        self.external.get(outpoint).map(|entry| LiveOutputMeta {
            coinbase: entry.coinbase,
            height: entry.height,
        })
    }
}

impl UtxoView for ResolvedUtxoView {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.lookup(outpoint)
    }
}

impl SpentOutputLookup for ResolvedUtxoView {
    fn entry(&self, outpoint: &OutPoint) -> Option<&LiveOutput> {
        self.entry(outpoint)
    }
}

struct BlockLocalUtxoView<'b> {
    base: Arc<ResolvedUtxoView>,
    txdata: &'b [Tx],
    height: u32,
    overlay: HashMap<OutPoint, Option<u32>>,
}

impl<'b> BlockLocalUtxoView<'b> {
    fn new(
        base: Arc<ResolvedUtxoView>,
        txdata: &'b [Tx],
        height: u32,
        overlay_capacity: usize,
    ) -> Self {
        Self {
            base,
            txdata,
            height,
            overlay: HashMap::with_capacity(overlay_capacity),
        }
    }

    fn lookup_meta(&self, outpoint: &OutPoint) -> Option<LiveOutputMeta> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let derived_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            self.txdata.get(derived_index)?.outputs.get(vout)?;
            return Some(LiveOutputMeta {
                coinbase: derived_index == 0,
                height: self.height,
            });
        }
        self.base.lookup_meta(outpoint)
    }

    fn spend_inputs(&mut self, tx: &Tx) {
        for input in &tx.inputs {
            self.overlay.insert(input.previous_output, None);
        }
    }

    fn add_outputs(
        &mut self,
        derived_index: u32,
        txid: Txid,
        output_count: usize,
    ) -> core::result::Result<(), ApplyError> {
        for vout in 0..output_count {
            let vout = u32::try_from(vout).map_err(|_| ApplyError::HeightOverflow(self.height))?;
            self.overlay
                .insert(OutPoint::new(txid, vout), Some(derived_index));
        }
        Ok(())
    }
}

impl UtxoView for BlockLocalUtxoView<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let derived_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            return self.txdata.get(derived_index)?.outputs.get(vout).cloned();
        }
        self.base.lookup(outpoint)
    }
}

#[cfg(test)]
#[path = "../tests/unit/test_fixtures.rs"]
mod test_fixtures;

#[cfg(test)]
#[path = "../tests/unit/apply/admission_tests.rs"]
mod admission_tests;

#[cfg(test)]
#[path = "../tests/unit/apply/chain_tx_count_tests.rs"]
mod chain_tx_count_tests;

#[cfg(test)]
#[path = "../tests/unit/apply/persistence_tests.rs"]
mod persistence_tests;

#[cfg(test)]
#[path = "../tests/unit/checkpoint_debt_tests.rs"]
mod checkpoint_debt_tests;
