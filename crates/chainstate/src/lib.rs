//! Authoritative chainstate mutation: connect, disconnect, and window apply.

pub use crate::error::{ApplyError, DisconnectError};
use arc_swap::ArcSwapOption;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_chain::TransitionDomain;
use bitcoin_rs_chain::{
    BlockTree, BlockTreeReader, ChainError, ChainTxCount, TipReader, TipSnapshot,
    TransitionAuthority, TransitionAuthorityGuard,
};
use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_primitives::{Block, Network, OutPoint, Tx, TxOut, Txid};
use bitcoin_rs_primitives::{Hash256, Header};
use bitcoin_rs_storage::DurableHeadStore;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_storage::InMemoryUndoStore;
pub use bitcoin_rs_storage::KvUndoStore;
pub use bitcoin_rs_storage::UndoStore;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_utxo::contract::{SpentOutputLookup, is_coinbase_tx};
use bitcoin_rs_utxo::{UtxoCoin, UtxoSet};
use connect::{apply_block_admitted, apply_committed_block_admitted};
use disconnect::disconnect_block_admitted;
pub use durable::recover_disconnect_marker;
use hashbrown::HashMap;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use scratch::SameBlockSpentSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use window::{PublishMode, apply_window_admitted};

mod connect;
mod disconnect;
mod durable;
mod prepare;
mod publication;
mod window;
pub use prepare::bytes_are_block;
pub use window::classify_apply_error;

pub mod assumeutxo;
pub use assumeutxo::{
    ActiveChainstateSummary, AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager,
    ChainstateRole, ChainstatesSummary, HistoricalChainstateSummary,
};

mod checkpoint;
use checkpoint::CheckpointError;
mod assumeutxo_snapshot;
/// Typed chainstate mutation failures.
mod error;
pub mod events;
mod journal;
mod maintenance;
pub mod recovery;
pub mod reorg;
mod scratch;

/// Historical script-verification policy owned by authoritative chainstate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationMode {
    /// Every script executes; assume-valid settings are ignored.
    Full,
    /// Skip scripts through a pinned assume-valid anchor.
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
#[derive(Clone, Copy, Debug)]
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
    closed: Arc<AtomicBool>,
    barrier: RwLock<()>,
}

impl ApplyAdmission {
    pub(crate) fn new() -> Self {
        Self {
            closed: Arc::new(AtomicBool::new(false)),
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
    pub(crate) fn close_permanently(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// Admission plus the chain-transition lock.
struct TransitionGuard<'a> {
    _transition: TransitionAuthorityGuard<'a>,
    _admission: RwLockReadGuard<'a, ()>,
}

fn begin_chain_transition<'a>(
    admission: &'a ApplyAdmission,
    chain_transition: &'a TransitionAuthority,
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
pub struct PruneAuthority {
    admission: Arc<ApplyAdmission>,
    chain_transition: TransitionAuthority,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    role: Arc<RwLock<ChainstateRole>>,
}

impl PruneAuthority {
    /// Acquires exclusive chain-mutation authority for one pruning pass.
    pub fn begin(&self) -> core::result::Result<PruneGuard<'_>, ApplyError> {
        let transition = begin_chain_transition(&self.admission, &self.chain_transition)?;
        // Pruning removes a prefix, so a requested height above the snapshot
        // base still removes the history needed to validate that base. Check
        // under the same transition lock that publishes role changes.
        let role = *self.role.read();
        if let Some(base_height) = role.base_height() {
            return Err(ApplyError::PruneDuringHistoricalValidation { base_height });
        }
        Ok(PruneGuard {
            _transition: transition,
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
pub(crate) struct AssumeValidGate {
    /// Pinned `(height, hash)` anchor, or `None` when no pin applies.
    anchor: Option<(u32, Hash256)>,
    /// Whether the active chain is currently verified to contain the anchor.
    trusted: AtomicBool,
    /// Whether the diverged-chain warning has already been emitted.
    warned: AtomicBool,
}

impl AssumeValidGate {
    /// Builds the gate for `network` gated on `configured_height`.
    #[must_use]
    fn new(network: Network, configured_height: u32) -> Self {
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
    #[cfg(test)]
    #[must_use]
    fn with_anchor(anchor: Option<(u32, Hash256)>) -> Self {
        Self {
            trusted: AtomicBool::new(anchor.is_none()),
            warned: AtomicBool::new(false),
            anchor,
        }
    }

    /// Returns whether historical script verification may currently be skipped.
    #[must_use]
    fn trusted(&self) -> bool {
        self.trusted.load(Ordering::Relaxed)
    }

    /// Re-evaluates trust against `tree`'s active chain.
    fn evaluate(&self, tree: &BlockTree) {
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
#[derive(Clone, Copy, Debug)]
pub(crate) enum BlockProvenance {
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
#[derive(Debug)]
pub struct DisconnectOutcome {
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
    Committed(Box<ConnectOutcome>),
    /// See `ARCH-07` in `docs/contracts/architecture.md`.
    Proposed,
}

/// Coherent read of the applied tip and its transaction count.
#[derive(Debug)]
pub struct ChainstateSnapshot {
    /// Authoritative applied tip, if any block has committed.
    pub applied: Option<TipSnapshot>,
    /// Cumulative transaction count of the applied chain.
    pub chain_tx_count: ChainTxCount,
}

/// Facts returned after Chainstate admits one contiguous header batch.
#[derive(Debug)]
pub struct HeaderAdmissionOutcome {
    /// Number of accepted inputs, including idempotent duplicates.
    pub accepted: usize,
    /// Hash of the final input header, when the batch was non-empty.
    pub announced_tip: Option<Hash256>,
    /// Height of `announced_tip` on the active header chain, when resolvable.
    pub active_height: Option<i32>,
}

/// Failure to admit a batch at the authoritative header-tree boundary.
#[derive(Debug, thiserror::Error)]
pub enum HeaderAdmissionError {
    /// Mutation admission was closed before header validation began.
    #[error("header admission refused: {0}")]
    Refused(ApplyError),
    /// Header validation rejected the batch.
    #[error(transparent)]
    Rejected(ChainError),
}

/// In-process facade for authoritative applied-chain mutation.
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
    pub(crate) chain_transition: TransitionAuthority,
    pub(crate) assume_valid_height: u32,
    pub(crate) assume_valid_gate: Arc<AssumeValidGate>,
    pub(crate) validation_mode: ValidationMode,
    /// The one resolved script-verification engine selection. Owned by node
    /// configuration (`validation.engine`); this handle passes it to the
    /// engine-specific seams of the shared block/tx validation pipeline.
    pub(crate) validation_engine: bitcoin_rs_consensus::ValidationEngine,
    /// Chainstate-journal writer, when the journal is enabled (issue #230).
    pub(crate) journal:
        Arc<RwLock<Option<bitcoin_rs_storage::chainstate_journal::SharedJournalWriter>>>,
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
    pub(crate) retention: bitcoin_rs_storage::MandatoryRetention,
    /// Process-wide initial-block-download latch owned by the chainstate.
    ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
    /// Operational role of this chainstate instance.
    pub(crate) role: Arc<RwLock<ChainstateRole>>,
}

/// Construction inputs for one authoritative chainstate service.
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
    /// The mutation role over the transition domain composition minted.
    pub chain_transition: TransitionAuthority,
    /// Highest assume-valid height.
    pub assume_valid_height: u32,
    /// Historical script-verification policy.
    pub validation_mode: ValidationMode,
    /// The one resolved script-verification engine selection.
    pub validation_engine: bitcoin_rs_consensus::ValidationEngine,
    /// Chainstate journal writer, when journal recovery is enabled.
    pub journal: Option<bitcoin_rs_storage::chainstate_journal::SharedJournalWriter>,
    /// Whether connects retain raw transaction bytes for node-owned consumers.
    pub capture_rawtx: bool,
    /// Whether connects retain canonical block bytes for node-owned consumers.
    pub capture_block_bytes: bool,
    /// The mandatory retained-history capability storage/pruning granted.
    pub retention: bitcoin_rs_storage::MandatoryRetention,
    /// Operational role of this chainstate instance.
    pub role: ChainstateRole,
}

/// Held while new chain mutations are blocked.
pub struct AdmissionGuard<'a> {
    _guard: RwLockWriteGuard<'a, ()>,
}

/// One admitted chain mutation.
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

    /// Disconnects `block`, which must be the current applied tip.
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
    #[expect(clippy::result_large_err)]
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
        let ibd = Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
            TipReader::new(Arc::clone(&parts.applied_tip)),
            BlockTreeReader::new(Arc::clone(&parts.block_tree)),
        ));
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
            chain_transition: parts.chain_transition,
            assume_valid_height: parts.assume_valid_height,
            assume_valid_gate,
            validation_mode: parts.validation_mode,
            validation_engine: parts.validation_engine,
            journal: Arc::new(RwLock::new(parts.journal)),
            checkpoint_publisher: None,
            capture_rawtx: parts.capture_rawtx,
            capture_block_bytes: parts.capture_block_bytes,
            retention: parts.retention,
            ibd,
            role: Arc::new(RwLock::new(parts.role)),
        }
    }

    /// Returns the operational role of this chainstate instance.
    #[must_use]
    pub fn role(&self) -> ChainstateRole {
        *self.role.read()
    }

    /// Sets the operational role of this chainstate instance.
    pub(crate) fn set_role(&self, role: ChainstateRole) {
        let _transition = self.chain_transition.lock();
        *self.role.write() = role;
    }

    /// Installs a verified UTXO snapshot and initializes the applied tip and chain tx count
    /// at the snapshot base height and block hash.
    ///
    /// # Errors
    ///
    /// Refuses missing or inconsistent base headers, closed admission, or a
    /// lifecycle record that cannot be persisted.
    fn install_snapshot(
        &self,
        snapshot_set: bitcoin_rs_utxo::UtxoSet,
        mut stats: bitcoin_rs_utxo::stats::CoinStats,
        pinned: &bitcoin_rs_primitives::AssumeUtxoData,
        persist: impl FnOnce(&BlockTree, &TipSnapshot) -> Result<(), AssumeUtxoError>,
    ) -> Result<(), AssumeUtxoError> {
        let _guard = self.admission.enter()?;
        let _transition = self.chain_transition.lock();
        let mut tree = self.block_tree.write();
        let node_id = tree
            .lookup(pinned.block_hash)
            .ok_or(AssumeUtxoError::SnapshotHeaderMissing(pinned.block_hash))?;
        let node = tree.node(node_id).map_err(ApplyError::from)?;
        if node.height != pinned.height {
            return Err(AssumeUtxoError::SnapshotHeaderHeightMismatch {
                expected: pinned.height,
                found: node.height,
            });
        }
        let tip_snapshot = TipSnapshot {
            tip_id: node_id,
            height: pinned.height,
            chainwork: node.chainwork,
            hash: pinned.block_hash,
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(pinned.chain_tx_count),
        };
        // All refusals precede publication. The transition stays held across the
        // lifecycle record and the whole coin/statistics/tip installation.
        persist(&tree, &tip_snapshot).inspect_err(|error| {
            if !matches!(error, AssumeUtxoError::ActivationBehindTip) {
                self.fail_closed_for_recovery();
            }
        })?;
        // This journal extends the old checkpoint, not the new snapshot root.
        // Snapshot recovery uses its immutable anchor and the certified suffix.
        *self.journal.write() = None;
        tree.restore_chain_tx_count(node_id, tip_snapshot.chain_tx_count)
            .map_err(ApplyError::from)
            .inspect_err(|_| self.fail_closed_for_recovery())?;
        self.utxo.replace_from(snapshot_set);
        stats.tx_count = pinned.chain_tx_count;
        self.coin_stats.reset(stats);
        crate::publication::publish_applied(
            self,
            &tip_snapshot,
            crate::events::HintKind::Connected,
        );
        *self.role.write() = ChainstateRole::AssumedActive {
            base_height: pinned.height,
            base_hash: pinned.block_hash,
        };

        Ok(())
    }

    /// Constructs an isolated historical chainstate from this chainstate.
    /// The historical chainstate has an independent UTXO set, detached events,
    /// separate transient undo/head stores, no body writer or active journal,
    /// and no external follower side-effects. Reopening replays from genesis.
    #[must_use]
    fn create_historical_counterpart(
        &self,
        base_height: u32,
        base_hash: Hash256,
        undo: Arc<bitcoin_rs_storage::InMemoryUndoStore>,
    ) -> Arc<Self> {
        let mut historical_utxo = bitcoin_rs_utxo::UtxoSet::new();
        let historical_coin_stats = Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::new(),
        ));
        historical_utxo.track_coin_stats((*historical_coin_stats).clone());

        let transition = bitcoin_rs_chain::TransitionDomain::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        let chain_tip = Arc::new(arc_swap::ArcSwapOption::empty());

        let parts = ChainstateParts {
            network: self.network,
            chain_tip,
            applied_tip,
            block_tree: Arc::clone(&self.block_tree),
            utxo: Arc::new(historical_utxo),
            coin_stats: historical_coin_stats,
            chain_events: Arc::new(crate::events::ChainEventPublisher::detached(
                self.chain_events.epoch(),
            )),
            block_body_store: None,
            undo_store: undo,
            durable_head: Arc::new(bitcoin_rs_storage::InMemoryDurableHeadStore::new()),
            shutdown,
            chain_transition: transition.authority(),
            assume_valid_height: 0,
            validation_mode: ValidationMode::Full,
            validation_engine: self.validation_engine,
            journal: None,
            capture_rawtx: false,
            capture_block_bytes: false,
            retention: self.retention.clone(),
            role: ChainstateRole::Historical {
                base_height,
                base_hash,
            },
        };
        Arc::new(Self::from_parts(parts))
    }

    /// Permanently closes chain mutation and asks the process to shut down.
    pub fn fail_closed_for_recovery(&self) {
        self.admission.close_permanently();
        self.shutdown.store(true, Ordering::Release);
    }

    /// Reports whether chain mutation admission is closed.
    #[must_use]
    pub fn is_closed_for_recovery(&self) -> bool {
        self.admission.closed.load(Ordering::Acquire)
    }

    /// Shares the admission-closed latch with the read-only surfaces (RPC
    /// and P2P), so every surface answers from one owner.
    #[must_use]
    pub fn closed_for_recovery_reader(&self) -> bitcoin_rs_chain::LatchReader {
        bitcoin_rs_chain::LatchReader::new(Arc::clone(&self.admission.closed))
    }

    /// Permanently closes mutation admission and waits for in-flight mutations.
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

    /// Returns a read-only best-work header-tip capability.
    #[must_use]
    pub fn header_tip_reader(&self) -> TipReader {
        TipReader::new(Arc::clone(&self.chain_tip))
    }

    /// Returns a read-only authoritative applied-tip capability.
    #[must_use]
    pub fn applied_tip_reader(&self) -> TipReader {
        TipReader::new(Arc::clone(&self.applied_tip))
    }

    /// Publishes the genesis connect outcome as the best-work header tip.
    pub fn publish_genesis_tip(&self, tip: TipSnapshot) {
        let tip = Arc::new(tip);
        self.chain_tip
            .rcu(|current| current.clone().or_else(|| Some(Arc::clone(&tip))));
    }

    /// Loads the current best-work header tip.
    #[must_use]
    pub fn header_tip(&self) -> Option<Arc<TipSnapshot>> {
        self.chain_tip.load_full()
    }

    /// Loads the current authoritative applied tip.
    #[must_use]
    pub fn applied_tip_snapshot(&self) -> Option<Arc<TipSnapshot>> {
        self.applied_tip.load_full()
    }

    /// Returns a cloneable read-only block-tree capability.
    #[must_use]
    pub fn block_tree_reader(&self) -> BlockTreeReader {
        BlockTreeReader::new(Arc::clone(&self.block_tree))
    }

    /// Fixture-only block-tree Arc clone. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn block_tree_handle(&self) -> Arc<RwLock<BlockTree>> {
        Arc::clone(&self.block_tree)
    }

    /// Returns the chainstate-owned initial-block-download latch.
    #[must_use]
    pub fn ibd_latch(&self) -> Arc<bitcoin_rs_chain::InitialBlockDownload> {
        Arc::clone(&self.ibd)
    }

    /// Returns the chainstate-owned synchronization progress, over this
    /// chainstate's tips, block tree, and initial-block-download latch.
    #[must_use]
    pub fn chain_progress_reader(&self) -> bitcoin_rs_chain::ChainProgressReader {
        bitcoin_rs_chain::ChainProgressReader::new(
            self.header_tip_reader(),
            self.applied_tip_reader(),
            self.block_tree_reader(),
            self.ibd_latch(),
        )
    }

    /// Fixture-only writable header-tip cell. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn chain_tip(&self) -> &ArcSwapOption<TipSnapshot> {
        &self.chain_tip
    }

    /// Fixture-only writable applied-tip cell. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn applied_tip(&self) -> &ArcSwapOption<TipSnapshot> {
        &self.applied_tip
    }

    /// Fixture-only writable block tree. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn block_tree(&self) -> &RwLock<BlockTree> {
        &self.block_tree
    }

    /// Fixture-only access to the authoritative UTXO set. Not present in
    /// production builds.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    /// Fixture-only writable UTXO handle. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn utxo_handle(&self) -> Arc<UtxoSet> {
        Arc::clone(&self.utxo)
    }

    /// Returns the UTXO owner's read-only lookup capability.
    #[must_use]
    pub fn utxo_reader(&self) -> bitcoin_rs_utxo::UtxoReader {
        bitcoin_rs_utxo::UtxoReader::new(Arc::clone(&self.utxo))
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

    /// Admits headers and publishes the best-work header tip under Chainstate's
    /// transition authority.
    pub fn admit_headers(
        &self,
        headers: &[Header],
    ) -> core::result::Result<HeaderAdmissionOutcome, HeaderAdmissionError> {
        let _transition = self
            .lock_transition()
            .map_err(HeaderAdmissionError::Refused)?;
        let mut tree = self.block_tree.write();
        let acceptance = bitcoin_rs_chain::accept_headers(
            &mut tree,
            headers,
            self.network,
            bitcoin_rs_chain::current_unix_seconds(),
            bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
        );
        // A rejected batch can still have inserted a valid prefix and moved
        // the tip; the gate follows whatever active chain exists now.
        self.assume_valid_gate.evaluate(&tree);
        let node_ids = acceptance.map_err(HeaderAdmissionError::Rejected)?;
        let announced_tip = node_ids
            .last()
            .and_then(|id| tree.node(*id).ok())
            .map(|node| node.hash);
        let active_height = tree
            .tip()
            .zip(announced_tip)
            .and_then(|(active_tip, hash)| {
                tree.active_height_of(active_tip.tip_id, hash)
                    .and_then(|height| i32::try_from(height).ok())
            });
        Ok(HeaderAdmissionOutcome {
            accepted: node_ids.len(),
            announced_tip,
            active_height,
        })
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
    pub(crate) fn reevaluate_assume_valid_with(&self, tree: &BlockTree) {
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

    /// Returns pruning authority coupled to this chainstate's transition role.
    pub fn prune_authority(&self) -> PruneAuthority {
        PruneAuthority {
            admission: Arc::clone(&self.admission),
            chain_transition: self.chain_transition.clone(),
            applied_tip: Arc::clone(&self.applied_tip),
            role: Arc::clone(&self.role),
        }
    }

    /// Admission plus the exclusive transition lock, without mempool generation.
    pub fn lock_transition(&self) -> core::result::Result<TransitionLock<'_>, ApplyError> {
        let guard = begin_chain_transition(&self.admission, &self.chain_transition)?;
        Ok(TransitionLock {
            chainstate: self,
            guard,
        })
    }

    /// Begins an admitted authoritative-chain mutation.
    pub fn begin_transition(&self) -> core::result::Result<ChainTransition<'_>, ApplyError> {
        Ok(self.lock_transition()?.into_transition())
    }

    /// Builds a synthetic, in-memory chainstate for fixtures.
    #[cfg(any(test, feature = "test-seam"))]
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
        Self::from_parts(ChainstateParts {
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
            shutdown: Arc::new(AtomicBool::new(false)),
            chain_transition: TransitionDomain::new().authority(),
            assume_valid_height: 0,
            validation_mode: ValidationMode::AssumeValid,
            validation_engine: bitcoin_rs_consensus::ValidationEngine::Native,
            journal: None,
            capture_rawtx: false,
            capture_block_bytes: false,
            retention: bitcoin_rs_storage::MandatoryRetention::in_memory(),
            role: ChainstateRole::Ordinary,
        })
    }

    /// Copies the published applied tip and its transaction count.
    #[must_use]
    pub fn snapshot(&self) -> ChainstateSnapshot {
        let applied = self.applied_tip.load_full().as_deref().cloned();
        let chain_tx_count = applied
            .as_ref()
            .map_or(ChainTxCount::UNKNOWN, |tip| tip.chain_tx_count);
        ChainstateSnapshot {
            applied,
            chain_tx_count,
        }
    }

    /// Publishes a checkpoint to settle rolled-back disconnect debt.
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

    /// Publishes the recovery checkpoint of the disconnect-marker recovery
    /// transaction.
    pub(crate) fn publish_recovery_checkpoint(&self) -> core::result::Result<(), CheckpointError> {
        let invalid = |reason: &str| {
            CheckpointError::Store(bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(
                reason.to_owned(),
            ))
        };
        let Some(publisher) = &self.checkpoint_publisher else {
            return Err(invalid(
                "disconnect recovery requires a configured checkpoint publisher",
            ));
        };
        match publisher.publish_recovered()? {
            crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => {
                Err(invalid("recovery found no applied tip to checkpoint"))
            }
            crate::checkpoint::CheckpointWrite::Published { .. } => Ok(()),
        }
    }

    /// Publishes a marker-preserving checkpoint to relieve journal pressure
    /// while boot replay is still below the durable head.
    ///
    /// The caller must release its transition first because publication takes
    /// the exclusive apply-admission barrier. Success compacts the journal but
    /// deliberately leaves recovery markers armed.
    pub(crate) fn publish_recovery_progress_checkpoint(
        &self,
    ) -> core::result::Result<(), CheckpointError> {
        let invalid = |reason: &str| {
            CheckpointError::Store(bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(
                reason.to_owned(),
            ))
        };
        let Some(publisher) = &self.checkpoint_publisher else {
            return Err(invalid(
                "journal backpressure recovery requires a configured checkpoint publisher",
            ));
        };
        match publisher.publish_recovery_progress()? {
            crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => Err(invalid(
                "journal backpressure recovery found no applied tip to checkpoint",
            )),
            crate::checkpoint::CheckpointWrite::Published { .. } => Ok(()),
        }
    }

    /// Admits a transition, connects `block`, then releases the transition lock.
    #[cfg(any(test, feature = "test-seam"))]
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

    /// Admits a transition, disconnects `block`, then releases the transition
    /// lock. Refusal and fatal-recovery semantics are defined by
    /// [`ChainTransition::disconnect`].
    #[cfg(any(test, feature = "test-seam"))]
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
    #[expect(clippy::result_large_err)]
    #[cfg(any(test, feature = "test-seam"))]
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
        let result = transition.connect_window(blocks, serialized);
        drop(transition);
        result
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
#[derive(Debug)]
struct DisconnectPlan {
    /// Parent tip with the cumulative count its tree node carries, which the
    /// disconnect commits and publishes unchanged.
    parent_tip: TipSnapshot,
    parent_prev_hash: Hash256,
    undo: bitcoin_rs_utxo::contract::UndoBatch,
    height: u32,
    tx_count_delta: u64,
}

/// How many consecutive blocks share one script-verification dispatch.
const SCRIPT_BATCH_WINDOW: usize = 1024;

/// How many bytes of block data one window may hold.
const SCRIPT_BATCH_MAX_BYTES: usize = 64 << 20;

/// Returns how many of `sizes` fit in one window.
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
    /// held, and the published tip and assume-valid gate were re-synchronized
    /// with the mutated tree; `BodyMutated` discards only the delivered body;
    /// `Operational` failures poisoned nothing; `Fatal` means mutation or
    /// durable-head state may be torn, so recovery must run before another
    /// mutation.
    pub disposition: WindowApplyDisposition,
    /// Hashes marked invalid under the held transition when `disposition` is
    /// [`WindowApplyDisposition::Permanent`]: the failed block and every
    /// descendant, in deterministic slab order. Empty otherwise, including a
    /// header that was never in the tree.
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

/// Whether a window failure invalidates the header branch, only its delivered
/// body, or neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowApplyDisposition {
    /// The failed block and its descendants can never be valid. Their header
    /// subtrees were invalidated under the window's chain transition, the
    /// best valid tip was republished from the mutated tree, and the
    /// assume-valid gate was re-evaluated; purge every returned hash from
    /// staged/download state without retrying.
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
    /// re-establish authoritative chainstate first. Nothing about the blocks
    /// is necessarily invalid, so no header subtree is purged — except a
    /// permanent failure whose subtree could not be marked, which escalates
    /// here because the tree may be partially marked.
    Fatal,
}

/// Chain context that determines the ordered transaction checks for one block.
#[derive(Eq, PartialEq)]
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
struct BlockValidationProof<'b> {
    prepared: PreparedApply<'b>,
    context: BlockValidationContext,
}

/// Prepared state returned by a successful window attempt.
enum ProvenApply<'b> {
    Proven(BlockValidationProof<'b>),
    AssumeValidSkipped(PreparedApply<'b>),
}

/// Everything a block's application needs that depends only on the block and
/// the outputs it spends, not on the chain state the commit will mutate.
struct PreparedApply<'b> {
    parsed: bitcoin_rs_consensus::kernel::BlockParse,
    /// Parse-once transaction state: identities computed once in
    /// [`parse_block_for_apply`], witness IDs on demand, and the prevout
    /// matrix installed once right before script verification.
    view: bitcoin_rs_consensus::BlockView<'b>,
    tx_plan: BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
}

/// Parses a block and resolves the outputs it spends.
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

#[expect(clippy::struct_excessive_bools)]
struct BlockTxPlan {
    only_coinbase: bool,
    needs_local_utxo_overlay: bool,
    overlay_capacity: usize,
    has_witness: bool,
    has_bip68_sequence_locks: bool,
    created_output_count: usize,
    spent_input_count: usize,
    same_block_spent: Option<SameBlockSpentSet>,
    same_block_spent_input_count: usize,
}

impl BlockTxPlan {
    /// Outpoints this block both creates and spends, empty when it has none.
    fn same_block_spent_set(&self) -> &SameBlockSpentSet {
        static NONE: std::sync::LazyLock<SameBlockSpentSet> =
            std::sync::LazyLock::new(SameBlockSpentSet::new);
        self.same_block_spent.as_ref().unwrap_or(&NONE)
    }
}

/// Creation metadata of a spent prevout: what maturity and sequence-lock
/// checks read, without materializing the output payload.
struct PrevoutMeta {
    coinbase: bool,
    height: u32,
}

impl PrevoutMeta {
    const fn of(coin: &UtxoCoin) -> Self {
        Self {
            coinbase: coin.coinbase,
            height: coin.height,
        }
    }
}

/// All external (already-committed) prevouts for one block, resolved in a single
/// parallel pass so `script_verify`, `coinbase_maturity`, and `bip68` reuse one
/// lookup table instead of hitting the `UtxoSet` repeatedly.
struct ResolvedUtxoView {
    external: HashMap<OutPoint, UtxoCoin>,
}

impl ResolvedUtxoView {
    /// Resolves a block's external prevouts from any source of live outputs.
    fn resolve<S: bitcoin_rs_utxo::contract::OutputSource + ?Sized>(
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
    fn entry(&self, outpoint: &OutPoint) -> Option<&UtxoCoin> {
        self.external.get(outpoint)
    }

    fn lookup_meta(&self, outpoint: &OutPoint) -> Option<PrevoutMeta> {
        self.external.get(outpoint).map(PrevoutMeta::of)
    }
}

impl UtxoView for ResolvedUtxoView {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.lookup(outpoint)
    }
}

impl SpentOutputLookup for ResolvedUtxoView {
    fn entry(&self, outpoint: &OutPoint) -> Option<&UtxoCoin> {
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

    fn lookup_meta(&self, outpoint: &OutPoint) -> Option<PrevoutMeta> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let derived_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            self.txdata.get(derived_index)?.outputs.get(vout)?;
            return Some(PrevoutMeta {
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
            let vout = u32::try_from(vout).map_err(|_| ApplyError::VoutOverflow { txid })?;
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
#[path = "../tests/unit/apply/observability_tests.rs"]
mod observability_tests;

#[cfg(test)]
#[path = "../tests/unit/apply/window_disposition_tests.rs"]
mod window_disposition_tests;

#[cfg(test)]
#[path = "../tests/unit/apply/window_tx_count_tests.rs"]
mod window_tx_count_tests;

#[cfg(test)]
#[path = "../tests/unit/apply/window_invalidation_tests.rs"]
mod window_invalidation_tests;

#[cfg(test)]
#[path = "../tests/unit/checkpoint_debt_tests.rs"]
mod checkpoint_debt_tests;

#[cfg(test)]
#[path = "../tests/unit/recovery_marker_order_tests.rs"]
mod recovery_marker_order_tests;
