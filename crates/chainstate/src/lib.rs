//! Authoritative chainstate mutation: connect, disconnect, and window apply.

pub use crate::error::{ApplyError, DisconnectError};
use arc_swap::ArcSwapOption;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_chain::TransitionDomain;
use bitcoin_rs_chain::{
    BlockTree, BlockTreeReader, ChainError, ChainTxCount, TipReader, TipSnapshot,
    TransitionAuthority, TransitionAuthorityGuard,
};
use bitcoin_rs_consensus::ScriptExecutionCache;
use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_primitives::{Block, BlockPayload, Network, OutPoint, Tx, TxOut, Txid};
use bitcoin_rs_primitives::{Hash256, Header};
use bitcoin_rs_storage::DurableHeadStore;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_storage::InMemoryUndoStore;
pub use bitcoin_rs_storage::KvUndoStore;
pub use bitcoin_rs_storage::UndoStore;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_utxo::contract::SpentOutputLookup;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_utxo::{UtxoCoin, UtxoSet};
use connect::{apply_block_admitted, apply_committed_block_admitted};
use disconnect::disconnect_block_admitted;
pub use durable::recover_disconnect_marker;
use hashbrown::HashMap;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use window::{PublishMode, apply_window_admitted};

mod block_spends;
mod connect;
mod disconnect;
mod durable;
mod prepare;
mod tip_wait;
mod window;
pub use prepare::bytes_are_block;
pub use window::classify_apply_error;

pub mod assumeutxo;
pub use assumeutxo::{
    ActiveChainstateSummary, AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager,
    ChainstateRole, ChainstatesReport, ChainstatesSummary, HistoricalChainstateSummary,
    HistoricalCheckpointRef,
};

mod checkpoint;
use checkpoint::CheckpointError;
mod assumeutxo_snapshot;
mod error;
pub mod events;
mod journal;
mod maintenance;
pub mod recovery;
pub mod reorg;
pub mod verify;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationMode {
    Full,
    AssumeValid,
    Fast,
}

impl ValidationMode {
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

#[derive(Clone, Copy, Debug)]
pub struct ChainstateJournalConfig {
    pub enabled: bool,
    pub blocks: u32,
    pub seconds: u64,
    pub rotate_mib: u64,
    pub max_journal_mib: u64,
    pub max_lag_blocks: u32,
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

pub struct JournalBootstrap {
    pub open_existing: bool,
    pub base_generation: u64,
    pub height: u32,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub chain_tx_count: u64,
    pub config: ChainstateJournalConfig,
}

type SameBlockSpentSet = hashbrown::HashSet<OutPoint>;

fn tx_count_delta_for(block: &Block) -> u64 {
    u64::try_from(block.txs.len()).unwrap_or(u64::MAX)
}

const LOCAL_OVERLAY_TXID_SET_THRESHOLD: usize = 8;

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

    pub(crate) fn pause(&self) -> RwLockWriteGuard<'_, ()> {
        self.barrier.write()
    }

    pub(crate) fn close_permanently(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

struct TransitionGuard<'a> {
    _transition: TransitionAuthorityGuard<'a>,
    _admission: RwLockReadGuard<'a, ()>,
    started: quanta::Instant,
}

impl Drop for TransitionGuard<'_> {
    fn drop(&mut self) {
        let transition_held_us = self.started.elapsed().as_micros();
        tracing::debug!(transition_held_us, "chainstate: transition held");
    }
}

fn begin_chain_transition<'a>(
    admission: &'a ApplyAdmission,
    chain_transition: &'a TransitionAuthority,
) -> core::result::Result<TransitionGuard<'a>, ApplyError> {
    let admission_guard = admission.enter()?;
    let transition = chain_transition.lock();
    let started = quanta::Instant::now();
    if let Err(err) = admission.ensure_open() {
        let transition_held_us = started.elapsed().as_micros();
        tracing::debug!(transition_held_us, "chainstate: transition held");
        return Err(err);
    }
    Ok(TransitionGuard {
        _transition: transition,
        _admission: admission_guard,
        started,
    })
}

pub struct TransitionLock<'a> {
    chainstate: &'a Chainstate,
    guard: TransitionGuard<'a>,
}

impl<'a> TransitionLock<'a> {
    #[must_use]
    pub fn into_transition(self) -> ChainTransition<'a> {
        ChainTransition {
            chainstate: self.chainstate,
            _lock: self.guard,
        }
    }
}

pub struct PruneAuthority {
    admission: Arc<ApplyAdmission>,
    chain_transition: TransitionAuthority,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    role: Arc<RwLock<ChainstateRole>>,
}

impl PruneAuthority {
    pub fn begin(&self) -> core::result::Result<PruneGuard<'_>, ApplyError> {
        let transition = begin_chain_transition(&self.admission, &self.chain_transition)?;
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

pub struct PruneGuard<'a> {
    _transition: TransitionGuard<'a>,
    applied_tip: &'a ArcSwapOption<TipSnapshot>,
}

impl PruneGuard<'_> {
    #[must_use]
    pub fn applied_tip_height(&self) -> Option<u32> {
        self.applied_tip.load().as_ref().map(|tip| tip.height)
    }
}

pub(crate) struct AssumeValidGate {
    anchor: Option<(u32, Hash256)>,
    trusted: AtomicBool,
    warned: AtomicBool,
}

impl AssumeValidGate {
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

    #[cfg(test)]
    #[must_use]
    fn with_anchor(anchor: Option<(u32, Hash256)>) -> Self {
        Self {
            trusted: AtomicBool::new(anchor.is_none()),
            warned: AtomicBool::new(false),
            anchor,
        }
    }

    #[must_use]
    fn trusted(&self) -> bool {
        self.trusted.load(Ordering::Relaxed)
    }

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

#[derive(Clone, Copy, Debug)]
pub(crate) enum BlockProvenance {
    Network,
    LocalReplay,
}

#[derive(Clone, Debug)]
pub struct ConnectOutcome {
    pub tip: TipSnapshot,
    pub commit_id: u64,
    pub height: u32,
    pub hash: Hash256,
    /// Transaction ids in block order.
    pub txids: Vec<Txid>,
    pub block_bytes: bytes::Bytes,
    pub raw_txs: Option<Vec<Vec<u8>>>,
}

#[derive(Debug)]
pub struct DisconnectOutcome {
    pub hash: Hash256,
    pub restored_parents: Vec<Txid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplyIntent {
    Commit,
    Propose,
}

enum ApplyFinish {
    Committed(Box<ConnectOutcome>),
    Proposed,
}

#[derive(Debug)]
pub struct ChainstateSnapshot {
    pub applied: Option<TipSnapshot>,
    pub chain_tx_count: ChainTxCount,
}

#[derive(Debug)]
pub struct HeaderAdmissionOutcome {
    pub accepted: usize,
    pub announced_tip: Option<Hash256>,
    pub active_height: Option<i32>,
    pub demoted_tip: Option<Hash256>,
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderAdmissionError {
    #[error("header admission refused: {0}")]
    Refused(ApplyError),
    #[error(transparent)]
    Rejected(ChainError),
}

pub type PowValidBlockHook = Arc<dyn Fn(&Block, Hash256, u32) + Send + Sync>;

pub type TipStagedHook = Arc<dyn Fn(&TipSnapshot, &Block) + Send + Sync>;

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
    pub(crate) tip_notification: Arc<tip_wait::TipNotification>,
    pub(crate) chain_transition: TransitionAuthority,
    pub(crate) assume_valid_height: u32,
    pub(crate) assume_valid_gate: Arc<AssumeValidGate>,
    pub(crate) validation_mode: ValidationMode,
    pub(crate) validation_engine: bitcoin_rs_consensus::ValidationEngine,
    pub(crate) script_cache: Option<Arc<ScriptExecutionCache>>,
    pub(crate) pow_valid_block: std::sync::Arc<std::sync::OnceLock<PowValidBlockHook>>,
    pub(crate) tip_staged: std::sync::Arc<std::sync::OnceLock<TipStagedHook>>,
    pub(crate) journal:
        Arc<RwLock<Option<bitcoin_rs_storage::chainstate_journal::SharedJournalWriter>>>,
    pub(crate) checkpoint_publisher: Option<Arc<crate::checkpoint::publisher::CheckpointPublisher>>,
    pub(crate) capture_rawtx: bool,
    pub(crate) capture_block_bytes: bool,
    pub(crate) retention: bitcoin_rs_storage::MandatoryRetention,
    pub(crate) history: bitcoin_rs_storage::pruning::HistoryAccess,
    ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
    pub(crate) role: Arc<RwLock<ChainstateRole>>,
}

pub struct ChainstateParts {
    pub network: Network,
    pub block_tree: BlockTree,
    pub restored_applied_tip: Option<TipSnapshot>,
    pub utxo: Arc<UtxoSet>,
    pub coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    pub chain_events: Arc<crate::events::ChainEventPublisher>,
    pub block_body_store: Option<Arc<dyn BlockBodyStore>>,
    pub undo_store: Arc<dyn UndoStore>,
    pub durable_head: Arc<dyn DurableHeadStore>,
    pub chain_transition: TransitionAuthority,
    pub assume_valid_height: u32,
    pub validation_mode: ValidationMode,
    pub validation_engine: bitcoin_rs_consensus::ValidationEngine,
    pub script_cache: Option<Arc<ScriptExecutionCache>>,
    pub journal: Option<bitcoin_rs_storage::chainstate_journal::SharedJournalWriter>,
    pub capture_rawtx: bool,
    pub capture_block_bytes: bool,
    pub retention: bitcoin_rs_storage::MandatoryRetention,
    pub history: bitcoin_rs_storage::pruning::HistoryAccess,
    pub role: ChainstateRole,
}

pub struct AdmissionGuard<'a> {
    _guard: RwLockWriteGuard<'a, ()>,
}

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

    pub fn connect(
        &self,
        payload: &BlockPayload,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        self.settle_apply(apply_committed_block_admitted(
            self.chainstate,
            payload,
            None,
            BlockProvenance::Network,
            PublishMode::Now,
        ))
    }

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

    #[expect(clippy::result_large_err)]
    pub fn connect_window(
        &self,
        payloads: &[&BlockPayload],
    ) -> core::result::Result<Vec<ConnectOutcome>, WindowApplyError> {
        let mut result = apply_window_admitted(self.chainstate, payloads);
        if let Err(error) = &mut result
            && (error.disposition == WindowApplyDisposition::Fatal
                || classify_apply_error(&error.source) == WindowApplyDisposition::Fatal)
        {
            error.disposition = WindowApplyDisposition::Fatal;
            self.chainstate.fail_closed_for_recovery();
        }
        result
    }

    pub fn chainstate(&self) -> &'a Chainstate {
        self.chainstate
    }
}

impl Chainstate {
    fn publish_applied(&self, tip: &TipSnapshot, kind: crate::events::HintKind) {
        {
            let _gate = self.tip_notification.gate.lock();
            self.applied_tip.store(Some(Arc::new(tip.clone())));
            self.tip_notification.changed.notify_all();
        }
        self.chain_events.record(kind, tip.height, tip.hash);
    }

    #[must_use]
    pub fn from_parts(mut parts: ChainstateParts) -> Self {
        let chain_tip = parts.block_tree.tip_handle();
        let assume_valid_gate = Arc::new(AssumeValidGate::new(
            parts.network,
            parts.assume_valid_height,
        ));
        assume_valid_gate.evaluate(&parts.block_tree);
        let block_tree = Arc::new(RwLock::new(parts.block_tree));
        let applied_tip = Arc::new(ArcSwapOption::new(parts.restored_applied_tip.map(Arc::new)));
        let ibd = Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
            TipReader::new(Arc::clone(&applied_tip)),
            BlockTreeReader::new(Arc::clone(&block_tree)),
        ));
        let shutdown = Arc::new(AtomicBool::new(false));
        Self {
            network: parts.network,
            chain_tip,
            applied_tip,
            block_tree,
            utxo: parts.utxo,
            coin_stats: parts.coin_stats,
            chain_events: parts.chain_events,
            block_body_store: parts.block_body_store,
            undo_store: parts.undo_store,
            durable_head: parts.durable_head,
            admission: Arc::new(ApplyAdmission::new()),
            shutdown,
            tip_notification: Arc::default(),
            chain_transition: parts.chain_transition,
            assume_valid_height: parts.assume_valid_height,
            assume_valid_gate,
            validation_mode: parts.validation_mode,
            validation_engine: parts.validation_engine,
            script_cache: parts.script_cache,
            pow_valid_block: std::sync::Arc::new(std::sync::OnceLock::new()),
            tip_staged: std::sync::Arc::new(std::sync::OnceLock::new()),
            journal: Arc::new(RwLock::new(parts.journal)),
            checkpoint_publisher: None,
            capture_rawtx: parts.capture_rawtx,
            capture_block_bytes: parts.capture_block_bytes,
            retention: parts.retention,
            history: parts.history,
            ibd,
            role: Arc::new(RwLock::new(parts.role)),
        }
    }

    #[must_use]
    pub fn role(&self) -> ChainstateRole {
        *self.role.read()
    }

    pub(crate) fn set_role(&self, role: ChainstateRole) {
        let _transition = self.chain_transition.lock();
        *self.role.write() = role;
    }

    fn install_snapshot(
        &self,
        snapshot_set: bitcoin_rs_utxo::UtxoSet,
        mut stats: bitcoin_rs_utxo::stats::CoinStats,
        pinned: &bitcoin_rs_primitives::AssumeUtxoData,
        persist: impl FnOnce(
            &BlockTree,
            &TipSnapshot,
            Option<&bitcoin_rs_storage::DurableHead>,
        ) -> Result<(), AssumeUtxoError>,
    ) -> Result<(), AssumeUtxoError> {
        let _guard = self.admission.enter()?;
        let _transition = self.chain_transition.lock();
        let tree = self.block_tree.read();
        let tip_snapshot = Self::snapshot_base_tip(&tree, pinned)?;
        let prior = self.durable_head.load().inspect_err(|_| {
            self.fail_closed_for_recovery();
        })?;
        let applied = self.applied_tip_snapshot();
        let durable_tip = prior.map(|head| (head.tip, head.height, head.chain_tx_count));
        let applied_tip = applied
            .as_ref()
            .map(|tip| (tip.hash, tip.height, tip.chain_tx_count.to_wire()));
        if durable_tip != applied_tip {
            self.fail_closed_for_recovery();
            return Err(AssumeUtxoError::SnapshotTipNotSettled {
                durable_tip,
                applied_tip,
            });
        }
        if applied
            .as_ref()
            .is_some_and(|tip| tip_snapshot.chainwork <= tip.chainwork)
        {
            return Err(AssumeUtxoError::ActivationBehindTip);
        }
        persist(&tree, &tip_snapshot, prior.as_ref()).inspect_err(|error| {
            if !matches!(error, AssumeUtxoError::FullRevalidationRequired) {
                self.fail_closed_for_recovery();
            }
        })?;
        drop(tree);
        let mut tree = self.block_tree.write();
        *self.journal.write() = None;
        tree.restore_chain_tx_count(tip_snapshot.tip_id, tip_snapshot.chain_tx_count)
            .map_err(ApplyError::from)
            .inspect_err(|_| self.fail_closed_for_recovery())?;
        self.utxo.replace_from(snapshot_set);
        stats.tx_count = pinned.chain_tx_count;
        self.coin_stats.reset(stats);
        self.publish_applied(&tip_snapshot, crate::events::HintKind::Connected);
        *self.role.write() = ChainstateRole::AssumedActive {
            base_height: pinned.height,
            base_hash: pinned.block_hash,
        };

        Ok(())
    }

    fn snapshot_base_tip(
        tree: &BlockTree,
        pinned: &bitcoin_rs_primitives::AssumeUtxoData,
    ) -> Result<TipSnapshot, AssumeUtxoError> {
        let node_id = tree
            .lookup(pinned.block_hash)
            .ok_or(AssumeUtxoError::SnapshotHeaderMissing(pinned.block_hash))?;
        let node = tree.node(node_id).map_err(ApplyError::from)?;
        if node.status == bitcoin_rs_chain::NodeStatus::Invalid {
            return Err(
                ApplyError::from(bitcoin_rs_chain::ChainError::KnownInvalidHeader {
                    hash: pinned.block_hash,
                })
                .into(),
            );
        }
        if node.height != pinned.height {
            return Err(AssumeUtxoError::SnapshotHeaderHeightMismatch {
                expected: pinned.height,
                found: node.height,
            });
        }
        let best_header = tree.tip();
        if best_header
            .as_ref()
            .and_then(|tip| tree.node_at_height_from(tip.tip_id, pinned.height))
            != Some(node_id)
        {
            return Err(AssumeUtxoError::SnapshotBaseNotOnBestHeaderChain {
                base_hash: pinned.block_hash,
                base_height: pinned.height,
                best_header: best_header.as_ref().map(|tip| tip.hash),
            });
        }
        Ok(TipSnapshot {
            tip_id: node_id,
            height: pinned.height,
            chainwork: node.chainwork,
            hash: pinned.block_hash,
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(pinned.chain_tx_count),
        })
    }

    fn create_historical_counterpart(
        &self,
        base_height: u32,
        base_hash: Hash256,
        undo: Arc<bitcoin_rs_storage::InMemoryUndoStore>,
        restored: Option<(UtxoSet, CoinStats, TipSnapshot)>,
    ) -> Result<Arc<Self>, crate::AssumeUtxoError> {
        let (mut historical_utxo, historical_stats, restored_tip) = match restored {
            Some((utxo, stats, tip)) => (utxo, stats, Some(tip)),
            None => (UtxoSet::new(), CoinStats::new(), None),
        };
        let historical_coin_stats = Arc::new(CoinStatsListener::new(historical_stats));
        historical_utxo.track_coin_stats((*historical_coin_stats).clone());

        let historical_head = Arc::new(bitcoin_rs_storage::InMemoryDurableHeadStore::new());
        if let Some(restored_tip) = &restored_tip {
            let head = bitcoin_rs_storage::DurableHead {
                assumeutxo: crate::AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 0,
                height: restored_tip.height,
                tip: restored_tip.hash,
                chain_tx_count: restored_tip.chain_tx_count.to_wire(),
                body_extent: None,
                undo_extent: None,
            };
            bitcoin_rs_storage::DurableHeadStore::commit(
                &*historical_head,
                None,
                &head,
                &bitcoin_rs_storage::CommitRecords::default(),
            )?;
        }
        let applied_tip = Arc::new(ArcSwapOption::new(restored_tip.map(Arc::new)));
        let chain_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        let assume_valid_gate = Arc::new(AssumeValidGate::new(self.network, 0));
        let ibd = Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
            TipReader::new(Arc::clone(&applied_tip)),
            BlockTreeReader::new(Arc::clone(&self.block_tree)),
        ));

        let historical = Self {
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
            durable_head: historical_head,
            admission: Arc::new(ApplyAdmission::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            tip_notification: Arc::default(),
            chain_transition: bitcoin_rs_chain::TransitionDomain::new().authority(),
            assume_valid_height: 0,
            assume_valid_gate,
            validation_mode: ValidationMode::Full,
            validation_engine: self.validation_engine,
            script_cache: self.script_cache.clone(),
            pow_valid_block: std::sync::Arc::new(std::sync::OnceLock::new()),
            tip_staged: std::sync::Arc::new(std::sync::OnceLock::new()),
            journal: Arc::new(RwLock::new(None)),
            checkpoint_publisher: None,
            capture_rawtx: false,
            capture_block_bytes: false,
            retention: self.retention.clone(),
            history: self.history.clone(),
            ibd,
            role: Arc::new(RwLock::new(ChainstateRole::Historical {
                base_height,
                base_hash,
            })),
        };
        Ok(Arc::new(historical))
    }

    #[must_use]
    pub fn shutdown_reader(&self) -> bitcoin_rs_chain::LatchReader {
        bitcoin_rs_chain::LatchReader::new(Arc::clone(&self.shutdown))
    }

    pub fn request_shutdown(&self) {
        let _gate = self.tip_notification.gate.lock();
        self.shutdown.store(true, Ordering::Release);
        self.tip_notification.changed.notify_all();
    }

    pub fn fail_closed_for_recovery(&self) {
        self.admission.close_permanently();
        self.request_shutdown();
    }

    #[must_use]
    pub fn is_closed_for_recovery(&self) -> bool {
        self.admission.closed.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn closed_for_recovery_reader(&self) -> bitcoin_rs_chain::LatchReader {
        bitcoin_rs_chain::LatchReader::new(Arc::clone(&self.admission.closed))
    }

    #[must_use]
    pub fn close(&self) -> AdmissionGuard<'_> {
        self.request_shutdown();
        AdmissionGuard {
            _guard: self.admission.close(),
        }
    }

    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    #[must_use]
    pub fn header_tip_reader(&self) -> TipReader {
        TipReader::new(Arc::clone(&self.chain_tip))
    }

    #[must_use]
    pub fn applied_tip_reader(&self) -> TipReader {
        TipReader::new(Arc::clone(&self.applied_tip))
    }

    pub fn publish_genesis_tip(&self, tip: TipSnapshot) {
        let tip = Arc::new(tip);
        self.chain_tip
            .rcu(|current| current.clone().or_else(|| Some(Arc::clone(&tip))));
    }

    #[must_use]
    pub fn header_tip(&self) -> Option<Arc<TipSnapshot>> {
        self.chain_tip.load_full()
    }

    #[must_use]
    pub fn applied_tip_snapshot(&self) -> Option<Arc<TipSnapshot>> {
        self.applied_tip.load_full()
    }

    pub fn set_pow_valid_block(&self, hook: PowValidBlockHook) -> Result<(), PowValidBlockHook> {
        self.pow_valid_block.set(hook)
    }

    pub fn set_tip_staged(&self, hook: TipStagedHook) -> Result<(), TipStagedHook> {
        self.tip_staged.set(hook)
    }

    #[must_use]
    pub fn block_tree_reader(&self) -> BlockTreeReader {
        BlockTreeReader::new(Arc::clone(&self.block_tree))
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn block_tree_handle(&self) -> Arc<RwLock<BlockTree>> {
        Arc::clone(&self.block_tree)
    }

    #[must_use]
    pub fn ibd_latch(&self) -> Arc<bitcoin_rs_chain::InitialBlockDownload> {
        Arc::clone(&self.ibd)
    }

    #[must_use]
    pub fn chain_progress_reader(&self) -> bitcoin_rs_chain::ChainProgressReader {
        bitcoin_rs_chain::ChainProgressReader::new(
            self.header_tip_reader(),
            self.applied_tip_reader(),
            self.block_tree_reader(),
            self.ibd_latch(),
        )
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn chain_tip(&self) -> &ArcSwapOption<TipSnapshot> {
        &self.chain_tip
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn applied_tip(&self) -> &ArcSwapOption<TipSnapshot> {
        &self.applied_tip
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn block_tree(&self) -> &RwLock<BlockTree> {
        &self.block_tree
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn utxo_handle(&self) -> Arc<UtxoSet> {
        Arc::clone(&self.utxo)
    }

    #[must_use]
    pub fn utxo_reader(&self) -> bitcoin_rs_utxo::UtxoReader {
        bitcoin_rs_utxo::UtxoReader::new(Arc::clone(&self.utxo))
    }

    #[must_use]
    pub fn coin_stats_handle(&self) -> Arc<bitcoin_rs_utxo::stats::CoinStatsListener> {
        Arc::clone(&self.coin_stats)
    }

    pub fn chain_events_handle(&self) -> Arc<crate::events::ChainEventPublisher> {
        Arc::clone(&self.chain_events)
    }

    #[must_use]
    pub fn chain_snapshot(&self) -> crate::events::ChainSnapshot {
        self.chain_events.snapshot()
    }

    #[must_use]
    pub fn block_body_store(&self) -> Option<&Arc<dyn BlockBodyStore>> {
        self.block_body_store.as_ref()
    }

    #[must_use]
    pub fn block_body_store_handle(&self) -> Option<Arc<dyn BlockBodyStore>> {
        self.block_body_store.clone()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

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
        self.assume_valid_gate.evaluate(&tree);
        let bitcoin_rs_chain::AcceptHeaders { ids, demoted_tip } =
            acceptance.map_err(HeaderAdmissionError::Rejected)?;
        let announced_tip = ids
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
            accepted: ids.len(),
            announced_tip,
            active_height,
            demoted_tip,
        })
    }

    pub fn set_capture_flags(&mut self, rawtx: bool, block_bytes: bool) {
        self.capture_rawtx = rawtx;
        self.capture_block_bytes = block_bytes;
    }

    pub fn reevaluate_assume_valid(&self) {
        self.assume_valid_gate.evaluate(&self.block_tree.read());
    }

    pub(crate) fn reevaluate_assume_valid_with(&self, tree: &BlockTree) {
        self.assume_valid_gate.evaluate(tree);
    }

    pub(crate) fn publish_chain_tip(&self, tip: Option<Arc<TipSnapshot>>, tree: &BlockTree) {
        self.chain_tip.store(tip);
        self.reevaluate_assume_valid_with(tree);
    }

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

    pub fn prune_authority(&self) -> PruneAuthority {
        PruneAuthority {
            admission: Arc::clone(&self.admission),
            chain_transition: self.chain_transition.clone(),
            applied_tip: Arc::clone(&self.applied_tip),
            role: Arc::clone(&self.role),
        }
    }

    pub fn lock_transition(&self) -> core::result::Result<TransitionLock<'_>, ApplyError> {
        let guard = begin_chain_transition(&self.admission, &self.chain_transition)?;
        Ok(TransitionLock {
            chainstate: self,
            guard,
        })
    }

    pub fn begin_transition(&self) -> core::result::Result<ChainTransition<'_>, ApplyError> {
        Ok(self.lock_transition()?.into_transition())
    }

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
        let assume_valid_gate = Arc::new(AssumeValidGate::new(network, 0));
        assume_valid_gate.evaluate(&block_tree.read());
        let ibd = Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
            TipReader::new(Arc::clone(&applied_tip)),
            BlockTreeReader::new(Arc::clone(&block_tree)),
        ));
        let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
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
            tip_notification: Arc::default(),
            chain_transition: TransitionDomain::new().authority(),
            assume_valid_height: 0,
            assume_valid_gate,
            validation_mode: ValidationMode::AssumeValid,
            validation_engine: bitcoin_rs_consensus::ValidationEngine::Native,
            script_cache: None,
            pow_valid_block: std::sync::Arc::new(std::sync::OnceLock::new()),
            tip_staged: std::sync::Arc::new(std::sync::OnceLock::new()),
            journal: Arc::new(RwLock::new(None)),
            checkpoint_publisher: None,
            capture_rawtx: false,
            capture_block_bytes: false,
            retention: bitcoin_rs_storage::MandatoryRetention::new(Arc::clone(&retention)),
            history: bitcoin_rs_storage::pruning::HistoryAccess::new(
                retention,
                bitcoin_rs_storage::pruning::RetentionBudget::from_blocks(
                    bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN,
                ),
            ),
            role: Arc::new(RwLock::new(ChainstateRole::Ordinary)),
            ibd,
        }
    }

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

    pub fn settle_disconnect_debt(&self) -> core::result::Result<bool, CheckpointError> {
        match &self.checkpoint_publisher {
            Some(publisher) => publisher.settle_disconnect_debt(),
            None => Ok(false),
        }
    }

    pub fn configure_checkpointing(
        &mut self,
        data_dir: &std::path::Path,
        durable_tip_height: Arc<std::sync::atomic::AtomicU32>,
        seed_offer: Option<bitcoin_rs_utxo::SeedOfferCell>,
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
                seed_offer,
            },
        ));
        Ok(())
    }

    pub fn publish_checkpoint(&self) -> core::result::Result<Option<u64>, CheckpointError> {
        let Some(publisher) = &self.checkpoint_publisher else {
            return Ok(None);
        };
        match publisher.publish()? {
            crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => Ok(None),
            crate::checkpoint::CheckpointWrite::Published { reference } => {
                Ok(Some(reference.generation))
            }
        }
    }

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

    #[cfg(any(test, feature = "test-seam"))]
    pub fn apply_block(
        &self,
        payload: &BlockPayload,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        let transition = self.begin_transition()?;
        let result = transition.connect(payload);
        drop(transition);
        result
    }

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

    #[expect(clippy::result_large_err)]
    #[cfg(any(test, feature = "test-seam"))]
    pub fn apply_window(
        &self,
        payloads: &[&BlockPayload],
    ) -> core::result::Result<Vec<ConnectOutcome>, WindowApplyError> {
        let transition = self.begin_transition().map_err(|source| WindowApplyError {
            applied: 0,
            committed: Vec::new(),
            source,
            disposition: WindowApplyDisposition::Operational,
            invalidated: Box::default(),
        })?;
        let result = transition.connect_window(payloads);
        drop(transition);
        result
    }

    pub fn validate_block(&self, payload: &BlockPayload) -> core::result::Result<(), ApplyError> {
        let _lock = self.lock_transition()?;
        match apply_block_admitted(
            self,
            payload,
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

#[derive(Debug)]
struct DisconnectPlan {
    parent_tip: TipSnapshot,
    parent_prev_hash: Hash256,
    undo: bitcoin_rs_utxo::contract::UndoBatch,
    height: u32,
    tx_count_delta: u64,
}

const SCRIPT_BATCH_WINDOW: usize = 1024;

const SCRIPT_BATCH_MAX_BYTES: usize = 64 << 20;

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

#[derive(Debug)]
pub struct WindowApplyError {
    pub applied: usize,
    pub committed: Vec<ConnectOutcome>,
    pub source: ApplyError,
    pub disposition: WindowApplyDisposition,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowApplyDisposition {
    Permanent,
    BodyMutated,
    Operational,
    Fatal,
}

#[derive(Eq, PartialEq)]
struct BlockValidationContext {
    hash: Hash256,
    parent: Hash256,
    height: u32,
    flags: bitcoin_rs_script::VerifyFlags,
    locktime_cutoff: u32,
}

#[derive(Clone, Copy)]
struct Bip68Context<'a> {
    validation: &'a BlockValidationContext,
    median_time_past: u32,
    softfork_state: bitcoin_rs_chain::SoftforkState,
    previous_tip_id: Option<bitcoin_rs_chain::node::NodeId>,
}

struct BlockValidationProof<'b> {
    prepared: PreparedApply<'b>,
    context: BlockValidationContext,
}

enum ProvenApply<'b> {
    Proven(BlockValidationProof<'b>),
    AssumeValidSkipped(PreparedApply<'b>),
}

struct PreparedApply<'b> {
    script_source: bitcoin_rs_consensus::kernel::BlockScriptSource,
    view: bitcoin_rs_consensus::BlockView<'b>,
    tx_plan: BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
}

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
    fn same_block_spent_set(&self) -> &SameBlockSpentSet {
        static NONE: std::sync::LazyLock<SameBlockSpentSet> =
            std::sync::LazyLock::new(SameBlockSpentSet::new);
        self.same_block_spent.as_ref().unwrap_or(&NONE)
    }
}

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

struct ResolvedUtxoView {
    external: HashMap<OutPoint, UtxoCoin>,
}

impl ResolvedUtxoView {
    fn resolve<S: bitcoin_rs_utxo::contract::OutputSource + ?Sized>(
        utxo: &S,
        block: &Block,
        tx_plan: &BlockTxPlan,
    ) -> Self {
        let same_block = tx_plan.same_block_spent.as_ref();
        let candidates = block
            .txs
            .iter()
            .filter(|tx| !tx.is_coinbase())
            .flat_map(|tx| &tx.inputs)
            .filter(|input| same_block.is_none_or(|set| !set.contains(&input.previous_output)))
            .map(|input| input.previous_output);
        Self {
            external: candidates
                .filter_map(|outpoint| utxo.get_entry(&outpoint).map(|entry| (outpoint, entry)))
                .collect(),
        }
    }
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.external.get(outpoint).map(|entry| entry.txout.clone())
    }

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
mod test_fixtures;

#[cfg(test)]
mod tests;
