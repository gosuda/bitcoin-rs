#[cfg(any(test, feature = "test-seam"))]
use crate::chain::TransitionDomain;
use crate::chain::{
    BlockTree, BlockTreeReader, ChainTxCount, TipReader, TipSnapshot, TransitionAuthority,
    TransitionAuthorityGuard,
};
pub use crate::error::{ApplyError, DisconnectError};
use arc_swap::ArcSwapOption;
use assumeutxo::commit_error;
use bitcoin_rs_consensus::ScriptExecutionCache;
use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_consensus::latch::{LatchReader, LatchWriter};
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_consensus::primitives::{Block, BlockImage, Network, OutPoint, TxOut, Txid};
use bitcoin_rs_storage::DurableHeadStore;
pub use bitcoin_rs_storage::KvUndoStore;
pub use bitcoin_rs_storage::UndoStore;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::utxo::contract::SpentOutputLookup;
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_storage::utxo::{UtxoCoin, UtxoSet};
use connect::apply_block_admitted;
use disconnect::disconnect_block_admitted;
pub use durable::recover_disconnect_marker;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use window::{PublishMode, apply_window_admitted};

mod block_spends;
mod connect;
mod disconnect;
mod durable;
mod header_admission;
pub use header_admission::{HeaderAdmissionError, HeaderAdmissionOutcome, HeaderResourceError};
#[cfg(any(test, feature = "test-seam"))]
#[doc(hidden)]
pub mod fuzzing {
    use std::sync::Arc;

    use crate::chain::{BlockTree, ChainError, NodeStatus, TipSnapshot};
    use arc_swap::ArcSwapOption;
    use bitcoin_rs_consensus::primitives::{Block, BlockImage, Hash256, Header, Network};
    use bitcoin_rs_storage::StorageError;
    use bitcoin_rs_storage::block_body::BlockBodyStore;
    use bitcoin_rs_storage::utxo::UtxoReader;
    use bitcoin_rs_storage::utxo::UtxoSet;
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
    use hashbrown::HashMap;
    use parking_lot::RwLock;

    use crate::events::ChainEventPublisher;
    use crate::{ApplyError, Chainstate, DisconnectError, recover_disconnect_marker};

    #[doc(hidden)]
    #[derive(Debug, thiserror::Error)]
    pub enum FuzzError {
        #[error(transparent)]
        Apply(#[from] ApplyError),
        #[error(transparent)]
        Disconnect(#[from] DisconnectError),
        #[error(transparent)]
        Chain(#[from] ChainError),
        #[error(transparent)]
        Storage(#[from] StorageError),
        #[error(transparent)]
        Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
        #[error("no durable head is committed")]
        MissingDurableHead,
        #[error("durable head is not above the checkpoint tip")]
        HeadBelowCheckpoint,
        #[error("block header {hash} is not retained")]
        MissingHeader { hash: Hash256 },
    }

    #[doc(hidden)]
    pub struct FuzzCheckpoint {
        tip: TipSnapshot,
        coin_count: usize,
        coin_stats: CoinStats,
    }

    impl FuzzCheckpoint {
        #[must_use]
        pub fn tip(&self) -> &TipSnapshot {
            &self.tip
        }

        #[must_use]
        pub fn coin_count(&self) -> usize {
            self.coin_count
        }
    }

    #[doc(hidden)]
    pub struct FuzzChain {
        chain: Chainstate,
        store: Arc<bitcoin_rs_storage::MemoryKvStore>,
        bodies: Arc<crate::test_support::MemoryBodies>,
        headers: RwLock<HashMap<Hash256, Header>>,
        network: Network,
    }

    fn over_store(
        mut chain: Chainstate,
        store: &Arc<bitcoin_rs_storage::MemoryKvStore>,
    ) -> Chainstate {
        let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = store.clone();
        let coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
            Arc::clone(&dyn_store),
            64 * 1024 * 1024,
        ));
        coins.track_coin_stats((*chain.coin_stats).clone());
        chain.durable_head = Arc::new(bitcoin_rs_storage::KvDurableHeadStore::new(Arc::clone(
            store,
        )));
        chain.undo_store = Arc::new(bitcoin_rs_storage::KvUndoStore::new(Arc::clone(&dyn_store)));
        chain.commit_authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(
            dyn_store,
            Arc::clone(&coins),
        ));
        chain.coins = coins;
        chain
    }

    impl FuzzChain {
        pub fn new(network: Network) -> Result<Self, FuzzError> {
            let store = Arc::new(bitcoin_rs_storage::MemoryKvStore::new());
            let chain = over_store(
                Chainstate::new(
                    network,
                    Arc::new(ArcSwapOption::empty()),
                    Arc::new(ArcSwapOption::empty()),
                    Arc::new(RwLock::new(BlockTree::new())),
                    Arc::new(UtxoSet::new()),
                    Arc::new(CoinStatsListener::new(CoinStats::default())),
                    Arc::new(ChainEventPublisher::detached(0)),
                ),
                &store,
            );
            let mut this = Self {
                chain,
                store,
                bodies: Arc::new(crate::test_support::MemoryBodies::default()),
                headers: RwLock::new(HashMap::new()),
                network,
            };
            this.attach_stores();
            let genesis = network.genesis_block();
            this.apply(&genesis)?;
            Ok(this)
        }

        fn attach_stores(&mut self) {
            self.chain.block_body_store = Some(self.bodies.clone());
        }

        pub fn apply(&self, block: &Block) -> Result<(), FuzzError> {
            let payload = BlockImage::from_local(block.clone());
            self.headers
                .write()
                .insert(Hash256::from(block.block_hash()), block.header);
            let outcome = self.chain.apply_block(&payload)?;
            self.bodies
                .persist_block_body(outcome.height, outcome.hash, payload.bytes())?;
            Ok(())
        }

        pub fn disconnect(&self, block: &Block) -> Result<(), FuzzError> {
            self.chain.disconnect_block(block)?;
            Ok(())
        }

        #[must_use]
        pub fn utxo(&self) -> UtxoReader {
            self.chain.utxo_reader()
        }

        #[must_use]
        pub fn applied_tip(&self) -> Option<TipSnapshot> {
            self.chain.applied_tip_snapshot().as_deref().cloned()
        }

        pub fn durable_head(&self) -> Result<Option<(u32, Hash256)>, FuzzError> {
            Ok(self
                .chain
                .durable_head
                .load()?
                .map(|head| (head.height, head.tip)))
        }

        pub fn flush(&self) -> Result<FuzzCheckpoint, FuzzError> {
            let tip = self.applied_tip().ok_or(FuzzError::MissingDurableHead)?;
            let Some((height, hash)) = self.durable_head()? else {
                return Err(FuzzError::MissingDurableHead);
            };
            if height != tip.height || hash != tip.hash {
                return Err(FuzzError::HeadBelowCheckpoint);
            }
            let coin_count = self.utxo().with_stable_view(|view| view.len())?;
            let coin_stats = self.chain.coin_stats.snapshot();
            Ok(FuzzCheckpoint {
                tip,
                coin_count,
                coin_stats,
            })
        }

        pub fn reopen(&self, checkpoint: &FuzzCheckpoint) -> Result<Self, FuzzError> {
            let Some((head_height, head_hash)) = self.durable_head()? else {
                return Err(FuzzError::MissingDurableHead);
            };
            if head_height < checkpoint.tip.height {
                return Err(FuzzError::HeadBelowCheckpoint);
            }
            if self
                .chain
                .undo_store
                .load_disconnect_marker()?
                .is_some_and(|marker| {
                    marker.phase == bitcoin_rs_storage::DisconnectPhase::RolledBack
                })
            {
                self.chain.undo_store.retire_disconnect_marker()?;
            }
            let headers = self.header_chain(head_hash)?;
            let mut tree = BlockTree::new();
            let mut parent = None;
            for header in &headers {
                parent = Some(tree.insert_node(parent, *header, NodeStatus::HeaderValid)?);
            }
            let restored_tip_id =
                tree.lookup(checkpoint.tip.hash)
                    .ok_or(FuzzError::MissingHeader {
                        hash: checkpoint.tip.hash,
                    })?;
            tree.restore_chain_tx_count(restored_tip_id, checkpoint.tip.chain_tx_count)?;
            let chain_tip = tree.tip_handle();
            let restored_node = tree.node(restored_tip_id)?;
            let restored_tip_snapshot = TipSnapshot {
                tip_id: restored_tip_id,
                height: restored_node.height,
                chainwork: restored_node.chainwork,
                hash: restored_node.hash,
                chain_tx_count: checkpoint.tip.chain_tx_count,
            };
            let restored_tip = Arc::new(ArcSwapOption::new(Some(Arc::new(restored_tip_snapshot))));
            let mut chain = over_store(
                Chainstate::new(
                    self.network,
                    chain_tip,
                    restored_tip,
                    Arc::new(RwLock::new(tree)),
                    Arc::new(UtxoSet::new()),
                    Arc::new(CoinStatsListener::new(checkpoint.coin_stats.clone())),
                    Arc::new(ChainEventPublisher::detached(0)),
                ),
                &self.store,
            );
            chain.block_body_store = Some(self.bodies.clone());
            recover_disconnect_marker(&chain)?;
            Ok(Self {
                chain,
                store: Arc::clone(&self.store),
                bodies: Arc::clone(&self.bodies),
                headers: RwLock::new(
                    self.headers
                        .read()
                        .iter()
                        .map(|(hash, header)| (*hash, *header))
                        .collect(),
                ),
                network: self.network,
            })
        }

        fn header_chain(&self, tip: Hash256) -> Result<Vec<Header>, FuzzError> {
            let headers = self.headers.read();
            let mut chain = Vec::new();
            let mut cursor = Some(tip);
            while let Some(hash) = cursor {
                let header = headers
                    .get(&hash)
                    .copied()
                    .ok_or(FuzzError::MissingHeader { hash })?;
                cursor = if hash == self.network.genesis_block_hash() {
                    None
                } else {
                    Some(Hash256::from(header.prev_blockhash))
                };

                chain.push(header);
            }
            chain.reverse();
            Ok(chain)
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::chain::ChainTxCount;
        use crate::chain::regtest_fixture::{
            genesis_time, mined_regtest_child_at, mined_regtest_child_at_time,
        };
        use bitcoin_rs_consensus::primitives::{Hash256, Network, OutPoint};

        use super::FuzzChain;
        use crate::test_fixtures::TestResult;

        #[test]
        fn reopen_keeps_the_certified_tx_count_for_the_next_block() -> TestResult {
            let chain = FuzzChain::new(Network::Regtest)?;
            let genesis = Network::Regtest.genesis_block();
            let first = mined_regtest_child_at(genesis.block_hash(), 1)?;
            chain.apply(&first)?;
            let checkpoint = chain.flush()?;
            let reopened = chain.reopen(&checkpoint)?;
            let second = mined_regtest_child_at(first.block_hash(), 2)?;
            reopened.apply(&second)?;
            let tip = reopened.applied_tip().ok_or("missing tip")?;
            assert_eq!(tip.chain_tx_count, ChainTxCount::established(3));
            Ok(())
        }

        #[test]
        fn reopen_maps_the_checkpoint_tip_onto_the_rebuilt_tree() -> TestResult {
            let chain = FuzzChain::new(Network::Regtest)?;
            let genesis = Network::Regtest.genesis_block();
            let first = mined_regtest_child_at_time(genesis.block_hash(), genesis_time() + 1, 1)?;
            chain.apply(&first)?;
            chain.disconnect(&first)?;
            let alternative =
                mined_regtest_child_at_time(genesis.block_hash(), genesis_time() + 2, 1)?;
            chain.apply(&alternative)?;
            let checkpoint = chain.flush()?;
            let reopened = chain.reopen(&checkpoint)?;
            let tip = reopened.applied_tip().ok_or("missing tip")?;
            assert_eq!(tip.hash, Hash256::from(alternative.block_hash()));
            let tree = reopened.chain.block_tree_handle();
            assert_eq!(tree.read().node(tip.tip_id)?.hash, tip.hash);
            Ok(())
        }

        #[test]
        fn reopen_keeps_the_undo_record_for_the_next_disconnect() -> TestResult {
            let chain = FuzzChain::new(Network::Regtest)?;
            let genesis = Network::Regtest.genesis_block();
            let first = mined_regtest_child_at(genesis.block_hash(), 1)?;
            chain.apply(&first)?;
            let checkpoint = chain.flush()?;
            let reopened = chain.reopen(&checkpoint)?;
            reopened.disconnect(&first)?;
            let tip = reopened.applied_tip().ok_or("missing tip")?;
            assert_eq!(tip.hash, Hash256::from(genesis.block_hash()));
            assert_eq!(reopened.utxo().with_stable_view(|view| view.len())?, 0);
            Ok(())
        }

        #[test]
        fn flush_and_reopen_read_the_coins_the_engine_committed() -> TestResult {
            let chain = FuzzChain::new(Network::Regtest)?;
            let genesis = Network::Regtest.genesis_block();
            let first = mined_regtest_child_at(genesis.block_hash(), 1)?;
            chain.apply(&first)?;
            let checkpoint = chain.flush()?;
            assert_eq!(checkpoint.coin_count(), first.txs[0].outputs.len());
            let reopened = chain.reopen(&checkpoint)?;
            let outpoint = OutPoint::new(first.txs[0].txid(), 0);
            let coin = reopened
                .utxo()
                .get(&outpoint)
                .map_err(|_| "coin read failed")?;
            assert_eq!(coin.as_ref(), first.txs[0].outputs.first());
            Ok(())
        }

        #[test]
        fn reopen_resumes_coin_stats_for_the_next_committed_block() -> TestResult {
            let chain = FuzzChain::new(Network::Regtest)?;
            let genesis = Network::Regtest.genesis_block();
            let first = mined_regtest_child_at(genesis.block_hash(), 1)?;
            chain.apply(&first)?;
            let checkpoint = chain.flush()?;
            let first_subsidy = first.txs[0].outputs[0].value.to_sat();
            assert_eq!(checkpoint.coin_stats.utxo_count, 1);
            assert_eq!(checkpoint.coin_stats.total_amount, first_subsidy);
            assert_eq!(checkpoint.coin_stats.height, 1);
            assert_eq!(checkpoint.coin_stats.tx_count, 2);
            let reopened = chain.reopen(&checkpoint)?;
            let second = mined_regtest_child_at(first.block_hash(), 2)?;
            reopened.apply(&second)?;
            let second_subsidy = second.txs[0].outputs[0].value.to_sat();
            let stats = reopened.chain.coin_stats.snapshot();
            assert_eq!(stats.utxo_count, 2);
            assert_eq!(stats.total_amount, first_subsidy + second_subsidy);
            assert_eq!(stats.height, 2);
            assert_eq!(stats.tx_count, 3);
            let coin_count = reopened.utxo().with_stable_view(|view| view.len())?;
            assert_eq!(usize::try_from(stats.utxo_count)?, coin_count);
            let first_coin = reopened
                .utxo()
                .get(&OutPoint::new(first.txs[0].txid(), 0))?
                .ok_or("first coin missing after reopen")?;
            let second_coin = reopened
                .utxo()
                .get(&OutPoint::new(second.txs[0].txid(), 0))?
                .ok_or("second coin missing after reopen")?;
            assert_eq!(
                first_coin.value.to_sat() + second_coin.value.to_sat(),
                stats.total_amount
            );
            Ok(())
        }
    }
}
mod prepare;
mod tip_wait;
mod window;
pub mod window_limits;
mod workspace;
pub use prepare::bytes_are_block;
pub use window::classify_apply_error;

pub mod assumeutxo;
pub mod manifest;
pub use assumeutxo::{
    ActivatedSnapshot, ActiveChainstateSummary, AssumeUtxoDiskStatus, AssumeUtxoError,
    AssumeUtxoManager, ChainstateRole, ChainstatesReport, ChainstatesSummary,
    HistoricalChainstateSummary, HistoricalCheckpointRef, recover_snapshot_activation,
};

mod assumeutxo_snapshot;
mod checkpoint;
pub use assumeutxo_snapshot::SnapshotAnchorError;
pub use checkpoint::{CheckpointError, CheckpointSetupError};
mod error;
pub mod events;
mod maintenance;
pub use maintenance::MaintenanceError;
pub mod recovery;
pub mod reorg;
pub mod verify;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationMode {
    Full,
    AssumeValid,
}

impl ValidationMode {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "full" => Some(Self::Full),
            "assume-valid" | "assume_valid" | "assumevalid" => Some(Self::AssumeValid),
            _ => None,
        }
    }
}

type SameBlockSpentSet = hashbrown::HashSet<OutPoint>;

fn tx_count_delta_for(block: &Block) -> u64 {
    u64::try_from(block.txs.len()).unwrap_or(u64::MAX)
}

const LOCAL_OVERLAY_TXID_SET_THRESHOLD: usize = 8;

pub(crate) struct ApplyAdmission {
    closed: LatchWriter,
    barrier: RwLock<()>,
    publication: Mutex<()>,
    #[cfg(test)]
    close_attempted: AtomicBool,
}

impl ApplyAdmission {
    pub(crate) fn new() -> Self {
        Self {
            closed: LatchWriter::new(),
            barrier: RwLock::new(()),
            publication: Mutex::new(()),
            #[cfg(test)]
            close_attempted: AtomicBool::new(false),
        }
    }

    fn ensure_open(&self) -> Result<(), ApplyError> {
        if self.closed.reader().is_triggered() {
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
        self.close_permanently();
        self.barrier.write()
    }

    pub(crate) fn pause(&self) -> RwLockWriteGuard<'_, ()> {
        self.barrier.write()
    }

    pub(crate) fn close_permanently(&self) {
        #[cfg(test)]
        self.close_attempted.store(true, Ordering::Release);
        let hooks = {
            let _publication = self.publication.lock();
            self.closed.trigger_deferred()
        };
        hooks();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.reader().is_triggered()
    }

    pub(crate) fn closed_reader(&self) -> LatchReader {
        self.closed.reader()
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
        if configured_height > 0 && anchor.is_none() {
            tracing::warn!(
                configured_height,
                "assume-valid height has no matching network pin; scripts will not be skipped"
            );
        }
        Self {
            trusted: AtomicBool::new(false),
            warned: AtomicBool::new(false),
            anchor,
        }
    }

    #[cfg(test)]
    #[must_use]
    fn with_anchor(anchor: Option<(u32, Hash256)>) -> Self {
        Self {
            trusted: AtomicBool::new(false),
            warned: AtomicBool::new(false),
            anchor,
        }
    }

    #[must_use]
    fn pin(&self) -> Option<(u32, Hash256)> {
        self.anchor
    }

    #[must_use]
    fn trusted(&self) -> bool {
        self.trusted.load(Ordering::Relaxed)
    }

    fn evaluate(&self, tree: &BlockTree) {
        let Some((pinned_height, pinned_hash)) = self.anchor else {
            self.trusted.store(false, Ordering::Relaxed);
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

/// Why a connect runs, and, for a durable gap replay, the proof that only the
/// gap replay path can mint (`WIN-07`).
#[derive(Clone, Copy, Debug)]
pub(crate) enum BlockProvenance {
    Network,
    LocalReplay(durable::ReplayToken),
    ColdReplay(durable::ReplayToken),
}

#[derive(Clone, Debug)]
pub struct ConnectOutcome {
    pub tip: TipSnapshot,
    pub commit_id: u64,
    pub height: u32,
    pub hash: Hash256,
    pub txids: Vec<Txid>,
    pub block_bytes: bytes::Bytes,
    pub raw_txs: Option<Vec<Vec<u8>>>,
    pub committed_facts: Option<std::sync::Arc<bitcoin_rs_storage::CommittedFacts>>,
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

pub type PowValidBlockHook = Arc<dyn Fn(&BlockImage, Hash256, u32) + Send + Sync>;

pub type TipStagedHook = Arc<dyn Fn(&TipSnapshot, &BlockImage) + Send + Sync>;

#[derive(Clone)]
pub struct Chainstate {
    pub(crate) network: Network,
    pub(crate) chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(crate) applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(crate) block_tree: Arc<RwLock<BlockTree>>,
    pub(crate) header_retention: Arc<header_admission::HeaderRetention>,
    pub(crate) header_role: Arc<header_admission::HeaderRoleRetention>,
    pub(crate) utxo: Arc<UtxoSet>,
    pub(crate) coin_stats: Arc<bitcoin_rs_storage::utxo::stats::CoinStatsListener>,
    pub(crate) chain_events: Arc<crate::events::ChainEventPublisher>,
    pub(crate) block_body_store: Option<Arc<dyn BlockBodyStore>>,
    pub(crate) undo_store: Arc<dyn UndoStore>,
    /// Owner of the durable-head row: the chain's durable commit point,
    /// advanced by one atomic batch per committed connect or disconnect
    /// before the tip publishes (`RCV-02`).
    pub(crate) durable_head: Arc<dyn DurableHeadStore>,
    pub(crate) coins: Arc<bitcoin_rs_storage::CoinStore>,
    pub(crate) commit_authority: Arc<bitcoin_rs_storage::CommitAuthority>,
    pub(crate) admission: Arc<ApplyAdmission>,
    pub(crate) shutdown: Arc<LatchWriter>,
    pub(crate) tip_notification: Arc<tip_wait::TipNotification>,
    pub(crate) chain_transition: TransitionAuthority,
    pub(crate) assume_valid_height: u32,
    pub(crate) assume_valid_gate: Arc<AssumeValidGate>,
    pub(crate) validation_mode: ValidationMode,
    pub(crate) validation_engine: bitcoin_rs_consensus::ValidationEngine,
    pub(crate) script_cache: Option<Arc<ScriptExecutionCache>>,
    pub(crate) pow_valid_block: std::sync::Arc<std::sync::OnceLock<PowValidBlockHook>>,
    pub(crate) tip_staged: std::sync::Arc<std::sync::OnceLock<TipStagedHook>>,
    pub(crate) checkpoint_publisher: Option<Arc<crate::checkpoint::publisher::CheckpointPublisher>>,
    pub(crate) capture_rawtx: bool,
    pub(crate) capture_block_bytes: bool,
    pub(crate) facts: Arc<FactsGate>,
    pub(crate) retention: bitcoin_rs_storage::MandatoryRetention,
    pub(crate) window_limits: crate::window_limits::WindowLimitsSource,
    pub(crate) prevout_charge: Option<bitcoin_rs_storage::budget::ChargeHandle>,
    pub(crate) history: bitcoin_rs_storage::pruning::HistoryAccess,
    ibd: Arc<crate::chain::InitialBlockDownload>,
    pub(crate) role: Arc<RwLock<ChainstateRole>>,
}

#[derive(Debug, Default)]
pub(crate) struct FactsGate {
    attached: AtomicBool,
    #[cfg(any(test, feature = "test-seam"))]
    builds: std::sync::atomic::AtomicUsize,
}

pub struct ChainstateParts {
    pub network: Network,
    pub block_tree: BlockTree,
    pub restored_applied_tip: Option<TipSnapshot>,
    pub utxo: Arc<UtxoSet>,
    pub coin_stats: Arc<bitcoin_rs_storage::utxo::stats::CoinStatsListener>,
    pub chain_events: Arc<crate::events::ChainEventPublisher>,
    pub block_body_store: Option<Arc<dyn BlockBodyStore>>,
    pub undo_store: Arc<dyn UndoStore>,
    pub durable_head: Arc<dyn DurableHeadStore>,
    pub coins: Arc<bitcoin_rs_storage::CoinStore>,
    pub commit_authority: Arc<bitcoin_rs_storage::CommitAuthority>,
    pub chain_transition: TransitionAuthority,
    pub assume_valid_height: u32,
    pub validation_mode: ValidationMode,
    pub validation_engine: bitcoin_rs_consensus::ValidationEngine,
    pub script_cache: Option<Arc<ScriptExecutionCache>>,
    pub capture_rawtx: bool,
    pub capture_block_bytes: bool,
    pub retention: bitcoin_rs_storage::MandatoryRetention,
    pub window_limits: crate::window_limits::WindowLimitsSource,
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
    pub fn connect(
        &self,
        payload: &BlockImage,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        let mut outcomes = self
            .connect_window(&[payload])
            .map_err(|error| *error.source)?;
        outcomes.pop().ok_or(ApplyError::DurableHeadCommit(
            bitcoin_rs_storage::StorageError::InvalidOperation("connect produced no outcome"),
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

    pub fn connect_window(
        &self,
        payloads: &[&BlockImage],
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
            self.header_role.published(tip.hash);
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
        let role = Arc::new(RwLock::new(parts.role));
        let header_retention = Arc::new(header_admission::HeaderRetention::default());
        let header_role =
            header_retention.register_role(Arc::clone(&applied_tip), Arc::clone(&role));
        let ibd = Arc::new(crate::chain::InitialBlockDownload::new(
            TipReader::new(Arc::clone(&applied_tip)),
            BlockTreeReader::new(Arc::clone(&block_tree)),
        ));
        Self {
            network: parts.network,
            chain_tip,
            applied_tip,
            block_tree,
            header_retention,
            header_role,
            utxo: parts.utxo,
            coin_stats: parts.coin_stats,
            chain_events: parts.chain_events,
            block_body_store: parts.block_body_store,
            undo_store: parts.undo_store,
            durable_head: parts.durable_head,
            coins: parts.coins,
            commit_authority: parts.commit_authority,
            admission: Arc::new(ApplyAdmission::new()),
            shutdown: Arc::new(LatchWriter::new()),
            tip_notification: Arc::default(),
            chain_transition: parts.chain_transition,
            assume_valid_height: parts.assume_valid_height,
            assume_valid_gate,
            validation_mode: parts.validation_mode,
            validation_engine: parts.validation_engine,
            script_cache: parts.script_cache,
            pow_valid_block: std::sync::Arc::new(std::sync::OnceLock::new()),
            tip_staged: std::sync::Arc::new(std::sync::OnceLock::new()),
            checkpoint_publisher: None,
            capture_rawtx: parts.capture_rawtx,
            capture_block_bytes: parts.capture_block_bytes,
            facts: Arc::new(FactsGate::default()),
            retention: parts.retention,
            window_limits: parts.window_limits,
            prevout_charge: None,
            history: parts.history,
            ibd,
            role,
        }
    }

    pub fn set_prevout_charge(&mut self, charge: bitcoin_rs_storage::budget::ChargeHandle) {
        self.prevout_charge = Some(charge);
    }

    #[must_use]
    pub fn role(&self) -> ChainstateRole {
        *self.role.read()
    }

    pub(crate) fn set_role(&self, role: ChainstateRole) {
        let _transition = self.chain_transition.lock();
        let _tree = self.block_tree.read();
        *self.role.write() = role;
    }

    pub(crate) fn install_snapshot<S, P>(
        &self,
        pinned: &bitcoin_rs_consensus::primitives::AssumeUtxoData,
        declared_coins: u64,
        stream: S,
        persist: P,
    ) -> Result<(), AssumeUtxoError>
    where
        S: FnOnce(
            &bitcoin_rs_storage::CoinStore,
        ) -> Result<assumeutxo_snapshot::StreamedCoins, AssumeUtxoError>,
        P: FnOnce(
            &bitcoin_rs_storage::CoinStore,
            &parking_lot::RwLock<BlockTree>,
            &TipSnapshot,
            Option<&bitcoin_rs_storage::DurableHead>,
            &bitcoin_rs_storage::SnapshotActivationMarker,
            &assumeutxo_snapshot::StreamedCoins,
        ) -> Result<(), AssumeUtxoError>,
    {
        let _guard = self.admission.enter()?;
        let _transition = self.chain_transition.lock();
        let (tip_snapshot, _header_retention) = {
            let tree = self.block_tree.read();
            let tip = Self::snapshot_base_tip(&tree, pinned)?;
            let retention = self.header_retention.pin_operation(&tree, &[tip.tip_id])?;
            (tip, retention)
        };
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
        let marker = bitcoin_rs_storage::SnapshotActivationMarker {
            base_hash: pinned.block_hash,
            coin_count: declared_coins,
            coin_digest: pinned.hash_serialized,
        };
        self.commit_authority
            .begin_snapshot_activation(prior.as_ref(), &marker)
            .map_err(commit_error)
            .inspect_err(|_| self.fail_closed_for_recovery())?;
        self.coins
            .wipe()
            .inspect_err(|_| self.fail_closed_for_recovery())
            .map_err(AssumeUtxoError::Storage)?;
        let streamed = match stream(&self.coins) {
            Ok(streamed) => streamed,
            Err(error) => return Err(self.discard_partial_ingest(error, prior.as_ref())),
        };
        if let Err(error) = persist(
            &self.coins,
            &self.block_tree,
            &tip_snapshot,
            prior.as_ref(),
            &marker,
            &streamed,
        ) {
            return Err(self.discard_partial_ingest(error, prior.as_ref()));
        }
        let mut tree = self.block_tree.write();
        tree.restore_chain_tx_count(tip_snapshot.tip_id, tip_snapshot.chain_tx_count)
            .map_err(ApplyError::from)
            .inspect_err(|_| self.fail_closed_for_recovery())?;
        let mut stats = streamed.coin_stats;
        stats.tx_count = pinned.chain_tx_count;
        self.coin_stats.reset(stats);
        self.publish_applied(&tip_snapshot, crate::events::HintKind::Connected);
        *self.role.write() = ChainstateRole::AssumedActive {
            base_height: pinned.height,
            base_hash: pinned.block_hash,
        };
        Ok(())
    }

    fn discard_partial_ingest(
        &self,
        error: AssumeUtxoError,
        prior: Option<&bitcoin_rs_storage::DurableHead>,
    ) -> AssumeUtxoError {
        match self.commit_authority.recover_snapshot_activation() {
            Ok(_) => {
                let rejected = matches!(
                    error,
                    AssumeUtxoError::SnapshotCommitmentMismatch { .. }
                        | AssumeUtxoError::Codec(
                            bitcoin_rs_storage::utxo::core_snapshot::SnapshotError::CommitmentMismatch { .. }
                        )
                );
                if prior.is_some() || !rejected {
                    self.fail_closed_for_recovery();
                } else if let Err(discard) =
                    self.commit_authority.clear_snapshot_activation_marker()
                {
                    self.fail_closed_for_recovery();
                    return AssumeUtxoError::PartialIngestNotDiscarded {
                        ingest: Box::new(error),
                        discard: discard.to_string(),
                    };
                }
                error
            }
            Err(discard) => {
                self.fail_closed_for_recovery();
                AssumeUtxoError::PartialIngestNotDiscarded {
                    ingest: Box::new(error),
                    discard: discard.to_string(),
                }
            }
        }
    }

    pub(crate) fn has_durable_head(&self) -> Result<bool, AssumeUtxoError> {
        Ok(self.durable_head.load()?.is_some())
    }

    fn snapshot_base_tip(
        tree: &BlockTree,
        pinned: &bitcoin_rs_consensus::primitives::AssumeUtxoData,
    ) -> Result<TipSnapshot, AssumeUtxoError> {
        let node_id = tree
            .lookup(pinned.block_hash)
            .ok_or(AssumeUtxoError::SnapshotHeaderMissing(pinned.block_hash))?;
        let node = tree.node(node_id).map_err(ApplyError::from)?;
        if node.status == crate::chain::NodeStatus::Invalid {
            return Err(
                ApplyError::from(crate::chain::ChainError::KnownInvalidHeader {
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
            chain_tx_count: crate::chain::ChainTxCount::established(pinned.chain_tx_count),
        })
    }

    fn create_historical_counterpart(
        &self,
        base_height: u32,
        base_hash: Hash256,
        engine: Option<Arc<dyn bitcoin_rs_storage::KvStore>>,
        restored_tip: Option<TipSnapshot>,
    ) -> Result<Arc<Self>, crate::AssumeUtxoError> {
        let historical_stats = match (&restored_tip, &engine) {
            (Some(tip), Some(image)) => crate::assumeutxo::engine_coin_stats(image.as_ref(), tip)?,
            (Some(_), None) => {
                return Err(crate::AssumeUtxoError::HistoricalCheckpointWithoutEngine);
            }
            (None, _) => CoinStats::new(),
        };
        let historical_coin_stats = Arc::new(CoinStatsListener::new(historical_stats));
        let mut historical_utxo = UtxoSet::new();
        historical_utxo.track_coin_stats((*historical_coin_stats).clone());

        let fresh_store = Arc::new(bitcoin_rs_storage::memory_kv::MemoryKvStore::default());
        if let Some(image) = engine {
            use bitcoin_rs_storage::KvStore;
            let families = [
                bitcoin_rs_storage::ColumnFamily::Coins,
                bitcoin_rs_storage::ColumnFamily::UndoData,
            ];
            for family in families {
                let mut batch = fresh_store.new_batch();
                for item in image.iter_prefix(family, &[])? {
                    let (key, value) = item?;
                    batch.put_value(family, &key, bytes::Bytes::from(value));
                }
                fresh_store.write_durable(batch)?;
            }
        }
        let historical_head = Arc::new(bitcoin_rs_storage::KvDurableHeadStore::new(Arc::clone(
            &fresh_store,
        )));
        let dyn_hist_store: Arc<dyn bitcoin_rs_storage::KvStore> = fresh_store;
        let historical_undo = Arc::new(bitcoin_rs_storage::KvUndoStore::new(Arc::clone(
            &dyn_hist_store,
        )));
        let hist_coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
            Arc::clone(&dyn_hist_store),
            64 * 1024 * 1024,
        ));
        hist_coins.track_coin_stats((*historical_coin_stats).clone());
        let hist_commit_authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(
            dyn_hist_store,
            Arc::clone(&hist_coins),
        ));
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
            hist_commit_authority
                .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: None,
                    next_head: head,
                    undo_rows: Vec::new(),
                    body_rows: Vec::new(),
                    attestation: None,
                    coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                })
                .map_err(crate::assumeutxo::commit_error)?;
        }
        let applied_tip = Arc::new(ArcSwapOption::new(restored_tip.map(Arc::new)));
        let role = Arc::new(RwLock::new(ChainstateRole::Historical {
            base_height,
            base_hash,
        }));
        let header_role = self
            .header_retention
            .register_role(Arc::clone(&applied_tip), Arc::clone(&role));
        let chain_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        let assume_valid_gate = Arc::new(AssumeValidGate::new(self.network, 0));
        let ibd = Arc::new(crate::chain::InitialBlockDownload::new(
            TipReader::new(Arc::clone(&applied_tip)),
            BlockTreeReader::new(Arc::clone(&self.block_tree)),
        ));

        let historical = Self {
            network: self.network,
            chain_tip,
            applied_tip,
            block_tree: Arc::clone(&self.block_tree),
            header_retention: Arc::clone(&self.header_retention),
            header_role,
            utxo: Arc::new(historical_utxo),
            coin_stats: historical_coin_stats,
            chain_events: Arc::new(crate::events::ChainEventPublisher::detached(
                self.chain_events.epoch(),
            )),
            block_body_store: None,
            undo_store: historical_undo,
            durable_head: historical_head,
            coins: hist_coins,
            commit_authority: hist_commit_authority,
            admission: Arc::new(ApplyAdmission::new()),
            shutdown: Arc::new(LatchWriter::new()),
            tip_notification: Arc::default(),
            chain_transition: crate::chain::TransitionDomain::new().authority(),
            assume_valid_height: 0,
            assume_valid_gate,
            validation_mode: ValidationMode::Full,
            validation_engine: self.validation_engine,
            script_cache: self.script_cache.clone(),
            pow_valid_block: std::sync::Arc::new(std::sync::OnceLock::new()),
            tip_staged: std::sync::Arc::new(std::sync::OnceLock::new()),
            checkpoint_publisher: None,
            capture_rawtx: false,
            capture_block_bytes: false,
            facts: Arc::new(FactsGate::default()),
            retention: self.retention.clone(),
            window_limits: crate::window_limits::default_window_limits_source(),
            prevout_charge: self.prevout_charge.clone(),
            history: self.history.clone(),
            ibd,
            role,
        };
        Ok(Arc::new(historical))
    }

    #[must_use]
    pub fn shutdown_reader(&self) -> bitcoin_rs_consensus::latch::LatchReader {
        self.shutdown.reader()
    }

    pub fn request_shutdown(&self) {
        self.shutdown.trigger();
        let _gate = self.tip_notification.gate.lock();
        self.tip_notification.changed.notify_all();
    }

    pub fn fail_closed_for_recovery(&self) {
        self.admission.close_permanently();
        self.request_shutdown();
    }

    #[must_use]
    pub fn is_closed_for_recovery(&self) -> bool {
        self.admission.is_closed()
    }

    #[must_use]
    pub fn closed_for_recovery_reader(&self) -> bitcoin_rs_consensus::latch::LatchReader {
        self.admission.closed_reader()
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

    #[must_use]
    pub fn durable_commit_id(&self) -> u64 {
        self.durable_head
            .load()
            .ok()
            .flatten()
            .map_or(0, |head| head.commit_id)
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
    pub fn ibd_latch(&self) -> Arc<crate::chain::InitialBlockDownload> {
        Arc::clone(&self.ibd)
    }

    #[must_use]
    pub fn chain_progress_reader(&self) -> crate::chain::ChainProgressReader {
        crate::chain::ChainProgressReader::new(
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
    pub fn utxo_reader(&self) -> bitcoin_rs_storage::utxo::UtxoReader {
        bitcoin_rs_storage::utxo::UtxoReader::with_coin_store(
            Arc::clone(&self.utxo),
            Arc::clone(&self.coins),
        )
    }
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn coins(&self) -> &bitcoin_rs_storage::CoinStore {
        &self.coins
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn commit_authority(&self) -> &Arc<bitcoin_rs_storage::CommitAuthority> {
        &self.commit_authority
    }

    #[must_use]
    pub fn coin_stats_handle(&self) -> Arc<bitcoin_rs_storage::utxo::stats::CoinStatsListener> {
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

    pub fn set_capture_flags(&mut self, rawtx: bool, block_bytes: bool) {
        self.capture_rawtx = rawtx;
        self.capture_block_bytes = block_bytes;
    }

    pub fn set_committed_facts_consumer(&self, attached: bool) {
        self.facts.attached.store(attached, Ordering::Relaxed);
    }

    #[must_use]
    pub(crate) fn wants_committed_facts(&self) -> bool {
        self.facts.attached.load(Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn committed_facts_builds(&self) -> usize {
        self.facts.builds.load(Ordering::SeqCst)
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
            BlockProvenance::LocalReplay(_) => true,
            BlockProvenance::ColdReplay(_) => false,
            BlockProvenance::Network => match self.validation_mode {
                ValidationMode::Full => false,
                ValidationMode::AssumeValid => {
                    let Some((pinned_height, pinned_hash)) = self.assume_valid_gate.pin() else {
                        return false;
                    };
                    if self.assume_valid_height == 0 || height > self.assume_valid_height {
                        return false;
                    }
                    if height > pinned_height {
                        return false;
                    }
                    if !self.assume_valid_gate.trusted() {
                        return false;
                    }
                    let tree = self.block_tree.read();
                    let Some(header_tip) = tree.tip() else {
                        return false;
                    };
                    tree.node_at_height_from(header_tip.tip_id, pinned_height)
                        .is_some_and(|pin_id| tree.lookup(pinned_hash) == Some(pin_id))
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
        coin_stats: Arc<bitcoin_rs_storage::utxo::stats::CoinStatsListener>,
        chain_events: Arc<crate::events::ChainEventPublisher>,
    ) -> Self {
        let role = Arc::new(RwLock::new(ChainstateRole::Ordinary));
        let header_retention = Arc::new(header_admission::HeaderRetention::default());
        let header_role =
            header_retention.register_role(Arc::clone(&applied_tip), Arc::clone(&role));
        let assume_valid_gate = Arc::new(AssumeValidGate::new(network, 0));
        assume_valid_gate.evaluate(&block_tree.read());
        let ibd = Arc::new(crate::chain::InitialBlockDownload::new(
            TipReader::new(Arc::clone(&applied_tip)),
            BlockTreeReader::new(Arc::clone(&block_tree)),
        ));
        let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
        let mem_store = Arc::new(bitcoin_rs_storage::memory_kv::MemoryKvStore::default());
        let durable_head = Arc::new(bitcoin_rs_storage::KvDurableHeadStore::new(Arc::clone(
            &mem_store,
        )));
        let undo_store = Arc::new(bitcoin_rs_storage::KvUndoStore::new(Arc::clone(&mem_store)));
        let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = mem_store;
        let coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
            Arc::clone(&dyn_store),
            64 * 1024 * 1024,
        ));
        let commit_authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(
            dyn_store,
            Arc::clone(&coins),
        ));
        Self {
            network,
            chain_tip,
            applied_tip,
            block_tree,
            header_retention,
            header_role,
            utxo,
            coin_stats,
            chain_events,
            block_body_store: None,
            undo_store,
            durable_head,
            coins,
            commit_authority,
            admission: Arc::new(ApplyAdmission::new()),
            shutdown: Arc::new(LatchWriter::new()),
            tip_notification: Arc::default(),
            chain_transition: TransitionDomain::new().authority(),
            assume_valid_height: 0,
            assume_valid_gate,
            validation_mode: ValidationMode::AssumeValid,
            validation_engine: bitcoin_rs_consensus::ValidationEngine::Native,
            script_cache: None,
            pow_valid_block: std::sync::Arc::new(std::sync::OnceLock::new()),
            tip_staged: std::sync::Arc::new(std::sync::OnceLock::new()),
            checkpoint_publisher: None,
            capture_rawtx: false,
            capture_block_bytes: false,
            facts: Arc::new(FactsGate::default()),
            retention: bitcoin_rs_storage::MandatoryRetention::new(Arc::clone(&retention)),
            window_limits: crate::window_limits::default_window_limits_source(),
            prevout_charge: None,
            history: bitcoin_rs_storage::pruning::HistoryAccess::new(
                retention,
                bitcoin_rs_storage::pruning::RetentionBudget::from_blocks(
                    bitcoin_rs_consensus::primitives::chain_constants::CORE_REORG_SAFETY_MARGIN,
                ),
            ),
            role,
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
    ) -> core::result::Result<(), CheckpointSetupError> {
        let checkpoint_data_dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(data_dir)?;
        let block_body_store = self
            .block_body_store
            .clone()
            .ok_or(CheckpointSetupError::MissingBlockBodyStore)?;
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
                coin_stats: Arc::clone(&self.coin_stats),
                data_dir: data_dir.to_path_buf(),
                chain_events: Arc::clone(&self.chain_events),
                durable_tip_height,
                store: Arc::clone(self.commit_authority.store()),
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

    #[cfg(any(test, feature = "test-seam"))]
    pub fn apply_block(
        &self,
        payload: &BlockImage,
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
    #[cfg(any(test, feature = "test-seam"))]
    pub fn set_commit_fault(&self, fault: Arc<dyn bitcoin_rs_storage::commit::CommitFault>) {
        self.commit_authority.set_fault(fault);
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn apply_window(
        &self,
        payloads: &[&BlockImage],
    ) -> core::result::Result<Vec<ConnectOutcome>, WindowApplyError> {
        let transition = self.begin_transition().map_err(|source| WindowApplyError {
            applied: 0,
            committed: Vec::new(),
            source: Box::new(source),
            disposition: WindowApplyDisposition::Operational,
            invalidated: Box::default(),
        })?;
        let result = transition.connect_window(payloads);
        drop(transition);
        result
    }

    pub fn validate_block(&self, payload: &BlockImage) -> core::result::Result<(), ApplyError> {
        let _lock = self.lock_transition()?;
        match apply_block_admitted(
            self,
            payload,
            None,
            connect::ApplyScope {
                provenance: BlockProvenance::Network,
                staged: None,
            },
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
    #[expect(dead_code)]
    parent_prev_hash: Hash256,
    undo: bitcoin_rs_storage::utxo::contract::UndoBatch,
    height: u32,
    tx_count_delta: u64,
}

pub use crate::window_limits::{
    WindowLimits, WindowLimitsSource, default_window_limits_source, window_len_within,
};

#[derive(Debug)]
pub struct WindowApplyError {
    pub applied: usize,
    pub committed: Vec<ConnectOutcome>,
    pub source: Box<ApplyError>,
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
        Some(self.source.as_ref())
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
    flags: bitcoin_rs_consensus::script::VerifyFlags,
    locktime_cutoff: u32,
}

#[derive(Clone, Copy)]
struct Bip68Context<'a> {
    validation: &'a BlockValidationContext,
    median_time_past: u32,
    softfork_state: crate::chain::SoftforkState,
    previous_tip_id: Option<crate::chain::node::NodeId>,
}

struct BlockValidationProof<'b> {
    prepared: PreparedApply<'b>,
    context: BlockValidationContext,
}

enum ProvenApply<'b> {
    Proven(BlockValidationProof<'b>),
    AssumeValidSkipped(PreparedApply<'b>),
    Unproven(PreparedApply<'b>),
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

impl bitcoin_rs_consensus::primitives::Sink for ByteEquality<'_> {
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

pub(crate) struct PrevoutHold {
    charge: Option<bitcoin_rs_storage::budget::ChargeHandle>,
    bytes: u64,
}

impl PrevoutHold {
    pub(crate) fn charge(
        handle: Option<bitcoin_rs_storage::budget::ChargeHandle>,
        bytes: u64,
    ) -> core::result::Result<Option<Self>, ApplyError> {
        let Some(handle) = handle else {
            return Ok(None);
        };
        if bytes == 0 {
            return Ok(Some(Self {
                charge: Some(handle),
                bytes: 0,
            }));
        }
        handle
            .charge(bytes)
            .map_err(|_| ApplyError::StagedBudgetExhausted)?;
        Ok(Some(Self {
            charge: Some(handle),
            bytes,
        }))
    }
}

impl Drop for PrevoutHold {
    fn drop(&mut self) {
        if let Some(charge) = self.charge.as_ref() {
            charge.release(self.bytes);
        }
    }
}

fn resolved_view_bytes(view: &ResolvedUtxoView) -> u64 {
    let slot = u64::try_from(core::mem::size_of::<Option<TxOut>>()).unwrap_or(u64::MAX);
    let outpoint = u64::try_from(core::mem::size_of::<OutPoint>()).unwrap_or(u64::MAX);
    view.external
        .values()
        .map(|coin| {
            let script = u64::try_from(coin.txout.script_pubkey.len()).unwrap_or(u64::MAX);
            slot.saturating_add(outpoint).saturating_add(script)
        })
        .fold(0_u64, u64::saturating_add)
}

pub(crate) fn prevout_slot_and_script_bytes(script_len: usize) -> u64 {
    let slot = u64::try_from(core::mem::size_of::<Option<TxOut>>()).unwrap_or(u64::MAX);
    let script = u64::try_from(script_len).unwrap_or(u64::MAX);
    slot.saturating_add(script)
}

pub(crate) fn prevout_vec_bytes(resolved: &[Vec<Option<TxOut>>]) -> u64 {
    resolved
        .iter()
        .flatten()
        .map(|prevout| {
            prevout_slot_and_script_bytes(
                prevout
                    .as_ref()
                    .map_or(0, |txout| txout.script_pubkey.len()),
            )
        })
        .fold(0_u64, u64::saturating_add)
}

struct ResolvedUtxoView {
    external: HashMap<OutPoint, UtxoCoin>,
    _hold: Option<PrevoutHold>,
}

const RESOLVE_TXIDS_PER_FETCH: usize = 64;

impl ResolvedUtxoView {
    fn external_outpoints(image: &BlockImage, tx_plan: &BlockTxPlan) -> Vec<OutPoint> {
        let same_block = tx_plan.same_block_spent.as_ref();
        (0..image.tx_count())
            .map(|i| image.tx(i))
            .filter(|tx| !tx.is_coinbase())
            .flat_map(|tx| (0..tx.input_count()).map(move |j| tx.input_outpoint(j)))
            .filter(|outpoint| same_block.is_none_or(|set| !set.contains(outpoint)))
            .collect()
    }
    fn group_outpoints_by_txid(
        outpoints: &[OutPoint],
    ) -> (Vec<Txid>, HashMap<Txid, Vec<OutPoint>>) {
        let mut txids = Vec::with_capacity(outpoints.len());
        let mut groups: HashMap<Txid, Vec<OutPoint>> = HashMap::with_capacity(outpoints.len());
        for outpoint in outpoints {
            let txid = outpoint.txid;
            groups
                .entry(txid)
                .or_insert_with(|| {
                    txids.push(txid);
                    Vec::new()
                })
                .push(*outpoint);
        }
        (txids, groups)
    }
    fn resolve<S: bitcoin_rs_storage::utxo::contract::OutputSource + ?Sized>(
        utxo: &S,
        image: &BlockImage,
        tx_plan: &BlockTxPlan,
    ) -> Self {
        let outpoints = Self::external_outpoints(image, tx_plan);
        let (txids, mut grouped) = Self::group_outpoints_by_txid(&outpoints);
        let mut external = HashMap::with_capacity(outpoints.len());
        for txids in txids.chunks(RESOLVE_TXIDS_PER_FETCH) {
            let chunk_len: usize = txids
                .iter()
                .filter_map(|txid| grouped.get(txid))
                .map(Vec::len)
                .sum();
            let mut chunk = Vec::with_capacity(chunk_len);
            for txid in txids {
                if let Some(pts) = grouped.remove(txid) {
                    chunk.extend(pts);
                }
            }
            let entries = utxo.get_entries(&chunk);
            external.extend(
                chunk
                    .into_iter()
                    .zip(entries)
                    .filter_map(|(outpoint, entry)| entry.map(|entry| (outpoint, entry))),
            );
        }
        Self {
            external,
            _hold: None,
        }
    }
    fn resolve_charged<S: bitcoin_rs_storage::utxo::contract::OutputSource + ?Sized>(
        utxo: &S,
        image: &BlockImage,
        tx_plan: &BlockTxPlan,
        charge: Option<bitcoin_rs_storage::budget::ChargeHandle>,
    ) -> core::result::Result<Self, ApplyError> {
        if charge.is_none() {
            return Ok(Self::resolve(utxo, image, tx_plan));
        }
        let outpoints = Self::external_outpoints(image, tx_plan);
        let (txids, mut grouped) = Self::group_outpoints_by_txid(&outpoints);
        let mut external = HashMap::with_capacity(outpoints.len());
        let mut hold: Option<PrevoutHold> = None;
        for txids in txids.chunks(RESOLVE_TXIDS_PER_FETCH) {
            let chunk_len: usize = txids
                .iter()
                .filter_map(|txid| grouped.get(txid))
                .map(Vec::len)
                .sum();
            let mut chunk = Vec::with_capacity(chunk_len);
            for txid in txids {
                if let Some(pts) = grouped.remove(txid) {
                    chunk.extend(pts);
                }
            }
            let entries = utxo.get_entries(&chunk);
            let probe = Self {
                external: chunk
                    .into_iter()
                    .zip(entries)
                    .filter_map(|(outpoint, entry)| entry.map(|entry| (outpoint, entry)))
                    .collect(),
                _hold: None,
            };
            let chunk_bytes = resolved_view_bytes(&probe);
            if let Some(handle) = charge.clone() {
                match hold.as_mut() {
                    Some(held) => {
                        handle
                            .charge(chunk_bytes)
                            .map_err(|_| ApplyError::StagedBudgetExhausted)?;
                        held.bytes = held.bytes.saturating_add(chunk_bytes);
                    }
                    None => {
                        hold = PrevoutHold::charge(Some(handle), chunk_bytes)?;
                    }
                }
            }
            external.extend(probe.external);
        }
        Ok(Self {
            external,
            _hold: hold,
        })
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
    image: &'b BlockImage,
    height: u32,
    overlay: HashMap<OutPoint, Option<u32>>,
}

impl<'b> BlockLocalUtxoView<'b> {
    fn new(
        base: Arc<ResolvedUtxoView>,
        image: &'b BlockImage,
        height: u32,
        overlay_capacity: usize,
    ) -> Self {
        Self {
            base,
            image,
            height,
            overlay: HashMap::with_capacity(overlay_capacity),
        }
    }

    fn lookup_meta(&self, outpoint: &OutPoint) -> Option<PrevoutMeta> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let derived_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            if derived_index >= self.image.tx_count() {
                return None;
            }
            let tx = self.image.tx(derived_index);
            if vout >= tx.output_count() {
                return None;
            }
            return Some(PrevoutMeta {
                coinbase: derived_index == 0,
                height: self.height,
            });
        }
        self.base.lookup_meta(outpoint)
    }

    fn spend_inputs(&mut self, tx: &bitcoin_rs_consensus::primitives::TransactionView<'_>) {
        for j in 0..tx.input_count() {
            self.overlay.insert(tx.input_outpoint(j), None);
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

    fn script_len(&self, outpoint: &OutPoint) -> Option<usize> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let derived_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            if derived_index >= self.image.tx_count() {
                return None;
            }
            let tx = self.image.tx(derived_index);
            if vout >= tx.output_count() {
                return None;
            }
            return Some(tx.output_script(vout).len());
        }
        self.base
            .entry(outpoint)
            .map(|coin| coin.txout.script_pubkey.len())
    }
}

impl UtxoView for BlockLocalUtxoView<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let derived_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            if derived_index >= self.image.tx_count() {
                return None;
            }
            let tx = self.image.tx(derived_index);
            if vout >= tx.output_count() {
                return None;
            }
            return Some(TxOut {
                value: tx.output_value(vout),
                script_pubkey: bitcoin_rs_consensus::primitives::Script::from_bytes(
                    tx.output_script(vout).to_vec(),
                ),
            });
        }
        self.base.lookup(outpoint)
    }
}

#[cfg(any(test, verification, kani))]
pub(crate) mod admission_model;

#[cfg(any(test, feature = "test-seam"))]
pub(crate) mod test_support {
    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_storage::StorageError;
    use bitcoin_rs_storage::block_body::BlockBodyStore;
    use hashbrown::HashMap;
    use parking_lot::RwLock;

    #[derive(Default)]
    pub(crate) struct MemoryBodies {
        bodies: RwLock<HashMap<(u32, Hash256), Vec<u8>>>,
    }

    impl BlockBodyStore for MemoryBodies {
        fn load_block_body_bounded(
            &self,
            height: u32,
            hash: Hash256,
            max_bytes: usize,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::BoundedReadError> {
            self.bodies
                .read()
                .get(&(height, hash))
                .map(|body| {
                    if body.len() > max_bytes {
                        Err(bitcoin_rs_storage::BoundedReadError::Limit {
                            size: body.len(),
                            limit: max_bytes,
                        })
                    } else {
                        Ok(body.clone())
                    }
                })
                .transpose()
        }

        fn persist_block_body(
            &self,
            height: u32,
            hash: Hash256,
            body: &[u8],
        ) -> Result<(), StorageError> {
            self.bodies.write().insert((height, hash), body.to_vec());
            Ok(())
        }

        fn load_block_body(
            &self,
            height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.bodies.read().get(&(height, hash)).cloned())
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test_fixtures {
    use std::sync::Arc;

    use crate::chain::{BlockTree, ChainTxCount, TipSnapshot};
    use arc_swap::ArcSwapOption;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockImage, Hash256, LockTime, Network, OutPoint, Sequence, Tx, TxIn, TxOut,
        Witness,
    };
    use bitcoin_rs_storage::utxo::UtxoSet;
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
    use parking_lot::{Mutex, RwLock};

    use crate::{ApplyError, Chainstate, TipStagedHook};

    pub(crate) fn handles(network: Network, utxo: Arc<UtxoSet>) -> Chainstate {
        Chainstate::new(
            network,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(BlockTree::new())),
            utxo,
            Arc::new(CoinStatsListener::new(CoinStats::default())),
            Arc::new(crate::events::ChainEventPublisher::detached(0)),
        )
    }

    pub(crate) fn handles_with_store<S: bitcoin_rs_storage::KvStore>(
        network: Network,
        utxo: Arc<UtxoSet>,
        store: Arc<S>,
    ) -> Chainstate {
        let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = store.clone();
        let coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
            Arc::clone(&dyn_store),
            64 * 1024 * 1024,
        ));
        let durable_head = Arc::new(bitcoin_rs_storage::KvDurableHeadStore::new(Arc::clone(
            &store,
        )));
        let undo_store = Arc::new(bitcoin_rs_storage::KvUndoStore::new(Arc::clone(&dyn_store)));
        let commit_authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(
            Arc::clone(&dyn_store),
            Arc::clone(&coins),
        ));
        let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
        Chainstate::from_parts(crate::ChainstateParts {
            network,
            block_tree: BlockTree::new(),
            restored_applied_tip: None,
            utxo,
            coin_stats: Arc::new(CoinStatsListener::new(CoinStats::default())),
            chain_events: Arc::new(crate::events::ChainEventPublisher::detached(0)),
            block_body_store: None,
            undo_store,
            durable_head,
            coins,
            commit_authority,
            chain_transition: crate::chain::TransitionDomain::new().authority(),
            assume_valid_height: 0,
            validation_mode: crate::ValidationMode::AssumeValid,
            validation_engine: bitcoin_rs_consensus::ValidationEngine::Native,
            script_cache: None,
            capture_rawtx: false,
            capture_block_bytes: false,
            retention: bitcoin_rs_storage::MandatoryRetention::new(Arc::clone(&retention)),
            history: bitcoin_rs_storage::pruning::HistoryAccess::new(
                retention,
                bitcoin_rs_storage::pruning::RetentionBudget::from_blocks(
                    bitcoin_rs_consensus::primitives::chain_constants::CORE_REORG_SAFETY_MARGIN,
                ),
            ),
            role: crate::ChainstateRole::Ordinary,
            window_limits: crate::window_limits::default_window_limits_source(),
        })
    }

    pub(crate) fn seed_genesis(handles: &Chainstate) -> Result<TipSnapshot, ApplyError> {
        let _pending_headers = handles.header_role.begin_application();
        let genesis = Network::Regtest.genesis_block();
        let tip = crate::connect::applied_header_tip(
            handles,
            Hash256::from(genesis.block_hash()),
            &BlockImage::from_local(genesis),
            0,
        )?;
        let tip = TipSnapshot {
            chain_tx_count: ChainTxCount::established(1),
            ..tip
        };
        handles.applied_tip.store(Some(Arc::new(tip.clone())));
        Ok(tip)
    }

    pub(crate) fn seed_durable_head(
        chain: &Chainstate,
        next: bitcoin_rs_storage::DurableHead,
    ) -> TestResult {
        <Chainstate>::commit_authority(chain)
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: None,
                next_head: next,
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(|error| {
                TestError::Storage(bitcoin_rs_storage::StorageError::backend(error.to_string()))
            })?;
        Ok(())
    }

    pub(crate) struct StagedFire {
        pub(crate) staged_hash: Hash256,
        pub(crate) staged_height: u32,
        pub(crate) block_hash: Hash256,
        pub(crate) published: Option<(Hash256, u32)>,
    }

    pub(crate) fn staging_recorder(
        chain: &Chainstate,
        fires: &Arc<Mutex<Vec<StagedFire>>>,
    ) -> TipStagedHook {
        let fires = Arc::clone(fires);
        let chain = chain.clone();
        Arc::new(move |staged, block| {
            let published = chain
                .applied_tip_snapshot()
                .map(|tip| (tip.hash, tip.height));
            fires.lock().push(StagedFire {
                staged_hash: staged.hash,
                staged_height: staged.height,
                block_hash: Hash256::from(block.block_hash()),
                published,
            });
        })
    }

    #[derive(Debug, thiserror::Error)]
    pub(crate) enum TestError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Var(#[from] std::env::VarError),
        #[error(transparent)]
        TryFromInt(#[from] std::num::TryFromIntError),
        #[error(transparent)]
        ParseInt(#[from] std::num::ParseIntError),
        #[error(transparent)]
        TryFromSlice(#[from] std::array::TryFromSliceError),
        #[error(transparent)]
        Storage(#[from] bitcoin_rs_storage::StorageError),
        #[error(transparent)]
        BoundedRead(#[from] bitcoin_rs_storage::BoundedReadError),
        #[error(transparent)]
        CheckpointLoad(#[from] bitcoin_rs_storage::checkpoint::CheckpointLoadError),
        #[error(transparent)]
        HistoryUnavailable(#[from] bitcoin_rs_storage::pruning::HistoryUnavailable),
        #[error(transparent)]
        Chain(#[from] crate::chain::ChainError),
        #[error(transparent)]
        HeaderAdmission(#[from] crate::HeaderAdmissionError),
        #[error(transparent)]
        RegtestFixture(#[from] crate::chain::regtest_fixture::RegtestFixtureError),
        #[error(transparent)]
        Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
        #[error(transparent)]
        Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
        #[error(transparent)]
        BlockSpends(#[from] bitcoin_rs_storage::utxo::contract::BlockSpendsError),
        #[error(transparent)]
        UndoLoad(#[from] bitcoin_rs_storage::utxo::contract::UndoLoadError),
        #[error(transparent)]
        BlockChange(#[from] bitcoin_rs_storage::utxo::contract::BlockChangeError),
        #[error(transparent)]
        Snapshot(#[from] bitcoin_rs_storage::utxo::core_snapshot::SnapshotError),
        #[error(transparent)]
        StateVerify(#[from] bitcoin_rs_storage::utxo::core_snapshot::StateVerifyError),
        #[error(transparent)]
        RawSeed(#[from] bitcoin_rs_storage::utxo::snapshot::RawSeedError<std::convert::Infallible>),
        #[error(transparent)]
        Apply(#[from] crate::ApplyError),
        #[error(transparent)]
        Disconnect(#[from] crate::DisconnectError),
        #[error(transparent)]
        Fuzz(#[from] crate::fuzzing::FuzzError),
        #[error(transparent)]
        AssumeUtxo(#[from] crate::assumeutxo::AssumeUtxoError),
        #[error(transparent)]
        Checkpoint(#[from] crate::CheckpointError),
        #[error(transparent)]
        HeaderCheckpoint(#[from] crate::checkpoint::headers::HeaderCheckpointError),
        #[error(transparent)]
        CheckpointSetup(#[from] crate::CheckpointSetupError),
        #[error(transparent)]
        DataDir(#[from] crate::events::DataDirError),
        #[error(transparent)]
        SnapshotAnchor(#[from] crate::SnapshotAnchorError),
        #[error(transparent)]
        BodyDecode(#[from] crate::verify::BodyDecodeError),
        #[error(transparent)]
        Verify(#[from] crate::verify::VerifyError),
        #[error(transparent)]
        Recovery(#[from] crate::recovery::RecoveryError),
        #[error(transparent)]
        Reorg(#[from] crate::reorg::ReorgError),
        #[error(transparent)]
        WindowApply(Box<crate::WindowApplyError>),
        #[error(transparent)]
        Sonic(#[from] sonic_rs::Error),
        #[error(transparent)]
        RecvTimeout(#[from] std::sync::mpsc::RecvTimeoutError),
        #[error("regrind {what} block: {source}")]
        Regrind {
            what: &'static str,
            #[source]
            source: crate::chain::regtest_fixture::RegtestFixtureError,
        },
        #[error("hook already installed: {0}")]
        HookAlreadyInstalled(&'static str),
        #[error("missing: {0}")]
        Missing(&'static str),
        #[error(transparent)]
        Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
        #[error("exhausted: {0}")]
        Exhausted(&'static str),
        #[error("worker panicked: {0}")]
        WorkerPanicked(&'static str),
        #[error("unexpected success: {0}")]
        UnexpectedSuccess(&'static str),
    }

    pub(crate) type TestResult<T = ()> = Result<T, TestError>;
    impl From<crate::WindowApplyError> for TestError {
        fn from(error: crate::WindowApplyError) -> Self {
            Self::WindowApply(Box::new(error))
        }
    }
    impl From<&'static str> for TestError {
        fn from(error: &'static str) -> Self {
            Self::Missing(error)
        }
    }

    pub(crate) type CoinScan = Vec<(Vec<u8>, Vec<u8>)>;

    pub(crate) fn coin_scan(chain: &Chainstate) -> Result<CoinScan, TestError> {
        let store = chain.commit_authority.store();
        store
            .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
            .collect::<Result<Vec<_>, _>>()
            .map_err(TestError::Storage)
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum CorpusSpend {
        MatureCoinbase { height: u32 },
        EarlierBlock { block: usize, tx: usize },
        SameBlock { tx: usize },
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct CorpusSpendPlan {
        pub spend: CorpusSpend,
    }

    #[derive(Clone, Debug, Default)]
    pub(crate) struct CorpusBlockPlan {
        pub spends: Vec<CorpusSpendPlan>,
    }

    pub(crate) struct Corpus {
        pub prefix: Vec<Block>,
        pub blocks: Vec<Block>,
    }

    pub(crate) const CORPUS_MATURITY_BLOCKS: u32 = 100;

    const CORPUS_SPEND_VALUE: u64 = 5_000_000_000;

    impl Corpus {
        pub(crate) fn build(plans: &[CorpusBlockPlan]) -> TestResult<Self> {
            let genesis = Network::Regtest.genesis_block();
            let mut parent = genesis.block_hash();
            let mut funded: Vec<Block> = Vec::new();
            for height in 1..=CORPUS_MATURITY_BLOCKS {
                let block = crate::chain::regtest_fixture::mined_regtest_child_at(parent, height)?;
                parent = block.block_hash();
                funded.push(block);
            }
            let mut generated: Vec<Block> = Vec::new();
            for (offset, plan) in plans.iter().enumerate() {
                let height = CORPUS_MATURITY_BLOCKS
                    + u32::try_from(offset)?
                        .checked_add(1)
                        .ok_or(TestError::Missing("corpus height overflow"))?;
                let mut block =
                    crate::chain::regtest_fixture::mined_regtest_child_at(parent, height)?;
                let mut created: Vec<Tx> = Vec::new();
                for spend in &plan.spends {
                    let previous_output = match spend.spend {
                        CorpusSpend::MatureCoinbase { height } => {
                            let index = usize::try_from(height)?
                                .checked_sub(1)
                                .ok_or(TestError::Missing("mature coinbase height"))?;
                            let coinbase = funded
                                .get(index)
                                .ok_or(TestError::Missing("mature coinbase block"))?;
                            OutPoint::new(coinbase.txs[0].txid(), 0)
                        }
                        CorpusSpend::EarlierBlock { block: index, tx } => {
                            let earlier = generated
                                .get(index)
                                .ok_or(TestError::Missing("earlier corpus block"))?;
                            let transaction = earlier
                                .txs
                                .get(tx + 1)
                                .ok_or(TestError::Missing("earlier corpus transaction"))?;
                            OutPoint::new(transaction.txid(), 0)
                        }
                        CorpusSpend::SameBlock { tx } => {
                            let transaction = created
                                .get(tx)
                                .ok_or(TestError::Missing("same-block transaction"))?;
                            OutPoint::new(transaction.txid(), 0)
                        }
                    };
                    created.push(corpus_spend_tx(previous_output));
                }
                block.txs.extend(created);
                block.header.merkle_root = crate::chain::regtest_fixture::merkle_root(&block.txs)
                    .ok_or(TestError::Missing("corpus merkle root"))?;
                crate::chain::regtest_fixture::mine_block_to_declared_target(&mut block)?;
                parent = block.block_hash();
                generated.push(block);
            }
            Ok(Self {
                prefix: funded,
                blocks: generated,
            })
        }

        pub(crate) fn payloads(&self) -> Vec<BlockImage> {
            self.blocks
                .iter()
                .map(|block| BlockImage::from_local(block.clone()))
                .collect()
        }
    }

    fn corpus_spend_tx(previous_output: OutPoint) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output,
                script_sig: vec![bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(CORPUS_SPEND_VALUE),
                script_pubkey: vec![bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    pub(crate) fn apply_headers(chain: &Chainstate, blocks: &[&Block]) -> TestResult {
        let headers: Vec<_> = blocks.iter().map(|block| block.header).collect();
        chain.admit_headers(&headers)?;
        Ok(())
    }

    pub(crate) fn commit_genesis_head(chain: &Chainstate) -> TestResult {
        let genesis = Network::Regtest.genesis_block();
        seed_durable_head(
            chain,
            bitcoin_rs_storage::DurableHead {
                assumeutxo: crate::AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 1,
                height: 0,
                tip: Hash256::from(genesis.block_hash()),
                chain_tx_count: 1,
                body_extent: None,
                undo_extent: None,
            },
        )
    }

    const CHURN_PREFIX_BLOCKS: u32 = 200;
    const CHURN_BLOCKS: u32 = 8;
    const CHURN_SPENDS_PER_BLOCK: u32 = 12;

    pub(crate) fn churn_corpus() -> TestResult<Corpus> {
        let mut parent = Network::Regtest.genesis_block().block_hash();
        let mut prefix = Vec::new();
        for height in 1..=CHURN_PREFIX_BLOCKS {
            let block = crate::chain::regtest_fixture::mined_regtest_child_at(parent, height)?;
            parent = block.block_hash();
            prefix.push(block);
        }
        let mut blocks = Vec::new();
        for block_index in 0..CHURN_BLOCKS {
            let height = CHURN_PREFIX_BLOCKS + 1 + block_index;
            let mut block = crate::chain::regtest_fixture::mined_regtest_child_at(parent, height)?;
            for spend in 0..CHURN_SPENDS_PER_BLOCK {
                let funded = usize::try_from(block_index * CHURN_SPENDS_PER_BLOCK + spend)?;
                let coinbase = prefix
                    .get(funded)
                    .ok_or(TestError::Missing("funded coinbase block"))?;
                block
                    .txs
                    .push(corpus_spend_tx(OutPoint::new(coinbase.txs[0].txid(), 0)));
            }
            block.header.merkle_root = crate::chain::regtest_fixture::merkle_root(&block.txs)
                .ok_or(TestError::Missing("churn merkle root"))?;
            crate::chain::regtest_fixture::mine_block_to_declared_target(&mut block)?;
            parent = block.block_hash();
            blocks.push(block);
        }
        Ok(Corpus { prefix, blocks })
    }

    pub(crate) fn funded_chain(
        corpus: &Corpus,
        limits: crate::window_limits::WindowLimits,
    ) -> TestResult<Chainstate> {
        let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        chain.set_capture_flags(false, true);
        chain.window_limits = Arc::new(move || limits);
        seed_genesis(&chain)?;
        commit_genesis_head(&chain)?;
        for block in &corpus.prefix {
            chain.apply_block(&BlockImage::from_local(block.clone()))?;
        }
        let blocks: Vec<&Block> = corpus.blocks.iter().collect();
        apply_headers(&chain, &blocks)?;
        Ok(chain)
    }
}

pub mod chain;
#[cfg(test)]
mod tests {
    use super::*;

    mod admission_tests {
        use std::sync::{Arc, mpsc};
        use std::time::Duration;

        use super::ApplyAdmission;
        use crate::ApplyError;

        #[test]
        fn shutdown_closes_admission_and_waits_for_in_flight_apply() {
            let admission = Arc::new(ApplyAdmission::new());
            let Ok(in_flight) = admission.enter() else {
                panic!("initial apply must be admitted");
            };
            let closing = Arc::clone(&admission);
            let (tx, rx) = mpsc::channel();
            let thread = std::thread::spawn(move || {
                let _exclusive = closing.close();
                assert!(tx.send(()).is_ok());
            });

            assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
            drop(in_flight);
            assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
            assert!(thread.join().is_ok());
            assert!(matches!(admission.enter(), Err(ApplyError::Shutdown)));
        }

        #[test]
        fn is_closed_for_recovery_tracks_the_fatal_close() {
            let chainstate = crate::test_fixtures::handles(
                bitcoin_rs_consensus::primitives::Network::Regtest,
                Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
            );
            assert!(
                !chainstate.is_closed_for_recovery(),
                "a fresh chainstate is open for mutation"
            );
            chainstate.fail_closed_for_recovery();
            assert!(
                chainstate.is_closed_for_recovery(),
                "failing closed must surface as the queryable recovery-closed fact"
            );
            assert!(
                matches!(chainstate.lock_transition(), Err(ApplyError::Shutdown)),
                "the same closure still refuses every later transition"
            );
        }

        #[test]
        fn shutdown_reader_unblocks_select_on_request_shutdown() {
            let chainstate = crate::test_fixtures::handles(
                bitcoin_rs_consensus::primitives::Network::Regtest,
                Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
            );
            let reader = chainstate.shutdown_reader();
            let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
            let (tx, rx) = crossbeam_channel::bounded(1);
            let thread = std::thread::spawn(move || {
                let _ = ready_tx.send(());
                crossbeam_channel::select! {
                    recv(reader.closed()) -> _ => {
                        let _ = tx.send(true);
                    }
                }
            });
            assert!(ready_rx.recv_timeout(Duration::from_secs(5)).is_ok());
            chainstate.request_shutdown();
            let unblocked = rx.recv_timeout(Duration::from_secs(5));
            assert!(
                unblocked.is_ok(),
                "select did not unblock on request_shutdown"
            );
            let _ = thread.join();
        }

        #[test]
        fn closed_for_recovery_reader_unblocks_select_on_fail_closed() {
            let chainstate = crate::test_fixtures::handles(
                bitcoin_rs_consensus::primitives::Network::Regtest,
                Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
            );
            let reader = chainstate.closed_for_recovery_reader();
            let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
            let (tx, rx) = crossbeam_channel::bounded(1);
            let thread = std::thread::spawn(move || {
                let _ = ready_tx.send(());
                crossbeam_channel::select! {
                    recv(reader.closed()) -> _ => {
                        let _ = tx.send(true);
                    }
                }
            });
            assert!(ready_rx.recv_timeout(Duration::from_secs(5)).is_ok());
            chainstate.fail_closed_for_recovery();
            let unblocked = rx.recv_timeout(Duration::from_secs(5));
            assert!(
                unblocked.is_ok(),
                "select did not unblock on fail_closed_for_recovery"
            );
            let _ = thread.join();
        }

        // ARCH-09
        #[test]
        fn shutdown_hooks_run_without_the_tip_gate() {
            use std::sync::atomic::{AtomicBool, Ordering};

            let chainstate = Arc::new(crate::test_fixtures::handles(
                bitcoin_rs_consensus::primitives::Network::Regtest,
                Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
            ));
            let gate_free = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&gate_free);
            let owner = Arc::clone(&chainstate);
            let _hook = chainstate.shutdown_reader().on_cancel(move || {
                observed.store(
                    owner.tip_notification.gate.try_lock().is_some(),
                    Ordering::SeqCst,
                );
            });
            chainstate.request_shutdown();
            assert!(
                gate_free.load(Ordering::SeqCst),
                "cancellation hooks must run without the tip gate held"
            );
        }

        // RCV-14
        #[test]
        fn recovery_closure_does_not_upgrade_an_apply_permit() {
            let admission = Arc::new(ApplyAdmission::new());
            let closing = Arc::clone(&admission);
            let (tx, rx) = mpsc::channel();
            let thread = std::thread::spawn(move || {
                let Ok(_permit) = closing.enter() else {
                    panic!("initial apply must be admitted");
                };
                closing.close_permanently();
                let _ = tx.send(());
            });
            assert!(rx.recv_timeout(Duration::from_secs(2)).is_ok());
            assert!(thread.join().is_ok());
            assert!(admission.is_closed());
            assert!(matches!(admission.enter(), Err(ApplyError::Shutdown)));
        }

        // RCV-14, SYNC-04
        #[test]
        fn recovery_closure_hooks_can_reenter_after_publication_unlocks() {
            let chain = Arc::new(crate::test_fixtures::handles(
                bitcoin_rs_consensus::primitives::Network::Regtest,
                Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
            ));
            let owner = Arc::clone(&chain);
            let _hook = chain.closed_for_recovery_reader().on_cancel(move || {
                assert!(owner.is_closed_for_recovery());
                owner.fail_closed_for_recovery();
            });
            let closing = Arc::clone(&chain);
            let (tx, rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                closing.fail_closed_for_recovery();
                let _ = tx.send(());
            });
            assert!(
                rx.recv_timeout(Duration::from_secs(2)).is_ok(),
                "recovery closure must return after its cancellation hook reenters closure"
            );
            assert!(worker.join().is_ok());
            assert!(chain.shutdown_reader().is_triggered());
            assert!(matches!(chain.lock_transition(), Err(ApplyError::Shutdown)));
        }
    }
    mod assumevalid_trust_tests {
        //! `AssumeValid` script trust fails closed and follows pin ancestry (#1742).

        use std::sync::Arc;

        use crate::chain::regtest_fixture::{
            merkle_root, mine_block_to_declared_target, mined_regtest_child_at as mined_child,
        };
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockHash, BlockImage, LockTime, Network, OutPoint, Sequence, Tx, TxIn,
            TxOut, Witness,
        };
        use bitcoin_rs_consensus::script::{
            VerifyFlags,
            opcode::{OP_PUSHNUM_1, OP_RETURN},
        };
        use bitcoin_rs_consensus::{ConsensusError, ValidationEngine};
        use bitcoin_rs_storage::utxo::UtxoSet;

        use super::{ApplyError, AssumeValidGate, BlockProvenance, Chainstate, ValidationMode};
        use crate::test_fixtures::{TestError, TestResult, handles, seed_genesis};

        struct SpendView(OutPoint, TxOut);

        impl bitcoin_rs_consensus::UtxoView for SpendView {
            fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
                (*outpoint == self.0).then(|| self.1.clone())
            }
        }

        fn remine(block: &mut Block) -> TestResult {
            block.header.merkle_root =
                merkle_root(&block.txs).ok_or(TestError::Missing("merkle root"))?;
            mine_block_to_declared_target(block)?;
            Ok(())
        }

        fn funded_chain() -> TestResult<(Chainstate, OutPoint, TxOut, BlockHash)> {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            let mut funding = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
            funding.txs[0].outputs = vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: vec![OP_PUSHNUM_1].into(),
            }];
            remine(&mut funding)?;
            chain.apply_block(&BlockImage::from_local(funding.clone()))?;
            let outpoint = OutPoint::new(funding.txs[0].txid(), 0);
            let prevout = funding.txs[0].outputs[0].clone();
            let mut parent = funding.block_hash();
            for height in 2..=100 {
                let child = mined_child(parent, height)?;
                chain.apply_block(&BlockImage::from_local(child.clone()))?;
                parent = child.block_hash();
            }
            Ok((chain, outpoint, prevout, parent))
        }

        fn spend_tx(funding: OutPoint, opcode: u8) -> Tx {
            Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: funding,
                    script_sig: vec![opcode].into(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: vec![OP_PUSHNUM_1].into(),
                }],
                lock_time: LockTime::ZERO,
            }
        }

        fn spend_block(parent: BlockHash, funding: OutPoint, opcode: u8) -> TestResult<Block> {
            let mut block = mined_child(parent, 101)?;
            block.txs.push(spend_tx(funding, opcode));
            remine(&mut block)?;
            Ok(block)
        }

        fn check_script_verdict(block: &Block, prevout: &TxOut) -> Result<(), ConsensusError> {
            let spend = &block.txs[1];
            bitcoin_rs_consensus::verify_transaction(
                spend,
                &SpendView(spend.inputs[0].previous_output, prevout.clone()),
                101,
                0,
                VerifyFlags::MANDATORY,
                ValidationEngine::Native,
                None,
            )
        }

        fn assert_script_invalid(block: &Block, prevout: &TxOut) {
            let verdict = check_script_verdict(block, prevout);
            assert!(
                matches!(verdict, Err(ConsensusError::Script { .. })),
                "the fixture spend must be script-invalid, got {verdict:?}"
            );
        }

        fn assert_script_valid(block: &Block, prevout: &TxOut) -> TestResult {
            check_script_verdict(block, prevout)?;
            Ok(())
        }

        fn assert_rejected_unchanged(
            chain: &Chainstate,
            result: &Result<crate::ConnectOutcome, ApplyError>,
            funding: &OutPoint,
            tip_before: bitcoin_rs_consensus::primitives::Hash256,
        ) -> TestResult {
            assert!(
                matches!(
                    result,
                    Err(ApplyError::Consensus(ConsensusError::Script { .. }))
                ),
                "the script-invalid spend must be rejected, got {result:?}"
            );
            assert_eq!(
                chain
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("tip"))?
                    .hash,
                tip_before
            );
            assert!(
                chain.utxo_reader().get(funding)?.is_some(),
                "the funding coin must stay unspent"
            );
            Ok(())
        }

        #[test]
        fn assume_valid_without_matching_pin_does_not_skip_scripts() -> TestResult {
            let (mut chain, funding, prevout, parent) = funded_chain()?;
            let invalid = spend_block(parent, funding, OP_RETURN)?;
            assert_script_invalid(&invalid, &prevout);
            chain.validation_mode = ValidationMode::AssumeValid;
            chain.assume_valid_height = 101;
            chain.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(None));
            chain.assume_valid_gate.evaluate(&chain.block_tree.read());
            let tip_before = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("tip"))?
                .hash;
            let failed = chain.apply_block(&BlockImage::from_local(invalid));
            assert_rejected_unchanged(&chain, &failed, &funding, tip_before)?;
            Ok(())
        }

        #[test]
        fn assume_valid_sibling_below_the_pin_runs_scripts() -> TestResult {
            let (mut chain, funding, prevout, parent) = funded_chain()?;
            let pin = spend_block(parent, funding, OP_PUSHNUM_1)?;
            assert_script_valid(&pin, &prevout)?;
            let mut successor = mined_child(pin.block_hash(), 102)?;
            remine(&mut successor)?;
            let sibling = spend_block(parent, funding, OP_RETURN)?;
            assert_script_invalid(&sibling, &prevout);
            chain.admit_headers(&[pin.header, successor.header, sibling.header])?;
            chain.validation_mode = ValidationMode::AssumeValid;
            chain.assume_valid_height = 101;
            chain.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((
                101,
                pin.block_hash().0,
            ))));
            chain.assume_valid_gate.evaluate(&chain.block_tree.read());
            assert!(
                chain.scripts_verified_upstream(BlockProvenance::Network, 101, pin.block_hash().0),
                "the pin itself is the reachability control"
            );
            let tip_before = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("tip"))?
                .hash;
            let failed = chain.apply_block(&BlockImage::from_local(sibling));
            assert_rejected_unchanged(&chain, &failed, &funding, tip_before)?;
            Ok(())
        }

        #[test]
        fn assume_valid_pin_at_its_own_height_still_skips_scripts() -> TestResult {
            let (mut chain, funding, prevout, parent) = funded_chain()?;
            let pin = spend_block(parent, funding, OP_PUSHNUM_1)?;
            assert_script_valid(&pin, &prevout)?;
            let mut successor = mined_child(pin.block_hash(), 102)?;
            remine(&mut successor)?;
            chain.admit_headers(&[pin.header, successor.header])?;
            chain.validation_mode = ValidationMode::AssumeValid;
            chain.assume_valid_height = 101;
            chain.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((
                101,
                pin.block_hash().0,
            ))));
            chain.assume_valid_gate.evaluate(&chain.block_tree.read());
            assert!(
                chain.scripts_verified_upstream(BlockProvenance::Network, 101, pin.block_hash().0),
                "the pin is on the best header chain and may skip"
            );
            chain.apply_block(&BlockImage::from_local(pin))?;
            assert_eq!(
                chain
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("tip"))?
                    .height,
                101
            );
            Ok(())
        }

        #[test]
        fn assume_valid_trust_is_revoked_when_a_reorg_drops_the_pin() -> TestResult {
            let (mut chain, funding, prevout, parent) = funded_chain()?;
            let pin = spend_block(parent, funding, OP_PUSHNUM_1)?;
            let mut pin_successor = mined_child(pin.block_hash(), 102)?;
            remine(&mut pin_successor)?;
            let branch_block = spend_block(parent, funding, OP_RETURN)?;
            assert_script_invalid(&branch_block, &prevout);
            let mut branch_second = mined_child(branch_block.block_hash(), 102)?;
            remine(&mut branch_second)?;
            let mut branch_third = mined_child(branch_second.block_hash(), 103)?;
            remine(&mut branch_third)?;
            chain.admit_headers(&[
                pin.header,
                pin_successor.header,
                branch_block.header,
                branch_second.header,
                branch_third.header,
            ])?;
            chain.validation_mode = ValidationMode::AssumeValid;
            chain.assume_valid_height = 101;
            chain.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((
                101,
                pin.block_hash().0,
            ))));
            chain.assume_valid_gate.evaluate(&chain.block_tree.read());
            let tip_before = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("tip"))?
                .hash;
            let failed = chain.apply_block(&BlockImage::from_local(branch_block));
            assert_rejected_unchanged(&chain, &failed, &funding, tip_before)?;
            Ok(())
        }
    }
    mod chain_tx_count_tests {
        use super::*;

        #[test]
        fn genesis_establishes_the_count_from_nothing() {
            assert_eq!(ChainTxCount::UNKNOWN, ChainTxCount::from_wire(0));
            assert_eq!(
                ChainTxCount::UNKNOWN.advance(0, 1),
                ChainTxCount::established(1)
            );
        }

        #[test]
        fn an_unknown_count_stays_unknown_above_genesis() {
            assert_eq!(
                ChainTxCount::UNKNOWN.advance(900_000, 2_500),
                ChainTxCount::UNKNOWN
            );
        }

        // RCV-13
        #[test]
        fn a_known_count_advances_and_rewinds_by_the_same_delta() {
            let counted = ChainTxCount::UNKNOWN
                .advance(0, 1)
                .advance(1, 7)
                .advance(2, 3);
            assert_eq!(counted, ChainTxCount::established(11));

            let rewound = counted.rewind(3).rewind(7);
            assert_eq!(rewound, ChainTxCount::established(1));
        }

        #[test]
        fn rewinding_an_unknown_count_leaves_it_unknown() {
            assert_eq!(ChainTxCount::UNKNOWN.rewind(5), ChainTxCount::UNKNOWN);
        }

        // RCV-13
        #[test]
        fn a_rewind_past_zero_admits_it_does_not_know_rather_than_clamping() {
            assert_eq!(
                ChainTxCount::established(4).rewind(9),
                ChainTxCount::UNKNOWN
            );
        }

        // RCV-13
        #[test]
        fn an_advance_past_u64_marks_the_count_unknown_instead_of_wrapping() {
            assert_eq!(
                ChainTxCount::established(u64::MAX - 1).advance(900_000, 3),
                ChainTxCount::UNKNOWN
            );
        }

        // RCV-13
        #[test]
        fn the_wire_encoding_round_trips_the_unknown_sentinel() {
            assert_eq!(ChainTxCount::from_wire(0), ChainTxCount::UNKNOWN);
            assert_eq!(ChainTxCount::UNKNOWN.to_wire(), 0);
            assert_eq!(ChainTxCount::from_wire(11).get(), Some(11));
            assert_eq!(ChainTxCount::established(11).to_wire(), 11);
        }
    }
    mod checkpoint_debt_tests {
        use std::collections::BTreeSet;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Network};
        use bitcoin_rs_storage::StorageError;
        use bitcoin_rs_storage::block_body::BlockBodyStore;
        use bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT;
        use bitcoin_rs_storage::utxo::UtxoSet;

        use crate::CheckpointError;
        use crate::test_fixtures::TestResult;
        use crate::test_support::MemoryBodies;

        fn checkpoint_dirs(root: &std::path::Path) -> TestResult<BTreeSet<String>> {
            let mut dirs = BTreeSet::new();
            for entry in std::fs::read_dir(root)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    dirs.insert(entry.file_name().to_string_lossy().into_owned());
                }
            }
            Ok(dirs)
        }

        #[test]
        fn checkpoint_refuses_inflight_disconnect_and_preserves_state() -> TestResult {
            let dir = tempfile::tempdir()?;
            let network = Network::Regtest;
            let mut handles = crate::test_fixtures::handles(network, Arc::new(UtxoSet::new()));
            handles.block_body_store = Some(Arc::new(MemoryBodies::default()));
            handles.apply_block(&BlockImage::from_local(network.genesis_block()))?;
            handles.configure_checkpointing(dir.path(), Arc::new(AtomicU32::new(0)))?;
            assert!(handles.publish_checkpoint()?.is_some());

            let checkpoint_root = dir.path().join(CHECKPOINT_ROOT);
            let armed_hash = Hash256::from_le_bytes(&[0xab; 32]);
            let armed_height = 10;
            handles
                .undo_store
                .arm_disconnect(armed_height, armed_hash)?;
            let marker_before = handles.undo_store.load_disconnect_marker()?;
            let current_before = std::fs::read(checkpoint_root.join("CURRENT"))?;
            let dirs_before = checkpoint_dirs(&checkpoint_root)?;

            let result = handles.publish_checkpoint();
            let Err(CheckpointError::DisconnectInFlight { hash, height }) = result else {
                panic!("expected DisconnectInFlight refusal, got {result:?}");
            };
            assert_eq!(hash, armed_hash);
            assert_eq!(height, armed_height);

            assert_eq!(handles.undo_store.load_disconnect_marker()?, marker_before);
            assert_eq!(
                std::fs::read(checkpoint_root.join("CURRENT"))?,
                current_before
            );
            assert_eq!(checkpoint_dirs(&checkpoint_root)?, dirs_before);
            Ok(())
        }

        // RCV-14, SYNC-04
        #[test]
        fn checkpoint_refuses_a_closed_for_recovery_chainstate() -> TestResult {
            let dir = tempfile::tempdir()?;
            let network = Network::Regtest;
            let mut handles = crate::test_fixtures::handles(network, Arc::new(UtxoSet::new()));
            handles.block_body_store = Some(Arc::new(MemoryBodies::default()));
            handles.apply_block(&BlockImage::from_local(network.genesis_block()))?;
            handles.configure_checkpointing(dir.path(), Arc::new(AtomicU32::new(0)))?;
            assert!(handles.publish_checkpoint()?.is_some());

            let checkpoint_root = dir.path().join(CHECKPOINT_ROOT);
            let current_before = std::fs::read(checkpoint_root.join("CURRENT"))?;
            let dirs_before = checkpoint_dirs(&checkpoint_root)?;

            handles.fail_closed_for_recovery();
            let result = handles.publish_checkpoint();
            let Err(CheckpointError::ClosedForRecovery) = result else {
                panic!("expected ClosedForRecovery refusal, got {result:?}");
            };

            assert_eq!(
                std::fs::read(checkpoint_root.join("CURRENT"))?,
                current_before
            );
            assert_eq!(checkpoint_dirs(&checkpoint_root)?, dirs_before);
            Ok(())
        }

        struct PausedBodySync {
            inner: MemoryBodies,
            pause: AtomicBool,
            entered: mpsc::SyncSender<()>,
            release: parking_lot::Mutex<mpsc::Receiver<()>>,
        }

        impl BlockBodyStore for PausedBodySync {
            fn persist_block_body(
                &self,
                height: u32,
                hash: Hash256,
                body: &[u8],
            ) -> Result<(), StorageError> {
                self.inner.persist_block_body(height, hash, body)
            }

            fn load_block_body(
                &self,
                height: u32,
                hash: Hash256,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                self.inner.load_block_body(height, hash)
            }

            fn sync(&self) -> Result<(), StorageError> {
                if self.pause.swap(false, Ordering::AcqRel) {
                    self.entered.send(()).map_err(StorageError::backend)?;
                    self.release.lock().recv().map_err(StorageError::backend)?;
                }
                Ok(())
            }
        }

        // RCV-14, SYNC-04
        #[test]
        fn recovery_closure_waits_for_admitted_checkpoint_and_refuses_later_publication()
        -> TestResult {
            let dir = tempfile::tempdir()?;
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::channel();
            let bodies = Arc::new(PausedBodySync {
                inner: MemoryBodies::default(),
                pause: AtomicBool::new(false),
                entered: entered_tx,
                release: parking_lot::Mutex::new(release_rx),
            });
            let mut chain =
                crate::test_fixtures::handles(Network::Regtest, Arc::new(UtxoSet::new()));
            chain.block_body_store = Some(bodies.clone());
            chain.apply_block(&BlockImage::from_local(Network::Regtest.genesis_block()))?;
            chain.configure_checkpointing(dir.path(), Arc::new(AtomicU32::new(0)))?;
            assert!(chain.publish_checkpoint()?.is_some());
            let root = dir.path().join(CHECKPOINT_ROOT);
            let previous = std::fs::read(root.join("CURRENT"))?;

            bodies.pause.store(true, Ordering::Release);
            let publishing = chain.clone();
            let publisher = std::thread::spawn(move || publishing.publish_checkpoint());
            entered_rx.recv_timeout(Duration::from_secs(2))?;
            let closing = chain.clone();
            let (closed_tx, closed_rx) = mpsc::channel();
            let closer = std::thread::spawn(move || {
                closing.fail_closed_for_recovery();
                let _ = closed_tx.send(());
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while !chain.admission.close_attempted.load(Ordering::Acquire) {
                if Instant::now() >= deadline {
                    let _ = release_tx.send(());
                    panic!("recovery closure never attempted the publication mutex");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let blocked = closed_rx.recv_timeout(Duration::from_millis(50));
            let closed_during_publication = chain.is_closed_for_recovery();
            release_tx.send(()).map_err(StorageError::backend)?;
            let published = publisher
                .join()
                .map_err(|_| "checkpoint thread panicked")??;
            closer
                .join()
                .map_err(|_| "recovery closure thread panicked")?;
            assert!(matches!(blocked, Err(mpsc::RecvTimeoutError::Timeout)));
            assert!(!closed_during_publication);
            assert!(published.is_some());
            assert!(chain.is_closed_for_recovery());
            assert!(chain.shutdown_reader().is_triggered());
            let current = std::fs::read(root.join("CURRENT"))?;
            assert_ne!(
                current, previous,
                "the admitted checkpoint precedes closure"
            );
            let directories = checkpoint_dirs(&root)?;
            assert!(matches!(
                chain.publish_checkpoint(),
                Err(CheckpointError::ClosedForRecovery)
            ));
            assert_eq!(std::fs::read(root.join("CURRENT"))?, current);
            assert_eq!(checkpoint_dirs(&root)?, directories);
            Ok(())
        }
    }
    mod coin_read_fault_tests {
        //! Coin-store read faults must surface as storage errors, never as block verdicts.

        #![allow(clippy::expect_used)]

        use std::collections::HashSet;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use crate::chain::regtest_fixture::{
            merkle_root, mine_block_to_declared_target, mined_regtest_child_at as mined_child,
        };
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockImage, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx,
            TxIn, TxOut, Witness,
        };
        use bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1;
        use bitcoin_rs_storage::commit::AcceptedPrefix;
        use bitcoin_rs_storage::durable_head::DurableHead;
        use bitcoin_rs_storage::memory_kv::MemoryKvStore;
        use bitcoin_rs_storage::utxo::UtxoSet;
        use bitcoin_rs_storage::{
            BufferedWriteBatch, CoinKey, ColumnFamily, KvIter, KvSnapshot, KvStore, PersistFault,
            PrefixScan, PrefixScanLimit, StorageError, WindowDelta, WriteCondition,
        };
        use parking_lot::Mutex;

        use crate::test_fixtures::{TestError, TestResult, handles_with_store, seed_genesis};
        use crate::{ApplyError, Chainstate, DisconnectError, WindowApplyDisposition};

        struct PoisonedStore {
            inner: MemoryKvStore,
            poisoned_keys: Mutex<HashSet<Vec<u8>>>,
            fail_multi_get: AtomicBool,
        }

        impl PoisonedStore {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    inner: MemoryKvStore::default(),
                    poisoned_keys: Mutex::new(HashSet::new()),
                    fail_multi_get: AtomicBool::new(false),
                })
            }

            fn poison_key(&self, key: &CoinKey) {
                self.poisoned_keys.lock().insert(key.as_bytes().to_vec());
            }

            fn fail_multi_get(&self) {
                self.fail_multi_get.store(true, Ordering::SeqCst);
            }

            fn injected() -> StorageError {
                StorageError::Io(std::io::Error::other("injected coin read failure"))
            }
        }

        impl KvStore for PoisonedStore {
            fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
                if cf == ColumnFamily::Coins && self.poisoned_keys.lock().contains(key) {
                    return Err(Self::injected());
                }
                self.inner.get(cf, key)
            }

            fn iter_prefix<'a>(
                &'a self,
                cf: ColumnFamily,
                prefix: &[u8],
            ) -> Result<KvIter<'a>, StorageError> {
                self.inner.iter_prefix(cf, prefix)
            }

            fn scan_prefix_from_bounded(
                &self,
                cf: ColumnFamily,
                prefix: &[u8],
                start: &[u8],
                limit: PrefixScanLimit,
            ) -> Result<PrefixScan, StorageError> {
                self.inner
                    .scan_prefix_from_bounded(cf, prefix, start, limit)
            }

            fn new_batch(&self) -> BufferedWriteBatch {
                self.inner.new_batch()
            }

            fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
                self.inner.write(batch)
            }

            fn write_durable_if(
                &self,
                conditions: &[WriteCondition<'_>],
                batch: BufferedWriteBatch,
            ) -> Result<bool, StorageError> {
                self.inner.write_durable_if(conditions, batch)
            }

            fn flush(&self) -> Result<(), StorageError> {
                self.inner.flush()
            }

            fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
                self.inner.snapshot()
            }

            fn multi_get(
                &self,
                cf: ColumnFamily,
                keys: &[&[u8]],
            ) -> Result<Vec<Option<bitcoin_rs_storage::Bytes>>, StorageError> {
                if cf == ColumnFamily::Coins {
                    if self.fail_multi_get.load(Ordering::SeqCst) {
                        return Err(Self::injected());
                    }
                    let poisoned = self.poisoned_keys.lock();
                    if keys.iter().any(|key| poisoned.contains(*key)) {
                        return Err(Self::injected());
                    }
                }
                self.inner.multi_get(cf, keys)
            }

            fn ingest_sorted(
                &self,
                cf: ColumnFamily,
                rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
                scratch: &std::path::Path,
            ) -> Result<u64, StorageError> {
                self.inner.ingest_sorted(cf, rows, scratch)
            }

            fn delete_range(
                &self,
                cf: ColumnFamily,
                start: &[u8],
                end: &[u8],
            ) -> Result<(), StorageError> {
                self.inner.delete_range(cf, start, end)
            }

            fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
                self.inner.checkpoint(dir)
            }

            fn engine_cache_bytes(&self) -> u64 {
                self.inner.engine_cache_bytes()
            }

            #[cfg(any(test, feature = "test-seam"))]
            fn arm_persist_fault(&self, fault: PersistFault) {
                self.inner.arm_persist_fault(fault);
            }
        }

        struct CoinReadFixture {
            chain: Chainstate,
            store: Arc<PoisonedStore>,
            payload: BlockImage,
            block: Block,
            coin_key: CoinKey,
        }

        fn coin_read_fixture() -> TestResult<CoinReadFixture> {
            let store = PoisonedStore::new();
            let chain =
                handles_with_store(Network::Regtest, Arc::new(UtxoSet::new()), store.clone());
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let genesis = Network::Regtest.genesis_block();
            let owner_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let coin_txid = owner_tx.txid();
            let coin_key = CoinKey(coin_txid.0.to_le_bytes());
            let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
                coin_txid.0,
                &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                    vout: 0,
                    value: 50_000,
                    script_pubkey: vec![OP_PUSHNUM_1],
                    coinbase: false,
                    height: 0,
                }],
            )
            .map_err(|_| TestError::Missing("synthetic coin record"))?;
            store.put(ColumnFamily::Coins, coin_key.as_bytes(), record.bytes())?;

            let spend_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(coin_txid, 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let mut block: Block = mined_child(genesis.block_hash(), 1)?;
            block.txs.push(spend_tx);
            block.header.merkle_root =
                merkle_root(&block.txs).ok_or(TestError::Missing("merkle root"))?;
            mine_block_to_declared_target(&mut block)?;
            chain.admit_headers(&[block.header])?;

            Ok(CoinReadFixture {
                chain,
                store,
                payload: BlockImage::from_local(block.clone()),
                block,
                coin_key,
            })
        }

        fn commit_genesis_head(chain: &Chainstate) -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            chain
                .commit_authority
                .commit_prefix(AcceptedPrefix {
                    expected_head: None,
                    next_head: DurableHead {
                        assumeutxo: crate::AssumeUtxoDiskStatus::Uninitialized,
                        commit_id: 1,
                        height: 0,
                        tip: Hash256::from(genesis.block_hash()),
                        chain_tx_count: 1,
                        body_extent: None,
                        undo_extent: None,
                    },
                    undo_rows: Vec::new(),
                    body_rows: Vec::new(),
                    attestation: None,
                    coin_delta: WindowDelta::default(),
                })
                .map_err(|error| {
                    TestError::Missing(match error {
                        bitcoin_rs_storage::CommitError::Storage(_) => {
                            "genesis head storage failure"
                        }
                        bitcoin_rs_storage::CommitError::AdmissionClosed => {
                            "genesis head admission closed"
                        }
                        bitcoin_rs_storage::CommitError::PreconditionFailed => {
                            "genesis head precondition"
                        }
                    })
                })?;
            Ok(())
        }

        // CMT-04
        #[test]
        fn validate_block_reports_coin_read_errors() -> TestResult {
            let fixture = coin_read_fixture()?;
            fixture.store.poison_key(&fixture.coin_key);
            let Err(error) = fixture.chain.validate_block(&fixture.payload) else {
                return Err(TestError::UnexpectedSuccess(
                    "a coin read failure must not read as a valid block",
                ));
            };
            assert!(
                matches!(error, ApplyError::CoinStoreRead(_)),
                "expected a typed coin store read error, got: {error}"
            );
            Ok(())
        }

        // CMT-04
        #[test]
        fn window_prepare_coin_read_error_is_fatal() -> TestResult {
            let fixture = coin_read_fixture()?;
            fixture.store.fail_multi_get();

            let Err(error) = fixture.chain.apply_window(&[&fixture.payload]) else {
                return Err(TestError::UnexpectedSuccess(
                    "a coin read failure must refuse the window",
                ));
            };
            assert!(
                matches!(error.source.as_ref(), ApplyError::CoinStoreRead(_)),
                "expected a typed coin store read error, got: {error}"
            );
            assert_eq!(error.disposition, WindowApplyDisposition::Fatal);

            let head = fixture
                .chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(
                head.height, 0,
                "the refused window must not advance the head"
            );
            Ok(())
        }

        // CMT-04
        #[test]
        fn coin_read_error_never_invalidates_the_block() -> TestResult {
            let fixture = coin_read_fixture()?;
            fixture.store.poison_key(&fixture.coin_key);
            let result = {
                let _fault = crate::window::prepare_fault::arm();
                fixture.chain.apply_window(&[&fixture.payload])
            };
            let Err(error) = result else {
                return Err(TestError::UnexpectedSuccess(
                    "a coin read failure must refuse the window",
                ));
            };
            assert!(
                matches!(error.source.as_ref(), ApplyError::CoinStoreRead(_)),
                "expected a typed coin store read error, got: {error}"
            );
            assert_eq!(error.disposition, WindowApplyDisposition::Fatal);
            assert!(
                error.invalidated.is_empty(),
                "a transient coin read failure must not invalidate a block: {:?}",
                error.invalidated
            );

            let head = fixture
                .chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(
                head.height, 0,
                "the refused window must not advance the head"
            );
            Ok(())
        }

        // CMT-04
        #[test]
        fn disconnect_coin_read_error_is_fatal_and_keeps_the_committed_head() -> TestResult {
            let fixture = coin_read_fixture()?;
            fixture.chain.apply_block(&fixture.payload)?;

            let head_before = fixture
                .chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            let tip_before = fixture
                .chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("applied tip"))?;
            let spend_outpoint = OutPoint::new(fixture.block.txs[1].txid(), 0);
            fixture.store.fail_multi_get();

            let Err(DisconnectError::Fatal {
                hash,
                height,
                source,
            }) = fixture.chain.disconnect_block(&fixture.block)
            else {
                return Err(TestError::UnexpectedSuccess(
                    "a coin read failure must refuse the disconnect",
                ));
            };
            assert_eq!(hash, Hash256::from(fixture.block.block_hash()));
            assert_eq!(height, 1);
            let ApplyError::CoinStoreRead(storage_error) = source.as_ref() else {
                return Err(TestError::Missing(
                    "the fatal disconnect must carry a coin store read error",
                ));
            };
            assert!(
                matches!(
                    storage_error,
                    StorageError::Io(injected) if injected.kind() == std::io::ErrorKind::Other
                ),
                "the fatal source must be the injected coin read fault, got {storage_error}"
            );

            let head_after = fixture
                .chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(
                head_after.height, head_before.height,
                "a failed disconnect must not move the committed head height"
            );
            assert_eq!(
                head_after.tip, head_before.tip,
                "a failed disconnect must not move the committed head tip"
            );
            assert_eq!(
                head_after.commit_id, head_before.commit_id,
                "a failed disconnect must not commit a new head"
            );
            let tip_after = fixture
                .chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("applied tip"))?;
            assert_eq!(
                tip_after.hash, tip_before.hash,
                "a failed disconnect must not move the applied tip"
            );
            assert!(
                fixture.chain.utxo_reader().get(&spend_outpoint)?.is_some(),
                "a failed disconnect must not drop the connected block's coins"
            );
            Ok(())
        }
    }
    mod facts_attach_tests {
        use std::sync::Arc;

        use bitcoin_rs_consensus::primitives::{
            Amount, BlockImage, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
            Witness,
        };
        use bitcoin_rs_storage::utxo::UtxoSet;

        use crate::chain::regtest_fixture::{
            coinbase, mined_block_with_prev_hash, mined_regtest_child_at as mined_child,
        };
        use crate::test_fixtures::{TestError, TestResult, handles, seed_genesis};

        // CMT-09
        #[test]
        fn connect_builds_no_facts_without_a_consumer() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            let genesis = Network::Regtest.genesis_block();
            let outcome = chain.apply_block(&BlockImage::from_local(mined_child(
                genesis.block_hash(),
                1,
            )?))?;

            assert!(
                outcome.committed_facts.is_none(),
                "no consumer is attached, so the connect must not build facts"
            );
            assert_eq!(
                chain.committed_facts_builds(),
                0,
                "no consumer is attached, so no CommittedFacts may be constructed"
            );
            Ok(())
        }

        // CMT-09
        #[test]
        fn connect_hands_facts_to_an_attached_consumer_unchanged() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            chain.set_committed_facts_consumer(true);
            seed_genesis(&chain)?;
            let genesis = Network::Regtest.genesis_block();
            let block = mined_child(genesis.block_hash(), 1)?;
            let expected_hash = *block.block_hash().as_bytes();
            let expected_txs = block.txs.len();
            let outcome = chain.apply_block(&BlockImage::from_local(block))?;

            assert_eq!(chain.committed_facts_builds(), 1);
            let facts = outcome
                .committed_facts
                .as_ref()
                .ok_or(TestError::Missing("attached consumer must receive facts"))?;
            assert_eq!(facts.commit_id, outcome.commit_id);
            assert_eq!(facts.blocks.len(), 1);
            assert_eq!(facts.blocks[0].height, 1);
            assert_eq!(facts.blocks[0].hash, expected_hash);
            assert_eq!(facts.blocks[0].txs.len(), expected_txs);
            Ok(())
        }

        fn spend(previous_output: OutPoint, value: u64) -> Tx {
            Tx {
                version: 1,
                inputs: vec![TxIn {
                    previous_output,
                    script_sig: Script::from_bytes(vec![0x51]),
                    sequence: Sequence::from_consensus(0xffff_ffff),
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                }],
                lock_time: LockTime::ZERO,
            }
        }

        // CMT-09
        #[test]
        fn attached_consumer_receives_spend_prevouts_and_scripts_unchanged() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            chain.set_committed_facts_consumer(true);
            seed_genesis(&chain)?;
            let mut parent = Network::Regtest.genesis_block().block_hash();
            for height in 1..=100 {
                let block = mined_block_with_prev_hash(parent, height, vec![coinbase(height)])?;
                chain.apply_block(&BlockImage::from_local(block.clone()))?;
                parent = block.block_hash();
            }

            let funding = coinbase(1);
            let funded = funding.outputs[0].clone();
            let spending = spend(OutPoint::new(funding.txid(), 0), 1_000);
            let block =
                mined_block_with_prev_hash(parent, 101, vec![coinbase(101), spending.clone()])?;
            let outcome = chain.apply_block(&BlockImage::from_local(block.clone()))?;

            let facts = outcome
                .committed_facts
                .as_ref()
                .ok_or(TestError::Missing("attached consumer must receive facts"))?;
            assert_eq!(facts.blocks.len(), 1);
            let committed = &facts.blocks[0];
            assert_eq!(committed.height, 101);
            assert_eq!(committed.hash, *block.block_hash().as_bytes());
            assert_eq!(committed.txs.len(), 2);

            let coinbase_facts = &committed.txs[0];
            assert!(coinbase_facts.inputs.is_empty());
            assert_eq!(coinbase_facts.outputs.len(), 1);
            assert_eq!(
                coinbase_facts.outputs[0].script.as_ref(),
                coinbase(101).outputs[0].script_pubkey.as_bytes()
            );

            let spend_facts = &committed.txs[1];
            assert_eq!(spend_facts.txid, *spending.txid().as_bytes());
            assert_eq!(spend_facts.inputs.len(), 1);
            let input = &spend_facts.inputs[0];
            assert_eq!(input.txid, *funding.txid().as_bytes());
            assert_eq!(input.vout, 0);
            assert_eq!(input.value, funded.value.to_sat());
            assert_eq!(input.script.as_ref(), funded.script_pubkey.as_bytes());
            assert_eq!(input.height, 1);
            assert!(input.coinbase);
            assert_eq!(spend_facts.outputs.len(), 1);
            assert_eq!(spend_facts.outputs[0].vout, 0);
            assert_eq!(spend_facts.outputs[0].value, 1_000);
            assert_eq!(
                spend_facts.outputs[0].script.as_ref(),
                spending.outputs[0].script_pubkey.as_bytes()
            );
            Ok(())
        }
    }
    mod facts_commit_id_tests {
        //! Committed facts carry the durable commit id (#PRJ-01).

        use std::sync::Arc;

        use crate::chain::regtest_fixture::mined_regtest_child_at as mined_child;
        use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Network};
        use bitcoin_rs_storage::utxo::UtxoSet;
        use bitcoin_rs_storage::{DurableHead, assumeutxo::AssumeUtxoDiskStatus};

        use super::Chainstate;
        use crate::test_fixtures::{TestResult, handles, seed_durable_head, seed_genesis};

        fn commit_genesis_head(chain: &Chainstate) -> TestResult<u64> {
            let genesis = Network::Regtest.genesis_block();
            let head = DurableHead {
                assumeutxo: AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 1,
                height: 0,
                tip: Hash256::from(genesis.block_hash()),
                chain_tx_count: 1,
                body_extent: None,
                undo_extent: None,
            };
            let commit_id = head.commit_id;
            seed_durable_head(chain, head)?;
            Ok(commit_id)
        }

        // PRJ-01
        #[test]
        fn committed_facts_carry_the_durable_commit_id() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            chain.set_committed_facts_consumer(true);
            seed_genesis(&chain)?;
            let genesis_commit = commit_genesis_head(&chain)?;

            let child = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
            let outcome = chain.apply_block(&BlockImage::from_local(child.clone()))?;

            assert!(outcome.commit_id > genesis_commit);
            let facts = outcome.committed_facts.as_ref().ok_or(
                crate::test_fixtures::TestError::Missing("committed facts on the live path"),
            )?;
            assert_eq!(
                facts.commit_id, outcome.commit_id,
                "facts must carry the commit id of the batch that published them"
            );
            assert_eq!(facts.blocks.len(), 1);
            assert_eq!(facts.blocks[0].height, 1);
            assert_eq!(facts.blocks[0].hash, *child.block_hash().as_bytes());
            Ok(())
        }
    }
    mod observability_tests {
        use std::sync::Arc;

        use bitcoin_rs_consensus::primitives::{BlockImage, Network};
        use bitcoin_rs_storage::utxo::UtxoSet;
        use hashbrown::HashSet;
        use metrics::{
            Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata,
            Recorder, SharedString, Unit,
        };
        use parking_lot::Mutex;

        use crate::chain::regtest_fixture::mined_regtest_child_at as mined_child;

        use crate::test_fixtures::{TestError, TestResult, handles, seed_genesis};

        const RETIRED_APPLY_METRICS: &[&str] = &[
            "node.apply_block.contextual_header_seconds",
            "node.apply_block.pow_self_consistency_seconds",
            "node.apply_block.coinbase_maturity_seconds",
            "node.apply_block.bip68_seconds",
            "node.apply_block.utxo_changes_seconds",
            "node.apply_block.durable_sync_seconds",
            "node.apply_block.durable_commit_seconds",
            "node.apply_block.script_verify_coinbase_only_seconds",
            "node.utxo.listener.event_batches_seconds",
        ];

        const RETIRED_WINDOW_METRICS: &[&str] = &[
            "node.durable_head.group_sync_seconds",
            "node.durable_head.group_commit_seconds",
            "node.durable_head.group_blocks",
            "node.window.checks_seconds",
        ];

        #[derive(Default)]
        struct NameRecorder {
            names: Arc<Mutex<HashSet<String>>>,
        }

        impl NameRecorder {
            fn saw(&self, name: &str) -> bool {
                self.names.lock().contains(name)
            }
        }

        #[derive(Default)]
        struct NameCell {
            names: Arc<Mutex<HashSet<String>>>,
            name: String,
        }

        impl CounterFn for NameCell {
            fn increment(&self, _value: u64) {
                self.names.lock().insert(self.name.clone());
            }

            fn absolute(&self, _value: u64) {
                self.names.lock().insert(self.name.clone());
            }
        }

        impl GaugeFn for NameCell {
            fn increment(&self, _value: f64) {
                self.names.lock().insert(self.name.clone());
            }

            fn decrement(&self, _value: f64) {
                self.names.lock().insert(self.name.clone());
            }

            fn set(&self, _value: f64) {
                self.names.lock().insert(self.name.clone());
            }
        }

        impl HistogramFn for NameCell {
            fn record(&self, _value: f64) {
                self.names.lock().insert(self.name.clone());
            }
        }

        impl Recorder for NameRecorder {
            fn describe_counter(
                &self,
                _key: KeyName,
                _unit: Option<Unit>,
                _description: SharedString,
            ) {
            }
            fn describe_gauge(
                &self,
                _key: KeyName,
                _unit: Option<Unit>,
                _description: SharedString,
            ) {
            }
            fn describe_histogram(
                &self,
                _key: KeyName,
                _unit: Option<Unit>,
                _description: SharedString,
            ) {
            }

            fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
                Counter::from_arc(Arc::new(NameCell {
                    names: Arc::clone(&self.names),
                    name: key.name().to_string(),
                }))
            }

            fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
                Gauge::from_arc(Arc::new(NameCell {
                    names: Arc::clone(&self.names),
                    name: key.name().to_string(),
                }))
            }

            fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
                Histogram::from_arc(Arc::new(NameCell {
                    names: Arc::clone(&self.names),
                    name: key.name().to_string(),
                }))
            }
        }

        fn assert_names_absent(recorder: &NameRecorder, names: &[&str]) {
            let recorded = recorder.names.lock();
            for name in names {
                assert!(
                    !recorded.contains(*name),
                    "{name} is a diagnostic (OBS-02/OBS-06) and must not reach the metrics API"
                );
            }
        }

        #[test]
        fn retired_apply_stage_timings_stay_off_caller_thread_metrics() -> TestResult {
            let recorder = NameRecorder::default();
            let genesis = Network::Regtest.genesis_block();
            metrics::with_local_recorder(&recorder, || -> TestResult {
                let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
                seed_genesis(&handles)?;
                let first = mined_child(genesis.block_hash(), 1)?;
                handles.apply_block(&BlockImage::from_local(first))?;
                Ok(())
            })?;
            assert_names_absent(&recorder, RETIRED_APPLY_METRICS);
            assert!(
                recorder.saw("node.apply_block.total_seconds"),
                "the apply.commit hot-path hook is a kept signal (OBS-04)"
            );
            assert!(
                recorder.saw("node.apply_block.txs_applied"),
                "the apply throughput counter is a kept operator signal (OBS-01)"
            );
            Ok(())
        }

        #[test]
        fn retired_group_and_check_timings_stay_off_caller_thread_metrics() -> TestResult {
            let recorder = NameRecorder::default();
            let genesis = Network::Regtest.genesis_block();
            metrics::with_local_recorder(&recorder, || -> TestResult {
                let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
                let first = mined_child(genesis.block_hash(), 1)?;
                let second = mined_child(first.block_hash(), 2)?;
                seed_genesis(&handles)?;
                {
                    let mut tree = handles.block_tree.write();
                    crate::chain::accept_headers(
                        &mut tree,
                        &[first.header, second.header],
                        Network::Regtest,
                        crate::chain::current_unix_seconds(),
                        crate::chain::HeaderValidationMode::LiveAdmission,
                    )?;
                }
                let first_payload = BlockImage::from_local(first);
                let second_payload = BlockImage::from_local(second);
                let payloads = [&first_payload, &second_payload];
                let transition = handles.begin_transition()?;
                transition.connect_window(&payloads)?;
                Ok(())
            })?;
            assert_names_absent(&recorder, RETIRED_WINDOW_METRICS);
            assert!(
                recorder.saw("node.window.verify_seconds"),
                "the apply.prove_window hot-path hook is a kept signal (OBS-04)"
            );
            Ok(())
        }

        #[test]
        fn window_commit_emits_transition_and_flush_diagnostics() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let fields = ProfileFields::default();
            capture_profile(&fields, || -> TestResult {
                let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
                let first = mined_child(genesis.block_hash(), 1)?;
                let second = mined_child(first.block_hash(), 2)?;
                seed_genesis(&handles)?;
                {
                    let mut tree = handles.block_tree.write();
                    crate::chain::accept_headers(
                        &mut tree,
                        &[first.header, second.header],
                        Network::Regtest,
                        crate::chain::current_unix_seconds(),
                        crate::chain::HeaderValidationMode::LiveAdmission,
                    )?;
                }
                let first_payload = BlockImage::from_local(first);
                let second_payload = BlockImage::from_local(second);
                let payloads = [&first_payload, &second_payload];
                let transition = handles.begin_transition()?;
                transition.connect_window(&payloads)?;
                Ok(())
            })?;
            for field in ["transition_held_us", "flush_wait_us"] {
                assert!(
                    fields.0.lock().contains(field),
                    "missing window diagnostic: {field}"
                );
            }
            Ok(())
        }

        #[derive(Clone, Default)]
        struct ProfileFields(Arc<Mutex<HashSet<String>>>);

        impl tracing::field::Visit for ProfileFields {
            fn record_debug(
                &mut self,
                _field: &tracing::field::Field,
                _value: &dyn std::fmt::Debug,
            ) {
            }

            fn record_u128(&mut self, field: &tracing::field::Field, _value: u128) {
                if field.name().ends_with("_us") {
                    self.0.lock().insert(field.name().to_owned());
                }
            }
        }

        impl tracing::Subscriber for ProfileFields {
            fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
                metadata.target().starts_with("bitcoin_rs_chain")
            }

            fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }

            fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

            fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {
            }

            fn event(&self, event: &tracing::Event<'_>) {
                event.record(&mut self.clone());
            }

            fn enter(&self, _span: &tracing::span::Id) {}

            fn exit(&self, _span: &tracing::span::Id) {}
        }

        fn capture_profile<T>(fields: &ProfileFields, action: impl FnOnce() -> T) -> T {
            let _registration_guard = tracing::Dispatch::new(ProfileFields::default());
            let dispatch = tracing::Dispatch::new(fields.clone());
            tracing::dispatcher::with_default(&dispatch, action)
        }

        #[test]
        fn proposal_emits_completed_validation_timings() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&handles)?;
            let block = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
            let fields = ProfileFields::default();
            let payload = bitcoin_rs_consensus::primitives::BlockImage::from_local(block);
            capture_profile(&fields, || handles.validate_block(&payload))?;
            for field in [
                "contextual_header_us",
                "script_verify_us",
                "coinbase_maturity_us",
                "bip68_us",
                "utxo_changes_us",
            ] {
                assert!(
                    fields.0.lock().contains(field),
                    "missing proposal timing: {field}"
                );
            }
            assert!(!fields.0.lock().contains("utxo_commit_us"));
            assert!(!fields.0.lock().contains("pow_self_us"));
            Ok(())
        }

        #[test]
        fn rejected_header_emits_only_completed_validation_timings() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&handles)?;
            let genesis = Network::Regtest.genesis_block();
            let mut block = mined_child(genesis.block_hash(), 1)?;
            block.header.time = genesis.header.time;
            let fields = ProfileFields::default();
            let payload = bitcoin_rs_consensus::primitives::BlockImage::from_local(block);
            let result = capture_profile(&fields, || handles.validate_block(&payload));
            assert!(matches!(
                result,
                Err(super::ApplyError::Chain(
                    crate::chain::ChainError::TimestampTooEarly { .. }
                ))
            ));
            assert!(fields.0.lock().contains("contextual_header_us"));
            assert!(!fields.0.lock().contains("pow_self_us"));
            assert!(!fields.0.lock().contains("utxo_commit_us"));
            Ok(())
        }

        #[test]
        fn rejected_spend_keeps_resolution_and_dispatch_timings() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&handles)?;
            let genesis = Network::Regtest.genesis_block();
            let mut block = mined_child(genesis.block_hash(), 1)?;
            let mut spend = block.txs[0].clone();
            spend.inputs[0].previous_output =
                bitcoin_rs_consensus::primitives::OutPoint::new(genesis.txs[0].txid(), 0);
            block.txs.push(spend);
            let mut leaves: Vec<_> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
            let root = bitcoin_rs_consensus::verify_block::compute_merkle_root(&mut leaves)
                .ok_or(TestError::Missing("test merkle root missing"))?;
            block.header.merkle_root =
                bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&root);
            let fields = ProfileFields::default();
            let payload = bitcoin_rs_consensus::primitives::BlockImage::from_local(block);
            let result = capture_profile(&fields, || handles.validate_block(&payload));
            assert!(matches!(
                result,
                Err(super::ApplyError::Consensus(
                    bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 0 }
                ))
            ));
            assert!(fields.0.lock().contains("script_resolution_us"));
            assert!(fields.0.lock().contains("script_verify_us"));
            assert!(!fields.0.lock().contains("coinbase_maturity_us"));
            assert!(!fields.0.lock().contains("utxo_commit_us"));
            Ok(())
        }
    }
    mod parse_once_tests {
        use std::sync::Arc;

        use crate::chain::regtest_fixture::mined_regtest_child_at as mined_child;
        use bitcoin_rs_consensus::kernel::{block_parse_call_count, reset_block_parse_call_count};
        use bitcoin_rs_consensus::primitives::layout::{
            parse_exact_call_count, reset_parse_exact_call_count,
        };
        use bitcoin_rs_consensus::primitives::{BlockImage, Network};
        use bitcoin_rs_storage::utxo::UtxoSet;

        use crate::test_fixtures::{TestResult, commit_genesis_head, handles, seed_genesis};

        // BLK-01
        #[test]
        fn normal_path_parses_each_block_once() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let genesis_hash = Network::Regtest.genesis_block().block_hash();
            let block = mined_child(genesis_hash, 1)?;
            let image = BlockImage::from_local(block.clone());

            reset_parse_exact_call_count();
            reset_block_parse_call_count();
            chain.admit_headers(&[block.header])?;
            chain.apply_block(&image)?;

            assert_eq!(
                block_parse_call_count(),
                0,
                "the normal path must not re-parse the block"
            );
            assert_eq!(
                parse_exact_call_count(),
                0,
                "the normal path must not re-parse the block bytes"
            );
            Ok(())
        }
    }
    mod persistence_tests {
        use std::sync::{Arc, mpsc};
        use std::time::{Duration, Instant};

        use crate::chain::ActiveTipWait as _;

        use crate::chain::regtest_fixture::{coinbase, mined_regtest_child_at as mined_child};
        use bitcoin_rs_consensus::MAX_SCRIPT_SIZE;
        use bitcoin_rs_consensus::primitives::{
            AssumeUtxoData, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, Network,
            OutPoint, Tx,
        };
        use bitcoin_rs_storage::utxo::UtxoSet;
        use bitcoin_rs_storage::utxo::contract::{BlockChangeInputs, build_block_changes};
        use bitcoin_rs_storage::{
            CommitRecords, DurableHead, InMemoryDurableHeadStore, PersistFault,
        };

        use hashbrown::HashMap;

        use super::{ApplyError, AssumeUtxoError, ResolvedUtxoView};
        use crate::test_fixtures::{
            TestError, TestResult, handles, handles_with_store, seed_genesis,
        };

        #[test]
        fn canonical_regtest_chain_connects_through_bip34_activation() -> TestResult {
            let network = Network::Regtest;
            let handles = handles(network, Arc::new(UtxoSet::new()));
            let genesis = network.genesis_block();
            handles.apply_block(&BlockImage::from_local(genesis.clone()))?;
            let mut parent = genesis.block_hash();
            for height in 1..=500 {
                let block = mined_child(parent, height)?;
                let outcome = handles.apply_block(&BlockImage::from_local(block.clone()))?;
                assert_eq!(outcome.tip.height, height);
                assert_eq!(outcome.hash, Hash256::from(block.block_hash()));
                assert_eq!(
                    outcome.tip.chain_tx_count,
                    crate::chain::ChainTxCount::established(u64::from(height) + 1)
                );
                parent = block.block_hash();
            }
            Ok(())
        }

        // ARCH-09, RCV-04
        #[test]
        fn undo_persist_failure_leaves_utxo_tip_and_tree_untouched() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let utxo = Arc::new(UtxoSet::new());
            let handles = handles(Network::Regtest, Arc::clone(&utxo));
            seed_genesis(&handles)?;

            let first = mined_child(genesis.block_hash(), 1)?;
            handles.apply_block(&BlockImage::from_local(first.clone()))?;
            let applied_hash = Hash256::from(first.block_hash());
            let utxo_len = utxo.len();
            handles
                .commit_authority
                .store()
                .arm_persist_fault(PersistFault::FailApply);
            let next = mined_child(first.block_hash(), 2)?;
            let next_hash = Hash256::from(next.block_hash());

            let observer = handles.clone();
            let stop = bitcoin_rs_consensus::latch::LatchWriter::new();
            let cancellation = stop.reader();
            let (answer_tx, answer_rx) = mpsc::channel();
            let waiter = std::thread::spawn(move || {
                answer_tx.send(observer.wait_for_tip(
                    crate::chain::TipWaitCondition::Changed(Some(applied_hash)),
                    None,
                    &cancellation,
                ))
            });
            let registration_deadline = Instant::now() + Duration::from_secs(2);
            while handles.tip_notification.changed.notify_all() == 0 {
                assert!(Instant::now() < registration_deadline, "waiter must park");
                std::thread::yield_now();
            }
            let outcome = handles.apply_block(&BlockImage::from_local(next.clone()));
            let pending = answer_rx.recv_timeout(Duration::from_millis(30));
            let remained_pending = matches!(pending, Err(mpsc::RecvTimeoutError::Timeout));
            stop.trigger();
            handles.wake_waiters();
            let observed = match pending {
                Ok(answer) => answer,
                Err(_) => answer_rx.recv_timeout(Duration::from_secs(2))?,
            };
            waiter
                .join()
                .map_err(|_| TestError::WorkerPanicked("tip observer"))?
                .map_err(|_| TestError::Exhausted("waiter send"))?;
            assert!(matches!(outcome, Err(ApplyError::DurableHeadCommit(_))));
            assert!(
                !remained_pending,
                "an unrecoverable undo failure closes admission and the shutdown wake releases the waiter"
            );
            assert_eq!(observed.map(|tip| tip.hash), Some(applied_hash));
            assert!(
                handles.is_closed_for_recovery(),
                "undo persistence is unrecoverable in-process, so the transition fails closed"
            );
            assert_eq!(
                handles.applied_tip.load_full().map(|tip| tip.hash),
                Some(applied_hash),
                "a failed durable commit must not publish a new tip"
            );
            assert_eq!(
                utxo.len(),
                utxo_len,
                "a failed durable commit must not commit UTXOs"
            );
            assert!(
                handles
                    .utxo_reader()
                    .get(&OutPoint::new(next.txs[0].txid(), 0))?
                    .is_none(),
                "a failed durable commit must not commit coin rows"
            );
            if let Some(node) = handles.block_tree.read().node_by_hash(next_hash) {
                assert!(
                    matches!(
                        node.status,
                        crate::chain::NodeStatus::Active | crate::chain::NodeStatus::HeaderValid
                    ),
                    "header may exist in the tree after a failed commit, but the block itself is never published"
                );
            }
            Ok(())
        }

        // RCV-08
        #[test]
        fn bip30_overwrite_undo_removes_the_overwritten_coin() -> TestResult {
            let utxo = UtxoSet::new();
            let block = Block {
                header: Header {
                    version: 1,
                    prev_blockhash: BlockHash::default(),
                    merkle_root: Hash256::default(),
                    time: 0,
                    bits: CompactTarget::from_consensus(0),
                    nonce: 0,
                },
                txs: vec![coinbase(7)],
            };
            let reused = OutPoint::new(block.txs[0].txid(), 0);
            let out = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                vout: 0,
                value: 4_242,
                script_pubkey: vec![0x51],
                coinbase: true,
                height: 91_722,
            };
            let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
                Hash256::from(reused.txid),
                &[out],
            )?;
            utxo.insert_parsed_record(record);

            let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
            let resolved = ResolvedUtxoView {
                external: HashMap::new(),
                _hold: None,
            };
            let (_changes, undo, _totals) = build_block_changes(
                &BlockChangeInputs {
                    block: &BlockImage::from_local(block.clone()),
                    height: 91_842,
                    txids: &txids,
                    same_block_spent: None,
                    add_capacity: 1,
                    remove_capacity: 0,
                    max_script_size: MAX_SCRIPT_SIZE,
                },
                &resolved,
            )?;

            assert_eq!(undo.removes(), [reused]);
            assert!(undo.restores().iter().all(|entry| entry.outpoint != reused));
            Ok(())
        }

        #[test]
        fn close_requests_shutdown() {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let shutdown = handles.shutdown_reader();
            assert!(!shutdown.is_triggered());

            let _closed = handles.close();

            assert!(shutdown.is_triggered());
        }

        #[test]
        fn direct_transition_fatal_error_closes_admission() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let mut handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&handles)?;
            let child = mined_child(genesis.block_hash(), 1)?;
            let incompatible = DurableHead {
                assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 1,
                height: 0,
                tip: Hash256::from_le_bytes(&[0x66; 32]),
                chain_tx_count: 1,
                body_extent: None,
                undo_extent: None,
            };
            let durable = Arc::new(InMemoryDurableHeadStore::new());
            durable.commit(None, &incompatible, &CommitRecords::default())?;
            handles.durable_head = durable;
            let shutdown = handles.shutdown_reader();

            let transition = handles.begin_transition()?;
            let outcome = transition.connect(&BlockImage::from_local(child));

            assert!(matches!(
                outcome,
                Err(ApplyError::DurableHeadLineage { .. })
            ));
            assert!(shutdown.is_triggered());
            drop(transition);
            assert!(matches!(
                handles.begin_transition(),
                Err(ApplyError::Shutdown)
            ));
            Ok(())
        }

        // RCV-08
        #[test]
        fn disconnect_off_durable_head_refuses_without_mutation() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let utxo = Arc::new(UtxoSet::new());
            let mut handles = handles(Network::Regtest, Arc::clone(&utxo));
            handles.apply_block(&BlockImage::from_local(genesis.clone()))?;
            let first = mined_child(genesis.block_hash(), 1)?;
            handles.apply_block(&BlockImage::from_local(first.clone()))?;
            let first_outpoint = OutPoint::new(first.txs[0].txid(), 0);
            assert!(handles.utxo_reader().get(&first_outpoint)?.is_some());

            handles.durable_head = Arc::new(InMemoryDurableHeadStore::new());

            let outcome = handles.begin_transition()?.disconnect(&first);
            let Err(crate::DisconnectError::Refused(error)) = outcome else {
                panic!("an uncertified disconnect must be refused, got {outcome:?}");
            };
            assert!(matches!(
                *error,
                ApplyError::DisconnectOffDurableHead { head: None, .. }
            ));
            assert_eq!(
                handles.applied_tip.load_full().map(|tip| tip.hash),
                Some(Hash256::from(first.block_hash())),
                "a refused disconnect must not move the applied tip"
            );
            assert!(
                handles.utxo_reader().get(&first_outpoint)?.is_some(),
                "a refused disconnect must not roll back the UTXO set"
            );
            assert_eq!(handles.undo_store.load_disconnect_marker()?, None);
            assert!(
                handles.begin_transition().is_ok(),
                "a refusal must leave admission open"
            );
            Ok(())
        }

        // RCV-02
        #[test]
        fn use_after_close_refuses_operations() {
            let utxo = Arc::new(UtxoSet::new());
            let handles = handles(Network::Regtest, utxo);
            assert!(!handles.is_closed_for_recovery());
            handles.fail_closed_for_recovery();
            assert!(handles.is_closed_for_recovery());

            assert!(matches!(
                handles.begin_transition(),
                Err(ApplyError::Shutdown)
            ));
            let genesis = Network::Regtest.genesis_block();
            let outcome = handles.apply_block(&BlockImage::from_local(genesis));
            assert!(matches!(outcome, Err(ApplyError::Shutdown)));
        }

        // RCV-09, RCV-11
        #[test]
        fn current_schema_version_mismatch_and_corruption_refuses_open() -> TestResult {
            use bitcoin_rs_storage::checkpoint::{
                CURRENT_SCHEMA_FILE, ensure_current_schema, open_data_dir,
            };
            let temp = tempfile::tempdir()?;
            let dir = open_data_dir(temp.path())?;

            std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"1\n")?;
            let result = ensure_current_schema(&dir);
            assert!(
                matches!(
                    &result,
                    Err(err) if err.kind() == std::io::ErrorKind::InvalidData
                ),
                "wrong schema epoch must be invalid data: {result:?}"
            );

            std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"0\n")?;
            assert!(ensure_current_schema(&dir).is_err());

            std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"2\n")?;
            assert!(ensure_current_schema(&dir).is_err());

            std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"corrupt\n")?;
            assert!(ensure_current_schema(&dir).is_err());

            std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"3\n")?;
            assert!(ensure_current_schema(&dir).is_err());

            std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"4\n")?;
            assert!(ensure_current_schema(&dir).is_err());

            std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"5\n")?;
            assert!(ensure_current_schema(&dir).is_err());

            std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"6\n")?;
            assert!(ensure_current_schema(&dir).is_ok());
            Ok(())
        }

        #[test]
        fn fresh_node_rejected_snapshot_ingest_clears_marker_and_preserves_later_coins()
        -> TestResult {
            let network = Network::Regtest;
            let genesis = network.genesis_block();
            let genesis_header = genesis.header;
            let store = Arc::new(bitcoin_rs_storage::memory_kv::MemoryKvStore::new());
            let utxo = Arc::new(UtxoSet::new());
            let chain = handles_with_store(network, utxo, Arc::clone(&store));

            crate::chain::accept_headers(
                &mut chain.block_tree.write(),
                core::slice::from_ref(&genesis_header),
                network,
                crate::chain::current_unix_seconds(),
                crate::chain::HeaderValidationMode::LiveAdmission,
            )?;

            let pinned = AssumeUtxoData {
                height: 0,
                block_hash: Hash256::from(genesis.block_hash()),
                hash_serialized: Hash256::from_le_bytes(&[0x11; 32]),
                chain_tx_count: 1,
                index_commitments: [None; 4],
            };

            let outcome = chain.install_snapshot(
                &pinned,
                0,
                |_coins| {
                    Err(AssumeUtxoError::SnapshotCommitmentMismatch {
                        expected: pinned.hash_serialized,
                        found: Hash256::from_le_bytes(&[0x22; 32]),
                    })
                },
                |_coins, _tree, _tip, _prior, _marker, _streamed| Ok(()),
            );

            assert!(matches!(
                outcome,
                Err(AssumeUtxoError::SnapshotCommitmentMismatch { .. })
            ));
            assert!(
                chain
                    .commit_authority
                    .in_flight_snapshot_activation()?
                    .is_none()
            );
            assert!(!chain.is_closed_for_recovery());
            assert!(chain.begin_transition().is_ok());

            chain.apply_block(&BlockImage::from_local(genesis.clone()))?;
            let first = mined_child(genesis.block_hash(), 1)?;
            chain.apply_block(&BlockImage::from_local(first.clone()))?;
            let first_outpoint = OutPoint::new(first.txs[0].txid(), 0);
            assert!(chain.utxo_reader().get(&first_outpoint)?.is_some());

            let store: Arc<dyn bitcoin_rs_storage::KvStore> = store;
            let coins_reopened = Arc::new(bitcoin_rs_storage::CoinStore::open(
                Arc::clone(&store),
                64 * 1024 * 1024,
            ));
            let authority_reopened =
                bitcoin_rs_storage::CommitAuthority::new(store, Arc::clone(&coins_reopened));
            assert!(
                matches!(authority_reopened.recover_snapshot_activation(), Ok(None)),
                "no leftover marker must be recovered on restart"
            );
            let first_txid_le = first.txs[0].txid().0.to_le_bytes();
            let first_key = bitcoin_rs_storage::CoinKey(first_txid_le);
            let Some(encoded) = coins_reopened.get(&first_key)? else {
                return Err(TestError::Missing(
                    "coin committed after rejected ingest must survive restart/recovery",
                ));
            };
            let record = bitcoin_rs_storage::utxo::UtxoRecord::from_encoded(
                encoded.to_vec().into_boxed_slice(),
            )?;
            assert_eq!(
                record.txid().to_le_bytes(),
                first_txid_le,
                "recovered coin row must carry the committed coinbase txid"
            );
            let expected = &first.txs[0].outputs[0];
            let mut saw_vout_zero = false;
            for output in record.outputs() {
                if output.vout != 0 {
                    continue;
                }
                saw_vout_zero = true;
                assert_eq!(
                    output.value,
                    expected.value.to_sat(),
                    "recovered coin value must match the committed block output"
                );
                assert_eq!(
                    output.script_pubkey,
                    expected.script_pubkey.as_bytes(),
                    "recovered coin script must match the committed block output"
                );
                assert!(
                    output.coinbase,
                    "recovered coin must be the height-1 coinbase output"
                );
                assert_eq!(
                    output.height, 1,
                    "recovered coin must have creation height 1"
                );
            }
            assert!(
                saw_vout_zero,
                "recovered coin record must contain the block's output 0"
            );

            Ok(())
        }
    }
    mod pow_valid_hook_tests {
        #![expect(
            clippy::expect_used,
            reason = "poisoned test-recorder locks must fail the test"
        )]

        use std::sync::{Arc, Mutex};

        use crate::chain::regtest_fixture::{
            merkle_root, mine_block_to_declared_target, mined_regtest_child_at as mined_child,
        };
        use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Network};
        use bitcoin_rs_storage::utxo::UtxoSet;

        use super::ApplyError;
        use crate::test_fixtures::{TestError, TestResult, handles, seed_genesis};

        type HookCalls = Arc<Mutex<Vec<(Hash256, u32)>>>;

        fn recording_hook(calls: &HookCalls) -> crate::PowValidBlockHook {
            let calls = Arc::clone(calls);
            Arc::new(move |_block, hash, height| {
                calls.lock().expect("hook calls").push((hash, height));
            })
        }

        #[test]
        fn pow_valid_hook_fires_once_for_tip_child_commit() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
            handles
                .set_pow_valid_block(recording_hook(&calls))
                .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
            let genesis_tip = seed_genesis(&handles)?;
            assert!(calls.lock().expect("hook calls").is_empty());

            let child = mined_child(genesis_tip.hash.into(), 1)?;
            let outcome = handles.apply_block(&BlockImage::from_local(child.clone()))?;
            assert_eq!(outcome.height, 1);
            let fired = calls.lock().expect("hook calls").clone();
            assert_eq!(fired.len(), 1, "one early fire per committed tip child");
            assert_eq!(fired[0].0, Hash256::from(child.block_hash()));
            assert_eq!(fired[0].1, 1);
            Ok(())
        }

        #[test]
        fn pow_valid_hook_skips_stale_parent_and_failed_connects() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
            handles
                .set_pow_valid_block(recording_hook(&calls))
                .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
            let genesis_tip = seed_genesis(&handles)?;
            for height in 1..=3 {
                let tip = handles
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("tip"))?;
                let block = mined_child(tip.hash.into(), height)?;
                handles.apply_block(&BlockImage::from_local(block))?;
            }
            assert_eq!(
                handles
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("tip"))?
                    .height,
                3
            );
            calls.lock().expect("hook calls").clear();

            let stale = mined_child(genesis_tip.hash.into(), 1)?;
            let stale_result: Result<_, ApplyError> =
                handles.apply_block(&BlockImage::from_local(stale));
            assert!(
                matches!(stale_result, Err(ApplyError::PrevHashMismatch { .. })),
                "a stale-parent block must fail before the hook"
            );
            assert!(
                calls.lock().expect("hook calls").is_empty(),
                "a stale-parent block never announces early"
            );
            assert_eq!(
                handles
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("tip"))?
                    .height,
                3,
                "a stale fork never moves the published tip"
            );

            let tip = handles
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("tip"))?;
            let mut falling = mined_child(tip.hash.into(), 4)?;
            let coinbase = falling
                .txs
                .first_mut()
                .ok_or(TestError::Missing("coinbase"))?
                .outputs
                .first_mut()
                .ok_or(TestError::Missing("coinbase output"))?;
            coinbase.value = bitcoin_rs_consensus::primitives::Amount::from_sat(
                coinbase
                    .value
                    .to_sat()
                    .checked_add(1)
                    .ok_or(TestError::Missing("value overflow"))?,
            );
            falling.header.merkle_root = merkle_root(&falling.txs)
                .ok_or(TestError::Missing("merkle root of non-empty block"))?;
            mine_block_to_declared_target(&mut falling).map_err(|source| TestError::Regrind {
                what: "overspend",
                source,
            })?;
            let failed: Result<_, ApplyError> =
                handles.apply_block(&BlockImage::from_local(falling.clone()));
            assert!(
                matches!(
                    failed,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::CoinbaseAmount { .. }
                    ))
                ),
                "an overspent coinbase must fail connect after rules"
            );
            let fired = calls.lock().expect("hook calls").clone();
            assert_eq!(
                fired.len(),
                1,
                "exactly the rules-boundary fire, nothing after the failure"
            );
            assert_eq!(fired[0].0, Hash256::from(falling.block_hash()));
            assert_eq!(
                handles
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("tip"))?
                    .height,
                3,
                "a failed connect leaves the published tip unchanged"
            );
            Ok(())
        }

        #[test]
        fn pow_valid_hook_skips_non_final_commit_intent_block() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
            handles
                .set_pow_valid_block(recording_hook(&calls))
                .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
            seed_genesis(&handles)?;
            let tip = handles
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("tip"))?;
            let mut non_final = mined_child(tip.hash.into(), 1)?;
            let coinbase = non_final
                .txs
                .first_mut()
                .ok_or(TestError::Missing("coinbase"))?;
            coinbase.lock_time = bitcoin_rs_consensus::primitives::LockTime::from_consensus(2);
            coinbase
                .inputs
                .first_mut()
                .ok_or(TestError::Missing("coinbase input"))?
                .sequence = bitcoin_rs_consensus::primitives::Sequence::from_consensus(0);
            non_final.header.merkle_root = merkle_root(&non_final.txs)
                .ok_or(TestError::Missing("merkle root of non-empty block"))?;
            mine_block_to_declared_target(&mut non_final).map_err(|source| TestError::Regrind {
                what: "non-final",
                source,
            })?;
            let failed: Result<_, ApplyError> =
                handles.apply_block(&BlockImage::from_local(non_final));
            assert!(
                matches!(
                    failed,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::Bip { .. }
                    ))
                ),
                "a non-final block must fail connect, got {failed:?}"
            );
            assert!(
                calls.lock().expect("hook calls").is_empty(),
                "a non-final block never announces early"
            );
            Ok(())
        }

        #[test]
        fn pow_valid_hook_requires_transaction_structure_and_legacy_sigop_budget() -> TestResult {
            for (sigops, empty_outputs) in [(1_000, false), (1_001, false), (0, true)] {
                let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
                seed_genesis(&handles)?;
                let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
                handles
                    .set_pow_valid_block(recording_hook(&calls))
                    .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
                let mut block = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
                if empty_outputs {
                    block.txs[0].outputs.clear();
                } else {
                    block.txs[0].outputs[0].script_pubkey =
                        vec![bitcoin_rs_consensus::script::opcode::OP_CHECKMULTISIG; sigops].into();
                }
                block.header.merkle_root =
                    merkle_root(&block.txs).ok_or(TestError::Missing("merkle root"))?;
                mine_block_to_declared_target(&mut block)?;
                let snapshot = handles.chain_snapshot();
                let tip = handles
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("tip"))?;
                let head = handles.durable_head.load()?;
                let stats = handles.coin_stats.snapshot().to_bytes();
                let result = handles.apply_block(&BlockImage::from_local(block));
                if sigops == 1_000 {
                    result?;
                    assert_eq!(calls.lock().expect("hook calls").len(), 1);
                    continue;
                }
                if empty_outputs {
                    assert!(
                        matches!(
                            result,
                            Err(ApplyError::Consensus(
                                bitcoin_rs_consensus::ConsensusError::EmptyOutputs
                            ))
                        ),
                        "{result:?}"
                    );
                } else {
                    assert!(
                        matches!(
                            result,
                            Err(ApplyError::Consensus(
                                bitcoin_rs_consensus::ConsensusError::SigopsLimit {
                                    cost: 80_080,
                                    max: 80_000
                                }
                            ))
                        ),
                        "{result:?}"
                    );
                }
                assert!(calls.lock().expect("hook calls").is_empty());
                assert_eq!(handles.chain_snapshot(), snapshot);
                assert_eq!(
                    handles
                        .applied_tip_snapshot()
                        .ok_or(TestError::Missing("tip"))?
                        .hash,
                    tip.hash
                );
                assert_eq!(handles.durable_head.load()?, head);
                assert_eq!(handles.coin_stats.snapshot().to_bytes(), stats);
                assert_eq!(handles.utxo.len(), 0);
            }
            Ok(())
        }

        #[test]
        fn pow_valid_hook_skips_bip34_violating_commit_intent_block() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
            handles
                .set_pow_valid_block(recording_hook(&calls))
                .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
            let mut tip_hash = seed_genesis(&handles)?.hash;
            for height in 1..=499 {
                let block = mined_child(tip_hash.into(), height)?;
                handles.apply_block(&BlockImage::from_local(block.clone()))?;
                tip_hash = Hash256::from(block.block_hash());
            }
            assert_eq!(
                handles
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("tip"))?
                    .height,
                499
            );
            calls.lock().expect("hook calls").clear();
            let mut violating = mined_child(tip_hash.into(), 500)?;
            violating
                .txs
                .first_mut()
                .ok_or(TestError::Missing("coinbase"))?
                .inputs
                .first_mut()
                .ok_or(TestError::Missing("coinbase input"))?
                .script_sig = vec![0x51, 0x00].into();
            violating.header.merkle_root = merkle_root(&violating.txs)
                .ok_or(TestError::Missing("merkle root of non-empty block"))?;
            mine_block_to_declared_target(&mut violating).map_err(|source| TestError::Regrind {
                what: "violating",
                source,
            })?;
            let failed: Result<_, ApplyError> =
                handles.apply_block(&BlockImage::from_local(violating));
            assert!(
                matches!(
                    failed,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::Bip { .. }
                    ))
                ),
                "a BIP34-violating block must fail connect, got {failed:?}"
            );
            assert!(
                calls.lock().expect("hook calls").is_empty(),
                "a BIP34-violating block never announces early"
            );
            Ok(())
        }

        #[test]
        fn hook_installation_after_a_clone_is_visible_through_both_handles() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let shadow = handles.clone();
            let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
            shadow
                .set_pow_valid_block(recording_hook(&calls))
                .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
            assert!(
                handles.set_pow_valid_block(recording_hook(&calls)).is_err(),
                "the original must see the clone's install and refuse a second one"
            );
            seed_genesis(&handles)?;
            let tip = handles
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("tip"))?;
            let child = mined_child(tip.hash.into(), 1)?;
            handles.apply_block(&BlockImage::from_local(child.clone()))?;
            let fired = calls.lock().expect("hook calls").clone();
            assert_eq!(fired.len(), 1, "the clone-installed hook must announce");
            assert_eq!(fired[0].0, Hash256::from(child.block_hash()));
            handles
                .set_tip_staged(Arc::new(|_, _| {}))
                .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
            assert!(
                shadow.set_tip_staged(Arc::new(|_, _| {})).is_err(),
                "the clone must see the install and refuse a second one"
            );
            Ok(())
        }

        #[test]
        fn pow_valid_hook_skips_legacy_sigop_violating_block() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
            handles
                .set_pow_valid_block(recording_hook(&calls))
                .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
            let genesis_tip = seed_genesis(&handles)?;
            let mut block = mined_child(genesis_tip.hash.into(), 1)?;
            block.txs[0].outputs[0].script_pubkey =
                vec![bitcoin_rs_consensus::script::opcode::OP_CHECKSIG; 20_001].into();
            block.header.merkle_root = merkle_root(&block.txs)
                .ok_or(TestError::Missing("merkle root of non-empty block"))?;
            mine_block_to_declared_target(&mut block).map_err(|source| TestError::Regrind {
                what: "legacy sigop",
                source,
            })?;
            let failed: Result<_, ApplyError> = handles.apply_block(&BlockImage::from_local(block));
            assert!(
                matches!(
                    &failed,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::SigopsLimit {
                            cost: 80_004,
                            max: 80_000,
                        }
                    ))
                ),
                "legacy sigop violation must fail connect, got {failed:?}"
            );
            assert!(
                calls.lock().expect("hook calls").is_empty(),
                "legacy sigop violation must be rejected before pow_valid hook"
            );
            Ok(())
        }

        #[test]
        fn proposal_intent_rejects_non_final_coinbase_parity() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&handles)?;
            let tip = handles
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("tip"))?;
            let mut non_final = mined_child(tip.hash.into(), 1)?;
            let coinbase = non_final
                .txs
                .first_mut()
                .ok_or(TestError::Missing("coinbase"))?;
            coinbase.lock_time = bitcoin_rs_consensus::primitives::LockTime::from_consensus(2);
            coinbase
                .inputs
                .first_mut()
                .ok_or(TestError::Missing("coinbase input"))?
                .sequence = bitcoin_rs_consensus::primitives::Sequence::from_consensus(0);
            non_final.header.merkle_root = merkle_root(&non_final.txs)
                .ok_or(TestError::Missing("merkle root of non-empty block"))?;
            mine_block_to_declared_target(&mut non_final).map_err(|source| TestError::Regrind {
                what: "non-final",
                source,
            })?;
            let payload = BlockImage::from_local(non_final);
            let failed = handles.validate_block(&payload);
            assert!(
                matches!(
                    &failed,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP113", .. }
                    ))
                ),
                "proposal intent must reject non-final coinbase under BIP113, got {failed:?}"
            );
            Ok(())
        }
    }
    mod recovery_marker_order_tests {
        use std::fs;
        use std::path::Path;

        use crate::chain::{BlockTree, TipSnapshot, accept_headers};
        use bitcoin_rs_consensus::primitives::Network;
        use bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER;
        use bitcoin_rs_storage::utxo::UtxoSet;
        use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
        use parking_lot::RwLock;

        use crate::checkpoint;
        use crate::checkpoint::headers::HeaderCheckpointConfig;
        use crate::checkpoint::{CHECKPOINT_ROOT, CURRENT_FILE, MANIFEST_FILE};
        use crate::recovery::{
            ResumeSource, prepare_initial_chainstate, prepare_initial_state_with_engine,
        };

        use crate::test_fixtures::TestResult;
        const NETWORK: Network = Network::Regtest;

        fn arm_full_revalidation_marker(data_dir: &Path) {
            fs::write(data_dir.join(FULL_REVALIDATION_MARKER), b"")
                .unwrap_or_else(|e| panic!("arm marker: {e}"));
        }

        fn genesis_tip() -> TestResult<(RwLock<BlockTree>, TipSnapshot)> {
            let genesis = NETWORK.genesis_block().header;
            let mut tree = BlockTree::new();
            let accepted = accept_headers(
                &mut tree,
                core::slice::from_ref(&genesis),
                NETWORK,
                crate::chain::current_unix_seconds(),
                crate::chain::HeaderValidationMode::LiveAdmission,
            )?;
            let tip_id = accepted.ids[0];
            let node = tree.node(tip_id)?;
            let tip = TipSnapshot {
                tip_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            };
            Ok((RwLock::new(tree), tip))
        }

        fn checkpoint_config() -> HeaderCheckpointConfig {
            HeaderCheckpointConfig {
                network: NETWORK,
                genesis: NETWORK.genesis_block_hash(),
            }
        }

        // RCV-10
        #[test]
        fn corrupt_checkpoint_with_marker_selects_cold_replay() -> TestResult {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path();
            crate::events::initialize_data_dir(data_dir)?;

            let gen_name = format!("gen-{:020}", 1u64);
            let checkpoint_root = data_dir.join(CHECKPOINT_ROOT);
            fs::create_dir_all(checkpoint_root.join(gen_name.as_str()))?;
            fs::write(
                checkpoint_root.join(gen_name.as_str()).join(MANIFEST_FILE),
                b"not valid json",
            )?;
            let current_json = format!(
                r#"{{"format":"bitcoin-rs-chainstate-current","version":1,"generation":1,"directory":"{gen_name}","manifest_sha256":"{}"}}"#,
                "00".repeat(32)
            );
            fs::write(checkpoint_root.join(CURRENT_FILE), current_json)?;

            let preload = checkpoint::load_checkpoint(data_dir, checkpoint_config());
            assert!(
                matches!(preload, Err(checkpoint::CheckpointLoadError::Corrupt(_))),
                "corrupt fixture must fail to load before the marker is armed"
            );

            arm_full_revalidation_marker(data_dir);

            let state = prepare_initial_chainstate(data_dir, NETWORK, None, None)?;

            assert!(
                matches!(state.resume_source, ResumeSource::Cold),
                "expected Cold resume source, got {:?}",
                state.resume_source
            );
            Ok(())
        }

        // RCV-10
        #[test]
        fn valid_checkpoint_with_marker_selects_cold_replay() -> TestResult {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path();
            crate::events::initialize_data_dir(data_dir)?;

            let (tree, tip) = genesis_tip()?;
            let store = bitcoin_rs_storage::checkpoint::open_data_dir(data_dir)?;
            let _ = checkpoint::write_checkpoint(
                data_dir,
                checkpoint_config(),
                &tree,
                &UtxoSet::new(),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&tip),
            )?;
            drop(store);

            let no_marker = prepare_initial_chainstate(data_dir, NETWORK, None, None)?;
            assert!(
                matches!(no_marker.resume_source, ResumeSource::Checkpoint),
                "a valid checkpoint without a marker must restore to Checkpoint, got {:?}",
                no_marker.resume_source
            );

            arm_full_revalidation_marker(data_dir);

            let state = prepare_initial_chainstate(data_dir, NETWORK, None, None)?;

            assert!(
                matches!(state.resume_source, ResumeSource::Cold),
                "a valid checkpoint must be bypassed when the marker is armed, got {:?}",
                state.resume_source
            );
            Ok(())
        }

        #[test]
        fn older_published_checkpoint_with_activation_marker_returns_cold_and_no_engine_image()
        -> TestResult {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path();
            crate::events::initialize_data_dir(data_dir)?;

            let (tree, tip) = genesis_tip()?;
            let store = bitcoin_rs_storage::checkpoint::open_data_dir(data_dir)?;
            let _ = checkpoint::write_checkpoint(
                data_dir,
                checkpoint_config(),
                &tree,
                &UtxoSet::new(),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&tip),
            )?;
            drop(store);

            let restored = prepare_initial_state_with_engine(data_dir, NETWORK, None, None)?;
            assert!(
                matches!(restored.initial.resume_source, ResumeSource::Checkpoint),
                "marker-free checkpoint must restore to Checkpoint, got {:?}",
                restored.initial.resume_source
            );
            assert!(
                restored.engine.is_some(),
                "marker-free checkpoint must restore with its engine image"
            );

            let in_flight = bitcoin_rs_storage::SnapshotActivationMarker {
                base_hash: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[0x42; 32]),
                coin_count: 100,
                coin_digest: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[0x77; 32]),
            };

            let in_flight_state =
                prepare_initial_state_with_engine(data_dir, NETWORK, None, Some(&in_flight))?;
            assert!(
                matches!(in_flight_state.initial.resume_source, ResumeSource::Cold),
                "in-flight activation marker must select Cold resume, got {:?}",
                in_flight_state.initial.resume_source
            );
            assert!(
                in_flight_state.engine.is_none(),
                "in-flight activation marker must return no engine image (None)"
            );

            Ok(())
        }
    }
    mod utxo_integrity_tests {
        use std::sync::Arc;

        use crate::chain::regtest_fixture::{
            coinbase, merkle_root, mine_block_to_declared_target, mined_block_with_prev_hash,
            mined_regtest_child_at as mined_child, mined_regtest_child_at_time,
        };
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockImage, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx,
            TxIn, TxOut, Witness,
        };
        use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget};
        use bitcoin_rs_storage::utxo::UtxoSet;
        use bitcoin_rs_storage::utxo::contract::{
            BlockChanges, UndoLoadError, UtxoAdd, populate_block_changes,
        };
        use bitcoin_rs_storage::{KvUndoStore, MandatoryRetention, RetentionRegistry, UndoStore};

        use super::Chainstate;
        use crate::test_fixtures::{TestError, TestResult, handles, seed_genesis};
        use crate::{ApplyError, DisconnectError};

        const PAY_TO_TRUE: u8 = 0x51;

        fn remine(block: &mut Block) -> TestResult {
            block.header.merkle_root =
                merkle_root(&block.txs).ok_or(TestError::Missing("merkle root"))?;
            mine_block_to_declared_target(block)?;
            Ok(())
        }

        fn pay_to_true(tx: &mut Tx) {
            for output in &mut tx.outputs {
                output.script_pubkey = Script::from_bytes(vec![PAY_TO_TRUE]);
            }
        }

        fn spend(funding: OutPoint, value: u64) -> Tx {
            Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: funding,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: Script::from_bytes(vec![PAY_TO_TRUE]),
                }],
            }
        }

        struct Fixture {
            chain: Chainstate,
            blocks: Vec<Block>,
            undo: Arc<KvUndoStore<dyn bitcoin_rs_storage::KvStore>>,
            retention: Arc<RetentionRegistry>,
        }

        fn chain_to(height: u32) -> TestResult<Fixture> {
            let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let undo = Arc::new(KvUndoStore::new(Arc::clone(chain.commit_authority.store())));
            let retention = Arc::new(RetentionRegistry::new());
            let undo_store: Arc<dyn bitcoin_rs_storage::UndoStore> = undo.clone();
            chain.undo_store = undo_store;
            chain.retention = MandatoryRetention::new(Arc::clone(&retention));
            chain.history = HistoryAccess::new(
                Arc::clone(&retention),
                RetentionBudget::from_blocks(
                    bitcoin_rs_consensus::primitives::chain_constants::CORE_REORG_SAFETY_MARGIN,
                ),
            );
            seed_genesis(&chain)?;
            let genesis = Network::Regtest.genesis_block();
            let mut blocks = vec![genesis.clone()];
            let mut parent = genesis.block_hash();
            for current in 1..=height {
                let mut block = mined_child(parent, current)?;
                if current == 1 {
                    pay_to_true(&mut block.txs[0]);
                    remine(&mut block)?;
                }
                chain.apply_block(&BlockImage::from_local(block.clone()))?;
                parent = block.block_hash();
                blocks.push(block);
            }
            Ok(Fixture {
                chain,
                blocks,
                undo,
                retention,
            })
        }

        fn coinbase_outpoint(block: &Block) -> OutPoint {
            OutPoint::new(block.txs[0].txid(), 0)
        }

        fn undo_record(
            undo: &KvUndoStore<dyn bitcoin_rs_storage::KvStore>,
            height: u32,
            block: &Block,
        ) -> TestResult<Vec<u8>> {
            undo.load_undo(height, Hash256::from(block.block_hash()))?
                .ok_or(TestError::Missing("persisted undo record"))
        }

        // RCV-08
        #[test]
        fn coinbase_maturity_refuses_depth_99_and_accepts_depth_100() -> TestResult {
            let refused = chain_to(99)?;
            let funding = coinbase_outpoint(&refused.blocks[1]);
            let spend_tx = spend(funding, 4_999_999_000);
            let block = mined_block_with_prev_hash(
                refused.blocks[99].block_hash(),
                100,
                vec![coinbase(100), spend_tx.clone()],
            )?;
            let outcome = refused.chain.apply_block(&BlockImage::from_local(block));
            assert!(
                matches!(
                    outcome,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::Bip {
                            bip: "COINBASE_MATURITY",
                            ..
                        }
                    ))
                ),
                "depth 99 coinbase spend must be refused, got {outcome:?}"
            );
            assert!(
                refused
                    .chain
                    .utxo_reader()
                    .get(&OutPoint::new(spend_tx.txid(), 0))?
                    .is_none(),
                "a refused coinbase spend must not enter the UTXO set"
            );
            assert_eq!(
                refused
                    .chain
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("tip"))?
                    .height,
                99,
                "a refused coinbase spend must not advance the tip"
            );

            let accepted = chain_to(100)?;
            let funding = coinbase_outpoint(&accepted.blocks[1]);
            let spend_tx = spend(funding, 4_999_999_000);
            let block = mined_block_with_prev_hash(
                accepted.blocks[100].block_hash(),
                101,
                vec![coinbase(101), spend_tx.clone()],
            )?;
            accepted.chain.apply_block(&BlockImage::from_local(block))?;
            assert!(
                accepted
                    .chain
                    .utxo_reader()
                    .get(&OutPoint::new(spend_tx.txid(), 0))?
                    .is_some(),
                "depth 100 coinbase spend must enter the UTXO set"
            );
            Ok(())
        }

        // RCV-08
        #[test]
        fn disconnect_refuses_missing_or_truncated_undo_and_keeps_state() -> TestResult {
            for truncated in [false, true] {
                let fixture = chain_to(2)?;
                let block = &fixture.blocks[2];
                let hash = Hash256::from(block.block_hash());
                if truncated {
                    let record = undo_record(&fixture.undo, 2, block)?;
                    fixture
                        .undo
                        .persist_undo(2, hash, &record[..record.len() - 1])?;
                } else {
                    fixture.undo.remove_archived(2, hash)?;
                }

                let outcome = fixture.chain.disconnect_block(block);
                let Err(DisconnectError::Refused(error)) = outcome else {
                    panic!("truncated={truncated}: unavailable undo must refuse, got {outcome:?}");
                };
                let expected = if truncated {
                    matches!(
                        *error,
                        ApplyError::UndoLoad(UndoLoadError::Unreadable { .. })
                    )
                } else {
                    matches!(*error, ApplyError::UndoLoad(UndoLoadError::Missing { .. }))
                };
                assert!(
                    expected,
                    "truncated={truncated}: unexpected refusal {error:?}"
                );
                assert_eq!(
                    fixture
                        .chain
                        .applied_tip_snapshot()
                        .ok_or(TestError::Missing("applied tip"))?
                        .hash,
                    hash,
                    "truncated={truncated}: a refused disconnect must not move the tip"
                );
                assert!(
                    fixture
                        .chain
                        .utxo_reader()
                        .get(&coinbase_outpoint(block))?
                        .is_some(),
                    "truncated={truncated}: a refused disconnect must not drop block coins"
                );
            }
            Ok(())
        }

        #[test]
        fn a_block_with_a_duplicate_live_txid_is_refused_at_any_height() -> TestResult {
            let fixture = chain_to(2)?;
            let funding = OutPoint::new(Hash256::from_le_bytes(&[0xF1; 32]).into(), 0);
            let mut seed = BlockChanges::default();
            seed.add(UtxoAdd::new(
                funding,
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: Script::from_bytes(vec![PAY_TO_TRUE]),
                },
                false,
                0,
            ));
            populate_block_changes(&fixture.chain.coins, &seed)?;
            let spend_tx = spend(funding, 900);
            let mut live = BlockChanges::default();
            live.add(UtxoAdd::new(
                OutPoint::new(spend_tx.txid(), 0),
                TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: Script::from_bytes(vec![PAY_TO_TRUE]),
                },
                false,
                0,
            ));
            populate_block_changes(&fixture.chain.coins, &live)?;

            let block = mined_block_with_prev_hash(
                fixture.blocks[2].block_hash(),
                3,
                vec![coinbase(3), spend_tx],
            )?;
            let outcome = fixture.chain.apply_block(&BlockImage::from_local(block));
            assert!(
                matches!(
                    outcome,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP30", .. }
                    ))
                ),
                "a duplicate txid with live outputs must be refused, got {outcome:?}"
            );
            Ok(())
        }

        struct NoopObserver;

        impl crate::reorg::ReorgObserver for NoopObserver {
            fn disconnected(&mut self, _: &crate::DisconnectOutcome) {}

            fn connected(
                &mut self,
                _: &bitcoin_rs_consensus::primitives::BlockImage,
                _: &crate::ConnectOutcome,
            ) {
            }

            fn reconsider_disconnected(
                &mut self,
                _: &bitcoin_rs_consensus::primitives::BlockImage,
            ) {
            }
        }

        // RCV-08
        #[test]
        fn a_reorg_below_the_retained_undo_window_refuses_before_mutation() -> TestResult {
            let fixture = chain_to(6)?;
            let genesis_time = Network::Regtest.genesis_block().header.time;
            let mut parent = fixture.blocks[2].block_hash();
            let mut fork = Vec::new();
            for height in 3..=7 {
                let block =
                    mined_regtest_child_at_time(parent, genesis_time + 100 + height, height)?;
                parent = block.block_hash();
                fork.push(block);
            }
            let headers: Vec<_> = fork.iter().map(|block| block.header).collect();
            fixture.chain.admit_headers(&headers)?;
            let target = fixture
                .chain
                .block_tree
                .read()
                .lookup(Hash256::from(
                    fork.last()
                        .ok_or(TestError::Missing("fork tip"))?
                        .block_hash(),
                ))
                .ok_or(TestError::Missing("fork target in the block tree"))?;

            fixture.retention.reserve(4).commit(4);
            let before = fixture
                .chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("applied tip"))?;
            let before_utxo = fixture.chain.utxo.lock_stable_view().hash_serialized_3()?;
            let error = crate::reorg::switch_to_branch(
                &fixture.chain,
                target,
                |_| None,
                &mut NoopObserver,
                |_, outcome| outcome,
            )
            .err()
            .ok_or(TestError::UnexpectedSuccess("a pruned reorg floor"))?;

            assert!(
                matches!(
                    error,
                    crate::reorg::ReorgError::RetentionUnavailable { floor: 3, .. }
                ),
                "the reorg must refuse at the pruned floor, got {error:?}"
            );
            assert_eq!(
                fixture
                    .chain
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("applied tip"))?
                    .hash,
                before.hash,
                "a refused reorg must not move the tip"
            );
            assert_eq!(
                fixture.chain.utxo.lock_stable_view().hash_serialized_3()?,
                before_utxo,
                "a refused reorg must not mutate the UTXO set"
            );
            assert_eq!(
                fixture
                    .chain
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("durable head"))?
                    .tip,
                before.hash,
                "a refused reorg must not move the durable head"
            );
            Ok(())
        }

        #[test]
        fn block_output_sums_at_the_money_boundary() -> TestResult {
            let fixture = chain_to(2)?;
            let funding = coinbase_outpoint(&fixture.blocks[1]);
            let max_money = Amount::MAX_MONEY.to_sat();

            let above = mined_block_with_prev_hash(
                fixture.blocks[2].block_hash(),
                3,
                vec![coinbase(3), spend(funding, max_money + 1)],
            )?;
            let outcome = fixture.chain.apply_block(&BlockImage::from_local(above));
            assert!(
                matches!(
                    outcome,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::OutputValueOverflow
                    ))
                ),
                "a MAX_MONEY+1 output sum must overflow, got {outcome:?}"
            );

            let exact = mined_block_with_prev_hash(
                fixture.blocks[2].block_hash(),
                3,
                vec![coinbase(3), spend(funding, max_money)],
            )?;
            let outcome = fixture.chain.apply_block(&BlockImage::from_local(exact));
            assert!(
                matches!(
                    outcome,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::InputsLessThanOutputs { .. }
                    ))
                ),
                "a MAX_MONEY output sum must pass the range check, got {outcome:?}"
            );
            Ok(())
        }

        fn seed_payable_coin(fixture: &Fixture, marker: u8, value: u64) -> TestResult<OutPoint> {
            let outpoint = OutPoint::new(Hash256::from_le_bytes(&[marker; 32]).into(), 0);
            let mut seed = BlockChanges::default();
            seed.add(UtxoAdd::new(
                outpoint,
                TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: Script::from_bytes(vec![PAY_TO_TRUE]),
                },
                false,
                0,
            ));
            populate_block_changes(&fixture.chain.coins, &seed)?;
            Ok(outpoint)
        }

        #[test]
        fn a_block_may_spend_a_same_block_output_only_in_creation_order() -> TestResult {
            let forward_fixture = chain_to(2)?;
            let funding = seed_payable_coin(&forward_fixture, 0xF2, 1_000)?;
            let parent = spend(funding, 900);
            let child = spend(OutPoint::new(parent.txid(), 0), 800);
            let forward = mined_block_with_prev_hash(
                forward_fixture.blocks[2].block_hash(),
                3,
                vec![coinbase(3), child.clone(), parent.clone()],
            )?;
            let outcome = forward_fixture
                .chain
                .apply_block(&BlockImage::from_local(forward));
            assert!(
                matches!(
                    outcome,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 0 }
                    ))
                ),
                "a forward same-block spend must be refused, got {outcome:?}"
            );
            assert!(
                forward_fixture.chain.utxo_reader().get(&funding)?.is_some(),
                "a refused forward spend must leave the funding coin"
            );
            assert!(
                forward_fixture
                    .chain
                    .utxo_reader()
                    .get(&OutPoint::new(child.txid(), 0))?
                    .is_none(),
                "a refused forward spend must not create its output"
            );

            let ordered_fixture = chain_to(2)?;
            let funding = seed_payable_coin(&ordered_fixture, 0xF2, 1_000)?;
            let parent = spend(funding, 900);
            let child = spend(OutPoint::new(parent.txid(), 0), 800);
            let ordered = mined_block_with_prev_hash(
                ordered_fixture.blocks[2].block_hash(),
                3,
                vec![coinbase(3), parent.clone(), child.clone()],
            )?;
            ordered_fixture
                .chain
                .apply_block(&BlockImage::from_local(ordered))?;
            assert!(
                ordered_fixture
                    .chain
                    .utxo_reader()
                    .get(&OutPoint::new(child.txid(), 0))?
                    .is_some(),
                "an in-order same-block spend must create its output"
            );
            assert!(
                ordered_fixture
                    .chain
                    .utxo_reader()
                    .get(&OutPoint::new(parent.txid(), 0))?
                    .is_none(),
            );
            Ok(())
        }

        #[test]
        fn a_block_cannot_spend_one_coin_twice() -> TestResult {
            let fixture = chain_to(2)?;
            let funding = seed_payable_coin(&fixture, 0xF3, 1_000)?;
            let first = spend(funding, 600);
            let second = spend(funding, 300);
            let block = mined_block_with_prev_hash(
                fixture.blocks[2].block_hash(),
                3,
                vec![coinbase(3), first.clone(), second.clone()],
            )?;
            let outcome = fixture.chain.apply_block(&BlockImage::from_local(block));
            assert!(
                matches!(
                    outcome,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 0 }
                    ))
                ),
                "a repeated same-block spend must be refused, got {outcome:?}"
            );
            assert!(
                fixture.chain.utxo_reader().get(&funding)?.is_some(),
                "a refused double spend must leave the funding coin"
            );
            for tx in [&first, &second] {
                assert!(
                    fixture
                        .chain
                        .utxo_reader()
                        .get(&OutPoint::new(tx.txid(), 0))?
                        .is_none(),
                    "a refused double spend must not create outputs"
                );
            }
            Ok(())
        }
    }
    mod window_commit_tests {
        use std::collections::HashMap;
        use std::sync::Arc;

        use crate::chain::regtest_fixture::{
            merkle_root, mine_block_to_declared_target, mined_block_with_prev_hash,
            mined_regtest_child_at as mined_child,
            mined_regtest_child_at_time as mined_child_at_time,
        };
        use bitcoin_rs_consensus::ConsensusError;
        use bitcoin_rs_consensus::bip30::is_bip30_exception;
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockImage, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx,
            TxIn, TxOut, Witness,
        };
        use bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1;
        use bitcoin_rs_storage::ColumnFamily;
        use bitcoin_rs_storage::coins::{CoinKey, CoinStore};
        use bitcoin_rs_storage::utxo::UtxoSet;

        use crate::ApplyError;
        use crate::Chainstate;
        use crate::test_fixtures::{
            Corpus, CorpusBlockPlan, CorpusSpend, CorpusSpendPlan, TestError, TestResult,
            apply_headers, coin_scan, commit_genesis_head, handles, seed_genesis,
        };
        use proptest::prelude::*;

        const OLDEST_SPENDABLE_COINBASE_HEIGHT: u32 = 1;

        fn remine(block: &mut Block) -> TestResult {
            block.header.merkle_root =
                merkle_root(&block.txs).ok_or(TestError::Missing("merkle root"))?;
            mine_block_to_declared_target(block)?;
            Ok(())
        }

        fn dump_payloads(blocks: &[Block]) -> Vec<BlockImage> {
            blocks
                .iter()
                .map(|block| BlockImage::from_local(block.clone()))
                .collect()
        }

        fn window_slices(len: usize, cuts: &[usize]) -> Vec<(usize, usize)> {
            let mut bounds: Vec<usize> = cuts
                .iter()
                .filter(|cut| **cut > 0 && **cut < len)
                .copied()
                .collect();
            bounds.sort_unstable();
            bounds.dedup();
            let mut slices = Vec::new();
            let mut start = 0;
            for end in bounds.into_iter().chain(std::iter::once(len)) {
                if end > start {
                    slices.push((start, end));
                    start = end;
                }
            }
            slices
        }

        fn generated_plan(shape: GeneratedShape) -> Vec<CorpusBlockPlan> {
            let first = CorpusBlockPlan {
                spends: vec![
                    CorpusSpendPlan {
                        spend: CorpusSpend::MatureCoinbase {
                            height: OLDEST_SPENDABLE_COINBASE_HEIGHT,
                        },
                    },
                    CorpusSpendPlan {
                        spend: CorpusSpend::SameBlock { tx: 0 },
                    },
                ],
            };
            let second = CorpusBlockPlan {
                spends: vec![
                    CorpusSpendPlan {
                        spend: CorpusSpend::EarlierBlock { block: 0, tx: 1 },
                    },
                    CorpusSpendPlan {
                        spend: CorpusSpend::SameBlock { tx: 0 },
                    },
                ],
            };
            match shape {
                GeneratedShape::SameWindow => vec![first, second],
                GeneratedShape::CrossWindow => vec![first, second, CorpusBlockPlan::default()],
                GeneratedShape::Mixed => vec![
                    first,
                    CorpusBlockPlan::default(),
                    second,
                    CorpusBlockPlan {
                        spends: vec![CorpusSpendPlan {
                            spend: CorpusSpend::EarlierBlock { block: 2, tx: 1 },
                        }],
                    },
                ],
            }
        }

        #[derive(Clone, Copy, Debug)]
        enum GeneratedShape {
            SameWindow,
            CrossWindow,
            Mixed,
        }

        // WIN-03, RCV-04
        proptest! {
        #![proptest_config(proptest::test_runner::Config {
            failure_persistence: Some(std::boxed::Box::new(
                proptest::test_runner::FileFailurePersistence::Direct(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../testdata/execution/regressions/lib.txt"
                )),
            )),
            ..(ProptestConfig {
                cases: std::env::var("PROPTEST_CASES")
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(24),
                ..ProptestConfig::default()
            })
        })]
                #[test]
                fn every_committed_prefix_equals_sequential_execution(
                    shape in 0_u8..3,
                    cut_a in 0_usize..5,
                    cut_b in 0_usize..5,
                ) {
                    let shape = match shape {
                        0 => GeneratedShape::SameWindow,
                        1 => GeneratedShape::CrossWindow,
                        _ => GeneratedShape::Mixed,
                    };
                    run_corpus_prefix_equivalence(shape, &[cut_a, cut_b])
                        .map_err(|error| TestCaseError::fail(format!("{error:?}")))?;
                }
            }

        fn run_corpus_prefix_equivalence(shape: GeneratedShape, cuts: &[usize]) -> TestResult {
            let corpus = Corpus::build(&generated_plan(shape))?;
            let payloads = corpus.payloads();

            let windowed = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&windowed)?;
            commit_genesis_head(&windowed)?;
            let sequential = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&sequential)?;
            commit_genesis_head(&sequential)?;

            for block in &corpus.prefix {
                let image = BlockImage::from_local(block.clone());
                windowed.apply_block(&image)?;
                sequential.apply_block(&image)?;
            }

            let block_refs: Vec<&Block> = corpus.blocks.iter().collect();
            apply_headers(&windowed, &block_refs)?;
            apply_headers(&sequential, &block_refs)?;

            let mut committed_prefix = 0;
            for (start, end) in window_slices(payloads.len(), cuts) {
                let window: Vec<&BlockImage> = payloads[start..end].iter().collect();
                let outcomes = windowed.apply_window(&window)?;
                assert_eq!(outcomes.len(), end - start);

                for payload in &payloads[start..end] {
                    sequential.apply_block(payload)?;
                    committed_prefix += 1;
                }

                let window_head = windowed
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("window durable head"))?;
                let oracle_head = sequential
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("oracle durable head"))?;
                assert_eq!(
                    (
                        window_head.height,
                        window_head.tip,
                        window_head.chain_tx_count
                    ),
                    (
                        oracle_head.height,
                        oracle_head.tip,
                        oracle_head.chain_tx_count
                    ),
                    "durable head must match the sequential oracle at committed prefix {committed_prefix}"
                );
                assert_eq!(
                    coin_scan(&windowed)?,
                    coin_scan(&sequential)?,
                    "engine coins must match the sequential oracle at committed prefix {committed_prefix}"
                );
            }
            Ok(())
        }

        // WIN-04
        #[test]
        fn create_and_spend_inside_prefix_never_reaches_coin_store() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let mut parent = Network::Regtest.genesis_block().block_hash();
            let mut funding = None;
            for height in 1..=100_u32 {
                let block = mined_child(parent, height)?;
                if height == 1 {
                    funding = Some(OutPoint::new(block.txs[0].txid(), 0));
                }
                chain.apply_block(&BlockImage::from_local(block.clone()))?;
                parent = block.block_hash();
            }
            let funding = funding.ok_or(TestError::Missing("funding coinbase"))?;

            let ephemeral_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: funding,
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let ephemeral_txid = ephemeral_tx.txid();
            let ephemeral_outpoint = OutPoint::new(ephemeral_txid, 0);

            let mut b101 = mined_child(parent, 101)?;
            b101.txs.push(ephemeral_tx);
            remine(&mut b101)?;

            let spend_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: ephemeral_outpoint,
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let mut b102 = mined_child(b101.block_hash(), 102)?;
            b102.txs.push(spend_tx);
            remine(&mut b102)?;

            let blocks = [b101, b102];
            let block_refs: Vec<&Block> = blocks.iter().collect();
            apply_headers(&chain, &block_refs)?;

            let payloads = dump_payloads(&blocks);
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

            chain.apply_window(&payload_refs)?;

            let key = CoinKey(ephemeral_txid.0.to_le_bytes());
            let store = chain.commit_authority.store();
            let raw_entry = store.get(ColumnFamily::Coins, key.as_bytes())?;
            assert!(
                raw_entry.is_none(),
                "ephemeral coin record must never reach the persistent engine coin store"
            );

            Ok(())
        }

        // WIN-08
        #[test]
        fn failure_at_block_j_commits_prefix_before_j() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let genesis = Network::Regtest.genesis_block();
            let b1 = mined_child(genesis.block_hash(), 1)?;
            let b2 = mined_child(b1.block_hash(), 2)?;
            let mut b3 = mined_child(b2.block_hash(), 3)?;
            b3.txs[0].outputs[0].value = Amount::from_sat(500_000_000_000);
            remine(&mut b3)?;

            apply_headers(&chain, &[&b1, &b2, &b3])?;

            let blocks = [b1.clone(), b2.clone(), b3.clone()];
            let payloads = dump_payloads(&blocks);
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

            let result = chain.apply_window(&payload_refs);
            assert!(result.is_err(), "window with corrupt block 3 must fail");

            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head must be committed"))?;
            assert_eq!(
                head.height, 2,
                "durable head must commit valid prefix up to height 2"
            );
            assert_eq!(head.tip, b2.block_hash().0);

            let b1_key = CoinKey(b1.txs[0].txid().0.to_le_bytes());
            let b2_key = CoinKey(b2.txs[0].txid().0.to_le_bytes());
            let b3_key = CoinKey(b3.txs[0].txid().0.to_le_bytes());
            assert!(chain.coins.get(&b1_key)?.is_some());
            assert!(chain.coins.get(&b2_key)?.is_some());
            assert!(chain.coins.get(&b3_key)?.is_none());

            Ok(())
        }

        // CMT-03
        #[test]
        fn crash_between_commit_and_cache_install_reloads_from_engine() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let genesis = Network::Regtest.genesis_block();
            let b1 = mined_child(genesis.block_hash(), 1)?;
            apply_headers(&chain, &[&b1])?;

            let payload = BlockImage::from_local(b1.clone());
            chain.apply_window(&[&payload])?;

            let store = Arc::clone(chain.commit_authority.store());
            let fresh_coins = CoinStore::open(store, 64 * 1024 * 1024);
            let cb_txid = b1.txs[0].txid();
            let key = CoinKey(cb_txid.0.to_le_bytes());

            let reloaded = fresh_coins
                .get(&key)?
                .ok_or(TestError::Missing("coin must reload from engine"))?;
            let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                reloaded.to_vec().into_boxed_slice(),
            )?;
            assert_eq!(record.txid(), cb_txid.0);

            Ok(())
        }

        // WIN-07
        #[test]
        fn bip30_overwrite_stays_explicit() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let b1 = mined_child(genesis.block_hash(), 1)?;
            let b2 = mined_child(b1.block_hash(), 2)?;
            let mut duplicate = mined_child(b2.block_hash(), 3)?;
            duplicate.txs[0] = b1.txs[0].clone();
            remine(&mut duplicate)?;
            let blocks = [b1.clone(), b2.clone(), duplicate.clone()];

            let windowed = fresh_regtest_chain_with_bodies()?;
            let block_refs: Vec<&Block> = blocks.iter().collect();
            apply_headers(&windowed, &block_refs)?;
            let payloads = dump_payloads(&blocks);
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();
            let error =
                windowed
                    .apply_window(&payload_refs)
                    .err()
                    .ok_or(TestError::UnexpectedSuccess(
                        "a duplicate txid outside the BIP30 exceptions must fail the window",
                    ))?;
            assert!(
                matches!(
                    *error.source,
                    ApplyError::Consensus(ConsensusError::Bip { .. })
                ),
                "the duplicate must be refused by the BIP30 rule, got {:?}",
                error.source
            );
            assert!(
                !is_bip30_exception(3, Hash256::from(duplicate.block_hash())),
                "regtest height 3 is not a BIP30 exception height"
            );

            let committed_head = windowed
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(
                committed_head.height, 2,
                "the valid prefix before the rejected block commits and the rejected block does not"
            );
            assert_eq!(committed_head.tip, b2.block_hash().0);
            let committed = committed_head.height;
            let sequential = fresh_regtest_chain_with_bodies()?;
            for block in blocks.iter().take(usize::try_from(committed)?) {
                sequential.apply_block(&BlockImage::from_local(block.clone()))?;
            }
            assert_chain_matches_oracle(
                &windowed,
                &sequential,
                "for the prefix before the duplicate",
            )
        }

        fn fresh_regtest_chain_with_bodies() -> TestResult<Chainstate> {
            let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            chain.block_body_store = Some(Arc::new(crate::test_support::MemoryBodies::default()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;
            Ok(chain)
        }

        fn winning_plan() -> Vec<CorpusBlockPlan> {
            vec![
                CorpusBlockPlan {
                    spends: vec![CorpusSpendPlan {
                        spend: CorpusSpend::MatureCoinbase {
                            height: OLDEST_SPENDABLE_COINBASE_HEIGHT,
                        },
                    }],
                },
                CorpusBlockPlan {
                    spends: vec![
                        CorpusSpendPlan {
                            spend: CorpusSpend::EarlierBlock { block: 0, tx: 0 },
                        },
                        CorpusSpendPlan {
                            spend: CorpusSpend::SameBlock { tx: 0 },
                        },
                    ],
                },
                CorpusBlockPlan {
                    spends: vec![CorpusSpendPlan {
                        spend: CorpusSpend::EarlierBlock { block: 1, tx: 1 },
                    }],
                },
            ]
        }

        struct NoopReorgObserver;

        impl crate::reorg::ReorgObserver for NoopReorgObserver {
            fn disconnected(&mut self, _: &crate::DisconnectOutcome) {}

            fn connected(&mut self, _: &BlockImage, _: &crate::ConnectOutcome) {}

            fn reconsider_disconnected(&mut self, _: &BlockImage) {}
        }

        fn assert_chain_matches_oracle(
            windowed: &Chainstate,
            sequential: &Chainstate,
            stage: &str,
        ) -> TestResult {
            let window_head = windowed
                .durable_head
                .load()?
                .ok_or(TestError::Missing("window durable head"))?;
            let oracle_head = sequential
                .durable_head
                .load()?
                .ok_or(TestError::Missing("oracle durable head"))?;
            assert_eq!(
                (
                    window_head.height,
                    window_head.tip,
                    window_head.chain_tx_count
                ),
                (
                    oracle_head.height,
                    oracle_head.tip,
                    oracle_head.chain_tx_count
                ),
                "durable head must match the sequential oracle {stage}"
            );
            assert_eq!(
                coin_scan(windowed)?,
                coin_scan(sequential)?,
                "engine coins must match the sequential oracle {stage}"
            );
            Ok(())
        }

        // REO-02, REO-03
        #[test]
        fn reorg_inside_committed_window_equals_winning_branch() -> TestResult {
            let losing = Corpus::build(&generated_plan(GeneratedShape::SameWindow))?;
            let winning = Corpus::build(&winning_plan())?;

            let windowed = fresh_regtest_chain_with_bodies()?;
            for block in &losing.prefix {
                windowed.apply_block(&BlockImage::from_local(block.clone()))?;
            }
            let losing_refs: Vec<&Block> = losing.blocks.iter().collect();
            apply_headers(&windowed, &losing_refs)?;
            let losing_payloads = losing.payloads();
            let losing_window: Vec<&BlockImage> = losing_payloads.iter().collect();
            windowed.apply_window(&losing_window)?;
            let committed_loser = windowed
                .durable_head
                .load()?
                .ok_or(TestError::Missing("losing window must commit a head"))?;
            let expected_height = u32::try_from(losing.prefix.len() + losing.blocks.len())?;
            assert_eq!(
                committed_loser.height, expected_height,
                "both losing blocks must sit inside one committed window"
            );

            let winning_refs: Vec<&Block> = winning.blocks.iter().collect();
            apply_headers(&windowed, &winning_refs)?;
            let winning_payloads = winning.payloads();
            let bodies: HashMap<Hash256, BlockImage> = winning
                .blocks
                .iter()
                .zip(&winning_payloads)
                .map(|(block, payload)| (Hash256::from(block.block_hash()), payload.clone()))
                .collect();
            let winning_tip = winning
                .blocks
                .last()
                .ok_or(TestError::Missing("winning branch has blocks"))?
                .block_hash();
            let target = windowed
                .block_tree
                .read()
                .lookup(Hash256::from(winning_tip))
                .ok_or(TestError::Missing("winning tip header"))?;
            crate::reorg::switch_to_branch(
                &windowed,
                target,
                |hash| bodies.get(&hash).cloned(),
                &mut NoopReorgObserver,
                |_, outcome| outcome,
            )?;
            let reorged = windowed
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("reorg publishes a tip"))?;
            assert_eq!(
                reorged.hash,
                Hash256::from(winning_tip),
                "the reorg moves the applied tip onto the winning branch"
            );

            let sequential = fresh_regtest_chain_with_bodies()?;
            for block in &losing.prefix {
                sequential.apply_block(&BlockImage::from_local(block.clone()))?;
            }
            apply_headers(&sequential, &winning_refs)?;
            for payload in &winning_payloads {
                sequential.apply_block(payload)?;
            }

            assert_chain_matches_oracle(&windowed, &sequential, "after the reorg")
        }

        // WIN-06, WIN-08
        #[test]
        fn unlinked_window_block_commits_only_prefix_with_matching_coins() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let linked = mined_child(genesis.block_hash(), 1)?;
            let unlinked = mined_child_at_time(genesis.block_hash(), genesis.header.time + 5, 1)?;
            let blocks = [linked.clone(), unlinked.clone()];
            let windowed = fresh_regtest_chain_with_bodies()?;
            let block_refs: Vec<&Block> = blocks.iter().collect();
            apply_headers(&windowed, &block_refs)?;
            let payloads = dump_payloads(&blocks);
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();
            assert!(
                windowed.apply_window(&payload_refs).is_err(),
                "a block that does not extend its predecessor must fail the window"
            );

            let committed = windowed.durable_head.load()?.map_or(0, |head| head.height);
            assert_eq!(
                committed, 1,
                "the linked block must commit before the unlinked block fails the window"
            );
            let linked_key = CoinKey(linked.txs[0].txid().0.to_le_bytes());
            assert!(
                coin_scan(&windowed)?
                    .iter()
                    .any(|(key, _)| key.as_slice() == linked_key.as_bytes()),
                "the linked coinbase must be live in the engine coin keyspace"
            );
            let sequential = fresh_regtest_chain_with_bodies()?;
            for block in blocks.iter().take(usize::try_from(committed)?) {
                sequential.apply_block(&BlockImage::from_local(block.clone()))?;
            }
            assert_chain_matches_oracle(
                &windowed,
                &sequential,
                "for the committed prefix of a failed window",
            )
        }
        // WIN-03, RCV-04
        #[test]
        fn fixed_window_committed_prefix_equals_sequential_execution() -> TestResult {
            let chain1 = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain1)?;
            commit_genesis_head(&chain1)?;

            let chain2 = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain2)?;
            commit_genesis_head(&chain2)?;

            let genesis = Network::Regtest.genesis_block();
            let b1 = mined_child(genesis.block_hash(), 1)?;
            let b2 = mined_child(b1.block_hash(), 2)?;
            let b3 = mined_child(b2.block_hash(), 3)?;
            let blocks = [b1, b2, b3];
            let block_refs: Vec<&Block> = blocks.iter().collect();

            apply_headers(&chain1, &block_refs)?;
            apply_headers(&chain2, &block_refs)?;

            let payloads = dump_payloads(&blocks);
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

            let window_outcomes = chain1.apply_window(&payload_refs)?;
            assert_eq!(window_outcomes.len(), 3);

            for payload in &payloads {
                let single = chain2.apply_window(&[payload])?;
                assert_eq!(single.len(), 1);
            }

            let head1 = chain1
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head 1"))?;
            let head2 = chain2
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head 2"))?;
            assert_eq!(head1.height, head2.height);
            assert_eq!(head1.tip, head2.tip);
            assert_eq!(head1.chain_tx_count, head2.chain_tx_count);

            for block in &blocks {
                let cb_txid = block.txs[0].txid();
                let key = CoinKey(cb_txid.0.to_le_bytes());
                let coin1 = chain1.coins.get(&key)?;
                let coin2 = chain2.coins.get(&key)?;
                assert_eq!(coin1, coin2, "coin state must match for {cb_txid}");
                assert!(coin1.is_some(), "coinbase output must exist");
            }

            Ok(())
        }

        fn insert_engine_coin(
            chain: &Chainstate,
            txid: bitcoin_rs_consensus::primitives::Txid,
        ) -> TestResult {
            let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
                txid.0,
                &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                    vout: 0,
                    value: 50_000,
                    script_pubkey: vec![OP_PUSHNUM_1],
                    coinbase: false,
                    height: 0,
                }],
            )
            .map_err(|_| TestError::Missing("synthetic coin record"))?;
            chain.commit_authority.store().put(
                ColumnFamily::Coins,
                CoinKey(txid.0.to_le_bytes()).as_bytes(),
                record.bytes(),
            )?;
            Ok(())
        }

        // WIN-07
        #[test]
        fn engine_coin_spent_inside_the_window_is_not_a_duplicate() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let genesis = Network::Regtest.genesis_block();
            let duplicate_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let duplicate_txid = duplicate_tx.txid();
            insert_engine_coin(&chain, duplicate_txid)?;

            let spend_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(duplicate_txid, 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };

            let mut b1 = mined_child(genesis.block_hash(), 1)?;
            b1.txs.push(spend_tx);
            remine(&mut b1)?;
            let b1_hash = b1.block_hash().0;
            let mut b2 = mined_child(b1.block_hash(), 2)?;
            b2.txs.push(duplicate_tx);
            remine(&mut b2)?;

            apply_headers(&chain, &[&b1, &b2])?;
            let blocks = [b1, b2];
            let payloads = dump_payloads(&blocks);
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

            let error = match chain.apply_window(&payload_refs) {
                Ok(outcomes) => panic!(
                    "a coin spent inside the window was reported as a duplicate; head at height {}",
                    outcomes.last().map_or(0, |outcome| outcome.height)
                ),
                Err(error) => error,
            };
            assert!(
                !matches!(
                    *error.source,
                    ApplyError::Consensus(ConsensusError::Bip { .. })
                ),
                "a coin spent inside the window is not a duplicate, got: {:?}",
                error.source
            );
            assert!(
                matches!(
                    *error.source,
                    ApplyError::Consensus(ConsensusError::MissingPrevout { .. })
                ),
                "block 2 must fail on its absent prevout, got: {:?}",
                error.source
            );

            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(head.height, 1);
            assert_eq!(head.tip, b1_hash);

            Ok(())
        }

        #[derive(Default)]
        struct RecordingCharge {
            balance: parking_lot::Mutex<(u64, u64)>,
        }

        impl bitcoin_rs_storage::budget::BudgetCharge for RecordingCharge {
            fn reserve_bytes(
                &self,
                _owner: bitcoin_rs_storage::budget::BudgetOwner,
                _bytes: u64,
            ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
                Ok(())
            }

            fn allocate_bytes(
                &self,
                _owner: bitcoin_rs_storage::budget::BudgetOwner,
                bytes: u64,
            ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
                let mut balance = self.balance.lock();
                balance.0 += bytes;
                balance.1 = balance.1.max(balance.0);
                Ok(())
            }

            fn release_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner, bytes: u64) {
                let mut balance = self.balance.lock();
                balance.0 = balance.0.saturating_sub(bytes);
            }

            fn available_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner) -> u64 {
                u64::MAX
            }
        }

        // BUD-06
        #[test]
        fn window_prevouts_are_charged_during_apply_and_released_after_commit() -> TestResult {
            let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let genesis = Network::Regtest.genesis_block();
            let duplicate_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            insert_engine_coin(&chain, duplicate_tx.txid())?;

            let spend_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(duplicate_tx.txid(), 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let mut b1 = mined_child(genesis.block_hash(), 1)?;
            b1.txs.push(spend_tx);
            remine(&mut b1)?;
            apply_headers(&chain, &[&b1])?;
            let payloads = dump_payloads(std::slice::from_ref(&b1));
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

            let charge = Arc::new(RecordingCharge::default());
            chain.set_prevout_charge(bitcoin_rs_storage::budget::ChargeHandle::new(
                charge.clone(),
                bitcoin_rs_storage::budget::BudgetOwner::StagedImages,
            ));
            chain.apply_window(&payload_refs)?;

            let (current, peak) = *charge.balance.lock();
            assert!(peak > 0, "the resolved window prevouts were never charged");
            assert_eq!(current, 0, "the window prevout charge returns after commit");
            Ok(())
        }

        #[test]
        fn engine_coin_duplicate_across_windows_is_rejected_by_bip30() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let genesis = Network::Regtest.genesis_block();
            let b1 = mined_child(genesis.block_hash(), 1)?;
            let b1_hash = b1.block_hash().0;
            let b2 = mined_child(b1.block_hash(), 2)?;
            insert_engine_coin(&chain, b2.txs[0].txid())?;

            apply_headers(&chain, &[&b1, &b2])?;
            let blocks = [b1, b2];
            let payloads = dump_payloads(&blocks);
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

            let error = match chain.apply_window(&payload_refs) {
                Ok(outcomes) => panic!(
                    "a coinbase already resident in the engine was accepted as new; head at height {}",
                    outcomes.last().map_or(0, |outcome| outcome.height)
                ),
                Err(error) => error,
            };
            assert!(
                matches!(
                    *error.source,
                    ApplyError::Consensus(ConsensusError::Bip { .. })
                ),
                "the duplicate must be refused by the BIP30 rule, got: {:?}",
                error.source
            );

            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(
                head.height, 1,
                "block 1 commits and the duplicate block does not"
            );
            assert_eq!(head.tip, b1_hash);

            Ok(())
        }

        // WIN-07
        #[test]
        fn gap_replay_token_keeps_the_duplicate_exemption() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let genesis = Network::Regtest.genesis_block();
            let b1 = mined_child(genesis.block_hash(), 1)?;
            apply_headers(&chain, &[&b1])?;
            let b1_payload = BlockImage::from_local(b1.clone());
            chain.apply_window(&[&b1_payload])?;

            let b2 = mined_block_with_prev_hash(b1.block_hash(), 2, vec![b1.txs[0].clone()])?;
            assert_eq!(b1.txs[0].txid(), b2.txs[0].txid());
            apply_headers(&chain, &[&b2])?;
            let b2_payload = BlockImage::from_local(b2);

            let mut group = crate::window::WindowGroup::new(
                crate::window_limits::default_window_limits_source()(),
            );
            let outcome = crate::connect::apply_block_admitted(
                &chain,
                &b2_payload,
                None,
                crate::connect::ApplyScope {
                    provenance: crate::BlockProvenance::LocalReplay(
                        crate::durable::replay_token_for_test(),
                    ),
                    staged: None,
                },
                crate::ApplyIntent::Commit,
                crate::window::PublishMode::Grouped(&mut group),
            );
            assert!(
                outcome.is_ok(),
                "the durable gap replay keeps its duplicate exemption"
            );
            Ok(())
        }

        // WIN-05
        #[test]
        fn corrupt_engine_coin_record_fails_closed() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let genesis = Network::Regtest.genesis_block();
            let owner_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let coin_txid = owner_tx.txid();
            chain.commit_authority.store().put(
                ColumnFamily::Coins,
                CoinKey(coin_txid.0.to_le_bytes()).as_bytes(),
                &[0xff; 5],
            )?;

            let spend_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(coin_txid, 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let mut block = mined_child(genesis.block_hash(), 1)?;
            block.txs.push(spend_tx);
            remine(&mut block)?;
            apply_headers(&chain, &[&block])?;
            let payload = BlockImage::from_local(block);

            let Err(error) = chain.apply_window(&[&payload]) else {
                return Err(TestError::UnexpectedSuccess(
                    "a corrupt coin record must refuse the window",
                ));
            };
            assert!(
                matches!(
                    error.source.as_ref(),
                    crate::ApplyError::UtxoCommit(
                        bitcoin_rs_storage::utxo::set::UtxoError::CorruptRecord
                    )
                ),
                "expected a typed corrupt-record error, got: {error}"
            );
            assert_eq!(error.disposition, crate::WindowApplyDisposition::Fatal);

            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(
                head.height, 0,
                "the refused window must not advance the head"
            );
            Ok(())
        }

        // BUD-06
        #[test]
        fn window_resolved_charge_returns_on_failure() -> TestResult {
            let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;
            let genesis = Network::Regtest.genesis_block();
            let b1 = mined_child(genesis.block_hash(), 1)?;
            let b2 = mined_block_with_prev_hash(b1.block_hash(), 2, vec![b1.txs[0].clone()])?;
            apply_headers(&chain, &[&b1, &b2])?;
            let payloads = dump_payloads(&[b1, b2]);
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();
            let charge = Arc::new(RecordingCharge::default());
            chain.set_prevout_charge(bitcoin_rs_storage::budget::ChargeHandle::new(
                charge.clone(),
                bitcoin_rs_storage::budget::BudgetOwner::StagedImages,
            ));
            let _ = chain
                .apply_window(&payload_refs)
                .err()
                .ok_or(TestError::Missing("window must fail"))?;
            let (current, _) = *charge.balance.lock();
            assert_eq!(current, 0);
            Ok(())
        }

        // BUD-06
        #[test]
        fn single_prepare_resolved_is_charged_and_released() -> TestResult {
            let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;
            let genesis = Network::Regtest.genesis_block();
            let owner = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let owner_txid = owner.txid();
            insert_engine_coin(&chain, owner_txid)?;
            let spend = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(owner_txid, 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let mut b1 = mined_child(genesis.block_hash(), 1)?;
            b1.txs.push(spend);
            remine(&mut b1)?;
            apply_headers(&chain, &[&b1])?;
            let payload = BlockImage::from_local(b1);
            let charge = Arc::new(RecordingCharge::default());
            chain.set_prevout_charge(bitcoin_rs_storage::budget::ChargeHandle::new(
                charge.clone(),
                bitcoin_rs_storage::budget::BudgetOwner::StagedImages,
            ));
            chain.apply_block(&payload)?;
            let (current, peak) = *charge.balance.lock();
            assert!(peak > 0);
            assert_eq!(current, 0);
            Ok(())
        }

        // BUD-06
        #[test]
        fn single_view_prevouts_refusal_returns_staged_exhausted() -> TestResult {
            let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;
            let genesis = Network::Regtest.genesis_block();
            let owner = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let owner_txid = owner.txid();
            insert_engine_coin(&chain, owner_txid)?;
            let spend = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(owner_txid, 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let mut b1 = mined_child(genesis.block_hash(), 1)?;
            b1.txs.push(spend);
            remine(&mut b1)?;
            apply_headers(&chain, &[&b1])?;
            let payload = BlockImage::from_local(b1);
            let charge = Arc::new(RefusingCharge);
            chain.set_prevout_charge(bitcoin_rs_storage::budget::ChargeHandle::new(
                charge,
                bitcoin_rs_storage::budget::BudgetOwner::StagedImages,
            ));
            let err = chain
                .apply_block(&payload)
                .err()
                .ok_or(TestError::Missing("refused block"))?;
            assert!(matches!(err, crate::ApplyError::StagedBudgetExhausted));
            Ok(())
        }

        struct RefusingCharge;

        impl bitcoin_rs_storage::budget::BudgetCharge for RefusingCharge {
            fn reserve_bytes(
                &self,
                _owner: bitcoin_rs_storage::budget::BudgetOwner,
                _bytes: u64,
            ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
                Err(bitcoin_rs_storage::budget::BudgetError::BudgetExhausted)
            }
            fn allocate_bytes(
                &self,
                _owner: bitcoin_rs_storage::budget::BudgetOwner,
                _bytes: u64,
            ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
                Err(bitcoin_rs_storage::budget::BudgetError::BudgetExhausted)
            }
            fn release_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner, _bytes: u64) {}
            fn available_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner) -> u64 {
                0
            }
        }

        struct BoundedCharge {
            limit: u64,
            current: parking_lot::Mutex<u64>,
            peak: parking_lot::Mutex<u64>,
            credits: parking_lot::Mutex<Vec<u64>>,
        }

        impl BoundedCharge {
            fn new(limit: u64) -> Self {
                Self {
                    limit,
                    current: parking_lot::Mutex::new(0),
                    peak: parking_lot::Mutex::new(0),
                    credits: parking_lot::Mutex::new(Vec::new()),
                }
            }
        }

        impl bitcoin_rs_storage::budget::BudgetCharge for BoundedCharge {
            fn reserve_bytes(
                &self,
                _owner: bitcoin_rs_storage::budget::BudgetOwner,
                _bytes: u64,
            ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
                Ok(())
            }

            fn allocate_bytes(
                &self,
                _owner: bitcoin_rs_storage::budget::BudgetOwner,
                bytes: u64,
            ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
                let mut cur = self.current.lock();
                if cur.saturating_add(bytes) > self.limit {
                    self.credits.lock().push(bytes);
                    return Err(bitcoin_rs_storage::budget::BudgetError::BudgetExhausted);
                }
                *cur += bytes;
                let mut peak = self.peak.lock();
                *peak = (*peak).max(*cur);
                Ok(())
            }

            fn release_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner, bytes: u64) {
                let mut credits = self.credits.lock();
                if let Some(index) = credits.iter().position(|credit| *credit == bytes) {
                    credits.remove(index);
                    return;
                }
                drop(credits);
                let mut cur = self.current.lock();
                *cur = cur.saturating_sub(bytes);
            }

            fn available_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner) -> u64 {
                let cur = *self.current.lock();
                self.limit.saturating_sub(cur)
            }
        }

        fn spend_of(previous: bitcoin_rs_consensus::primitives::Txid, sats: u64) -> Tx {
            Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(previous, 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(sats),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            }
        }

        fn bip30_tail_fixture()
        -> TestResult<(Block, Block, Vec<bitcoin_rs_consensus::primitives::Txid>)> {
            let genesis = Network::Regtest.genesis_block();
            let first_owner = spend_of(genesis.txs[0].txid(), 50_000).txid();
            let tail_owners: Vec<_> = (0..4_u64)
                .map(|index| spend_of(genesis.txs[0].txid(), 51_000 + index).txid())
                .collect();
            let mut b1 = mined_child(genesis.block_hash(), 1)?;
            b1.txs.push(spend_of(first_owner, 40_000));
            remine(&mut b1)?;
            let mut b2 = mined_child(b1.block_hash(), 2)?;
            for (index, owner) in tail_owners.iter().enumerate() {
                b2.txs
                    .push(spend_of(*owner, 30_000 + u64::try_from(index)?));
            }
            remine(&mut b2)?;
            let mut engine_coins = vec![first_owner, b2.txs[0].txid()];
            engine_coins.extend(tail_owners);
            Ok((b1, b2, engine_coins))
        }

        fn bip30_tail_chain(
            b1: &Block,
            b2: &Block,
            engine_coins: &[bitcoin_rs_consensus::primitives::Txid],
        ) -> TestResult<Chainstate> {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;
            for txid in engine_coins {
                insert_engine_coin(&chain, *txid)?;
            }
            apply_headers(&chain, &[b1, b2])?;
            Ok(chain)
        }

        // BUD-06, WIN-07
        #[test]
        fn tail_window_after_a_duplicate_split_is_not_starved_by_the_completed_window() -> TestResult
        {
            let (b1, b2, engine_coins) = bip30_tail_fixture()?;
            let payloads = dump_payloads(&[b1.clone(), b2.clone()]);

            let mut separate = bip30_tail_chain(&b1, &b2, &engine_coins)?;
            let first_window = Arc::new(BoundedCharge::new(u64::MAX));
            separate.set_prevout_charge(bitcoin_rs_storage::budget::ChargeHandle::new(
                first_window.clone(),
                bitcoin_rs_storage::budget::BudgetOwner::StagedImages,
            ));
            separate.apply_window(&[&payloads[0]])?;
            let tail_window = Arc::new(BoundedCharge::new(u64::MAX));
            separate.set_prevout_charge(bitcoin_rs_storage::budget::ChargeHandle::new(
                tail_window.clone(),
                bitcoin_rs_storage::budget::BudgetOwner::StagedImages,
            ));
            let refused = separate
                .apply_window(&[&payloads[1]])
                .err()
                .ok_or(TestError::Missing("the duplicate block must be refused"))?;
            assert!(matches!(
                *refused.source,
                ApplyError::Consensus(ConsensusError::Bip { .. })
            ));
            let (first_settled, first_peak) =
                (*first_window.current.lock(), *first_window.peak.lock());
            let (tail_settled, tail_peak) = (*tail_window.current.lock(), *tail_window.peak.lock());
            assert_eq!((first_settled, tail_settled), (0, 0));
            assert!(first_peak > 0, "the first window must charge its prevouts");
            assert!(
                tail_peak > first_peak,
                "the tail window must need more than the first window"
            );

            let mut chained = bip30_tail_chain(&b1, &b2, &engine_coins)?;
            let bounded = Arc::new(BoundedCharge::new(tail_peak));
            chained.set_prevout_charge(bitcoin_rs_storage::budget::ChargeHandle::new(
                bounded.clone(),
                bitcoin_rs_storage::budget::BudgetOwner::StagedImages,
            ));
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();
            let error = chained
                .apply_window(&payload_refs)
                .err()
                .ok_or(TestError::Missing("the duplicate block must be refused"))?;
            assert!(
                matches!(
                    *error.source,
                    ApplyError::Consensus(ConsensusError::Bip { .. })
                ),
                "the duplicate block must reach the BIP30 rule: {:?}",
                error.source
            );
            assert_eq!(
                *bounded.peak.lock(),
                tail_peak,
                "the tail window must be admitted with the first window's charge released"
            );
            assert_eq!(*bounded.current.lock(), 0);
            let head = chained
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(head.height, 1);
            Ok(())
        }

        #[test]
        fn window_prevouts_refusal_releases_charge_without_leak() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let owner_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let owner_txid = owner_tx.txid();
            let spend_tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(owner_txid, 0),
                    script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
                }],
                lock_time: LockTime::ZERO,
            };
            let mut b1 = mined_child(genesis.block_hash(), 1)?;
            b1.txs.push(spend_tx);
            remine(&mut b1)?;
            let payloads = dump_payloads(std::slice::from_ref(&b1));
            let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

            let staged_chain =
        |charge: Arc<dyn bitcoin_rs_storage::budget::BudgetCharge>| -> TestResult<Chainstate> {
            let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;
            insert_engine_coin(&chain, owner_txid)?;
            apply_headers(&chain, &[&b1])?;
            chain.set_prevout_charge(bitcoin_rs_storage::budget::ChargeHandle::new(
                charge,
                bitcoin_rs_storage::budget::BudgetOwner::StagedImages,
            ));
            Ok(chain)
        };

            let unlimited = Arc::new(RecordingCharge::default());
            let unlimited_chain = staged_chain(unlimited.clone())?;
            unlimited_chain.apply_window(&payload_refs)?;
            let (settled, total_peak) = *unlimited.balance.lock();
            assert_eq!(
                settled, 0,
                "the committed window releases its prevout charge"
            );
            assert!(
                total_peak > 0,
                "the resolved window prevouts were never charged"
            );

            let boundary = Arc::new(BoundedCharge::new(total_peak));
            let boundary_chain = staged_chain(boundary.clone())?;
            boundary_chain.apply_window(&payload_refs)?;
            let settled = *boundary.current.lock();
            let peak = *boundary.peak.lock();
            assert_eq!(
                peak, total_peak,
                "the boundary window must charge its resolved view and its prevouts"
            );
            assert_eq!(
                settled, 0,
                "the committed boundary window releases its prevout charge"
            );

            let limit = total_peak - 1;
            let bounded = Arc::new(BoundedCharge::new(limit));
            let refused_chain = staged_chain(bounded.clone())?;
            let error = match refused_chain.apply_window(&payload_refs) {
                Ok(outcomes) => panic!(
                    "a limit under the prevout charge must refuse the window; head at height {}",
                    outcomes.last().map_or(0, |outcome| outcome.height)
                ),
                Err(error) => error,
            };
            assert!(
                matches!(error.source.as_ref(), ApplyError::StagedBudgetExhausted),
                "the prevout allocation must refuse with a staged budget error, got: {:?}",
                error.source
            );

            let resolved_charge = *bounded.peak.lock();
            let prevout_charge = total_peak - resolved_charge;
            assert!(
                resolved_charge > 0,
                "the resolved engine-coin view must stay charged at the refusal"
            );
            assert!(
                prevout_charge > 0,
                "the prevout allocation must need more than the resolved view"
            );
            assert!(
                resolved_charge <= limit,
                "the limit must admit the resolved view charge"
            );
            assert!(
                limit < resolved_charge + prevout_charge,
                "the limit must refuse the prevout allocation"
            );
            assert_eq!(
                *bounded.current.lock(),
                0,
                "a refused window must release any partial prevout charge"
            );
            Ok(())
        }
    }
    mod window_disposition_tests {
        use crate::chain::ChainError;
        use bitcoin_rs_consensus::primitives::Hash256;
        use bitcoin_rs_consensus::{ConsensusError, ScriptEngine, ValidationEngine};
        use bitcoin_rs_storage::StorageError;

        use crate::{ApplyError, CheckpointError, WindowApplyDisposition, classify_apply_error};
        use ApplyError::{
            BlockBodyPersistence, BlockOutputsExceedInputs, BlockValueOverflow,
            RecoveryPublication, UndoPersistence,
        };

        // SYNC-04
        #[test]
        fn apply_errors_classify_into_their_documented_dispositions() {
            use ApplyError::{Chain, Consensus, DurableHeadCommit, ProofOfWork};
            use ConsensusError::{
                Kernel, MerkleRoot, MissingCoinbase, PrevoutCount, PrevoutMatrixSize,
                PrevoutMismatch, Script, SignetSolution, SixtyFourByteMutation, UnsupportedEngine,
            };
            use WindowApplyDisposition::{BodyMutated, Fatal, Operational, Permanent};

            let script = |engine| Script {
                input_index: 0,
                reason: "script failed".to_owned(),
                engine,
            };
            let cases = [
                (
                    Consensus(UnsupportedEngine {
                        engine: ValidationEngine::Kernel,
                    }),
                    Operational,
                ),
                (
                    Consensus(PrevoutCount {
                        input_count: 2,
                        prevout_count: 1,
                    }),
                    Operational,
                ),
                (
                    Consensus(PrevoutMatrixSize {
                        expected: 2,
                        actual: 1,
                    }),
                    Operational,
                ),
                (Consensus(PrevoutMismatch { input_index: 1 }), Operational),
                (Consensus(Kernel("parse failed".to_owned())), Operational),
                (Consensus(script(ScriptEngine::Kernel)), Permanent),
                (Consensus(script(ScriptEngine::Native)), Permanent),
                (Consensus(SignetSolution), Permanent),
                (
                    ProofOfWork {
                        hash: Hash256::default(),
                    },
                    Permanent,
                ),
                (
                    Chain(ChainError::NbitsMismatch {
                        height: 2016,
                        expected: 1,
                        actual: 2,
                    }),
                    Permanent,
                ),
                (Consensus(MerkleRoot), BodyMutated),
                (Consensus(SixtyFourByteMutation), BodyMutated),
                (Consensus(MissingCoinbase), Permanent),
                (
                    DurableHeadCommit(StorageError::backend("head batch lost")),
                    Fatal,
                ),
                (
                    UndoPersistence(StorageError::backend("RocksDbError: Poisoned")),
                    Fatal,
                ),
                (
                    BlockBodyPersistence(StorageError::backend("block append failed")),
                    Fatal,
                ),
                (BlockValueOverflow, Permanent),
                (BlockOutputsExceedInputs, Permanent),
                (
                    RecoveryPublication(Box::new(CheckpointError::Storage(StorageError::backend(
                        "checkpoint write lost",
                    )))),
                    Fatal,
                ),
            ];

            for (error, expected) in cases {
                assert_eq!(classify_apply_error(&error), expected, "{error}");
            }
        }
    }
    mod window_flush_budget_tests {
        use std::sync::Arc;

        use bitcoin_rs_consensus::primitives::BlockImage;
        use bitcoin_rs_storage::commit::{AcceptedPrefix, CommitError, CommitFault};
        use parking_lot::Mutex;

        use crate::test_fixtures::{TestResult, churn_corpus, funded_chain};
        use crate::window_limits::WindowLimits;

        #[derive(Default)]
        struct BatchRecorder {
            carried: Mutex<Vec<usize>>,
        }

        impl CommitFault for BatchRecorder {
            fn before_commit(&self, prefix: &AcceptedPrefix) -> Result<(), CommitError> {
                self.carried.lock().push(carried_bytes(prefix));
                Ok(())
            }
        }

        fn carried_bytes(prefix: &AcceptedPrefix) -> usize {
            let undo: usize = prefix
                .undo_rows
                .iter()
                .map(|(_, _, bytes)| bytes.len())
                .sum();
            let coins: usize = prefix
                .coin_delta
                .records
                .iter()
                .map(|(key, record)| {
                    key.as_bytes().len() + record.as_ref().map_or(0, bytes::Bytes::len)
                })
                .sum();
            undo + coins
        }

        // BUD-06
        #[test]
        fn window_batches_stay_within_ceiling_under_undo_and_coin_churn() -> TestResult {
            let corpus = churn_corpus()?;
            let payloads: Vec<BlockImage> = corpus.payloads();
            let block_total: usize = payloads.iter().map(|payload| payload.bytes().len()).sum();
            let limits = WindowLimits {
                max_bytes: block_total + 1,
                ..WindowLimits::durable_head_defaults()
            };

            let windowed = funded_chain(&corpus, limits)?;
            let recorder = Arc::new(BatchRecorder::default());
            windowed.set_commit_fault(recorder.clone());
            let refs: Vec<&BlockImage> = payloads.iter().collect();
            windowed.apply_window(&refs)?;
            let batches = recorder.carried.lock().clone();

            let oracle = funded_chain(&corpus, limits)?;
            let single = Arc::new(BatchRecorder::default());
            oracle.set_commit_fault(single.clone());
            for payload in &payloads {
                oracle.apply_window(&[payload])?;
            }
            let single_batches = single.carried.lock().clone();
            assert_eq!(
                single_batches.len(),
                payloads.len(),
                "each single-block window must commit exactly one batch"
            );

            let largest_block_charge = payloads
                .iter()
                .zip(&single_batches)
                .map(|(payload, carried)| payload.bytes().len() + carried)
                .max()
                .unwrap_or(0);
            let ceiling = limits.max_bytes + largest_block_charge;
            assert!(
                !batches.is_empty(),
                "the window must commit at least one batch"
            );
            for (index, carried) in batches.iter().enumerate() {
                assert!(
                    *carried <= ceiling,
                    "batch {index} carries {carried} undo and coin bytes, above the ceiling {ceiling}"
                );
            }
            Ok(())
        }
    }
    mod window_invalidation_tests {
        use std::sync::Arc;

        use crate::chain::NodeStatus;
        use crate::chain::regtest_fixture::mined_regtest_child_at as mined_child;
        use bitcoin_rs_consensus::ConsensusError;
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, LockTime,
            Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
        };
        use bitcoin_rs_storage::utxo::UtxoSet;
        use parking_lot::Mutex;

        use super::{
            ApplyError, AssumeValidGate, Chainstate, WindowApplyDisposition, WindowApplyError,
        };
        use crate::test_fixtures::{
            StagedFire, TestError, TestResult, handles, seed_durable_head, seed_genesis,
            staging_recorder,
        };

        fn empty_child(prev_blockhash: BlockHash, height: u32) -> TestResult<Block> {
            let mut block = Block {
                header: Header {
                    version: 1,
                    prev_blockhash,
                    merkle_root: Hash256::default(),
                    time: 1_296_688_602_u32.saturating_add(height),
                    bits: CompactTarget::from_consensus(0x207f_ffff),
                    nonce: 0,
                },
                txs: Vec::new(),
            };
            crate::chain::regtest_fixture::mine_header_to_declared_target(&mut block.header)
                .map_err(|_| TestError::Exhausted("test nonce"))?;
            Ok(block)
        }

        fn coinbase_less_child(prev_blockhash: BlockHash, script_len: usize) -> TestResult<Block> {
            let tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: Script::from_bytes(vec![0x51; script_len]),
                }],
                lock_time: LockTime::ZERO,
            };
            assert_eq!(tx.base_size(), 60 + script_len);
            let txs = vec![tx];
            let merkle_root = crate::chain::regtest_fixture::merkle_root(&txs)
                .ok_or(TestError::Missing("test body has no root"))?;
            let mut header = Header {
                version: 1,
                prev_blockhash,
                merkle_root,
                time: 1_296_688_603,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            crate::chain::regtest_fixture::mine_header_to_declared_target(&mut header)
                .map_err(|_| TestError::Exhausted("test nonce"))?;
            Ok(Block { header, txs })
        }

        fn deliver_coinbase_less_body(
            script_len: usize,
        ) -> TestResult<(WindowApplyError, NodeStatus, NodeStatus, Hash256)> {
            let genesis = Network::Regtest.genesis_block();
            let chainstate: Chainstate = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chainstate)?;
            let block = coinbase_less_child(genesis.block_hash(), script_len)?;
            let hash = Hash256::from(block.block_hash());
            chainstate
                .block_tree
                .write()
                .insert_header(block.header, NodeStatus::HeaderValid)?;
            let before = {
                let tree = chainstate.block_tree.read();
                tree.lookup(hash)
                    .and_then(|id| tree.node(id).ok())
                    .map(|node| node.status)
                    .ok_or(TestError::Missing(
                        "the header must be in the tree after insert",
                    ))?
            };

            let payload = BlockImage::from_local(block);
            let error =
                chainstate
                    .apply_window(&[&payload])
                    .err()
                    .ok_or(TestError::UnexpectedSuccess(
                        "a coinbase-less body must not commit",
                    ))?;
            let tree = chainstate.block_tree.read();
            let after = tree
                .lookup(hash)
                .and_then(|id| tree.node(id).ok())
                .map(|node| node.status)
                .ok_or(TestError::Missing("the header must stay in the tree"))?;
            let applied = chainstate
                .applied_tip()
                .load_full()
                .map(|tip| tip.hash)
                .ok_or(TestError::Missing("an applied tip must be published"))?;
            Ok((error, before, after, applied))
        }

        // SYNC-04
        #[test]
        fn a_64_byte_transaction_in_a_coinbase_less_body_leaves_its_header_valid() -> TestResult {
            let (error, before, after, applied) = deliver_coinbase_less_body(4)?;
            assert!(
                matches!(
                    *error.source,
                    ApplyError::Consensus(ConsensusError::SixtyFourByteMutation)
                ),
                "got {:?}",
                *error.source
            );
            assert_eq!(error.disposition, WindowApplyDisposition::BodyMutated);
            assert!(
                error.invalidated.is_empty(),
                "a mutated body must not invalidate its header subtree"
            );
            assert_eq!(
                after, before,
                "a mutated body must preserve its header's preexisting status"
            );
            assert_ne!(
                after,
                NodeStatus::Invalid,
                "a mutated body must not prove its header invalid"
            );
            assert_eq!(
                applied,
                Hash256::from(Network::Regtest.genesis_block().block_hash()),
                "a rejected body must not move the applied tip"
            );
            Ok(())
        }

        // SYNC-04
        #[test]
        fn a_coinbase_less_body_of_another_size_still_poisons_its_header() -> TestResult {
            let (error, _, status, _) = deliver_coinbase_less_body(0)?;
            assert!(
                matches!(
                    *error.source,
                    ApplyError::Consensus(ConsensusError::MissingCoinbase)
                ),
                "got {:?}",
                *error.source
            );
            assert_eq!(error.disposition, WindowApplyDisposition::Permanent);
            assert_eq!(error.invalidated.len(), 1);
            assert_eq!(status, NodeStatus::Invalid);
            Ok(())
        }

        #[test]
        fn window_invalidation_reevaluates_assume_valid() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let mut handles: Chainstate = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&handles)?;

            let anchor = empty_child(genesis.block_hash(), 1)?;
            let anchor_hash = Hash256::from(anchor.block_hash());
            handles
                .block_tree
                .write()
                .insert_header(anchor.header, NodeStatus::HeaderValid)?;
            handles.assume_valid_gate =
                Arc::new(AssumeValidGate::with_anchor(Some((1, anchor_hash))));
            handles
                .assume_valid_gate
                .evaluate(&handles.block_tree.read());
            assert!(
                handles.assume_valid_gate.trusted(),
                "the anchor on the active header chain must start trusted"
            );

            let anchor_payload = BlockImage::from_local(anchor);
            let outcome = handles.apply_window(&[&anchor_payload]);
            let error = outcome.err().ok_or(TestError::UnexpectedSuccess(
                "an empty block must not commit",
            ))?;
            assert_eq!(error.disposition, WindowApplyDisposition::Permanent);
            assert_eq!(error.invalidated.to_vec(), vec![anchor_hash]);

            assert!(
                !handles.assume_valid_gate.trusted(),
                "window invalidation must re-evaluate the assume-valid gate"
            );
            let tip = handles.chain_tip().load_full().ok_or(TestError::Missing(
                "window invalidation must republish the best valid tip",
            ))?;
            assert_eq!(tip.hash, Hash256::from(genesis.block_hash()));
            Ok(())
        }

        #[test]
        fn a_failing_window_stages_only_its_last_successful_block() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let genesis_hash = Hash256::from(genesis.block_hash());
            let chainstate: Chainstate = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chainstate)?;
            seed_durable_head(
                &chainstate,
                bitcoin_rs_storage::DurableHead {
                    assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
                    commit_id: 1,
                    height: 0,
                    tip: genesis_hash,
                    chain_tx_count: 1,
                    body_extent: None,
                    undo_extent: None,
                },
            )?;

            let first = mined_child(genesis.block_hash(), 1)?;
            let second = mined_child(first.block_hash(), 2)?;
            let second_hash = Hash256::from(second.block_hash());
            let bad = empty_child(second.block_hash(), 3)?;
            let bad_hash = Hash256::from(bad.block_hash());
            {
                let mut tree = chainstate.block_tree.write();
                crate::chain::accept_headers(
                    &mut tree,
                    &[first.header, second.header, bad.header],
                    Network::Regtest,
                    crate::chain::current_unix_seconds(),
                    crate::chain::HeaderValidationMode::LiveAdmission,
                )?;
            }
            let first_payload = BlockImage::from_local(first);
            let second_payload = BlockImage::from_local(second);
            let bad_payload = BlockImage::from_local(bad);
            let payloads = [&first_payload, &second_payload, &bad_payload];

            let fires: Arc<Mutex<Vec<StagedFire>>> = Arc::new(Mutex::new(Vec::new()));
            chainstate
                .set_tip_staged(staging_recorder(&chainstate, &fires))
                .map_err(|_| {
                    TestError::HookAlreadyInstalled("the staged-tip hook installs once")
                })?;

            let error =
                chainstate
                    .apply_window(&payloads)
                    .err()
                    .ok_or(TestError::UnexpectedSuccess(
                        "an empty trailing body must not commit",
                    ))?;
            assert!(
                matches!(
                    *error.source,
                    ApplyError::Consensus(ConsensusError::BlockBaseSize { .. })
                ),
                "got {:?}",
                *error.source
            );
            assert_eq!(error.disposition, WindowApplyDisposition::Permanent);
            assert_eq!(error.applied, 2, "two blocks committed before the failure");
            assert_eq!(error.committed.len(), 2);
            assert_eq!(
                error.committed[1].hash, second_hash,
                "the committed prefix ends at the last successful block"
            );

            let fires = fires.lock();
            assert_eq!(
                fires.len(),
                1,
                "the failure-prefix flush hands off exactly one staged tip"
            );
            assert_eq!(
                fires[0].staged_hash, second_hash,
                "the handoff names the last successful block, not the failed one"
            );
            assert_eq!(fires[0].staged_height, 2);
            assert_eq!(
                fires[0].block_hash, second_hash,
                "the borrowed body is the last success, never the failed block"
            );
            assert!(
                fires[0].block_hash != bad_hash,
                "the failed block must never reach the hook"
            );
            assert_eq!(
                fires[0].published,
                Some((genesis_hash, 0)),
                "the applied tip is still the pre-window tip at fire time"
            );

            let applied = chainstate.applied_tip_snapshot().ok_or(TestError::Missing(
                "the committed prefix must publish an applied tip",
            ))?;
            assert_eq!(
                applied.hash, second_hash,
                "the failure-prefix flush publishes the last success, not the failure"
            );
            Ok(())
        }
    }
    mod window_pipeline_tests {
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        use parking_lot::Mutex;

        use crate::chain::regtest_fixture::{
            merkle_root, mine_block_to_declared_target, mined_regtest_child_at as mined_child,
            mined_regtest_child_at_time as mined_child_at_time,
        };
        use crate::chain::{ChainTxCount, NodeId};
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockHash, BlockImage, Hash256, LockTime, Network, OutPoint, Script,
            Sequence, Tx, TxIn, TxOut, Txid, Witness,
        };
        use bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1;
        use bitcoin_rs_storage::StorageError;
        use bitcoin_rs_storage::utxo::UtxoSet;

        use super::{ApplyError, Chainstate, WindowApplyDisposition};
        use crate::test_fixtures::{
            TestError, TestResult, apply_headers, commit_genesis_head, handles, seed_genesis,
        };

        /// The group cap `RCV-02` states: 64 blocks or 8 MiB of block data, whichever first.
        const GROUP_BLOCKS: usize = 64;

        fn remine(block: &mut Block) -> TestResult {
            block.header.merkle_root =
                merkle_root(&block.txs).ok_or(TestError::Missing("merkle root"))?;
            mine_block_to_declared_target(block)?;
            Ok(())
        }

        fn coinbase_child(prev: BlockHash, height: u32, script: &[u8]) -> TestResult<Block> {
            let mut block = mined_child(prev, height)?;
            block.txs[0].outputs = vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(script.to_vec()),
            }];
            remine(&mut block)?;
            Ok(block)
        }

        fn spend_tx(funding: OutPoint, value: u64) -> Tx {
            Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: funding,
                    script_sig: vec![OP_PUSHNUM_1].into(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: vec![OP_PUSHNUM_1].into(),
                }],
                lock_time: LockTime::ZERO,
            }
        }

        fn block_with_spend(prev: BlockHash, height: u32, spend: Tx) -> TestResult<Block> {
            let mut block = mined_child(prev, height)?;
            block.txs.push(spend);
            remine(&mut block)?;
            Ok(block)
        }

        fn coinbase_less_block(
            prev: BlockHash,
            height: u32,
            script_len: usize,
        ) -> TestResult<Block> {
            let mut block = mined_child(prev, height)?;
            block.txs = vec![Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1; script_len]),
                }],
                lock_time: LockTime::ZERO,
            }];
            remine(&mut block)?;
            Ok(block)
        }

        fn dump_payloads(blocks: &[Block]) -> Vec<BlockImage> {
            blocks
                .iter()
                .map(|block| BlockImage::from_local(block.clone()))
                .collect()
        }

        struct CrashOnCommitFault {
            fail_on_commit: u64,
        }

        impl bitcoin_rs_storage::commit::CommitFault for CrashOnCommitFault {
            fn before_commit(
                &self,
                prefix: &bitcoin_rs_storage::commit::AcceptedPrefix,
            ) -> Result<(), bitcoin_rs_storage::CommitError> {
                if prefix.next_head.commit_id == self.fail_on_commit {
                    return Err(bitcoin_rs_storage::CommitError::Storage(
                        StorageError::InvalidOperation("injected durable head commit failure"),
                    ));
                }
                Ok(())
            }
        }

        struct NoopObserver;

        impl crate::reorg::ReorgObserver for NoopObserver {
            fn disconnected(&mut self, _: &crate::DisconnectOutcome) {}

            fn connected(
                &mut self,
                _: &bitcoin_rs_consensus::primitives::BlockImage,
                _: &crate::ConnectOutcome,
            ) {
            }

            fn reconsider_disconnected(
                &mut self,
                _: &bitcoin_rs_consensus::primitives::BlockImage,
            ) {
            }
        }

        fn node_id(chain: &Chainstate, hash: BlockHash) -> TestResult<NodeId> {
            chain
                .block_tree
                .read()
                .lookup(Hash256::from(hash))
                .ok_or(TestError::Missing("header missing from the block tree"))
        }

        // RCV-02
        #[test]
        fn a_window_commits_every_block_in_order() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let mut blocks = Vec::new();
            let mut parent = Network::Regtest.genesis_block().block_hash();
            for height in 1..=3 {
                let block = mined_child(parent, height)?;
                parent = block.block_hash();
                blocks.push(block);
            }
            let refs: Vec<&Block> = blocks.iter().collect();
            apply_headers(&chain, &refs)?;
            let payloads = dump_payloads(&blocks);
            let window: Vec<&BlockImage> = payloads.iter().collect();

            let outcomes = chain.apply_window(&window)?;

            let expected: Vec<(u32, Hash256)> = blocks
                .iter()
                .enumerate()
                .map(|(index, block)| {
                    (
                        u32::try_from(index).unwrap_or(u32::MAX) + 1,
                        Hash256::from(block.block_hash()),
                    )
                })
                .collect();
            let observed: Vec<(u32, Hash256)> = outcomes
                .iter()
                .map(|outcome| (outcome.height, outcome.hash))
                .collect();
            assert_eq!(
                observed, expected,
                "the applied window publishes its blocks in chain order, one outcome per block"
            );
            assert_eq!(
                outcomes[2].tip.chain_tx_count,
                ChainTxCount::established(4),
                "the last outcome carries the cumulative count of every staged block, not a per-block delta"
            );

            let applied = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("the window publishes a tip"))?;
            assert_eq!(
                applied.hash, expected[2].1,
                "the applied tip names the last block of the window"
            );
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("the window writes a head"))?;
            assert_eq!(
                (head.height, head.tip),
                (3, expected[2].1),
                "the durable head names the last block of the window"
            );
            Ok(())
        }

        #[test]
        fn partial_header_admission_commits_the_valid_prefix_and_remains_usable() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;
            let first = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
            let missing_parent = BlockHash::from(Hash256::from_le_bytes(&[0x37; 32]));
            let orphan = mined_child(missing_parent, 2)?;
            let payloads = dump_payloads(&[first.clone(), orphan]);
            let window: Vec<&BlockImage> = payloads.iter().collect();

            let error = chain
                .apply_window(&window)
                .err()
                .ok_or(TestError::Missing("missing parent rejects the suffix"))?;
            assert_eq!(error.disposition, WindowApplyDisposition::Operational);
            assert_eq!(error.applied, 1);
            assert_eq!(error.committed.len(), 1);
            assert_eq!(error.committed[0].hash, Hash256::from(first.block_hash()));
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("prefix head"))?;
            assert_eq!(
                (head.height, head.tip),
                (1, Hash256::from(first.block_hash()))
            );
            assert_eq!(
                chain
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("prefix tip"))?
                    .hash,
                Hash256::from(first.block_hash())
            );

            let next = mined_child(first.block_hash(), 2)?;
            let next_image = BlockImage::from_local(next.clone());
            let outcomes = chain.apply_window(&[&next_image])?;
            assert_eq!(outcomes.len(), 1);
            assert_eq!(
                (outcomes[0].height, outcomes[0].hash),
                (2, Hash256::from(next.block_hash()))
            );
            Ok(())
        }

        // SYNC-04
        #[test]
        fn a_poisoned_undo_store_settles_the_window_fatal() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;
            chain
                .commit_authority
                .store()
                .arm_persist_fault(bitcoin_rs_storage::PersistFault::FailApply);

            let block = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
            apply_headers(&chain, &[&block])?;
            let payloads = dump_payloads(&[block]);
            let window: Vec<&BlockImage> = payloads.iter().collect();

            let error = chain.apply_window(&window).err().ok_or(TestError::Missing(
                "a poisoned undo store must fail the window",
            ))?;

            assert!(
                matches!(*error.source, ApplyError::DurableHeadCommit(_)),
                "the failure must name the durable commit, got {:?}",
                *error.source
            );
            assert_eq!(
                error.disposition,
                WindowApplyDisposition::Fatal,
                "an unusable undo store is durable corruption: retry cannot recover it, so the window settles fatal"
            );
            assert_eq!(error.applied, 0, "no block commits on a failed undo write");
            assert_eq!(error.committed.len(), 0);
            assert_eq!(
                chain.applied_tip_snapshot().map(|tip| tip.height),
                Some(0),
                "a failed undo write publishes no applied tip"
            );
            Ok(())
        }

        // RCV-02
        #[test]
        fn a_window_commits_a_block_that_spends_the_previous_blocks_output() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let mut parent = Network::Regtest.genesis_block().block_hash();
            let mut funding = None;
            for height in 1..=100_u32 {
                let block = coinbase_child(parent, height, &[OP_PUSHNUM_1])?;
                if height == 1 {
                    funding = Some(OutPoint::new(block.txs[0].txid(), 0));
                }
                chain.apply_block(&BlockImage::from_local(block.clone()))?;
                parent = block.block_hash();
            }
            let funding =
                funding.ok_or(TestError::Missing("the fixture mined the funding coinbase"))?;

            let first_spend = spend_tx(funding, 9_000);
            let first_spend_outpoint = OutPoint::new(first_spend.txid(), 0);
            let first = block_with_spend(parent, 101, first_spend)?;
            let second = block_with_spend(
                first.block_hash(),
                102,
                spend_tx(first_spend_outpoint, 8_000),
            )?;
            let blocks = [first, second];
            let refs: Vec<&Block> = blocks.iter().collect();
            apply_headers(&chain, &refs)?;
            let payloads = dump_payloads(&blocks);
            let window: Vec<&BlockImage> = payloads.iter().collect();

            let outcomes = chain.apply_window(&window)?;

            assert_eq!(outcomes.len(), 2, "both window blocks commit");
            assert_eq!(
                (outcomes[0].height, outcomes[1].height),
                (101, 102),
                "the spending block commits only after the block that funded it"
            );
            assert_eq!(
                outcomes[0].tip.chain_tx_count,
                ChainTxCount::established(103),
                "the funding block counts the 101 earlier transactions plus its own two"
            );
            assert_eq!(
                outcomes[1].tip.chain_tx_count,
                ChainTxCount::established(105),
                "the dependent block spends the funding block's output, so its count builds on 103"
            );
            let applied = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("the window publishes a tip"))?;
            assert_eq!(
                applied.hash,
                Hash256::from(blocks[1].block_hash()),
                "the dependent spend is committed and published as the window tip"
            );
            assert!(
                chain.utxo_reader().get(&first_spend_outpoint)?.is_none(),
                "the dependent block spends the funding block's output, so that coin leaves the utxo set"
            );
            Ok(())
        }

        // RCV-02
        #[test]
        fn a_window_with_an_invalid_middle_block_commits_only_the_valid_prefix() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let first = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
            let second = mined_child(first.block_hash(), 2)?;
            let bad = coinbase_less_block(second.block_hash(), 3, 0)?;
            let trailing = mined_child(bad.block_hash(), 4)?;
            let blocks = [first, second, bad, trailing];
            let refs: Vec<&Block> = blocks.iter().collect();
            apply_headers(&chain, &refs)?;
            let payloads = dump_payloads(&blocks);
            let window: Vec<&BlockImage> = payloads.iter().collect();

            let error = chain.apply_window(&window).err().ok_or(TestError::Missing(
                "a body without a coinbase must not commit",
            ))?;
            assert!(
                matches!(
                    *error.source,
                    ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingCoinbase)
                ),
                "a body whose only transaction is not a coinbase is rejected as missing its coinbase, got {:?}",
                *error.source
            );

            assert_eq!(
                error.applied, 2,
                "only the blocks before the invalid middle block commit"
            );
            let committed: Vec<(u32, Hash256)> = error
                .committed
                .iter()
                .map(|outcome| (outcome.height, outcome.hash))
                .collect();
            assert_eq!(
                committed,
                vec![
                    (1, Hash256::from(blocks[0].block_hash())),
                    (2, Hash256::from(blocks[1].block_hash())),
                ],
                "the committed prefix is the two valid blocks, in order"
            );
            assert_eq!(
                error.disposition,
                WindowApplyDisposition::Permanent,
                "a body without a coinbase is a permanent body defect"
            );
            let mut invalidated: Vec<Hash256> = error.invalidated.to_vec();
            invalidated.sort_unstable();
            let mut expected_invalidated = vec![
                Hash256::from(blocks[2].block_hash()),
                Hash256::from(blocks[3].block_hash()),
            ];
            expected_invalidated.sort_unstable();
            assert_eq!(
                invalidated, expected_invalidated,
                "the invalid body invalidates its own header subtree, including the trailing block"
            );

            let applied = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("the prefix publishes a tip"))?;
            assert_eq!(
                (applied.height, applied.hash),
                (2, Hash256::from(blocks[1].block_hash())),
                "the applied tip stops at the last valid block of the prefix"
            );
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("the prefix writes a head"))?;
            assert_eq!(
                (head.height, head.tip),
                (2, Hash256::from(blocks[1].block_hash())),
                "the durable head names the last valid block of the prefix, never the invalid one"
            );
            Ok(())
        }

        // RCV-02
        #[test]
        fn a_window_prepared_against_a_replaced_tip_discards_the_stale_branch() -> TestResult {
            let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            chain.block_body_store = Some(Arc::new(crate::test_support::MemoryBodies::default()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;
            let genesis = Network::Regtest.genesis_block();
            let genesis_time = genesis.header.time;

            let old_first = mined_child_at_time(genesis.block_hash(), genesis_time + 10, 1)?;
            let old_second = mined_child_at_time(old_first.block_hash(), genesis_time + 11, 2)?;
            let old_second_hash = old_second.block_hash();
            let old_blocks = [old_first, old_second];
            let old_refs: Vec<&Block> = old_blocks.iter().collect();
            apply_headers(&chain, &old_refs)?;
            let old_payloads = dump_payloads(&old_blocks);
            let old_window: Vec<&BlockImage> = old_payloads.iter().collect();
            chain.apply_window(&old_window)?;

            let new_first = mined_child_at_time(genesis.block_hash(), genesis_time + 20, 1)?;
            let new_second = mined_child_at_time(new_first.block_hash(), genesis_time + 21, 2)?;
            let new_third = mined_child_at_time(new_second.block_hash(), genesis_time + 22, 3)?;
            let new_third_hash = new_third.block_hash();
            let new_blocks = [new_first, new_second, new_third];
            let new_refs: Vec<&Block> = new_blocks.iter().collect();
            apply_headers(&chain, &new_refs)?;
            let new_payloads = dump_payloads(&new_blocks);
            let bodies: HashMap<Hash256, BlockImage> = new_blocks
                .iter()
                .zip(&new_payloads)
                .map(|(block, payload)| (Hash256::from(block.block_hash()), payload.clone()))
                .collect();
            let target = node_id(&chain, new_third_hash)?;
            crate::reorg::switch_to_branch(
                &chain,
                target,
                |hash| bodies.get(&hash).cloned(),
                &mut NoopObserver,
                |_, outcome| outcome,
            )?;
            let reorged = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("the branch switch publishes a tip"))?;
            assert_eq!(
                reorged.hash,
                Hash256::from(new_third_hash),
                "the reorg moves the applied tip onto the longer branch"
            );

            let successor = mined_child_at_time(new_third_hash, genesis_time + 30, 4)?;
            let stale = mined_child_at_time(old_second_hash, genesis_time + 12, 3)?;
            let mixed = [successor, stale];
            let mixed_refs: Vec<&Block> = mixed.iter().collect();
            apply_headers(&chain, &mixed_refs)?;
            let mixed_payloads = dump_payloads(&mixed);
            let mixed_window: Vec<&BlockImage> = mixed_payloads.iter().collect();

            let error = chain
                .apply_window(&mixed_window)
                .err()
                .ok_or(TestError::Missing(
                    "a block from the replaced branch cannot extend the new tip",
                ))?;

            assert_eq!(
                error.applied, 1,
                "only the block extending the reorged tip commits; the stale block is discarded"
            );
            assert_eq!(
                error.committed.len(),
                1,
                "the stale block is never committed"
            );
            assert_eq!(
                error.committed[0].hash,
                Hash256::from(mixed[0].block_hash()),
                "the committed outcome names the block that extended the reorged tip"
            );
            assert!(
                matches!(*error.source, ApplyError::PrevHashMismatch { .. }),
                "the stale block is refused because its predecessor is not the applied tip, got {:?}",
                *error.source
            );
            assert_eq!(
                error.disposition,
                WindowApplyDisposition::Operational,
                "a stale predecessor is retryable, not a permanent body defect"
            );
            let applied = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("the applied tip survives"))?;
            assert_eq!(
                applied.hash,
                Hash256::from(mixed[0].block_hash()),
                "the applied tip is the block that extended the reorged chain, not the stale one"
            );
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("the head survives"))?;
            assert_eq!(
                (head.height, head.tip),
                (4, Hash256::from(mixed[0].block_hash())),
                "the durable head names the committed block of the reorged chain"
            );
            Ok(())
        }

        // RCV-02
        #[test]
        fn a_window_holds_its_transition_until_a_concurrent_shutdown_acquires_it() -> TestResult {
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            seed_genesis(&chain)?;
            commit_genesis_head(&chain)?;

            let mut blocks = Vec::new();
            let mut parent = Network::Regtest.genesis_block().block_hash();
            for height in 1..=3 {
                let block = mined_child(parent, height)?;
                parent = block.block_hash();
                blocks.push(block);
            }
            let refs: Vec<&Block> = blocks.iter().collect();
            apply_headers(&chain, &refs)?;

            let requested = Arc::new(AtomicU64::new(0));
            let closer: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> =
                Arc::new(Mutex::new(None));
            let hook: crate::TipStagedHook = {
                let chain = chain.clone();
                let requested = Arc::clone(&requested);
                let closer = Arc::clone(&closer);
                Arc::new(
                    move |_staged: &crate::chain::TipSnapshot, _block: &BlockImage| {
                        let chain = chain.clone();
                        let closing = Arc::new(AtomicU64::new(0));
                        let closer_flag = Arc::clone(&closing);
                        let handle = std::thread::spawn(move || {
                            closer_flag.store(1, Ordering::SeqCst);
                            let _guard = chain.close();
                        });
                        while closing.load(Ordering::SeqCst) == 0 {
                            std::thread::yield_now();
                        }
                        requested.fetch_add(1, Ordering::SeqCst);
                        closer.lock().replace(handle);
                    },
                )
            };
            chain
                .set_tip_staged(hook)
                .map_err(|_| TestError::HookAlreadyInstalled("staged-tip"))?;
            let payloads = dump_payloads(&blocks);
            let window: Vec<&BlockImage> = payloads.iter().collect();

            let outcomes = chain.apply_window(&window)?;

            assert_eq!(
                requested.load(Ordering::SeqCst),
                1,
                "the staged-tip hook runs once, inside the window's transition"
            );
            let handle = closer.lock().take().ok_or(TestError::Missing(
                "the shutdown thread was spawned from the hook",
            ))?;
            handle
                .join()
                .map_err(|_| TestError::WorkerPanicked("shutdown thread"))?;
            assert_eq!(
                outcomes.len(),
                3,
                "a shutdown requested while the window runs cannot cut the window short"
            );
            assert_eq!(
                outcomes[2].hash,
                Hash256::from(blocks[2].block_hash()),
                "the whole window commits in order before the shutdown acquires the transition"
            );
            let applied = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("the window publishes a tip"))?;
            assert_eq!(
                applied.hash,
                Hash256::from(blocks[2].block_hash()),
                "the published tip is the complete window, not a partial prefix"
            );
            assert!(
                chain.is_closed_for_recovery(),
                "the shutdown that waited for the window closes admission after it"
            );
            let refused = chain
                .apply_window(&window)
                .err()
                .ok_or(TestError::Missing("closed admission refuses a new window"))?;
            assert!(
                matches!(*refused.source, ApplyError::Shutdown),
                "a window after the shutdown is refused at admission, got {:?}",
                *refused.source
            );
            Ok(())
        }

        // RCV-02
        #[test]
        fn a_window_crash_at_a_group_commit_boundary_keeps_the_last_complete_group() -> TestResult {
            let body_blocks = u32::try_from(GROUP_BLOCKS.saturating_add(1))?;
            let mut blocks = Vec::new();
            let mut parent = Network::Regtest.genesis_block().block_hash();
            for height in 1..=body_blocks {
                let block = mined_child(parent, height)?;
                parent = block.block_hash();
                blocks.push(block);
            }
            let payloads = dump_payloads(&blocks);

            for (fail_on_commit, committed_blocks) in [(2_u64, 0_usize), (3, GROUP_BLOCKS)] {
                let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
                seed_genesis(&chain)?;
                chain
                    .commit_authority
                    .set_fault(Arc::new(CrashOnCommitFault { fail_on_commit }));
                commit_genesis_head(&chain)?;
                let refs: Vec<&Block> = blocks.iter().collect();
                apply_headers(&chain, &refs)?;
                let window: Vec<&BlockImage> = payloads.iter().collect();

                let error = chain.apply_window(&window).err().ok_or(TestError::Missing(
                    "a failed durable head commit must abort the window",
                ))?;

                assert_eq!(
                    error.disposition,
                    WindowApplyDisposition::Fatal,
                    "a failed durable head commit is unrecoverable without restart"
                );
                assert_eq!(
                    error.applied, committed_blocks,
                    "a crash on commit {fail_on_commit} leaves exactly the groups committed before it"
                );
                assert_eq!(
                    error.committed.len(),
                    committed_blocks,
                    "only flushed groups count as committed after a crash on commit {fail_on_commit}"
                );
                let head = chain
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("the genesis head survives the crash"))?;
                let applied = chain
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("the pre-crash tip survives"))?;
                let expected_hash = committed_blocks
                    .checked_sub(1)
                    .and_then(|index| blocks.get(index))
                    .map_or_else(
                        || Hash256::from(Network::Regtest.genesis_block().block_hash()),
                        |block| Hash256::from(block.block_hash()),
                    );
                let expected_height = u32::try_from(committed_blocks).unwrap_or(u32::MAX);
                assert_eq!(
                    (head.height, head.tip),
                    (expected_height, expected_hash),
                    "the durable head after a crash on commit {fail_on_commit} names the last complete group"
                );
                assert_eq!(
                    (applied.height, applied.hash),
                    (expected_height, expected_hash),
                    "the published tip after a crash on commit {fail_on_commit} agrees with the durable head"
                );
            }
            Ok(())
        }
    }
    mod window_tx_count_tests {
        use std::sync::Arc;

        use crate::chain::ChainTxCount;
        use crate::chain::regtest_fixture::mined_regtest_child_at as mined_child;
        use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Network, Witness};
        use bitcoin_rs_storage::DurableHead;
        use bitcoin_rs_storage::utxo::UtxoSet;
        use parking_lot::Mutex;

        use crate::test_fixtures::{
            StagedFire, TestError, TestResult, handles, seed_durable_head, seed_genesis,
            staging_recorder,
        };

        #[test]
        fn a_grouped_window_publishes_each_blocks_own_prefix_count() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let genesis = Network::Regtest.genesis_block();
            seed_genesis(&handles)?;
            seed_durable_head(
                &handles,
                DurableHead {
                    assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
                    commit_id: 1,
                    height: 0,
                    tip: Hash256::from(genesis.block_hash()),
                    chain_tx_count: 1,
                    body_extent: None,
                    undo_extent: None,
                },
            )?;

            let first = mined_child(genesis.block_hash(), 1)?;
            let second = mined_child(first.block_hash(), 2)?;
            let third = mined_child(second.block_hash(), 3)?;
            {
                let mut tree = handles.block_tree.write();
                crate::chain::accept_headers(
                    &mut tree,
                    &[first.header, second.header, third.header],
                    Network::Regtest,
                    crate::chain::current_unix_seconds(),
                    crate::chain::HeaderValidationMode::LiveAdmission,
                )?;
            }
            let first_payload = BlockImage::from_local(first);
            let second_payload = BlockImage::from_local(second);
            let third_payload = BlockImage::from_local(third);
            let payloads = [&first_payload, &second_payload, &third_payload];

            let transition = handles.begin_transition()?;
            let outcomes = transition.connect_window(&payloads)?;

            assert_eq!(outcomes.len(), 3, "one drained outcome per staged block");
            let prefix_counts = [
                ChainTxCount::established(2),
                ChainTxCount::established(3),
                ChainTxCount::established(4),
            ];
            for (outcome, expected) in outcomes.iter().zip(prefix_counts) {
                assert_eq!(
                    outcome.tip.chain_tx_count, expected,
                    "each staged tip carries its own cumulative count, not the group's final one"
                );
            }

            let events = handles.chain_events.snapshot();
            assert_eq!(events.sequence, 3);
            assert_eq!(events.tip_height, 3);
            assert_eq!(events.tip_hash, outcomes[2].hash);

            let applied = handles.applied_tip.load_full();
            assert_eq!(
                applied.as_deref(),
                Some(&outcomes[2].tip),
                "the cell names the last published tip"
            );

            let head = handles.durable_head.load()?.ok_or(TestError::Missing(
                "the group's one batch wrote the durable head",
            ))?;
            assert_eq!(head.height, 3);
            assert_eq!(head.tip, outcomes[2].hash);
            assert_eq!(
                head.chain_tx_count, 4,
                "the head certifies the final group count"
            );
            assert!(
                outcomes
                    .iter()
                    .all(|outcome| outcome.commit_id == head.commit_id),
                "one receipt certifies the whole committed prefix"
            );
            Ok(())
        }

        #[test]
        fn a_grouped_window_stages_only_its_newest_block_before_the_sync() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let genesis = Network::Regtest.genesis_block();
            let genesis_hash = Hash256::from(genesis.block_hash());
            seed_genesis(&handles)?;
            seed_durable_head(
                &handles,
                DurableHead {
                    assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
                    commit_id: 1,
                    height: 0,
                    tip: genesis_hash,
                    chain_tx_count: 1,
                    body_extent: None,
                    undo_extent: None,
                },
            )?;

            let first = mined_child(genesis.block_hash(), 1)?;
            let second = mined_child(first.block_hash(), 2)?;
            let third = mined_child(second.block_hash(), 3)?;
            let third_hash = Hash256::from(third.block_hash());
            {
                let mut tree = handles.block_tree.write();
                crate::chain::accept_headers(
                    &mut tree,
                    &[first.header, second.header, third.header],
                    Network::Regtest,
                    crate::chain::current_unix_seconds(),
                    crate::chain::HeaderValidationMode::LiveAdmission,
                )?;
            }
            let first_payload = BlockImage::from_local(first);
            let second_payload = BlockImage::from_local(second);
            let third_payload = BlockImage::from_local(third);
            let payloads = [&first_payload, &second_payload, &third_payload];

            let fires: Arc<Mutex<Vec<StagedFire>>> = Arc::new(Mutex::new(Vec::new()));
            handles
                .set_tip_staged(staging_recorder(&handles, &fires))
                .map_err(|_| {
                    TestError::HookAlreadyInstalled("the staged-tip hook installs once")
                })?;

            let outcomes = handles.apply_window(&payloads)?;
            assert_eq!(outcomes.len(), 3, "one drained outcome per staged block");

            let fires = fires.lock();
            assert_eq!(fires.len(), 1, "one group commits, so one staging handoff");
            assert_eq!(
                fires[0].staged_hash, third_hash,
                "the handoff names the newest staged block, not an ancestor"
            );
            assert_eq!(fires[0].staged_height, 3);
            assert_eq!(
                fires[0].block_hash, third_hash,
                "the borrowed body is the caller's newest block"
            );
            assert_eq!(
                fires[0].published,
                Some((genesis_hash, 0)),
                "the applied tip is still the pre-window tip at fire time: \
         the staged tip publishes only with the group's durable receipt"
            );

            let applied = handles
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("the group must publish an applied tip"))?;
            assert_eq!(applied.hash, third_hash);
            Ok(())
        }

        #[test]
        fn corrupted_window_bytes_fail_payload_construction() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let genesis = Network::Regtest.genesis_block();
            seed_genesis(&handles)?;
            let payload = BlockImage::from_local(mined_child(genesis.block_hash(), 1)?);
            let raw = payload.bytes().to_vec();

            let mut truncated = raw.clone();
            truncated.pop();
            assert!(
                BlockImage::from_raw(bytes::Bytes::from(truncated)).is_err(),
                "a truncated stream must fail construction, before any count is consulted"
            );

            let mut trailed = raw;
            trailed.push(0x00);
            assert!(
                BlockImage::from_raw(bytes::Bytes::from(trailed)).is_err(),
                "trailing bytes must fail construction, before any count is consulted"
            );

            let applied = handles
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("seeded tip"))?;
            assert_eq!(
                applied.hash,
                Hash256::from(genesis.block_hash()),
                "rejected construction stages nothing"
            );
            Ok(())
        }

        #[test]
        fn witness_only_mutation_fails_payload_construction() -> TestResult {
            let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let genesis = Network::Regtest.genesis_block();
            seed_genesis(&handles)?;
            let mut changed = mined_child(genesis.block_hash(), 1)?;
            let txid = changed.txs[0].txid();
            changed.txs[0].inputs[0].witness = Witness::from_stack(vec![vec![0u8; 32]]);
            assert_eq!(
                changed.txs[0].txid(),
                txid,
                "witness data stays outside the txid"
            );

            let raw = BlockImage::from_local(changed).bytes().to_vec();
            let count_at = raw.len() - 38;
            assert_eq!(raw[count_at], 0x01, "witness item-count site");
            let mut broken = raw;
            broken[count_at] = 0x02;
            assert!(
                BlockImage::from_raw(bytes::Bytes::from(broken)).is_err(),
                "a witness count the stream cannot back must fail construction"
            );

            let applied = handles
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("seeded tip"))?;
            assert_eq!(
                applied.hash,
                Hash256::from(genesis.block_hash()),
                "rejected construction stages nothing"
            );
            Ok(())
        }
    }
}
