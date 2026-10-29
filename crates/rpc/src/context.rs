use alloc::sync::Arc;
#[cfg(any(test, feature = "test-seam"))]
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{
    BlockBodyReadError, BlockBodySource, BlockTreeReader, LatchReader, TipReader, TipSnapshot,
    softfork_state,
};
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_mempool::BodyInterest;
use bitcoin_rs_mempool::{AdmissionChain, ChainAdmissionSnapshot, MempoolGateway, PrevoutMeta};

#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_mempool::{Mempool, MempoolLimits, MempoolObserver};
use bitcoin_rs_mining::MiningControl;
#[cfg(feature = "pool")]
use bitcoin_rs_mining::pool::ledger as pool_ledger;
use bitcoin_rs_primitives::{
    BlockHash, CompactTarget, Hash256, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    layout::ParsedBlock, unix_time_secs,
};

use crate::error::RpcError;

use crate::compressed_tx::{
    LookupError, MAX_CUMULATIVE_BODY_BYTES, MAX_CUMULATIVE_BODY_LOADS, MAX_RESOLVER_STATE_BYTES,
    MAX_RETAINED_BODIES, MAX_RETAINED_BODY_BYTES, MAX_RETAINED_BYTES_TOTAL,
    MAX_RETAINED_INDEX_BYTES, PrevoutResolver, ResolvedPrevout,
};

use bitcoin::hex::DisplayHex as _;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_consensus::ValidationEngine;
#[cfg(test)]
use bitcoin_rs_primitives::{Amount, Script};
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use hashbrown::HashMap;
use parking_lot::Mutex;
#[cfg(any(test, feature = "test-seam"))]
use parking_lot::RwLock;
use std::path::PathBuf;
use std::time::Instant;

/// Core `sendrawtransaction` default `maxfeerate`: 0.1 BTC/kvB in sat/kvB.
pub const DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB: u64 = 10_000_000;

/// Block and undo responses materialize a body and its projection.
/// Bound concurrent materializations independently of socket connections.
const MAX_CONCURRENT_BLOCK_RENDERS: usize = 2;

#[derive(Debug)]
struct BlockRenderBudget {
    in_flight: AtomicUsize,
}

impl BlockRenderBudget {
    const fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<BlockRenderPermit> {
        let mut in_flight = self.in_flight.load(Ordering::Acquire);
        loop {
            if in_flight >= MAX_CONCURRENT_BLOCK_RENDERS {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                in_flight,
                in_flight + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(BlockRenderPermit {
                        budget: Arc::clone(self),
                    });
                }
                Err(actual) => in_flight = actual,
            }
        }
    }
}

pub(crate) struct BlockRenderPermit {
    budget: Arc<BlockRenderBudget>,
}

impl Drop for BlockRenderPermit {
    fn drop(&mut self) {
        let previous = self.budget.in_flight.fetch_sub(1, Ordering::Release);
        debug_assert!(previous > 0, "block render permit count underflowed");
    }
}

use bitcoin_rs_index::block_log::{
    BlockLogReader, BlockRecord, record_at_height, record_at_height_hash,
};
use bitcoin_rs_index::query_api::RollbackWarningSource;

#[derive(Debug)]
pub struct SyncProgress {
    pub network: Network,
    pub blocks: u32,
    pub headers: u32,
    pub best_block_hash: Hash256,
    pub difficulty: f64,
    pub time: u64,
    pub median_time: u64,
    pub verification_progress: f64,
    pub initial_block_download: bool,
    pub chain_work: String,
    pub size_on_disk: u64,
    pub pruned: bool,
    pub prune_height: Option<u32>,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct PruneStatus {
    pub pruned: bool,
    pub pruneheight: Option<u32>,
}

#[derive(Debug, Default)]
pub struct PruneResult {
    pub pruneheight: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum PruneServiceError {
    /// Storage or backend-specific pruning failure.
    #[error("{0}")]
    Failed(String),
}

impl PruneServiceError {
    #[must_use]
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }
}

pub trait PruneService: Send + Sync {
    fn prune_to_height(&self, requested_height: u32) -> Result<PruneResult, PruneServiceError>;

    fn status(&self) -> PruneStatus;
}

pub trait ChainControl: Send + Sync {
    fn load_txoutset(
        &self,
        _path: &std::path::Path,
    ) -> Result<SnapshotImport, SnapshotControlError> {
        Err(SnapshotControlError::Unavailable(
            "snapshot import is not attached to this chain control".to_owned(),
        ))
    }

    /// A relative `path` resolves below the node data directory.
    ///
    /// The file is created only if nothing exists at `path`; an existing entry is
    /// refused and never replaced. A request cancelled through `cancellation`, or a
    /// node that begins shutting down, answers [`SnapshotControlError::Interrupted`]
    /// and leaves no file behind.
    fn dump_txoutset(
        &self,
        path: &std::path::Path,
        cancellation: &LatchReader,
    ) -> Result<SnapshotExport, SnapshotControlError>;

    fn chainstates(&self) -> Result<ChainstatesInfo, SnapshotControlError> {
        Err(SnapshotControlError::Unavailable(
            "chainstate lifecycle is not attached to this chain control".to_owned(),
        ))
    }

    fn invalidate_block(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), ChainControlError>;

    /// `check_level` is Core's `0..=4` level and `nblocks` counts back from the applied
    /// tip, zero meaning the whole chain.
    ///
    /// The answer is true only when every block in the window was checked and passed; a
    /// window that reaches history this node does not hold, and any damaged block or
    /// undo record, answer false. A request cancelled through `cancellation` answers
    /// [`ChainControlError::Interrupted`]; a chainstate closed for recovery answers
    /// [`ChainControlError::Unavailable`].
    fn verify_chain(
        &self,
        check_level: u8,
        nblocks: u32,
        cancellation: &LatchReader,
    ) -> Result<bool, ChainControlError>;
}

#[derive(Debug, serde::Serialize)]
pub struct SnapshotImport {
    /// Number of unspent outputs loaded, not transaction records.
    pub coins_loaded: u64,
    pub tip_hash: String,
    pub base_height: u32,
    /// UTF-8 display of the absolute input path, rendered before activation.
    /// Non-UTF-8 filesystem bytes are replaced for JSON output only.
    pub path: String,
}

#[derive(Debug, serde::Serialize)]
pub struct SnapshotExport {
    /// Number of unspent outputs written, not transaction records.
    pub coins_written: u64,
    pub base_hash: String,
    pub base_height: u32,
    /// UTF-8 display of the absolute output path. Non-UTF-8 filesystem bytes
    /// in a parent directory are replaced for JSON output only.
    pub path: String,
    /// `hash_serialized_3` commitment of the written coins, in RPC display order.
    pub txoutset_hash: String,
    /// Transactions in the chain up to and including the base block.
    pub nchaintx: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct ChainstatesInfo {
    pub headers: u32,
    /// Historical role first, active role last.
    pub chainstates: Vec<ChainstateInfo>,
}

#[derive(Debug, serde::Serialize)]
pub struct ChainstateInfo {
    pub blocks: u32,
    pub bestblockhash: String,
    /// Transaction-based estimate; unavailable counts are omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verificationprogress: Option<f64>,
    /// Pinned base for a snapshot-derived active role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_blockhash: Option<String>,
    /// Whether these coins have been verified from genesis.
    pub validated: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotControlError {
    /// Input path cannot be opened or is not a regular file.
    #[error("{0}")]
    File(String),
    /// The file or its compiled trust anchor was rejected before activation.
    #[error("{0}")]
    Invalid(String),
    /// The lifecycle cannot accept this request at present.
    #[error("{0}")]
    Unavailable(String),
    /// Activation, persistence, or post-commit consumer settlement failed.
    #[error("{0}")]
    Failed(String),
    #[error("Snapshot export interrupted")]
    Interrupted,
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum ChainControlError {
    /// The requested block is unknown.
    #[error("unknown block")]
    UnknownBlock,
    /// Genesis cannot be invalidated.
    #[error("cannot invalidate the genesis block")]
    Genesis,
    /// The mutation failed after its request was accepted.
    #[error("{0}")]
    Failed(String),
    /// Verification stopped because the requesting caller cancelled it.
    #[error("block verification interrupted")]
    Interrupted,
    /// Verification refused because the chainstate is closed for recovery.
    #[error("chainstate is unavailable for verification")]
    Unavailable,
}

pub use bitcoin_rs_index::{
    DerivedIndexInfo, DerivedIndexQuery, ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord,
    ScriptIndexSnapshot, SpendingRecord, TxQueryError, TxUnavailableCause,
};

pub struct ContextHandles {
    pub silent_payments: bool,
    pub compressed_transactions: bool,
    pub chain: ChainHandles,
    pub mempool: MempoolHandles,
    pub indexes: IndexHandles,
    pub network: NetworkHandles,
    pub mining: MiningHandles,
    pub pool: PoolHandles,
    pub zmq_publisher: Arc<dyn crate::zmq::ZmqPublisher>,
    pub debug_log_path: Option<PathBuf>,
}

pub struct ChainHandles {
    pub chain_tip: TipReader,
    pub applied_tip: TipReader,
    pub active_tip_wait: Option<Arc<dyn bitcoin_rs_chain::ActiveTipWait>>,
    pub progress: bitcoin_rs_chain::ChainProgressReader,
    pub closed_for_recovery: LatchReader,
    pub blocks: BlockLogReader,
    pub utxo: bitcoin_rs_utxo::UtxoReader,
    pub coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    pub block_tree: BlockTreeReader,
    pub chain_network: Network,
    pub chain_transition: bitcoin_rs_chain::StableRead,
    pub block_body_source: Option<Arc<dyn BlockBodySource>>,
    pub block_undo_source: Option<Arc<dyn bitcoin_rs_utxo::contract::BlockUndoSource>>,
    pub prune_service: Option<Arc<dyn PruneService>>,
    pub chain_control: Option<Arc<dyn ChainControl>>,
    pub rollback_warnings: Option<Arc<dyn RollbackWarningSource>>,
}

pub struct ChainAdmissionView {
    utxo: bitcoin_rs_utxo::UtxoReader,
    applied_tip: TipReader,
    block_tree: BlockTreeReader,
    network: Network,
}

impl ChainAdmissionView {
    #[must_use]
    pub const fn new(
        utxo: bitcoin_rs_utxo::UtxoReader,
        applied_tip: TipReader,
        block_tree: BlockTreeReader,
        network: Network,
    ) -> Self {
        Self {
            utxo,
            applied_tip,
            block_tree,
            network,
        }
    }
}

impl AdmissionChain for ChainAdmissionView {
    fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
        let tip = self.applied_tip.load_full();
        let height = tip.as_ref().map_or(0, |tip| tip.height);
        let tree = self.block_tree.read();
        let tip_node = tip.as_ref().and_then(|tip| tree.lookup(tip.hash));
        let locktime_cutoff = tip_node
            .and_then(|node| tree.median_time_past_at(node))
            .unwrap_or(0);
        let next_softfork =
            tip_node.map(|node| softfork_state(&tree, self.network, Some(node), height + 1));
        let csv_active = next_softfork.as_ref().is_some_and(|state| state.csv_active);
        let next_block_script_flags = {
            let state = next_softfork.unwrap_or(bitcoin_rs_consensus::SoftforkState {
                csv_active: false,
                segwit_active: false,
            });
            bitcoin_rs_consensus::verify_block::verify_flags(
                self.network,
                height + 1,
                Hash256::default(),
                state,
            )
        };
        let mut mtp_cache: HashMap<u32, u32> = HashMap::new();
        let mut prevout_meta: HashMap<OutPoint, PrevoutMeta> = HashMap::new();
        let mut prevouts = Vec::new();
        for input in &tx.inputs {
            let Some(coin) = self.utxo.get_entry(&input.previous_output) else {
                continue;
            };
            let mtp = *mtp_cache.entry(coin.height).or_insert_with(|| {
                tip_node
                    .and_then(|tip| {
                        coin.height
                            .checked_sub(1)
                            .and_then(|prior| tree.node_at_height_from(tip, prior))
                    })
                    .and_then(|prior| tree.median_time_past_at(prior))
                    .unwrap_or(0)
            });
            prevout_meta.insert(
                input.previous_output,
                PrevoutMeta {
                    height: coin.height,
                    mtp,
                    coinbase: coin.coinbase,
                },
            );
            prevouts.push((input.previous_output, coin.txout));
        }
        let confirmed = self
            .utxo
            .has_live_outputs_for_txid(&Hash256::from(tx.txid()));
        Some(ChainAdmissionSnapshot {
            prevouts,
            prevout_meta,
            height,
            locktime_cutoff,
            csv_active,
            next_block_script_flags,
            confirmed,
        })
    }
}

pub struct MempoolHandles {
    pub gateway: Arc<MempoolGateway>,
}

#[derive(Default)]
pub struct IndexHandles {
    pub derived_index: Option<Arc<dyn DerivedIndexQuery>>,
    pub script_index: Option<Arc<dyn ScriptIndexQuery>>,
    pub compact_filters: Option<Arc<dyn bitcoin_rs_index::CompactFilterQuery>>,
    pub esplora_tx_index: Option<Arc<dyn DerivedIndexQuery>>,
    pub derived_index_status: Option<Arc<dyn bitcoin_rs_index::DerivedIndexCapabilitySource>>,
}

pub struct NetworkHandles {
    pub peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    pub p2p: Arc<bitcoin_rs_p2p::P2pService>,
    pub local_services: u64,
    pub overlay: bitcoin_rs_p2p::overlay::OverlayConfig,
}

#[cfg(feature = "pool")]
pub trait PoolOperator: Send + Sync {
    fn ledger(&self) -> &pool_ledger::Ledger;
    fn payout_policy(&self) -> pool_ledger::PayoutPolicy;
}

#[derive(Default)]
pub struct PoolHandles {
    #[cfg(feature = "pool")]
    pub operator: Option<Arc<dyn PoolOperator>>,
}

#[derive(Default)]
pub struct MiningHandles {
    pub mining_control: Option<Arc<dyn MiningControl>>,
}

pub struct Context {
    #[cfg(feature = "silent-payments")]
    pub(crate) silent_payments: Option<Mutex<()>>,
    pub(crate) compressed_transactions: bool,
    pub chain: ChainHandles,
    pub mempool: MempoolHandles,
    pub indexes: IndexHandles,
    pub network: NetworkHandles,
    pub mining: MiningHandles,
    pub pool: PoolHandles,
    pub zmq_publisher: Arc<dyn crate::zmq::ZmqPublisher>,
    pub debug_log_path: Option<PathBuf>,
    server_bound_at: Mutex<Option<Instant>>,
    block_render_budget: Arc<BlockRenderBudget>,
    pub(crate) active_calls: ActiveCalls,
}

pub(crate) struct ActiveCalls {
    entries: Mutex<Vec<ActiveCallEntry>>,
    next_id: AtomicU64,
}

struct ActiveCallEntry {
    id: u64,
    method: String,
    started: Instant,
}

pub(crate) struct ActiveCallGuard<'a> {
    calls: &'a ActiveCalls,
    id: u64,
}

impl Drop for ActiveCallGuard<'_> {
    fn drop(&mut self) {
        self.calls
            .entries
            .lock()
            .retain(|entry| entry.id != self.id);
    }
}

impl ActiveCalls {
    fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }

    pub(crate) fn begin(&self, method: &str) -> ActiveCallGuard<'_> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.entries.lock().push(ActiveCallEntry {
            id,
            method: method.to_owned(),
            started: Instant::now(),
        });
        ActiveCallGuard { calls: self, id }
    }

    pub(crate) fn snapshot(&self) -> Vec<(String, u64)> {
        self.entries
            .lock()
            .iter()
            .map(|entry| {
                let micros = u64::try_from(entry.started.elapsed().as_micros()).unwrap_or(u64::MAX);
                (entry.method.clone(), micros)
            })
            .collect()
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context").finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for ChainHandles {
    fn default() -> Self {
        Self::with_transition(bitcoin_rs_chain::TransitionDomain::new().stable_read())
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl ChainHandles {
    #[must_use]
    fn with_transition(chain_transition: bitcoin_rs_chain::StableRead) -> Self {
        let coin_stats_listener = bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        );
        let mut utxo = bitcoin_rs_utxo::UtxoSet::new();
        utxo.track_coin_stats(coin_stats_listener.clone());
        let chain_tip = TipReader::new(Arc::new(ArcSwapOption::empty()));
        let applied_tip = TipReader::new(Arc::new(ArcSwapOption::empty()));
        let block_tree = BlockTreeReader::new(Arc::new(parking_lot::RwLock::new(
            bitcoin_rs_chain::BlockTree::new(),
        )));
        let progress = bitcoin_rs_chain::ChainProgressReader::new(
            chain_tip.clone(),
            applied_tip.clone(),
            block_tree.clone(),
            Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
                applied_tip.clone(),
                block_tree.clone(),
            )),
        );
        Self {
            chain_tip,
            applied_tip,
            active_tip_wait: None,
            progress,
            closed_for_recovery: LatchReader::new(Arc::new(core::sync::atomic::AtomicBool::new(
                false,
            ))),
            blocks: BlockLogReader::fixture_empty(),
            utxo: bitcoin_rs_utxo::UtxoReader::new(Arc::new(utxo)),
            coin_stats: Arc::new(coin_stats_listener),
            block_tree,
            chain_network: Network::Mainnet,
            chain_transition,
            block_body_source: None,
            block_undo_source: None,
            prune_service: None,
            chain_control: None,
            rollback_warnings: None,
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for MempoolHandles {
    fn default() -> Self {
        Self {
            gateway: Arc::new(MempoolGateway::new(
                Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                None,
                ValidationEngine::Native,
                None,
            )),
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for NetworkHandles {
    fn default() -> Self {
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig::default(),
            LatchReader::fixture_never(),
        ));
        Self {
            peer_table: p2p.table(),
            p2p,
            local_services: 0x09,
            overlay: bitcoin_rs_p2p::overlay::OverlayConfig::default(),
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for ContextHandles {
    fn default() -> Self {
        Self {
            silent_payments: false,
            compressed_transactions: false,
            chain: ChainHandles::default(),
            mempool: MempoolHandles::default(),
            indexes: IndexHandles::default(),
            network: NetworkHandles::default(),
            mining: MiningHandles::default(),
            pool: PoolHandles::default(),
            zmq_publisher: Arc::new(crate::zmq::NoOpZmqPublisher),
            debug_log_path: None,
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    #[must_use]
    #[cfg(any(test, feature = "test-seam"))]
    pub fn new() -> Self {
        Self::from_handles(ContextHandles::default())
    }

    #[must_use]
    #[cfg(any(test, feature = "test-seam"))]
    pub fn new_with_mempool_observer(observer: Arc<dyn MempoolObserver>) -> Self {
        Self::from_handles(ContextHandles {
            mempool: MempoolHandles {
                gateway: Arc::new(MempoolGateway::new(
                    Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                    Some((observer, BodyInterest::Metadata)),
                    ValidationEngine::Native,
                    None,
                )),
            },
            ..ContextHandles::default()
        })
    }

    #[must_use]
    pub fn from_handles(handles: ContextHandles) -> Self {
        let ContextHandles {
            silent_payments,
            compressed_transactions,
            chain,
            mempool,
            indexes,
            network,
            mining,
            pool,
            zmq_publisher,
            debug_log_path,
        } = handles;
        #[cfg(not(feature = "silent-payments"))]
        let _ = silent_payments;
        Self {
            #[cfg(feature = "silent-payments")]
            silent_payments: silent_payments.then(|| Mutex::new(())),
            compressed_transactions,
            chain,
            mempool,
            indexes,
            network,
            mining,
            pool,
            zmq_publisher,
            debug_log_path,
            server_bound_at: Mutex::new(None),
            block_render_budget: Arc::new(BlockRenderBudget::new()),
            active_calls: ActiveCalls::new(),
        }
    }

    pub(crate) fn mark_server_bound(&self) {
        *self.server_bound_at.lock() = Some(Instant::now());
    }

    pub(crate) fn server_start(&self) -> Instant {
        *self.server_bound_at.lock().get_or_insert_with(Instant::now)
    }

    #[must_use]
    pub fn with_esplora_derived_index(
        mut self,
        derived_index: Option<Arc<dyn DerivedIndexQuery>>,
    ) -> Self {
        self.indexes.esplora_tx_index = derived_index;
        self
    }

    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.chain.block_body_source = Some(source);
        self
    }

    #[must_use]
    pub fn with_mining_control(mut self, mining_control: Arc<dyn MiningControl>) -> Self {
        self.mining.mining_control = Some(mining_control);
        self
    }

    #[must_use]
    pub fn with_chain_control(mut self, chain_control: Arc<dyn ChainControl>) -> Self {
        self.chain.chain_control = Some(chain_control);
        self
    }

    #[must_use]
    pub fn with_chain_transition(mut self, chain_transition: bitcoin_rs_chain::StableRead) -> Self {
        self.chain.chain_transition = chain_transition;
        self
    }

    pub(crate) fn try_acquire_block_render(&self) -> Option<BlockRenderPermit> {
        self.block_render_budget.try_acquire()
    }

    #[cfg(feature = "zmq")]
    #[must_use]
    pub(crate) fn zmq_notifications(&self) -> Vec<crate::zmq::ZmqNotifier> {
        self.zmq_publisher.active_notifiers()
    }
}

struct FlatRow {
    txid: Txid,
    first_flat: u32,
    output_count: u32,
}

struct RetainedBody {
    height: u32,
    rows: Vec<FlatRow>,
    txs: Vec<Tx>,
    index_bytes: usize,
    tx_bytes: usize,
}

fn retained_tx_bytes(txs: &[Tx]) -> usize {
    txs.iter()
        .map(|tx| {
            core::mem::size_of::<Tx>()
                + tx.inputs.len() * core::mem::size_of::<TxIn>()
                + tx.outputs.len() * core::mem::size_of::<TxOut>()
                + tx.inputs
                    .iter()
                    .map(|input| {
                        input.script_sig.len()
                            + input.witness.len() * core::mem::size_of::<Vec<u8>>()
                            + input.witness.iter().map(Vec::len).sum::<usize>()
                    })
                    .sum::<usize>()
                + tx.outputs
                    .iter()
                    .map(|output| output.script_pubkey.len())
                    .sum::<usize>()
        })
        .sum()
}

pub(crate) struct RpcPrevoutResolver<'ctx> {
    ctx: &'ctx Context,
    view: AppliedView,
    _permit: BlockRenderPermit,
    cancellation: LatchReader,
    bodies: Vec<RetainedBody>,
    retained_tx_bytes: usize,
    retained_index_bytes: usize,
    /// Cumulative body loads performed (distinct reads; eviction reloads
    /// count again, so cycling past the retained slots cannot do unbounded
    /// parse work under the exclusion). Never decremented.
    loads: usize,
    loaded_bytes: usize,
    memo: HashMap<OutPoint, Option<ResolvedPrevout>>,
    state_bytes: usize,
}

impl<'ctx> RpcPrevoutResolver<'ctx> {
    /// # Errors
    /// Returns retryable `Misc` (-1) when both block-render slots are
    /// busy; the caller never queues behind a render.
    pub(crate) fn new(ctx: &'ctx Context, cancellation: LatchReader) -> Result<Self, RpcError> {
        let permit = ctx
            .try_acquire_block_render()
            .ok_or_else(|| RpcError::Misc("block rendering is busy; retry".to_owned()))?;
        Ok(Self {
            ctx,
            view: ctx.chain.applied_view(),
            _permit: permit,
            cancellation,
            bodies: Vec::new(),
            retained_tx_bytes: 0,
            retained_index_bytes: 0,
            loads: 0,
            loaded_bytes: 0,
            memo: HashMap::new(),
            state_bytes: 0,
        })
    }

    #[must_use]
    pub(crate) fn view_matches_current(&self) -> bool {
        let current = self.ctx.chain.applied_view();
        match (self.view.tip(), current.tip()) {
            (None, None) => true,
            (Some(before), Some(now)) => before.height == now.height && before.hash == now.hash,
            _ => false,
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.is_triggered() || !self.view_matches_current()
    }

    fn ensure_body(&mut self, height: u32) -> Result<(), LookupError> {
        if self.bodies.iter().any(|body| body.height == height) {
            return Ok(());
        }
        if self.is_cancelled() {
            return Err(LookupError::Cancelled);
        }
        let record = self
            .ctx
            .chain
            .block_by_height_in_view(&self.view, height)
            .ok_or(LookupError::Missing)?;
        let source = self
            .ctx
            .chain
            .block_body_source
            .as_ref()
            .ok_or(LookupError::BodyMissing(height))?;
        if self.loads >= MAX_CUMULATIVE_BODY_LOADS {
            return Err(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::Loads,
            ));
        }
        let bytes = source
            .block_body(height, record.hash)
            .map_err(|error| match error {
                BlockBodyReadError::Corrupt(_) => LookupError::CorruptBody(height),
                BlockBodyReadError::Read(_) => LookupError::BodyReadFailed(height),
            })?
            .ok_or(LookupError::BodyMissing(height))?;
        if bytes.len() > MAX_RETAINED_BODY_BYTES {
            return Err(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::BodyBytes,
            ));
        }
        if self.loaded_bytes.saturating_add(bytes.len()) > MAX_CUMULATIVE_BODY_BYTES {
            return Err(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::LoadBytes,
            ));
        }
        self.loads += 1;
        self.loaded_bytes = self.loaded_bytes.saturating_add(bytes.len());
        let index_bytes = bytes.len() / 60 * 40;
        if index_bytes > MAX_RETAINED_INDEX_BYTES {
            return Err(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::IndexBytes,
            ));
        }
        let (rows, txs) = {
            let parsed =
                ParsedBlock::parse_exact(&bytes).map_err(|_| LookupError::CorruptBody(height))?;
            let mut rows = Vec::with_capacity(parsed.transactions().len());
            let mut txs = Vec::with_capacity(parsed.transactions().len());
            let mut flat = 0_u32;
            for parsed_tx in parsed.transactions() {
                let tx = parsed_tx.materialize();
                let output_count = u32::try_from(tx.outputs.len())
                    .map_err(|_| LookupError::CorruptBody(height))?;
                rows.push(FlatRow {
                    txid: tx.txid(),
                    first_flat: flat,
                    output_count,
                });
                flat = flat
                    .checked_add(output_count)
                    .ok_or(LookupError::CorruptBody(height))?;
                txs.push(tx);
            }
            (rows, txs)
        };
        let tx_bytes = retained_tx_bytes(&txs);
        while self.bodies.len() >= MAX_RETAINED_BODIES
            || self.retained_tx_bytes + tx_bytes > MAX_RETAINED_BODY_BYTES
            || self.retained_index_bytes + index_bytes > MAX_RETAINED_INDEX_BYTES
            || self.retained_tx_bytes + self.retained_index_bytes + tx_bytes + index_bytes
                > MAX_RETAINED_BYTES_TOTAL
        {
            let Some(evicted) = (!self.bodies.is_empty()).then(|| self.bodies.remove(0)) else {
                return Err(LookupError::LimitExceeded(
                    crate::compressed_tx::Limit::Bodies,
                ));
            };
            self.retained_tx_bytes -= evicted.tx_bytes;
            self.retained_index_bytes -= evicted.index_bytes;
        }
        self.retained_tx_bytes += tx_bytes;
        self.retained_index_bytes += index_bytes;
        self.bodies.push(RetainedBody {
            height,
            rows,
            txs,
            index_bytes,
            tx_bytes,
        });
        Ok(())
    }

    fn body_tx_ref(&mut self, height: u32, txid: &Txid) -> Result<Option<&Tx>, LookupError> {
        self.ensure_body(height)?;
        let Some(body) = self.bodies.iter().find(|body| body.height == height) else {
            return Err(LookupError::BodyMissing(height));
        };
        Ok(body
            .rows
            .iter()
            .zip(body.txs.iter())
            .find_map(|(row, tx)| (row.txid == *txid).then_some(tx)))
    }

    fn body_txout(
        &mut self,
        height: u32,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<TxOut>, LookupError> {
        let vout = usize::try_from(vout).map_err(|_| LookupError::Missing)?;
        let Some(tx) = self.body_tx_ref(height, txid)? else {
            return Ok(None);
        };
        Ok(tx.outputs.get(vout).cloned())
    }

    fn resolve_prevout(
        &mut self,
        outpoint: &OutPoint,
    ) -> Result<Option<ResolvedPrevout>, LookupError> {
        if let Some(coin) = self.ctx.chain.utxo.get_entry(outpoint) {
            return Ok(Some(ResolvedPrevout {
                txout: coin.txout,
                confirmed_height: Some(coin.height),
            }));
        }
        let height = match self.ctx.indexes.derived_index.as_ref() {
            Some(index) => index
                .transaction_height(&outpoint.txid)
                .map_err(|_| LookupError::Missing)?,
            None => None,
        };
        let Some(height) = height else {
            return Ok(None);
        };
        let Some(txout) = self.body_txout(height, &outpoint.txid, outpoint.vout)? else {
            return Ok(None);
        };
        Ok(Some(ResolvedPrevout {
            txout,
            confirmed_height: Some(height),
        }))
    }
}

impl PrevoutResolver for RpcPrevoutResolver<'_> {
    fn prevout(&mut self, outpoint: &OutPoint) -> Result<Option<ResolvedPrevout>, LookupError> {
        if let Some(cached) = self.memo.get(outpoint) {
            return Ok(cached.clone());
        }
        let resolved = self.resolve_prevout(outpoint)?;
        let charge = 96_usize
            + resolved
                .as_ref()
                .map_or(0, |prevout| prevout.txout.script_pubkey.len());
        let total = self
            .state_bytes
            .checked_add(charge)
            .ok_or(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::State,
            ))?;
        if total > MAX_RESOLVER_STATE_BYTES {
            return Err(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::State,
            ));
        }
        self.state_bytes = total;
        self.memo.insert(*outpoint, resolved.clone());
        Ok(resolved)
    }

    fn flat_output_index(
        &mut self,
        height: u32,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<u32>, LookupError> {
        match self.ensure_body(height) {
            Err(LookupError::Missing) => return Ok(None),
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        let Some(body) = self.bodies.iter().find(|body| body.height == height) else {
            return Err(LookupError::BodyMissing(height));
        };
        Ok(body
            .rows
            .iter()
            .find(|row| row.txid == *txid && vout < row.output_count)
            .map(|row| row.first_flat + vout))
    }

    fn outpoint_at(
        &mut self,
        height: u32,
        flat_index: u32,
    ) -> Result<Option<(OutPoint, ResolvedPrevout)>, LookupError> {
        match self.ensure_body(height) {
            Err(LookupError::Missing) => return Ok(None),
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        let located = self.bodies.iter().find_map(|body| {
            if body.height != height {
                return None;
            }
            body.rows.iter().find_map(|row| {
                (flat_index >= row.first_flat && flat_index < row.first_flat + row.output_count)
                    .then_some((row.txid, flat_index - row.first_flat))
            })
        });
        let Some((txid, vout)) = located else {
            return Ok(None);
        };
        let Some(txout) = self.body_txout(height, &txid, vout)? else {
            return Ok(None);
        };
        Ok(Some((
            OutPoint::new(txid, vout),
            ResolvedPrevout {
                txout,
                confirmed_height: Some(height),
            },
        )))
    }

    fn cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

impl ChainHandles {
    /// Runs a read with authoritative UTXO and applied-tip transitions excluded.
    ///
    /// INVARIANT: this is mutable-chainstate exclusion, not status synchronization:
    /// published status reads answer from a retained `AppliedView` capture and never
    /// call it.
    pub(crate) fn with_stable_chainstate<R>(&self, read: impl FnOnce() -> R) -> R {
        let _transition = self.chain_transition.lock();
        read()
    }

    #[must_use]
    fn prune_status(&self) -> PruneStatus {
        self.prune_service
            .as_ref()
            .map_or_else(PruneStatus::default, |service| service.status())
    }

    #[must_use]
    pub fn sync_progress(&self) -> SyncProgress {
        let applied = self.applied_view();
        self.sync_progress_at(&applied)
    }

    #[must_use]
    pub(crate) fn sync_progress_at(&self, applied: &AppliedView) -> SyncProgress {
        let chain = self
            .progress
            .progress_at(applied.tip(), self.chain_network, unix_time_secs());
        let prune_status = self.prune_status();
        SyncProgress {
            network: self.chain_network,
            blocks: chain.blocks,
            headers: chain.headers,
            best_block_hash: chain.best_block_hash,
            difficulty: chain
                .bits
                .map_or(0.0, |bits| self.difficulty_for_bits(bits)),
            time: chain.time,
            median_time: chain.median_time,
            verification_progress: chain.verification_progress,
            initial_block_download: chain.initial_block_download,
            chain_work: chain.chain_work.map_or_else(
                || "00".to_owned(),
                |work| {
                    let bytes: [u8; 32] = work.to_be_bytes();
                    bytes.to_lower_hex_string()
                },
            ),
            size_on_disk: self
                .block_storage_disk_usage()
                .unwrap_or_else(|| self.blocks.read().size_on_disk()),
            pruned: prune_status.pruned,
            prune_height: prune_status.pruneheight,
        }
    }

    #[must_use]
    pub fn difficulty_for_bits(&self, bits: CompactTarget) -> f64 {
        bitcoin_rs_mining::difficulty_for_bits(bits)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn add_block(&self, record: BlockRecord) {
        self.blocks.write().push(record);
    }

    #[must_use]
    pub(crate) fn admission_chain(&self) -> ChainAdmissionView {
        ChainAdmissionView::new(
            self.utxo.clone(),
            self.applied_tip.clone(),
            self.block_tree.clone(),
            self.chain_network,
        )
    }

    #[must_use]
    pub(crate) fn applied_height(&self) -> u32 {
        self.applied_view().height()
    }

    #[must_use]
    pub(crate) fn applied_hash(&self) -> Hash256 {
        self.applied_view().hash(self.chain_network)
    }

    fn hash_at_height_from_tip(&self, tip: &TipSnapshot, height: u32) -> Option<Hash256> {
        if height > tip.height {
            return None;
        }
        if height == tip.height {
            return Some(tip.hash);
        }
        let tree = self.block_tree.read();
        let node_id = tree.node_at_height_from(tip.tip_id, height)?;
        Some(tree.node(node_id).ok()?.hash)
    }

    #[must_use]
    pub(crate) fn active_hash_at_height(&self, height: u32) -> Option<Hash256> {
        self.active_hash_in_view(&self.applied_view(), height)
    }

    pub(crate) fn header_record(&self, hash: Hash256) -> Option<BlockRecord> {
        let tree = self.block_tree.read();
        let node = tree.node_by_hash(hash)?;
        Some(BlockRecord {
            hash: BlockHash::from(hash),
            height: node.height,
            body_size: 0,
            header: consensus_bytes(&node.header).try_into().ok().map(Box::new),
            tx_count: 0,
            time: node.header.time,
        })
    }

    #[must_use]
    pub(crate) fn block_hash_at_height(&self, height: u32) -> Option<Hash256> {
        self.block_hash_at_height_in_view(&self.applied_view(), height)
    }

    #[must_use]
    pub(crate) fn block_hash_at_height_in_view(
        &self,
        view: &AppliedView,
        height: u32,
    ) -> Option<Hash256> {
        if let Some(tip) = view.tip() {
            return self.hash_at_height_from_tip(tip, height);
        }
        if height == 0 {
            return Some(self.chain_network.genesis_block_hash());
        }
        record_at_height(&self.blocks.read(), height).map(|candidate| Hash256::from(candidate.hash))
    }

    #[must_use]
    pub fn block_by_hash(&self, hash: Hash256) -> Option<BlockRecord> {
        if let Some(mut record) = self.header_record(hash) {
            if let Some(cached) = record_at_height_hash(&self.blocks.read(), record.height, hash) {
                let mut cached = cached.clone();
                cached.header = record.header.take();
                return Some(cached);
            }
            if let Some(metadata) = self
                .block_body_source
                .as_ref()
                .and_then(|source| source.block_body_metadata(record.height, BlockHash::from(hash)))
            {
                record.body_size = metadata.body_size;
                record.tx_count = metadata.tx_count;
            }
            return Some(record);
        }
        None
    }

    #[must_use]
    pub(crate) fn block_by_height(&self, height: u32) -> Option<BlockRecord> {
        self.block_by_height_in_view(&self.applied_view(), height)
    }

    #[must_use]
    pub(crate) fn block_by_height_in_view(
        &self,
        view: &AppliedView,
        height: u32,
    ) -> Option<BlockRecord> {
        if let Some(tip) = view.tip() {
            let hash = self.hash_at_height_from_tip(tip, height)?;
            return self.block_by_hash(hash);
        }
        record_at_height(&self.blocks.read(), height).cloned()
    }

    #[must_use]
    pub fn block_body_bytes(&self, record: &BlockRecord) -> Option<Vec<u8>> {
        self.block_body_source
            .as_ref()?
            .block_body(record.height, record.hash)
            .ok()
            .flatten()
    }

    #[must_use]
    fn block_storage_disk_usage(&self) -> Option<u64> {
        self.block_body_source.as_ref()?.disk_usage()
    }

    #[must_use]
    pub(crate) fn block_body_hex(&self, record: &BlockRecord) -> Option<String> {
        Some(self.block_body_bytes(record)?.to_lower_hex_string())
    }

    #[must_use]
    pub(crate) fn median_time_past_for_hash(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Option<u32> {
        let tree = self.block_tree.read();
        let node_id = tree.lookup(hash)?;
        tree.median_time_past_at(node_id)
    }

    #[must_use]
    pub(crate) fn height_for_hash(&self, hash: bitcoin_rs_primitives::Hash256) -> Option<u32> {
        self.block_tree.read().height_of_hash(hash)
    }

    #[must_use]
    pub(crate) fn chain_work_hex_for_hash(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Option<String> {
        let tree = self.block_tree.read();
        let node = tree.node_by_hash(hash)?;
        let bytes: [u8; 32] = node.chainwork.to_be_bytes();
        Some(bytes.to_lower_hex_string())
    }
}

pub(crate) struct AppliedView {
    tip: Option<Arc<TipSnapshot>>,
}

impl ChainHandles {
    #[must_use]
    pub(crate) fn applied_view(&self) -> AppliedView {
        AppliedView {
            tip: self.applied_tip.load_full(),
        }
    }

    #[must_use]
    pub(crate) fn active_hash_in_view(&self, view: &AppliedView, height: u32) -> Option<Hash256> {
        let tip = view.tip()?;
        self.hash_at_height_from_tip(tip, height)
    }
}

impl AppliedView {
    #[must_use]
    pub(crate) fn tip(&self) -> Option<&TipSnapshot> {
        self.tip.as_deref()
    }

    #[must_use]
    pub(crate) fn height(&self) -> u32 {
        self.tip.as_ref().map_or(0, |tip| tip.height)
    }

    #[must_use]
    pub(crate) fn hash(&self, network: Network) -> Hash256 {
        self.tip
            .as_ref()
            .map_or_else(|| network.genesis_block_hash(), |tip| tip.hash)
    }

    #[must_use]
    pub(crate) fn chain_tx_count(&self) -> Option<u64> {
        self.tip.as_ref().and_then(|tip| tip.chain_tx_count.get())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;

#[cfg(test)]
mod admission_chain_tests;

#[cfg(test)]
pub(crate) struct BlockBodies {
    pub(crate) bodies: Vec<(u32, BlockHash, Vec<u8>)>,
}

#[cfg(test)]
impl BlockBodySource for BlockBodies {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        Ok(self
            .bodies
            .iter()
            .find(|(candidate_height, candidate_hash, _)| {
                *candidate_height == height && *candidate_hash == hash
            })
            .map(|(_, _, body)| body.clone()))
    }
}
