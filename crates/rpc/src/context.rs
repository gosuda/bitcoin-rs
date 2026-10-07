use alloc::sync::Arc;
#[cfg(any(test, feature = "test-seam"))]
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{
    BlockBodySource, BlockTreeReader, LatchReader, TipReader, TipSnapshot, softfork_state,
};
use bitcoin_rs_mempool::{AdmissionChain, ChainAdmissionSnapshot, MempoolGateway, PrevoutMeta};
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_mempool::{Mempool, MempoolLimits, MempoolObserver};
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_primitives::{
    BlockHash, CompactTarget, Hash256, Network, OutPoint, Tx, consensus_bytes, unix_time_secs,
};

use bitcoin::hex::DisplayHex as _;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_consensus::ValidationEngine;
#[cfg(test)]
use bitcoin_rs_primitives::{Amount, Script, Txid};
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use std::path::PathBuf;
use std::time::Instant;

#[cfg(test)]
const SERIALIZED_BLOCK_HEADER_LEN: usize = 80;

/// Core `sendrawtransaction` default `maxfeerate`: 0.1 BTC/kvB in sat/kvB.
///
/// RPC selects this default when no request override is supplied. Embedded
/// `Node::broadcast` also selects it; Esplora owns its request cap separately.
pub const DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB: u64 = 10_000_000;

/// Full-block REST responses materialize the block and a response buffer.
/// Bound concurrent materializations independently of socket connections.
const MAX_CONCURRENT_REST_BLOCK_RENDERS: usize = 2;

#[derive(Debug)]
struct RestRenderBudget {
    in_flight: AtomicUsize,
}

impl RestRenderBudget {
    const fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<RestRenderPermit> {
        let mut in_flight = self.in_flight.load(Ordering::Acquire);
        loop {
            if in_flight >= MAX_CONCURRENT_REST_BLOCK_RENDERS {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                in_flight,
                in_flight + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(RestRenderPermit {
                        budget: Arc::clone(self),
                    });
                }
                Err(actual) => in_flight = actual,
            }
        }
    }
}

pub(crate) struct RestRenderPermit {
    budget: Arc<RestRenderBudget>,
}

impl Drop for RestRenderPermit {
    fn drop(&mut self) {
        let previous = self.budget.in_flight.fetch_sub(1, Ordering::Release);
        debug_assert!(previous > 0, "REST render permit count underflowed");
    }
}

use bitcoin_rs_index::block_log::{BlockLog, BlockRecord, record_at_height, record_at_height_hash};
use bitcoin_rs_index::query_api::RollbackWarningSource;

/// Typed synchronization progress behind `getblockchaininfo`.
#[derive(Debug)]
pub struct SyncProgress {
    /// Consensus network the node follows.
    pub network: Network,
    /// Blocks fully applied to chainstate.
    pub blocks: u32,
    /// Validated headers known to the node (may lead `blocks` during sync).
    pub headers: u32,
    /// Hash of the best fully applied block.
    pub best_block_hash: Hash256,
    /// Difficulty at the applied tip (Core `GetDifficulty`).
    pub difficulty: f64,
    /// Applied tip header timestamp, UNIX seconds.
    pub time: u64,
    /// Median time past of the last eleven applied blocks.
    pub median_time: u64,
    /// Core `GuessVerificationProgress` in the inclusive range `[0, 1]`.
    pub verification_progress: f64,
    /// Whether the node is still in initial block download.
    pub initial_block_download: bool,
    /// Applied chain work, big-endian hex (`"00"` before the first tip).
    pub chain_work: String,
    /// Bytes the block store occupies on disk.
    pub size_on_disk: u64,
    /// Whether pruning is enabled.
    pub pruned: bool,
    /// Prune floor height, present only on a pruned node.
    pub prune_height: Option<u32>,
}

/// Current pruning state reported by chain RPCs.
#[derive(Copy, Clone, Debug, Default)]
pub struct PruneStatus {
    /// Whether block pruning is enabled for this node.
    pub pruned: bool,
    /// Highest manual prune height completed by the backing service.
    pub pruneheight: Option<u32>,
}

/// Summary of one completed manual prune request.
#[derive(Debug, Default)]
pub struct PruneResult {
    /// Highest prune height now recorded by the service.
    pub pruneheight: u32,
}

/// Error returned by the node-owned pruning implementation.
#[derive(Debug, thiserror::Error)]
pub enum PruneServiceError {
    /// Storage or backend-specific pruning failure.
    #[error("{0}")]
    Failed(String),
}

impl PruneServiceError {
    /// Wraps a concrete backend error message without coupling RPC to a storage crate.
    #[must_use]
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }
}

/// Node-owned storage mutator used by `pruneblockchain`.
pub trait PruneService: Send + Sync {
    /// Deletes persisted block/undo data below `requested_height`.
    fn prune_to_height(&self, requested_height: u32) -> Result<PruneResult, PruneServiceError>;

    /// Reports whether pruning is enabled and the highest completed prune height.
    fn status(&self) -> PruneStatus;
}

/// Node-owned control plane for consensus-affecting chain RPCs.
pub trait ChainControl: Send + Sync {
    /// Invalidates a block and descendants and selects the best remaining chain.
    fn invalidate_block(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), ChainControlError>;
}

/// Failure from a node-owned chain mutation.
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
}

pub use bitcoin_rs_index::{
    DerivedIndexInfo, DerivedIndexQuery, ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord,
    ScriptIndexSnapshot, SpendingRecord, TxQueryError,
};

/// The complete description of one RPC context, grouped by node capability:
/// chain, mempool, indexes, network, and mining.
///
/// A struct-of-structs grouping, not a trait layer. [`Context::from_handles`]
/// is the single composition point: one `ContextHandles` value carries every
/// production capability, including the authoritative chain-transition
/// barrier, the durable block-body reader, and the optional surfaces (prune,
/// chain control, ZMQ publisher, debug log). The handler surface reads only
/// these capability groups — RPC consumes node capabilities and never names a
/// storage backend or backend engine type, and production wiring attaches
/// nothing to a constructed `Context` afterwards.
pub struct ContextHandles {
    /// Chain capability: tips, block log, UTXO set, block tree, transition
    /// barrier, and the chain-owned control surfaces.
    pub chain: ChainHandles,
    /// Mempool capability: the mutation gateway in front of the pool.
    pub mempool: MempoolHandles,
    /// Index capability: transaction and script index query adapters.
    pub indexes: IndexHandles,
    /// Network capability: peer registry, reachability, and connection control.
    pub network: NetworkHandles,
    /// Mining capability: the template coordinator, when one is attached.
    pub mining: MiningHandles,
    /// Live ZMQ notification publisher backing the notifier surface.
    pub zmq_publisher: Arc<dyn crate::zmq::ZmqPublisher>,
    /// Configured node debug-log path for `getrpcinfo`.
    pub debug_log_path: Option<PathBuf>,
}

/// Chain capability handles.
pub struct ChainHandles {
    /// Best header-chain tip. Read-only: only Chainstate publishes.
    pub chain_tip: TipReader,
    /// Best fully-applied block tip. Read-only: only Chainstate publishes.
    pub applied_tip: TipReader,
    /// Chainstate-owned synchronization progress, including the
    /// process-wide initial-block-download latch shared with P2P so both
    /// surfaces answer identically.
    pub progress: bitcoin_rs_chain::ChainProgressReader,
    /// Chain-mutation admission latch: the same fact
    /// `Chainstate::is_closed_for_recovery` publishes, exposed read-only and
    /// kept separate from the initial-block-download decision in
    /// [`Self::progress`] by that fact's invariant.
    pub closed_for_recovery: LatchReader,
    /// Applied block metadata log.
    pub blocks: Arc<RwLock<BlockLog>>,
    /// Authoritative UTXO set, read-only: mutation stays with the chain
    /// owner through `utxo::contract`.
    pub utxo: bitcoin_rs_utxo::UtxoReader,
    /// Incremental UTXO statistics.
    pub coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    /// Shared block tree.
    pub block_tree: BlockTreeReader,
    /// Consensus network.
    pub chain_network: Network,
    /// Excludes authoritative chain transitions while a read runs.
    ///
    /// Production supplies the role minted alongside chainstate's mutation
    /// role. `Self::with_transition` accepts a caller-supplied role but cannot
    /// verify its provenance; callers can mint an unrelated domain through
    /// [`bitcoin_rs_chain::TransitionDomain::new`].
    pub chain_transition: bitcoin_rs_chain::StableRead,
    /// Durable block-body reader for metadata-only block records.
    pub block_body_source: Option<Arc<dyn BlockBodySource>>,
    /// Optional storage pruning mutator.
    pub prune_service: Option<Arc<dyn PruneService>>,
    /// Optional node-owned chain mutation service.
    pub chain_control: Option<Arc<dyn ChainControl>>,
    /// Rollback-evidence warning source for `getblockchaininfo`.
    pub rollback_warnings: Option<Arc<dyn RollbackWarningSource>>,
}

/// Borrowed provisional chain facts used by both RPC and P2P admission.
///
/// The view contains no gateway or full node/context reference. Height and MTP
/// use one applied tip; coins are read without taking the chain-transition
/// mutex. The chain owner brackets authoritative mutations with the gateway's
/// generation fence, and gateway generation/sequence revalidation discards any
/// facts collected across such a mutation before they can affect admission.
pub struct ChainAdmissionView {
    utxo: bitcoin_rs_utxo::UtxoReader,
    applied_tip: TipReader,
    block_tree: BlockTreeReader,
    network: Network,
}

impl ChainAdmissionView {
    /// Borrows the chain owner's existing handles without retaining state.
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
        // CSV activation at the next block gates BIP68 relative locks,
        // matching the block-connect and mining evaluation contexts.
        let csv_active = tip_node.is_some_and(|node| {
            softfork_state(&tree, self.network, Some(node), height + 1).csv_active
        });
        // Confirmed coin metadata for BIP68 and coinbase maturity. Height `h`
        // uses the MTP of the block before `h`, the same derivation the
        // block-connect path applies. MTP lookups are cached per height.
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
        // Live confirmed coins are positive chain evidence. The RPC lookup
        // cache may contain unconfirmed bodies and cannot supply this fact.
        // No live outputs means unknown, not proof that the tx is unconfirmed.
        let confirmed = self
            .utxo
            .has_live_outputs_for_txid(&Hash256::from(tx.txid()));
        Some(ChainAdmissionSnapshot {
            prevouts,
            prevout_meta,
            height,
            locktime_cutoff,
            csv_active,
            confirmed,
        })
    }
}

/// Mempool capability handles.
pub struct MempoolHandles {
    /// The process-wide mutation gateway in front of the in-memory pool.
    pub gateway: Arc<MempoolGateway>,
}

/// Index capability handles.
#[derive(Default)]
pub struct IndexHandles {
    /// Complete transaction-index query adapter.
    pub derived_index: Option<Arc<dyn DerivedIndexQuery>>,
    /// Generic script-index query adapter.
    pub script_index: Option<Arc<dyn ScriptIndexQuery>>,
    /// Complete transaction lookup used by Esplora output projections. It may
    /// exist without [`Self::derived_index`] because it does not advertise
    /// the Core `--txindex` contract.
    pub esplora_tx_index: Option<Arc<dyn DerivedIndexQuery>>,
    /// Live txindex status for the `getcapabilities` projection.
    pub derived_index_status: Option<Arc<dyn bitcoin_rs_index::DerivedIndexCapabilitySource>>,
}

/// Network capability handles.
pub struct NetworkHandles {
    /// Authoritative live peer sessions.
    pub peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    /// P2P service runtime owner for network mutations and state.
    pub p2p: Arc<bitcoin_rs_p2p::P2pService>,
    /// Service flags the node advertises, as resolved at P2P startup —
    /// `NETWORK` on an unpruned node, `NETWORK_LIMITED` on a pruned one.
    pub local_services: u64,
}

/// Mining capability handles.
#[derive(Default)]
pub struct MiningHandles {
    /// Node-owned mining coordinator. `None` when mining is not wired.
    pub mining_control: Option<Arc<dyn MiningControl>>,
}

/// Shared state consumed by JSON-RPC handlers.
///
/// The subsystem graph lives behind the capability groups ([`ChainHandles`],
/// [`MempoolHandles`], [`IndexHandles`], [`NetworkHandles`], [`MiningHandles`]);
/// `Context` itself carries only those groups plus presentation-local state
/// (the ZMQ publisher surface, the debug-log path, the REST render budget,
/// and the listener bind epoch). Handlers read capabilities through the
/// groups; production wiring attaches nothing after construction.
pub struct Context {
    /// Chain capability: tips, block log, UTXO set, block tree, transition
    /// barrier, and the chain-owned control surfaces.
    pub chain: ChainHandles,
    /// Mempool capability: the mutation gateway in front of the pool.
    pub mempool: MempoolHandles,
    /// Index capability: transaction, script, and Esplora query adapters.
    pub indexes: IndexHandles,
    /// Network capability: peer registry, reachability, and connection control.
    pub network: NetworkHandles,
    /// Mining capability: the template coordinator, when one is attached.
    pub mining: MiningHandles,
    /// Live ZMQ publisher, also the source of active notifier metadata.
    pub zmq_publisher: Arc<dyn crate::zmq::ZmqPublisher>,
    /// Configured node debug-log path for `getrpcinfo`.
    pub debug_log_path: Option<PathBuf>,
    /// Instant this context's RPC listener bound, set by `RpcServer::bind`
    /// and read by `uptime`. Kept per context rather than process-global so
    /// two servers in one process report their own epochs; `None` (never
    /// bound, e.g. unit tests) makes `uptime` measure from its first call.
    server_bound_at: Mutex<Option<Instant>>,
    /// Limits concurrent full-block REST response materializations.
    rest_render_budget: Arc<RestRenderBudget>,
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context").finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for ChainHandles {
    /// Builds the empty synthetic chain world used by tests.
    ///
    /// The transition role here is minted from a private domain nothing else in
    /// the process shares, so a context built this way excludes no transition
    /// at all. That is correct for a fixture and wrong for a node: production
    /// wiring supplies the role from the node's transition domain when it
    /// builds `ChainHandles`. Reader capability types expose no constructor
    /// of their own; the domain is what creates each role.
    fn default() -> Self {
        Self::with_transition(bitcoin_rs_chain::TransitionDomain::new().stable_read())
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl ChainHandles {
    /// Builds the synthetic chain world over a caller-supplied transition role.
    ///
    /// This is what a test that also drives a real node uses: it passes the
    /// role composition minted for that node, so the resulting context and the
    /// chainstate it reads exclude each other's transitions. The other fields
    /// are empty publications with no owner behind them.
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
            progress,
            closed_for_recovery: LatchReader::new(Arc::new(core::sync::atomic::AtomicBool::new(
                false,
            ))),
            blocks: Arc::new(RwLock::new(BlockLog::new())),
            utxo: bitcoin_rs_utxo::UtxoReader::new(Arc::new(utxo)),
            coin_stats: Arc::new(coin_stats_listener),
            block_tree,
            chain_network: Network::Mainnet,
            chain_transition,
            block_body_source: None,
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
            gateway: MempoolGateway::shared(
                Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                ValidationEngine::Native,
            )
            .unwrap_or_else(|error| panic!("mempool gateway intern: {error}")),
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for NetworkHandles {
    fn default() -> Self {
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig::default(),
            Arc::new(core::sync::atomic::AtomicBool::new(false)),
        ));
        Self {
            peer_table: p2p.table(),
            p2p,
            local_services: 0x09,
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for ContextHandles {
    /// Builds the empty synthetic capability set used by tests. Production
    /// wiring supplies every capability it owns.
    fn default() -> Self {
        Self {
            chain: ChainHandles::default(),
            mempool: MempoolHandles::default(),
            indexes: IndexHandles::default(),
            network: NetworkHandles::default(),
            mining: MiningHandles::default(),
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
    /// Builds an empty context over the default synthetic handles. Test
    /// convenience; production composes a complete [`ContextHandles`]
    /// through [`Self::from_handles`].
    #[must_use]
    #[cfg(any(test, feature = "test-seam"))]
    pub fn new() -> Self {
        Self::from_handles(ContextHandles::default())
    }

    /// Builds an empty context whose mempool gateway carries `observer`.
    ///
    /// Like [`Self::new`] but the gateway is constructed with the supplied
    /// observer instead of `None`. Test-only: production wiring constructs
    /// the gateway through `NodeState::open`.
    #[must_use]
    #[cfg(any(test, feature = "test-seam"))]
    pub fn new_with_mempool_observer(observer: Arc<dyn MempoolObserver>) -> Self {
        Self::from_handles(ContextHandles {
            mempool: MempoolHandles {
                gateway: MempoolGateway::shared_with(
                    Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                    observer,
                    ValidationEngine::Native,
                )
                .unwrap_or_else(|error| panic!("mempool gateway intern: {error}")),
            },
            ..ContextHandles::default()
        })
    }

    /// Composes one context from a complete [`ContextHandles`] value.
    ///
    /// This is the single production composition point. PRE: `handles` names
    /// every capability the context will use, including the authoritative
    /// chain-transition barrier supplied by the chain owner. POST: the
    /// context carries that full set; the groups' `pub` fields still permit
    /// post-hoc attachment, which only test fixtures use.
    /// INVARIANT: production wiring supplies the chain owner's barrier
    /// (e.g. `chainstate.transition_barrier()`); the synthetic
    /// `ContextHandles::default` path builds a private barrier for tests.
    #[must_use]
    pub fn from_handles(handles: ContextHandles) -> Self {
        let ContextHandles {
            chain,
            mempool,
            indexes,
            network,
            mining,
            zmq_publisher,
            debug_log_path,
        } = handles;
        Self {
            chain,
            mempool,
            indexes,
            network,
            mining,
            zmq_publisher,
            debug_log_path,
            server_bound_at: Mutex::new(None),
            rest_render_budget: Arc::new(RestRenderBudget::new()),
        }
    }

    /// Marks the instant this context's RPC listener bound. A rebind
    /// overwrites the epoch so `uptime` measures the live server.
    pub(crate) fn mark_server_bound(&self) {
        *self.server_bound_at.lock() = Some(Instant::now());
    }

    /// Uptime epoch for `uptime`: the recorded bind instant, or — for a
    /// context that never binds a server — the first call's instant.
    pub(crate) fn server_start(&self) -> Instant {
        *self.server_bound_at.lock().get_or_insert_with(Instant::now)
    }

    /// Attaches the internal transaction lookup required for Esplora output
    /// projections without exposing it to Core transaction-index RPCs.
    #[must_use]
    pub fn with_esplora_derived_index(
        mut self,
        derived_index: Option<Arc<dyn DerivedIndexQuery>>,
    ) -> Self {
        self.indexes.esplora_tx_index = derived_index;
        self
    }

    /// Returns `self` with a durable block body source.
    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.chain.block_body_source = Some(source);
        self
    }

    /// Attaches the node-owned mining coordinator to a context built without
    /// handles (`Context::new`). Production wiring passes the coordinator
    /// through `ContextHandles::mining` instead.
    #[must_use]
    pub fn with_mining_control(mut self, mining_control: Arc<dyn MiningControl>) -> Self {
        self.mining.mining_control = Some(mining_control);
        self
    }

    /// Attaches the node-owned chain mutation service.
    #[must_use]
    pub fn with_chain_control(mut self, chain_control: Arc<dyn ChainControl>) -> Self {
        self.chain.chain_control = Some(chain_control);
        self
    }

    /// Attaches the transition-exclusion role composition minted for this node.
    ///
    /// PRE: `chain_transition` is the read role over the same
    ///   [`bitcoin_rs_chain::TransitionDomain`] chainstate's mutation role uses.
    /// POST: exclusive chainstate reads use it; see
    ///   [`ChainHandles::with_stable_chainstate`].
    /// INVARIANT: published status reads do not acquire it, so a block
    ///   transition cannot stall `getblockchaininfo` or `getchaintxstats`.
    #[must_use]
    pub fn with_chain_transition(mut self, chain_transition: bitcoin_rs_chain::StableRead) -> Self {
        self.chain.chain_transition = chain_transition;
        self
    }

    /// Acquires a bounded full-block REST render slot, if one is available.
    pub(crate) fn try_acquire_rest_render(&self) -> Option<RestRenderPermit> {
        self.rest_render_budget.try_acquire()
    }

    /// Returns active ZMQ notification metadata from the live publisher.
    #[cfg(feature = "zmq")]
    #[must_use]
    pub(crate) fn zmq_notifications(&self) -> Vec<crate::zmq::ZmqNotifier> {
        self.zmq_publisher.active_notifiers()
    }
}

impl ChainHandles {
    /// Runs a read with authoritative UTXO and applied-tip transitions excluded.
    ///
    /// PRE: `read` does not reacquire the transition role.
    /// POST: `read` completes before the exclusion guard is released, so its
    ///   live tip and UTXO observations describe one uninterrupted chainstate.
    /// INVARIANT: this is mutable-chainstate exclusion, not status
    ///   synchronization: published status reads answer from a retained
    ///   `AppliedView` capture and never call it.
    pub(crate) fn with_stable_chainstate<R>(&self, read: impl FnOnce() -> R) -> R {
        let _transition = self.chain_transition.lock();
        read()
    }

    /// Returns the pruning state reported by `getblockchaininfo`.
    #[must_use]
    fn prune_status(&self) -> PruneStatus {
        self.prune_service
            .as_ref()
            .map_or_else(PruneStatus::default, |service| service.status())
    }

    /// Typed synchronization progress: the `getblockchaininfo` facts without
    /// RPC JSON. Chainwork is the applied tip's when one exists.
    ///
    /// PRE: none.
    /// POST: progress projected from one applied publication captured here.
    /// INVARIANT: neither capture nor projection acquires `chain_transition`,
    ///   so a block transition in progress cannot stall this response.
    #[must_use]
    pub fn sync_progress(&self) -> SyncProgress {
        let applied = self.applied_view();
        self.sync_progress_at(&applied)
    }

    /// Synchronization progress projected from a retained applied publication.
    ///
    /// PRE: `applied` is the view this response is built from.
    /// POST: the chain facts are Chainstate's [`bitcoin_rs_chain::ChainProgress`]
    ///   at that view; this adds Core's difficulty rendering and the storage
    ///   facts. The header height is sampled separately, so best-header may
    ///   lead applied.
    /// INVARIANT: the projection never reloads the applied publication.
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

    /// Returns the f64 difficulty for `bits` using Bitcoin Core's calculation.
    ///
    /// Keep the operation order here in sync with Core's `GetDifficulty`;
    /// changing the repeated 256 scaling into an equivalent exponentiation can
    /// change the final floating-point bit.
    #[must_use]
    pub fn difficulty_for_bits(&self, bits: CompactTarget) -> f64 {
        bitcoin_rs_mining::difficulty_for_bits(bits)
    }

    /// Stores a block record for block and header RPCs.
    pub fn add_block(&self, record: BlockRecord) {
        self.blocks.write().push(record);
    }

    /// Borrows the provisional chain capability shared with P2P admission.
    #[must_use]
    pub(crate) fn admission_chain(&self) -> ChainAdmissionView {
        ChainAdmissionView::new(
            self.utxo.clone(),
            self.applied_tip.clone(),
            self.block_tree.clone(),
            self.chain_network,
        )
    }

    /// Returns the current best-applied-block height (lags the header tip when
    /// headers are ahead of downloaded blocks).
    #[must_use]
    pub(crate) fn applied_height(&self) -> u32 {
        self.applied_view().height()
    }

    /// Returns the current best-applied-block hash.
    ///
    /// Before the first applied tip is published the canonical chain is the
    /// genesis-only chain, exactly as `applied_height` already reports `0` and
    /// `block_hash_at_height(0)` answers the genesis hash — callers must never
    /// see an all-zero tip for a chain that always has a height-0 block.
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

    /// Returns the applied-chain hash at `height`, from the restored header index.
    #[must_use]
    pub(crate) fn active_hash_at_height(&self, height: u32) -> Option<Hash256> {
        self.active_hash_in_view(&self.applied_view(), height)
    }

    fn header_record(&self, hash: Hash256) -> Option<BlockRecord> {
        let tree = self.block_tree.read();
        let node = tree.node_by_hash(hash)?;
        Some(BlockRecord {
            hash: BlockHash::from(hash),
            height: node.height,
            body_size: 0,
            // The one place a header is produced. Every constructor leaves the
            // field empty, so the tree node reached here is the single source of
            // truth for what a block's header is.
            header: consensus_bytes(&node.header).try_into().ok().map(Box::new),
            tx_count: 0,
            time: node.header.time,
        })
    }

    /// Resolves a block record for `hash`.
    ///
    /// The restored header tree is the only identity authority. A hash it does
    /// not know resolves to `None`, even when the block log carries a record for
    /// it. For a tree-resolved `(height, hash)` pair, the log may contribute
    /// matching durable body metadata.
    #[must_use]
    pub(crate) fn record_for_hash(&self, hash: Hash256) -> Option<BlockRecord> {
        // Tree authority resolves identity first; the exact `(height, hash)`
        // record may then enrich its payload fields.
        if let Some(mut record) = self.header_record(hash) {
            // The tree already gave us the height, so this is a binary search
            // over a height-ordered log rather than a walk of every record on
            // the chain. `getblock` and `getblockheader` both land here.
            if let Some(cached) = record_at_height_hash(&self.blocks.read(), record.height, hash) {
                // The cached record supplies the payload facts — size and
                // transaction count — and the tree supplies the header, because
                // the log does not store one. Returning the cached record as it
                // stands would answer with no header at all.
                //
                // Costs no extra lock: `header_record` has already taken and
                // released the tree guard, and the header it produced outlives
                // it.
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

    /// Returns the block hash for an applied height.
    ///
    /// Once an applied tip exists, its ancestry is authoritative and heights
    /// above it are absent even when header sync has found a better fork.
    /// Before the first applied-tip publication, genesis and cache-only test
    /// records remain available.
    #[must_use]
    pub(crate) fn block_hash_at_height(&self, height: u32) -> Option<Hash256> {
        if let Some(tip) = self.applied_tip.load_full() {
            return self.hash_at_height_from_tip(&tip, height);
        }
        if height == 0 {
            return Some(self.chain_network.genesis_block_hash());
        }
        record_at_height(&self.blocks.read(), height).map(|candidate| Hash256::from(candidate.hash))
    }

    /// Returns the applied-chain hash at `height` within a retained view.
    ///
    /// PRE: `view` is the response's retained applied publication.
    /// POST: that branch's hash at `height`; with no applied tip yet, the
    ///   genesis hash at height 0 or the block-log record's hash, which is the
    ///   cache-only fallback such contexts use.
    /// INVARIANT: reads the tree and the log as necessary but never reloads
    ///   `applied_tip`, so one response cannot straddle two applied branches.
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

    /// Returns a known block by hash.
    #[must_use]
    pub fn block_by_hash(&self, hash: Hash256) -> Option<BlockRecord> {
        self.record_for_hash(hash)
    }

    /// Returns the applied block at a height.
    ///
    /// Once an applied tip exists, its ancestry is authoritative. The session
    /// vector is a cache-only fallback before the first applied-tip publication.
    #[must_use]
    pub(crate) fn block_by_height(&self, height: u32) -> Option<BlockRecord> {
        self.block_by_height_in_view(&self.applied_view(), height)
    }

    /// Returns the applied block at `height` within a retained view.
    ///
    /// PRE: `view` is the response's retained applied publication.
    /// POST: that branch's record at `height`; with no applied tip yet, the
    ///   block-log record, which is the cache-only fallback such contexts use.
    /// INVARIANT: reads the log as necessary but never reloads `applied_tip`,
    ///   so one response cannot straddle two applied branches.
    #[must_use]
    pub(crate) fn block_by_height_in_view(
        &self,
        view: &AppliedView,
        height: u32,
    ) -> Option<BlockRecord> {
        if let Some(tip) = view.tip() {
            let hash = self.hash_at_height_from_tip(tip, height)?;
            return self.record_for_hash(hash);
        }
        record_at_height(&self.blocks.read(), height).cloned()
    }

    /// Returns serialized block bytes from durable body storage.
    #[must_use]
    pub fn block_body_bytes(&self, record: &BlockRecord) -> Option<Vec<u8>> {
        self.block_body_source
            .as_ref()?
            .block_body(record.height, record.hash)
    }

    /// Bytes the node's block storage occupies on disk, when it can say.
    ///
    /// `None` when there is no durable body source, or it does not track usage.
    #[must_use]
    fn block_storage_disk_usage(&self) -> Option<u64> {
        self.block_body_source.as_ref()?.disk_usage()
    }

    /// Returns lowercase serialized block hex from durable body storage.
    #[must_use]
    pub(crate) fn block_body_hex(&self, record: &BlockRecord) -> Option<String> {
        Some(self.block_body_bytes(record)?.to_lower_hex_string())
    }

    /// Returns the median-time-past at the block with `hash`, or `None` if the
    /// block is not in the tree.
    #[must_use]
    pub(crate) fn median_time_past_for_hash(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Option<u32> {
        let tree = self.block_tree.read();
        let node_id = tree.lookup(hash)?;
        tree.median_time_past_at(node_id)
    }

    /// Returns the block height for `hash` via the in-memory `BlockTree`, or
    /// `None` if no node with that hash is known to the tree.
    ///
    /// Composes `BlockTree::height_of_hash` (chain crate commit `ef9ff41`).
    #[must_use]
    pub(crate) fn height_for_hash(&self, hash: bitcoin_rs_primitives::Hash256) -> Option<u32> {
        self.block_tree.read().height_of_hash(hash)
    }

    /// Returns the 64-char lowercase hex chainwork at the block with `hash`.
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

/// One retained applied-tip publication.
///
/// A response that reports several applied facts builds them from a single
/// value of this type, so height, hash, work, and count cannot come from
/// different blocks.
///
/// PRE: the publisher stores complete immutable [`TipSnapshot`] values.
/// POST: the view retains the result of exactly one `applied_tip` load; no
///   transition exclusion, tree lock, UTXO lock, count-register read, or retry
///   loop occurs in capture.
/// INVARIANT: the facts projected from this view describe the same
///   publication even if the publisher advances afterward.
pub(crate) struct AppliedView {
    tip: Option<Arc<TipSnapshot>>,
}

impl ChainHandles {
    /// Captures the applied publication the response is built from.
    ///
    /// PRE: none; this reads the published tip cell.
    /// POST: a view holding exactly one `applied_tip` load result, empty
    ///   before the first publication.
    /// INVARIANT: capture never acquires `chain_transition`, so a response
    ///   that reports only applied facts does not wait on a block transition.
    #[must_use]
    pub(crate) fn applied_view(&self) -> AppliedView {
        AppliedView {
            tip: self.applied_tip.load_full(),
        }
    }

    /// Returns the applied-chain hash at `height` within a retained view.
    ///
    /// PRE: `view` is the response's retained applied publication.
    /// POST: that tip's ancestor hash at `height`, or `None` for no tip, a
    ///   height above the tip, or missing ancestry.
    /// INVARIANT: reads the block tree as necessary but never reloads
    ///   `applied_tip`, so the answer cannot describe a newer branch.
    #[must_use]
    pub(crate) fn active_hash_in_view(&self, view: &AppliedView, height: u32) -> Option<Hash256> {
        let tip = view.tip()?;
        self.hash_at_height_from_tip(tip, height)
    }
}

impl AppliedView {
    /// The captured snapshot, or `None` before the first publication.
    ///
    /// PRE: use a captured view.
    /// POST: the retained snapshot.
    /// INVARIANT: does not reload a publisher.
    #[must_use]
    pub(crate) fn tip(&self) -> Option<&TipSnapshot> {
        self.tip.as_deref()
    }

    /// The applied height, `0` with no tip.
    ///
    /// PRE: use a captured view.
    /// POST: the captured tip's height, or the empty-tip default `0`.
    /// INVARIANT: does not reload a publisher.
    #[must_use]
    pub(crate) fn height(&self) -> u32 {
        self.tip.as_ref().map_or(0, |tip| tip.height)
    }

    /// The applied block hash, genesis with no tip.
    ///
    /// PRE: use a captured view and the network the response describes.
    /// POST: the captured tip's hash, or that network's genesis hash when the
    ///   view is empty.
    /// INVARIANT: does not reload a publisher.
    #[must_use]
    pub(crate) fn hash(&self, network: Network) -> Hash256 {
        self.tip
            .as_ref()
            .map_or_else(|| network.genesis_block_hash(), |tip| tip.hash)
    }

    /// The applied-chain transaction count, `None` when unknown.
    ///
    /// PRE: use a captured view.
    /// POST: the captured tip's count, or `None` for an empty view or a tip
    ///   whose count is not yet known. A present tip with an unknown count is
    ///   not guessed as zero.
    /// INVARIANT: does not reload a publisher or read a count register.
    #[must_use]
    pub(crate) fn chain_tx_count(&self) -> Option<u64> {
        self.tip.as_ref().and_then(|tip| tip.chain_tx_count.get())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    /// A txindex status source stand-in, so the identity test can prove the
    /// capability travels to `indexes` without a live index runtime.
    struct ReadySource;

    impl bitcoin_rs_index::DerivedIndexCapabilitySource for ReadySource {
        fn capability(&self) -> bitcoin_rs_index::CapabilityStatus {
            bitcoin_rs_index::derived_index_status(true, bitcoin_rs_index::CapabilityState::Ready)
        }
    }

    /// The context and every capability group are shareable because the
    /// compiler derives it, not because a `SAFETY` comment claims it.
    ///
    /// A field that is not thread-safe fails this test at compile time and
    /// names its type, so the fix is a real bound on the owning subsystem
    /// rather than a new `unsafe impl`.
    #[test]
    fn context_and_groups_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<Context>();
        assert_send_sync::<ContextHandles>();
        assert_send_sync::<ChainHandles>();
        assert_send_sync::<IndexHandles>();
        assert_send_sync::<NetworkHandles>();
        assert_send_sync::<bitcoin_rs_chain::InitialBlockDownload>();
    }

    /// The count travels inside the applied tip: one publication replaces
    /// tip and count together, so no reader can pair one with the other's
    /// successor.
    #[test]
    fn applied_tip_publication_carries_the_transaction_count() {
        let ctx = Context::new();
        let counted = |count| {
            Arc::new(TipSnapshot {
                tip_id: bitcoin_rs_chain::NodeId::new(0),
                height: 0,
                chainwork: bitcoin_rs_chain::ChainWork::ZERO,
                hash: bitcoin_rs_primitives::Hash256::default(),
                chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(count),
            })
        };
        ctx.chain.applied_tip.store(Some(counted(1)));
        assert_eq!(ctx.chain.applied_view().chain_tx_count(), Some(1));
        ctx.chain.applied_tip.store(Some(counted(42)));
        assert_eq!(ctx.chain.applied_view().chain_tx_count(), Some(42));
    }

    /// Every fact projected from one view describes the publication that view
    /// captured, even after the publisher advances to a new tip.
    #[test]
    fn applied_view_uses_one_publication() {
        use bitcoin_rs_chain::{ChainTxCount, ChainWork, NodeId};

        let ctx = Context::new();
        let tip = |height: u32, byte: u8, work: u64, count| {
            Arc::new(TipSnapshot {
                tip_id: NodeId::new(height),
                height,
                chainwork: ChainWork::from(work),
                hash: Hash256::from_le_bytes(&[byte; 32]),
                chain_tx_count: count,
            })
        };

        // Before the first publication every projection answers with its
        // documented empty default.
        let empty = ctx.chain.applied_view();
        assert_eq!(empty.tip(), None);
        assert_eq!(empty.height(), 0);
        assert_eq!(
            empty.hash(Network::Mainnet),
            Network::Mainnet.genesis_block_hash()
        );
        assert_eq!(empty.chain_tx_count(), None);

        let a = tip(10, 0xaa, 7, ChainTxCount::established(100));
        let b = tip(20, 0xbb, 9, ChainTxCount::established(200));
        ctx.chain.applied_tip.store(Some(Arc::clone(&a)));
        let view = ctx.chain.applied_view();
        // The publisher advances while the response is still being built.
        ctx.chain.applied_tip.store(Some(b));

        assert_eq!(view.height(), 10, "height must stay at the capture");
        assert_eq!(
            view.hash(Network::Mainnet),
            Hash256::from_le_bytes(&[0xaa_u8; 32]),
            "hash must stay at the capture"
        );
        assert_eq!(
            view.tip().map(|tip| tip.chainwork),
            Some(ChainWork::from(7_u64)),
            "work must stay at the capture"
        );
        assert_eq!(view.chain_tx_count(), Some(100), "count must stay");

        // A fresh capture sees the newer publication.
        assert_eq!(ctx.chain.applied_view().height(), 20);

        // A present tip whose count is unknown stays unknown: it is never
        // guessed as zero, which would differ from it by an entire chain.
        ctx.chain
            .applied_tip
            .store(Some(tip(30, 0xcc, 11, ChainTxCount::UNKNOWN)));
        let unknown = ctx.chain.applied_view();
        assert_eq!(unknown.height(), 30);
        assert_eq!(unknown.chain_tx_count(), None);
    }

    /// Capturing a view never waits on the transition barrier. This pins the
    /// primitive only; the status readers keep their own barrier until their
    /// separate change.
    #[test]
    fn applied_view_does_not_wait_for_transition() -> anyhow::Result<()> {
        use std::sync::mpsc;
        use std::time::Duration;

        let barrier = bitcoin_rs_chain::TransitionDomain::new().stable_read();
        let ctx = Arc::new(Context::new().with_chain_transition(barrier.clone()));
        ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
            tip_id: bitcoin_rs_chain::NodeId::new(0),
            height: 5,
            chainwork: bitcoin_rs_chain::ChainWork::ZERO,
            hash: bitcoin_rs_primitives::Hash256::default(),
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(1),
        })));

        let transition = barrier.lock();
        let worker = Arc::clone(&ctx);
        let (tx, rx) = mpsc::channel();
        let join = std::thread::spawn(move || {
            let _sent = tx.send(worker.chain.applied_view().height());
        });
        let height = rx
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| anyhow::anyhow!("capture blocked behind the transition barrier"))?;
        assert_eq!(height, 5, "the capture must see the published tip");
        join.join()
            .map_err(|_| anyhow::anyhow!("capture worker panicked"))?;
        drop(transition);
        Ok(())
    }

    /// The embedded call and the RPC handler reach the gateway through the
    /// one shared admission operation. The same accepted transaction commits
    /// on both surfaces, the same policy refusal is reported by both, and
    /// neither surface inserts a refused transaction.
    ///
    /// A log whose heights are non-decreasing but not a clean `0..n`.
    ///
    /// Height 3 is recorded three times, as two reorgs leave it; the log starts
    /// at height 1, as a restored or pruned log may; and heights 6 and 7 are
    /// missing. All three break the "record for height `h` is at index `h`"
    /// assumption the direct-index fast path tries first.
    ///
    /// The starting height is load-bearing. With the log starting at zero, index
    /// 3 holds the *first* record at height 3, so a fast path that skipped the
    /// "is the predecessor lower?" guard would answer correctly anyway. Starting
    /// at one puts a duplicate at index 3 and the run head at index 2, which is
    /// where the two disagree.
    fn shaped_records() -> Vec<BlockRecord> {
        const HEIGHTS: [u32; 8] = [1, 2, 3, 3, 3, 4, 8, 9];
        HEIGHTS
            .into_iter()
            .enumerate()
            .map(|(index, height)| {
                let mut hash = [0_u8; 32];
                // Distinct per record, not per height: the duplicates have to be
                // distinguishable by hash or the walk has nothing to walk.
                hash[0] = u8::try_from(index).unwrap_or(0);
                let mut record =
                    BlockRecord::synthetic(height, BlockHash::from(Hash256::from_le_bytes(&hash)));
                record.time = 1_000 + u32::try_from(index).unwrap_or(0);
                record
            })
            .collect()
    }

    /// Every record at a duplicated height must be reachable by its own hash.
    ///
    /// A search that stopped at the run's first record would answer `None` for
    /// the others, turning `getblock` on a stale branch into "block not found".
    #[test]
    fn every_record_at_a_duplicated_height_is_reachable() {
        let records = shaped_records();
        let duplicates = records
            .iter()
            .filter(|record| record.height == 3)
            .map(|record| (record.hash, record.time))
            .collect::<Vec<_>>();
        assert_eq!(duplicates.len(), 3, "the fixture must duplicate height 3");

        for (hash, time) in duplicates {
            assert_eq!(
                record_at_height_hash(&records, 3, Hash256::from(hash)).map(|r| r.time),
                Some(time),
                "a record at a duplicated height was not reachable by its hash"
            );
        }
    }

    /// `block_by_height` with no applied tip reads the log directly.
    ///
    /// That fallback used to scan for the first record at the height and now
    /// searches for it. It is the path a Context takes before the first tip is
    /// published, and nothing covered it: a mutation replacing it with "the last
    /// record in the log" stayed green.
    #[test]
    fn block_by_height_without_an_applied_tip_reads_the_log() {
        let ctx = Context::new();
        for record in shaped_records() {
            ctx.chain.add_block(record);
        }

        for height in 0_u32..12 {
            let expected = shaped_records()
                .into_iter()
                .find(|candidate| candidate.height == height)
                .map(|record| record.hash);
            assert_eq!(
                ctx.chain.block_by_height(height).map(|record| record.hash),
                expected,
                "block_by_height disagrees with the log at height {height}"
            );
        }
    }

    /// A reorg leaves the losing block in the log beside the winner, so a height
    /// can address two records. The binary search lands anywhere in that run,
    /// which is why the lookup walks it and compares hashes; returning the first
    /// record at the height would hand back the wrong block on exactly the shape
    /// this exists for.
    #[test]
    fn record_at_height_hash_picks_the_matching_hash_within_a_duplicate_height() {
        let first = Hash256::from_le_bytes(&[0x11_u8; 32]);
        let second = Hash256::from_le_bytes(&[0x22_u8; 32]);
        let records = vec![
            BlockRecord::synthetic(0, BlockHash::from(Hash256::from_le_bytes(&[0x00_u8; 32]))),
            BlockRecord::synthetic(1, BlockHash::from(first)),
            BlockRecord::synthetic(1, BlockHash::from(second)),
            BlockRecord::synthetic(2, BlockHash::from(Hash256::from_le_bytes(&[0x33_u8; 32]))),
        ];

        assert_eq!(
            record_at_height_hash(&records, 1, second).map(|record| Hash256::from(record.hash)),
            Some(second),
            "the second record at the height must be reachable, not just the first"
        );
        assert_eq!(
            record_at_height_hash(&records, 1, first).map(|record| Hash256::from(record.hash)),
            Some(first)
        );
        assert!(
            record_at_height_hash(&records, 1, Hash256::from_le_bytes(&[0x99_u8; 32])).is_none(),
            "a hash absent from the height run must not resolve to a sibling"
        );
    }

    /// Heights `[1, 1, 2]` are chosen so the dense fast path indexes straight
    /// onto the *second* of the duplicates: `records[1]` has height 1, so the
    /// height check alone would accept it. Only the guard on the preceding
    /// record rejects it and sends the lookup to the search that finds the run
    /// start. A log starting at height 0 never exercises that, which is how an
    /// earlier version of this test passed while the guard was removed.
    #[test]
    fn record_at_height_returns_the_first_record_of_a_duplicate_height() {
        let first = Hash256::from_le_bytes(&[0x11_u8; 32]);
        let records = vec![
            BlockRecord::synthetic(1, BlockHash::from(first)),
            BlockRecord::synthetic(1, BlockHash::from(Hash256::from_le_bytes(&[0x22_u8; 32]))),
            BlockRecord::synthetic(2, BlockHash::from(Hash256::from_le_bytes(&[0x33_u8; 32]))),
        ];

        assert_eq!(
            record_at_height(&records, 1).map(|record| Hash256::from(record.hash)),
            Some(first),
            "the dense index lands on the second duplicate; the first must win"
        );
        assert!(record_at_height(&records, 7).is_none());
    }

    /// The dense fast path indexes straight into the log. It must not fire when
    /// the log does not start at height zero, or it would answer with whatever
    /// record happens to sit at that index.
    #[test]
    fn record_at_height_does_not_trust_the_index_on_a_sparse_log() {
        let wanted = Hash256::from_le_bytes(&[0x44_u8; 32]);
        let records = vec![
            BlockRecord::synthetic(10, BlockHash::from(Hash256::from_le_bytes(&[0x0a_u8; 32]))),
            BlockRecord::synthetic(11, BlockHash::from(wanted)),
            BlockRecord::synthetic(12, BlockHash::from(Hash256::from_le_bytes(&[0x0c_u8; 32]))),
        ];

        assert_eq!(
            record_at_height(&records, 11).map(|record| Hash256::from(record.hash)),
            Some(wanted),
            "a log that does not start at zero must still resolve by search"
        );
        assert!(record_at_height(&records, 1).is_none());
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn from_handles_shares_chain_handles_with_caller() {
        use alloc::sync::Arc;

        let chain_tip = Arc::new(ArcSwapOption::empty());
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let utxo = Arc::new(bitcoin_rs_utxo::UtxoSet::new());
        let coin_stats = Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        ));
        let block_tree = Arc::new(RwLock::new(bitcoin_rs_chain::BlockTree::new()));
        let progress = bitcoin_rs_chain::ChainProgressReader::new(
            TipReader::new(Arc::clone(&chain_tip)),
            TipReader::new(Arc::clone(&applied_tip)),
            BlockTreeReader::new(Arc::clone(&block_tree)),
            Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
                TipReader::new(Arc::clone(&applied_tip)),
                BlockTreeReader::new(Arc::clone(&block_tree)),
            )),
        );
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig::default(),
            Arc::new(core::sync::atomic::AtomicBool::new(false)),
        ));
        let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
        let ctx = Context::from_handles(ContextHandles {
            chain: ChainHandles {
                chain_tip: TipReader::new(Arc::clone(&chain_tip)),
                applied_tip: TipReader::new(Arc::clone(&applied_tip)),
                progress,
                blocks: Arc::new(RwLock::new(BlockLog::new())),
                utxo: bitcoin_rs_utxo::UtxoReader::new(Arc::clone(&utxo)),
                coin_stats: Arc::clone(&coin_stats),
                block_tree: BlockTreeReader::new(Arc::clone(&block_tree)),
                chain_network: Network::Mainnet,
                chain_transition: chain_transition.clone(),
                ..ChainHandles::default()
            },
            mempool: MempoolHandles {
                gateway: MempoolGateway::shared(
                    Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                    ValidationEngine::Native,
                )
                .unwrap_or_else(|error| panic!("mempool gateway intern: {error}")),
            },
            network: NetworkHandles {
                peer_table: p2p.table(),
                p2p: Arc::clone(&p2p),
                local_services: 0x09,
            },
            ..ContextHandles::default()
        });
        // Identity is not observable: the two roles are distinct types with no
        // comparison. Exclusion is, and exclusion is what the wiring has to
        // guarantee — a guard taken from the context must block the caller's
        // own role, which fails if the context was wired to another domain.
        let held = ctx.chain.chain_transition.lock();
        assert!(
            chain_transition.try_lock().is_none(),
            "the caller's role must exclude the same transitions the context does"
        );
        drop(held);
        // The count travels inside the applied tip: one publication replaces
        // tip and count together, through the cell the caller shares.
        let snapshot = |count| {
            Arc::new(TipSnapshot {
                tip_id: bitcoin_rs_chain::NodeId::new(0),
                height: 7,
                chainwork: bitcoin_rs_chain::ChainWork::ZERO,
                hash: Hash256::from_le_bytes(&[7; 32]),
                chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(count),
            })
        };
        chain_tip.store(Some(snapshot(1)));
        assert_eq!(
            ctx.chain.chain_tip.load_full().map(|tip| tip.height),
            Some(7),
            "chain_tip must be shared with caller"
        );
        applied_tip.store(Some(snapshot(1)));
        assert_eq!(
            ctx.chain.applied_tip.load_full().map(|tip| tip.height),
            Some(7),
            "applied_tip must be shared with caller"
        );
        assert_eq!(ctx.chain.applied_view().chain_tx_count(), Some(1));
        applied_tip.store(Some(snapshot(42)));
        assert_eq!(ctx.chain.applied_view().chain_tx_count(), Some(42));
        let progress = ctx.chain.progress.progress(Network::Mainnet, 0);
        assert_eq!(
            (progress.blocks, progress.headers),
            (7, 7),
            "progress must read the caller's tips"
        );
        assert!(
            Arc::ptr_eq(&ctx.chain.utxo.fixture_set(), &utxo),
            "utxo must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.chain.coin_stats, &coin_stats),
            "coin_stats must be shared with caller"
        );
        {
            let genesis = Network::Regtest.genesis_block();
            let genesis_id = block_tree
                .write()
                .insert_node(
                    None,
                    genesis.header,
                    bitcoin_rs_chain::node::NodeStatus::Active,
                )
                .expect("genesis insert");
            assert!(
                ctx.chain.block_tree.read().node(genesis_id).is_ok(),
                "block_tree must be shared with caller"
            );
        }
        assert!(
            Arc::ptr_eq(&ctx.network.p2p, &p2p),
            "p2p service must be shared with caller"
        );
    }

    /// One retained publication answers a whole status response: after the
    /// publisher advances to a second tip, the view captured at the first still
    /// reports that first tip's height, hash, work, and count together.
    #[test]
    fn status_keeps_the_captured_applied_pair() {
        let ctx = Context::new();
        let tip = |height: u32, byte: u8, work: u64, count| {
            Arc::new(TipSnapshot {
                tip_id: bitcoin_rs_chain::NodeId::new(height),
                height,
                chainwork: bitcoin_rs_chain::ChainWork::from(work),
                hash: Hash256::from_le_bytes(&[byte; 32]),
                chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(count),
            })
        };
        ctx.chain.applied_tip.store(Some(tip(3, 0xaa, 7, 42)));
        let captured = ctx.chain.applied_view();

        // The publisher advances while the response is still being built.
        ctx.chain.applied_tip.store(Some(tip(9, 0xbb, 9, 84)));

        let progress = ctx.chain.sync_progress_at(&captured);
        assert_eq!(progress.blocks, 3, "blocks must stay at the capture");
        assert_eq!(
            progress.best_block_hash,
            Hash256::from_le_bytes(&[0xaa_u8; 32]),
            "the applied hash must stay at the capture"
        );
        assert_eq!(
            progress.chain_work,
            format!("{:064x}", bitcoin_rs_chain::ChainWork::from(7_u64)),
            "chainwork must stay at the capture"
        );
        assert_eq!(
            captured.chain_tx_count(),
            Some(42),
            "the captured count must stay paired with the captured tip"
        );

        // A fresh capture follows the publisher; header height is sampled apart.
        assert_eq!(ctx.chain.sync_progress().blocks, 9);
    }

    #[test]
    fn rest_render_budget_releases_dropped_permits() {
        let ctx = Context::new();
        let first = ctx.try_acquire_rest_render().expect("first permit");
        let second = ctx.try_acquire_rest_render().expect("second permit");
        assert!(ctx.try_acquire_rest_render().is_none());
        drop(first);
        assert!(ctx.try_acquire_rest_render().is_some());
        drop(second);
    }

    #[test]
    fn new_context_wires_utxo_commits_to_coin_stats() {
        use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
        use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};

        let ctx = Context::new();
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[1_u8; 32])), 0);
        let txout = TxOut {
            value: Amount::from_sat(125_000),
            script_pubkey: Script::new(),
        };
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(outpoint, txout, true, 7));

        bitcoin_rs_utxo::contract::commit_block_changes(
            &ctx.chain.utxo.fixture_set(),
            &changes,
            &Hash256::default(),
        )
        .unwrap_or_else(|err| panic!("commit_block failed: {err}"));

        let snapshot = ctx.chain.coin_stats.snapshot();
        assert_eq!(snapshot.utxo_count, 1);
        assert_eq!(snapshot.total_amount, 125_000);
    }

    #[test]
    fn block_record_from_block_is_metadata_only() {
        let block = Network::Regtest.genesis_block();
        let record = BlockRecord::from_block(0, &block);

        assert_eq!(record.hash, block.block_hash());
        assert_eq!(record.height, 0);
        assert_eq!(record.body_size, consensus_bytes(&block).len());
        assert_eq!(record.header, None);
        assert_eq!(record.tx_count, block.txs.len());
        assert_eq!(record.time, block.header.time);
    }

    #[test]
    fn context_reads_metadata_only_block_record_from_body_source() {
        struct SingleBlockSource {
            height: u32,
            hash: BlockHash,
            body: Vec<u8>,
        }

        impl BlockBodySource for SingleBlockSource {
            fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
                (height == self.height && hash == self.hash).then(|| self.body.clone())
            }
        }

        let block = Network::Regtest.genesis_block();
        let body = consensus_bytes(&block);
        let record = BlockRecord::from_block(0, &block);
        let source = Arc::new(SingleBlockSource {
            height: 0,
            hash: record.hash,
            body: body.clone(),
        });
        let ctx = Context::from_handles(ContextHandles {
            chain: ChainHandles {
                block_body_source: Some(source),
                ..ChainHandles::default()
            },
            ..ContextHandles::default()
        });
        ctx.chain.add_block(record.clone());

        assert_eq!(record.body_size, consensus_bytes(&block).len());
        assert_eq!(
            ctx.chain.block_body_bytes(&record).as_deref(),
            Some(body.as_slice())
        );
        let expected_hex = body.to_lower_hex_string();
        assert_eq!(
            ctx.chain.block_body_hex(&record).as_deref(),
            Some(expected_hex.as_str())
        );
    }

    /// The hex a caller sees must be byte-identical to what the stored `String`
    /// used to hold; only where it is produced changed.
    ///
    /// Read through a resolved record now, because that is where a header comes
    /// from: the tree, via `record_for_hash`. A record built straight from a
    /// block has none.
    #[test]
    fn header_hex_is_unchanged_by_sourcing_the_header_from_the_tree() {
        let block = Network::Regtest.genesis_block();
        let ctx = Arc::new(Context::new());
        {
            let mut tree = ctx.chain.block_tree.write();
            let _ = tree.insert_node(None, block.header, bitcoin_rs_chain::NodeStatus::Active);
        }
        let hash = Hash256::from(block.block_hash());
        let Some(record) = ctx.chain.record_for_hash(hash) else {
            panic!("the tree knows this hash");
        };

        assert_eq!(
            record.header_hex(),
            consensus_bytes(&block.header).to_lower_hex_string()
        );
        assert_eq!(record.header_hex().len(), SERIALIZED_BLOCK_HEADER_LEN * 2);
    }

    /// The tree's header must reach a caller even when the log has the block.
    ///
    /// `record_for_hash` returns the cached record for its payload facts — size,
    /// transaction count — and that record has no header. Returning
    /// it unchanged would answer with none, which is what an earlier revision of
    /// this change did until this test caught it.
    #[test]
    fn record_for_hash_answers_with_the_tree_header_for_a_cached_record() {
        let block = Network::Regtest.genesis_block();
        let ctx = Arc::new(Context::new());
        {
            let mut tree = ctx.chain.block_tree.write();
            let _ = tree.insert_node(None, block.header, bitcoin_rs_chain::NodeStatus::Active);
        }
        let cached = BlockRecord::from_block(0, &block);
        let hash = Hash256::from(cached.hash);
        let expected_body_size = cached.body_size;
        let expected_tx_count = cached.tx_count;
        assert!(cached.header_bytes().is_none(), "the log stores no header");
        ctx.chain.add_block(cached);

        let Some(record) = ctx.chain.record_for_hash(hash) else {
            panic!("the tree knows this hash");
        };
        assert_eq!(
            record.header_bytes().map(<[u8; 80]>::as_slice),
            Some(consensus_bytes(&block.header).as_slice()),
            "the resolved record must carry the tree's header"
        );
        assert_eq!(
            record.body_size, expected_body_size,
            "the cached body size must survive the header splice"
        );
        assert_eq!(
            record.tx_count, expected_tx_count,
            "the cached transaction count must survive the header splice"
        );
    }
    /// A log-only hash must not make a block identity visible.
    ///
    /// The old tree-miss fallback scanned every log record and accepted the
    /// matching hash, making unknown-hash RPC cost linear in chain length and
    /// allowing fixture-only state to masquerade as a real node identity.
    #[test]
    fn block_by_hash_ignores_log_records_the_tree_does_not_know() {
        let ctx = Context::new();
        let hash = Hash256::from_le_bytes(&[3_u8; 32]);
        ctx.chain
            .add_block(BlockRecord::synthetic(3, BlockHash::from(hash)));

        assert!(ctx.chain.record_for_hash(hash).is_none());
        assert!(ctx.chain.block_by_hash(hash).is_none());
    }

    /// A record with no header must render as the empty string, the way an empty
    /// `String` field did, so callers that inspected it for emptiness still see
    /// what they saw.
    #[test]
    fn synthetic_record_has_no_header_and_renders_empty_hex() {
        let record =
            BlockRecord::synthetic(7, BlockHash::from(Hash256::from_le_bytes(&[3_u8; 32])));

        assert!(record.header_bytes().is_none());
        assert_eq!(record.header_hex(), "");
    }

    /// Covers the record the block tree derives, which had no test at all.
    ///
    /// `header_record` builds its header with `try_into().ok()`, so a length that
    /// does not fit yields `None` and the header vanishes silently — where the
    /// old `String` field would at least have carried something. A mutation that
    /// dropped the header from this path failed no test before this one existed.
    #[test]
    fn tree_derived_record_carries_the_header() {
        use bitcoin_rs_chain::NodeStatus;
        use bitcoin_rs_primitives::Header;

        let ctx = Context::new();
        let header = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 7,
        };
        let hash = {
            let mut tree = ctx.chain.block_tree.write();
            let id = tree
                .insert_node(None, header, NodeStatus::Active)
                .expect("genesis inserts");
            tree.node(id).expect("inserted node").hash
        };

        // Nothing was pushed into `blocks`, so the record can only come from the
        // tree.
        let record = ctx
            .chain
            .record_for_hash(hash)
            .expect("tree resolves the hash");

        assert_eq!(
            record.header_bytes().map(|bytes| &bytes[..]),
            Some(consensus_bytes(&header).as_slice()),
            "the tree-derived record must carry the header the tree holds"
        );
        assert_eq!(
            record.header_hex(),
            consensus_bytes(&header).to_lower_hex_string()
        );
    }

    #[test]
    fn height_for_hash_returns_none_when_tree_empty() {
        let ctx = Context::new();
        let unknown = bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xff_u8; 32]);

        assert!(ctx.chain.height_for_hash(unknown).is_none());
    }
    #[test]
    fn block_by_height_prefers_tree_identity_over_stale_cache()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_chain::NodeStatus;
        use bitcoin_rs_primitives::Header;

        let ctx = Context::new();
        let (child_hash, stale_hash) = {
            let mut tree = ctx.chain.block_tree.write();
            let genesis = Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let mut child = Header {
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: 1_000_900,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            child.nonce = 1;
            let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::Active)?;
            let child_hash = tree.node(child_id)?.hash;
            let applied_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing child tip"))?;
            ctx.chain
                .applied_tip
                .store(Some(Arc::new((*applied_tip).clone())));
            // Stale cache entry at the SAME height as the tree child but with a
            // different hash. The active-tree identity must win over this cache.
            let stale_hash = Hash256::from_le_bytes(&[0xa5_u8; 32]);
            ctx.chain
                .add_block(BlockRecord::synthetic(1, BlockHash::from(stale_hash)));
            (child_hash, stale_hash)
        };

        assert_ne!(child_hash, stale_hash, "test fixture hashes must differ");
        let found = ctx
            .chain
            .block_by_height(1)
            .ok_or_else(|| std::io::Error::other("tree child missing at height 1"))?;
        assert_eq!(
            found.hash,
            BlockHash::from(child_hash),
            "active-tree identity must win over a stale cached hash"
        );
        assert_eq!(found.height, 1);
        Ok(())
    }

    #[test]
    fn height_lookups_follow_applied_tip_when_header_fork_leads()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_chain::NodeStatus;
        use bitcoin_rs_primitives::Header;

        let ctx = Context::new();
        let (applied_tip, header_tip) = {
            let mut tree = ctx.chain.block_tree.write();
            let genesis = Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let applied = Header {
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: 1_000_900,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
            };
            let applied_id = tree.insert_node(Some(genesis_id), applied, NodeStatus::Active)?;
            let applied_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
            assert_eq!(applied_tip.tip_id, applied_id);

            let fork = Header {
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: 1_000_901,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 2,
            };
            let fork_id = tree.insert_node(Some(genesis_id), fork, NodeStatus::HeaderValid)?;
            let fork_tip = Header {
                version: 1,
                prev_blockhash: fork.compute_hash(),
                merkle_root: Hash256::default(),
                time: 1_001_800,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 3,
            };
            let header_tip_id =
                tree.insert_node(Some(fork_id), fork_tip, NodeStatus::HeaderValid)?;
            let header_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing header tip"))?;
            assert_eq!(header_tip.tip_id, header_tip_id);
            (applied_tip, header_tip)
        };

        ctx.chain
            .applied_tip
            .store(Some(Arc::new((*applied_tip).clone())));
        ctx.chain
            .chain_tip
            .store(Some(Arc::new((*header_tip).clone())));
        ctx.chain
            .add_block(BlockRecord::synthetic(2, BlockHash::from(header_tip.hash)));

        assert_eq!(
            ctx.chain.active_hash_at_height(1),
            Some(applied_tip.hash),
            "height lookup must stay on the applied branch"
        );
        assert_eq!(ctx.chain.block_hash_at_height(1), Some(applied_tip.hash));
        assert_eq!(
            ctx.chain
                .block_by_height(1)
                .map(|record| Hash256::from(record.hash)),
            Some(applied_tip.hash)
        );
        assert!(ctx.chain.block_hash_at_height(2).is_none());
        assert!(ctx.chain.block_by_height(2).is_none());
        Ok(())
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn ibd_latch_judges_the_contexts_own_tree() {
        use alloc::sync::Arc;

        fn insert_recent_tip(ctx: &Context, now: u64) -> TipSnapshot {
            let genesis = Network::Regtest.genesis_block();
            let mut tree = ctx.chain.block_tree.write();
            let genesis_id = tree
                .insert_node(
                    None,
                    genesis.header,
                    bitcoin_rs_chain::node::NodeStatus::Active,
                )
                .expect("genesis insert");
            let mut child = genesis.header;
            child.prev_blockhash = genesis.block_hash();
            child.time = u32::try_from(now - 60).unwrap_or(u32::MAX);
            child.nonce = 1;
            let child_id = tree
                .insert_node(
                    Some(genesis_id),
                    child,
                    bitcoin_rs_chain::node::NodeStatus::Active,
                )
                .expect("child insert");
            let node = tree.node(child_id).expect("inserted node");
            TipSnapshot {
                tip_id: child_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            }
        }

        let chain_tip = TipReader::new(Arc::new(ArcSwapOption::empty()));
        let applied_tip = Arc::new(ArcSwapOption::empty());

        let block_tree = Arc::new(RwLock::new(bitcoin_rs_chain::BlockTree::new()));
        let status: Arc<dyn bitcoin_rs_index::DerivedIndexCapabilitySource> = Arc::new(ReadySource);
        let ctx = Context::from_handles(ContextHandles {
            chain: ChainHandles {
                chain_tip: chain_tip.clone(),
                applied_tip: TipReader::new(Arc::clone(&applied_tip)),
                chain_transition: bitcoin_rs_chain::TransitionDomain::new().stable_read(),
                progress: bitcoin_rs_chain::ChainProgressReader::new(
                    chain_tip,
                    TipReader::new(Arc::clone(&applied_tip)),
                    BlockTreeReader::new(Arc::clone(&block_tree)),
                    Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
                        TipReader::new(Arc::clone(&applied_tip)),
                        BlockTreeReader::new(Arc::clone(&block_tree)),
                    )),
                ),
                blocks: Arc::new(RwLock::new(BlockLog::new())),
                utxo: bitcoin_rs_utxo::UtxoReader::new(Arc::new(bitcoin_rs_utxo::UtxoSet::new())),
                coin_stats: Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
                    bitcoin_rs_utxo::stats::CoinStats::default(),
                )),
                prune_service: None,
                chain_control: None,
                block_tree: BlockTreeReader::new(Arc::clone(&block_tree)),
                chain_network: Network::Mainnet,
                block_body_source: None,
                closed_for_recovery: LatchReader::new(Arc::new(
                    core::sync::atomic::AtomicBool::new(false),
                )),
                rollback_warnings: None,
            },
            mempool: MempoolHandles {
                gateway: MempoolGateway::shared(
                    Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                    ValidationEngine::Native,
                )
                .unwrap_or_else(|error| panic!("mempool gateway intern: {error}")),
            },
            indexes: IndexHandles {
                derived_index: None,
                esplora_tx_index: None,
                script_index: None,
                derived_index_status: Some(Arc::clone(&status)),
            },
            network: NetworkHandles::default(),
            mining: MiningHandles {
                mining_control: None,
            },
            ..ContextHandles::default()
        });

        // With the regtest work floor at zero and the tip recent, only the
        // tree lookup can make `is_active` answer false; a latch holding any
        // other tree finds no node and keeps reporting true.
        let now = 1_800_000_000_u64;
        let tip = insert_recent_tip(&ctx, now);
        ctx.chain.applied_tip.store(Some(Arc::new(tip)));
        assert!(
            !ctx.chain
                .progress
                .initial_block_download(now, Network::Regtest),
            "the latch must judge the tip it reaches through the context's tree"
        );
        assert!(
            Arc::ptr_eq(
                ctx.indexes
                    .derived_index_status
                    .as_ref()
                    .expect("index status keeps its own slot"),
                &status
            ),
            "the txindex status source must be shared with caller"
        );
    }
}

#[cfg(test)]
mod admission_chain_tests {
    use anyhow::Context as _;
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::{Header, LockTime, Sequence, TxIn, TxOut, Witness};
    use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn spendable_script() -> Vec<u8> {
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&Sha256::digest([0x51]));
        script
    }

    fn spending(outpoint: OutPoint) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::from_bytes(spendable_script()),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn publish_tip(ctx: &Context, time: u32) -> anyhow::Result<()> {
        let mut tree = ctx.chain.block_tree.write();
        let parent = ctx.chain.applied_tip.load_full().map(|tip| tip.tip_id);
        let previous_hash = match parent {
            Some(id) => BlockHash::from(tree.node(id)?.hash),
            None => BlockHash::default(),
        };
        let id = tree
            .insert_node(
                parent,
                Header {
                    version: 1,
                    prev_blockhash: previous_hash,
                    merkle_root: Hash256::default(),
                    time,
                    bits: CompactTarget::from_consensus(0x207f_ffff),
                    nonce: time,
                },
                NodeStatus::Active,
            )
            .context("insert tip node")?;
        let node = tree.node(id)?;
        ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        })));
        Ok(())
    }

    #[test]
    fn stable_chainstate_reader_does_not_block_transaction_admission() -> anyhow::Result<()> {
        use sonic_rs::{JsonValueTrait as _, json};

        let ctx = Arc::new(Context::new());
        let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[8; 32])), 0);
        let tx = spending(outpoint);
        let txid = tx.txid();
        let raw = consensus_bytes(&tx).to_lower_hex_string();
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            outpoint,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(spendable_script()),
            },
            false,
            0,
        ));
        bitcoin_rs_utxo::contract::commit_block_changes(
            &ctx.chain.utxo.fixture_set(),
            &changes,
            &Hash256::default(),
        )?;

        // Stable whole-chain readers hold this mutex without changing the
        // generation. Admission must succeed through its real RPC path while
        // such a reader is active, rather than spending its retry budget on
        // contention that says nothing about stale chain facts.
        let accepted = ctx.chain.with_stable_chainstate(|| {
            crate::handlers::tx::sendrawtransaction(&ctx, &json!([raw]))
        })?;
        assert_eq!(accepted.as_str(), Some(txid.to_string()).as_deref());
        assert!(ctx.mempool.gateway.read().contains_txid(&txid));
        Ok(())
    }

    #[test]
    fn unconfirmed_transaction_is_admitted_from_a_peer() -> anyhow::Result<()> {
        use bitcoin_rs_mempool::{AdmissionOrigin, PeerToken, SubmitOutcome};
        let ctx = Context::new();
        let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[9; 32])), 0);
        let tx = spending(outpoint);
        let txid = tx.txid();
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            outpoint,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(spendable_script()),
            },
            false,
            0,
        ));
        bitcoin_rs_utxo::contract::commit_block_changes(
            &ctx.chain.utxo.fixture_set(),
            &changes,
            &Hash256::default(),
        )?;
        assert!(
            !ctx.chain
                .admission_chain()
                .snapshot(&tx)
                .context("snapshot")?
                .confirmed
        );
        let result = ctx.mempool.gateway.submit_transaction(
            Arc::new(tx),
            AdmissionOrigin::Peer(PeerToken {
                addr: std::net::SocketAddr::from(([127, 0, 0, 1], 18444)),
                connection_id: 1,
            }),
            None,
            0,
            &ctx.chain.admission_chain(),
        )?;
        assert!(matches!(result, SubmitOutcome::Committed(_)));
        assert!(ctx.mempool.gateway.read().contains_txid(&txid));
        Ok(())
    }

    #[test]
    fn confirmed_hint_requires_live_chain_outputs() -> anyhow::Result<()> {
        let ctx = Context::new();
        let tx = spending(OutPoint::new(
            Txid::from(Hash256::from_le_bytes(&[10; 32])),
            0,
        ));
        let output = OutPoint::new(tx.txid(), 0);
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(output, tx.outputs[0].clone(), false, 0));
        bitcoin_rs_utxo::contract::commit_block_changes(
            &ctx.chain.utxo.fixture_set(),
            &changes,
            &Hash256::default(),
        )?;
        assert!(
            ctx.chain
                .admission_chain()
                .snapshot(&tx)
                .context("snapshot")?
                .confirmed
        );
        Ok(())
    }

    #[test]
    fn admission_chain_uses_current_handles_and_one_applied_tip() -> anyhow::Result<()> {
        let mut ctx = Context::new();
        let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[7; 32])), 0);
        let tx = spending(outpoint);
        assert_eq!(
            ctx.chain
                .admission_chain()
                .snapshot(&tx)
                .context("empty snapshot")?
                .prevouts,
            []
        );

        // A borrowed capability observes current handles even in isolated
        // contexts that replace test state after construction.
        ctx.chain.utxo =
            bitcoin_rs_utxo::UtxoReader::new(Arc::new(bitcoin_rs_utxo::UtxoSet::new()));
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            outpoint,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
            false,
            0,
        ));
        bitcoin_rs_utxo::contract::commit_block_changes(
            &ctx.chain.utxo.fixture_set(),
            &changes,
            &Hash256::default(),
        )
        .context("fund input")?;
        publish_tip(&ctx, 100)?;
        publish_tip(&ctx, 200)?;
        let snapshot = ctx
            .chain
            .admission_chain()
            .snapshot(&tx)
            .context("snapshot")?;
        assert_eq!(snapshot.height, 1);
        assert_eq!(snapshot.locktime_cutoff, 200);
        assert_eq!(snapshot.prevouts.len(), 1);
        assert_eq!(snapshot.prevouts[0].0, outpoint);
        assert_eq!(snapshot.prevouts[0].1.value, 10_000);
        assert!(
            !snapshot.confirmed,
            "an input UTXO is not evidence that the spending transaction is confirmed"
        );
        Ok(())
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn admission_envelopes_share_gateway_outcomes() -> anyhow::Result<()> {
        use sonic_rs::{JsonValueTrait as _, Value, json};

        use crate::error::RpcError;
        use crate::handlers::tx;

        let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[21; 32])), 0);
        let spend = spending(outpoint);
        let raw = consensus_bytes(&spend).to_lower_hex_string();
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            outpoint,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(spendable_script()),
            },
            false,
            0,
        ));

        // Accepted: the handler commits the funded transaction through the
        // gateway.
        let rpc_ctx = Arc::new(Context::new());
        bitcoin_rs_utxo::contract::commit_block_changes(
            &rpc_ctx.chain.utxo.fixture_set(),
            &changes,
            &Hash256::default(),
        )?;
        let accepted = tx::sendrawtransaction(&rpc_ctx, &json!([raw]))?;
        assert_eq!(accepted.as_str(), Some(spend.txid().to_string()).as_deref());
        assert!(rpc_ctx.mempool.gateway.read().contains_txid(&spend.txid()));

        // Refused: an unknown prevout is refused and not inserted.
        let orphan = spending(OutPoint::new(
            Txid::from(Hash256::from_le_bytes(&[22; 32])),
            0,
        ));
        let orphan_raw = consensus_bytes(&orphan).to_lower_hex_string();
        let refused = tx::sendrawtransaction(&rpc_ctx, &json!([orphan_raw]))
            .expect_err("an unknown prevout must be refused");
        assert_eq!(refused.code(), RpcError::CORE_VERIFY_ERROR);
        assert!(!rpc_ctx.mempool.gateway.read().contains_txid(&orphan.txid()));

        // Preview: testmempoolaccept answers for the funded transaction
        // without inserting it.
        let preview_ctx = Arc::new(Context::new());
        bitcoin_rs_utxo::contract::commit_block_changes(
            &preview_ctx.chain.utxo.fixture_set(),
            &changes,
            &Hash256::default(),
        )?;
        let rows = tx::testmempoolaccept(&preview_ctx, &json!([[raw]]))?;
        assert_eq!(
            rows.get(0)
                .and_then(|row| row.get("allowed"))
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(
            !preview_ctx
                .mempool
                .gateway
                .read()
                .contains_txid(&spend.txid()),
            "the accepted preview must not insert"
        );
        Ok(())
    }
}
