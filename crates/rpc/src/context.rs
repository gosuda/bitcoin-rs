use alloc::sync::Arc;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockBodySource, TipSnapshot, softfork_state};
use bitcoin_rs_mempool::{
    AdmissionChain, ChainAdmissionSnapshot, Mempool, MempoolGateway, MempoolLimits,
    MempoolObserver, MutationResult, PrevoutMeta,
};
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_primitives::{
    BlockHash, CompactTarget, Hash256, Network, OutPoint, Tx, Txid, consensus_bytes,
};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, Script};
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use std::path::PathBuf;
use std::time::Instant;

use crate::compat::convert::hex_encode;

#[cfg(test)]
const SERIALIZED_BLOCK_HEADER_LEN: usize = 80;

/// Core `sendrawtransaction` default `maxfeerate`: 0.1 BTC/kvB in sat/kvB.
///
/// The node applies the identical cap to every admission surface, including
/// the embedded [`bitcoin_rs_node::Node::broadcast`], via
/// [`Context::admit_transaction`].
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

/// Network counters and peer metadata exposed by network RPCs.
#[derive(Clone, Debug, Default)]
pub struct NetworkState {
    /// Number of connected peers.
    pub connection_count: u64,
    /// Total bytes received since startup.
    pub bytes_recv: u64,
    /// Total bytes sent since startup.
    pub bytes_sent: u64,
    /// Unix timestamp for the counters.
    pub timestamp: u64,
}

/// Typed synchronization progress behind `getblockchaininfo`.
#[derive(Clone, Debug, PartialEq)]
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
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneStatus {
    /// Whether block pruning is enabled for this node.
    pub pruned: bool,
    /// Highest manual prune height completed by the backing service.
    pub pruneheight: Option<u32>,
}

/// Summary of one completed manual prune request.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneResult {
    /// Height requested by the RPC caller.
    pub requested_height: u32,
    /// Highest prune height now recorded by the service.
    pub pruneheight: u32,
    /// Serialized block-body rows removed from storage.
    pub block_rows_removed: u64,
    /// Serialized undo rows removed from storage.
    pub undo_rows_removed: u64,
    /// Payload bytes removed from storage.
    pub bytes_freed: u64,
}

/// Error returned by the node-owned pruning implementation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
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
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
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

/// Handles owned by the node and observed by the RPC context, grouped by
/// node capability: chain, mempool, indexes, network, and mining.
///
/// A struct-of-structs grouping, not a trait layer. `Context::from_handles`
/// consumes one `ContextHandles` value and moves each group into the context
/// unchanged — RPC consumes node capabilities and never names a storage
/// backend or backend engine type.
#[derive(Clone)]
pub struct ContextHandles {
    /// Chain capability: tips, block log, UTXO set, and block tree.
    pub chain: ChainHandles,
    /// Mempool capability: the in-memory transaction pool.
    pub mempool: MempoolHandles,
    /// Index capability: transaction and script index query adapters.
    pub indexes: IndexHandles,
    /// Network capability: peer registry, reachability, and connection control.
    pub network: NetworkHandles,
    /// Mining capability: the template coordinator, when one is attached.
    pub mining: MiningHandles,
}

/// Chain capability handles.
///
/// The group owns the node's applied-chain authorities: the two published
/// tips, the transition barrier that brackets them, the shared
/// initial-block-download latch, and the readable stores behind them.
#[derive(Clone)]
pub struct ChainHandles {
    /// Best header-chain tip.
    pub chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Best fully-applied block tip.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Serializes whole-chainstate RPC reads with node-owned connect/disconnect transitions.
    chain_transition: Arc<Mutex<()>>,
    /// Process-wide initial-block-download latch over the applied chain,
    /// shared with P2P so both surfaces answer identically.
    pub ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
    /// Applied block metadata log.
    pub blocks: Arc<RwLock<BlockLog>>,
    /// Transactions retained for direct RPC lookup.
    pub transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    /// Authoritative UTXO set.
    pub utxo: Arc<bitcoin_rs_utxo::UtxoSet>,
    /// Incremental UTXO statistics.
    pub coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    /// Optional storage pruning mutator.
    pub prune_service: Option<Arc<dyn PruneService>>,
    /// Optional node-owned chain mutation service.
    pub chain_control: Option<Arc<dyn ChainControl>>,
    /// Consensus network.
    pub chain_network: Network,
    /// Shared block tree.
    pub block_tree: Arc<parking_lot::RwLock<bitcoin_rs_chain::BlockTree>>,
    /// Optional durable block body reader for metadata-only block records.
    pub block_body_source: Option<Arc<dyn BlockBodySource>>,
    /// Rollback-evidence warning source for `getblockchaininfo`.
    ///
    /// `None` in test contexts; populated by `NodeState` with the process-wide
    /// `WarningStore`. Each request loads one immutable snapshot.
    pub rollback_warnings: Option<Arc<dyn RollbackWarningSource>>,
}

impl ChainHandles {
    /// Builds the chain capability group over handles owned elsewhere.
    ///
    /// PRE: the supplied handles belong to the same node; `ibd` is that node's
    ///   shared initial-block-download decision.
    /// POST: the group owns these exact handles, the optional adapters are
    ///   `None`, and the unattached transition barrier is the empty-context
    ///   default.
    /// INVARIANT: construction copies no subsystem state and creates no second
    ///   initial-block-download latch or transaction-count authority.
    #[must_use]
    pub fn new(
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
        utxo: Arc<bitcoin_rs_utxo::UtxoSet>,
        coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
        block_tree: Arc<parking_lot::RwLock<bitcoin_rs_chain::BlockTree>>,
        chain_network: Network,
        ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
    ) -> Self {
        Self {
            chain_tip,
            applied_tip,
            chain_transition: Arc::new(Mutex::new(())),
            ibd,
            blocks,
            transactions,
            utxo,
            coin_stats,
            prune_service: None,
            chain_control: None,
            chain_network,
            block_tree,
            block_body_source: None,
            rollback_warnings: None,
        }
    }
}

/// Borrowed provisional chain facts used by both RPC and P2P admission.
///
/// The view contains no gateway or full node/context reference. Height and MTP
/// use one applied tip; coins are read without taking the chain-transition
/// mutex. The chain owner brackets authoritative mutations with the gateway's
/// generation fence, and gateway generation/sequence revalidation discards any
/// facts collected across such a mutation before they can affect admission.
pub struct ChainAdmissionView<'a> {
    utxo: &'a bitcoin_rs_utxo::UtxoSet,
    applied_tip: &'a ArcSwapOption<TipSnapshot>,
    block_tree: &'a RwLock<bitcoin_rs_chain::BlockTree>,
    network: Network,
}

impl<'a> ChainAdmissionView<'a> {
    /// Borrows the chain owner's existing handles without retaining state.
    #[must_use]
    pub const fn new(
        utxo: &'a bitcoin_rs_utxo::UtxoSet,
        applied_tip: &'a ArcSwapOption<TipSnapshot>,
        block_tree: &'a RwLock<bitcoin_rs_chain::BlockTree>,
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

impl AdmissionChain for ChainAdmissionView<'_> {
    fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
        let tip = self.applied_tip.load_full();
        let height = tip.as_ref().map_or(0, |tip| tip.height);
        let tree = self.block_tree.read();
        let tip_node = tip.as_ref().and_then(|tip| tree.lookup(tip.hash));
        let locktime_cutoff = tip_node
            .and_then(|node| tree.median_time_past_at(node, 11))
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
                    .and_then(|prior| tree.median_time_past_at(prior, 11))
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
#[derive(Clone)]
pub struct MempoolHandles {
    /// The process-wide mutation gateway in front of the in-memory pool.
    pub mempool: Arc<MempoolGateway>,
}

/// Index capability handles.
#[derive(Clone, Default)]
pub struct IndexHandles {
    /// Complete transaction-index query adapter.
    ///
    /// `None` when transaction indexing is disabled.
    pub derived_index: Option<Arc<dyn DerivedIndexQuery>>,
    /// Complete transaction lookup used internally by Esplora projections.
    ///
    /// This may be available with `--scriptindex` even when `derived_index` is
    /// absent, because it does not advertise the Core `--txindex` contract.
    pub esplora_tx_index: Option<Arc<dyn DerivedIndexQuery>>,
    /// Generic script-index query adapter.
    pub script_index: Option<Arc<dyn ScriptIndexQuery>>,
    /// Live txindex status for the `getcapabilities` projection.
    pub derived_index_status: Option<Arc<dyn crate::capabilities::DerivedIndexCapabilitySource>>,
}

/// Network capability handles.
#[derive(Clone)]
pub struct NetworkHandles {
    /// Network state.
    pub network: Arc<RwLock<NetworkState>>,
    /// Whether the node accepts or starts P2P connections.
    pub network_active: Arc<core::sync::atomic::AtomicBool>,
    /// Authoritative live peer sessions.
    pub peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    /// Channel that requests outbound P2P connections, tagged with the
    /// origin that asked for each one.
    pub p2p_outbound_sender: Option<crossbeam_channel::Sender<bitcoin_rs_p2p::OutboundDial>>,
    /// Manual IP/CIDR bans.
    pub banned: Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
    /// Persisted `addnode add` entries.
    pub added_nodes: Arc<parking_lot::RwLock<Vec<std::net::SocketAddr>>>,
}

/// Mining capability handles.
#[derive(Clone)]
pub struct MiningHandles {
    /// Node-owned mining coordinator. `None` when mining is not wired.
    pub mining_control: Option<Arc<dyn MiningControl>>,
}

/// Shared state consumed by JSON-RPC handlers.
///
/// The context holds one capability group per node subsystem plus the fields
/// that belong to no subsystem. It stores no subsystem state of its own: a new
/// capability extends its own group instead of widening this declaration.
pub struct Context {
    /// Chain capabilities: published tips, block log, UTXO set, block tree,
    /// and the shared initial-block-download latch.
    pub chain: ChainHandles,
    /// Mempool mutation gateway: the only production route that takes the
    /// pool write lock, publishing ordered mutation events to observers.
    pub mempool: Arc<MempoolGateway>,
    /// Index capabilities: transaction and script index query adapters.
    pub indexes: IndexHandles,
    /// Network capabilities: peer sessions, counters, and connection control.
    pub network: NetworkHandles,
    /// Optional node-owned mining coordinator.
    pub mining_control: Option<Arc<dyn MiningControl>>,

    /// Instant this context's RPC listener bound, set by `RpcServer::bind`
    /// and read by `uptime`. Kept per context rather than process-global so
    /// two servers in one process report their own epochs; `None` (never
    /// bound, e.g. unit tests) makes `uptime` measure from its first call.
    server_bound_at: Mutex<Option<Instant>>,
    /// Live ZMQ publisher, also the source of active notifier metadata.
    pub zmq_publisher: Arc<dyn crate::zmq::ZmqPublisher>,
    /// Configured node debug-log path for `getrpcinfo`.
    pub debug_log_path: Option<PathBuf>,
    /// Limits concurrent full-block REST response materializations.
    rest_render_budget: Arc<RestRenderBudget>,
}
// SAFETY: `Context` is shared by RPC worker threads. Each mutable subsystem
// handle behind it uses atomics, channels, or locks for interior mutation.
// `UtxoSet` is likewise internally sharded behind locks; RPC currently only
// calls read-only aggregate counters through this handle.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for Context {}

// SAFETY: See the `Send` impl above. Shared access to all contained mutable
// state is mediated by thread-safe primitives or UTXO shard locks.
unsafe impl Sync for Context {}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context").finish_non_exhaustive()
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    /// Builds an empty context suitable for tests and early startup.
    #[must_use]
    pub fn new() -> Self {
        Self::build_fixture(None)
    }

    /// Builds an empty context whose mempool gateway carries `observer`.
    ///
    /// Like [`Self::new`] but the gateway is constructed with the supplied
    /// observer instead of `None`. Test-only: production wiring constructs
    /// the gateway through `NodeState::open`.
    #[must_use]
    pub fn new_with_mempool_observer(observer: Arc<dyn MempoolObserver>) -> Self {
        Self::build_fixture(Some(observer))
    }

    /// Assembles one internally consistent fixture set.
    ///
    /// PRE: `observer` is this fixture's mempool observer, or `None`.
    /// POST: every capability group owns fresh, unattached handles on
    ///   `Network::Mainnet`, and the mempool gateway carries `observer`.
    /// INVARIANT: the shared initial-block-download latch reads the same
    ///   applied-tip cell and block tree the chain group owns, so publishing a
    ///   tip through the group moves both readers.
    #[allow(clippy::arc_with_non_send_sync)]
    fn build_fixture(observer: Option<Arc<dyn MempoolObserver>>) -> Self {
        let coin_stats_listener = bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        );
        let mut utxo = bitcoin_rs_utxo::UtxoSet::new();
        utxo.set_listener(Box::new(coin_stats_listener.clone()));
        let coin_stats = Arc::new(coin_stats_listener);
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let mempool = match observer {
            Some(observer) => MempoolGateway::shared_with(pool, observer),
            None => MempoolGateway::shared(pool),
        };
        let chain_tip = Arc::new(ArcSwapOption::empty());
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let blocks = Arc::new(RwLock::new(BlockLog::new()));
        let transactions = Arc::new(RwLock::new(HashMap::new()));
        let block_tree = Arc::new(parking_lot::RwLock::new(bitcoin_rs_chain::BlockTree::new()));
        let ibd = Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
            Network::Mainnet,
        ));
        let chain = ChainHandles::new(
            chain_tip,
            applied_tip,
            blocks,
            transactions,
            Arc::new(utxo),
            coin_stats,
            block_tree,
            Network::Mainnet,
            ibd,
        );
        Self {
            chain,
            mempool,
            indexes: IndexHandles::default(),
            network: NetworkHandles {
                network: Arc::new(RwLock::new(NetworkState::default())),
                network_active: Arc::new(core::sync::atomic::AtomicBool::new(true)),
                peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
                p2p_outbound_sender: None,
                banned: Arc::new(RwLock::new(Vec::new())),
                added_nodes: Arc::new(RwLock::new(Vec::new())),
            },
            mining_control: None,
            server_bound_at: Mutex::new(None),
            zmq_publisher: Arc::new(crate::zmq::NoOpZmqPublisher),
            debug_log_path: None,
            rest_render_budget: Arc::new(RestRenderBudget::new()),
        }
    }

    /// Builds a context that shares pre-existing handles owned elsewhere.
    ///
    /// PRE: `handles` groups the node's live capability objects.
    /// POST: the context owns those exact groups and unwraps the two
    ///   single-handle input groups; the RPC-local fields are fresh.
    /// INVARIANT: no group is flattened or rebuilt, so a publication through
    ///   the node's own handle is visible to every RPC worker.
    #[must_use]
    pub fn from_handles(handles: ContextHandles) -> Self {
        let ContextHandles {
            chain,
            mempool: MempoolHandles { mempool },
            indexes,
            network,
            mining: MiningHandles { mining_control },
        } = handles;
        Self {
            chain,
            mempool,
            indexes,
            network,
            mining_control,
            server_bound_at: Mutex::new(None),
            zmq_publisher: Arc::new(crate::zmq::NoOpZmqPublisher),
            debug_log_path: None,
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

    /// Attaches the rollback-evidence warning source for `getblockchaininfo`.
    #[must_use]
    pub fn with_rollback_warnings(mut self, source: Arc<dyn RollbackWarningSource>) -> Self {
        self.chain.rollback_warnings = Some(source);
        self
    }

    /// Attaches the node-owned pruning mutator used by `pruneblockchain`.
    #[must_use]
    pub fn with_prune_service(mut self, prune_service: Arc<dyn PruneService>) -> Self {
        self.chain.prune_service = Some(prune_service);
        self
    }

    /// Attaches the node-owned mining coordinator to a context built without
    /// handles (`Context::new`). Production wiring passes the coordinator
    /// through `ContextHandles::mining` instead.
    #[must_use]
    pub fn with_mining_control(mut self, mining_control: Arc<dyn MiningControl>) -> Self {
        self.mining_control = Some(mining_control);
        self
    }

    /// Attaches the node-owned chain mutation service.
    #[must_use]
    pub fn with_chain_control(mut self, chain_control: Arc<dyn ChainControl>) -> Self {
        self.chain.chain_control = Some(chain_control);
        self
    }

    /// Shares the node's authoritative connect/disconnect lock with RPC readers.
    #[must_use]
    pub fn with_chain_transition(mut self, chain_transition: Arc<Mutex<()>>) -> Self {
        self.chain.chain_transition = chain_transition;
        self
    }

    /// Attaches the live ZMQ publisher used by `getzmqnotifications`.
    #[must_use]
    pub fn with_zmq_publisher(mut self, publisher: Arc<dyn crate::zmq::ZmqPublisher>) -> Self {
        self.zmq_publisher = publisher;
        self
    }

    /// Attaches the configured node debug-log path.
    #[must_use]
    pub fn with_debug_log_path(mut self, path: PathBuf) -> Self {
        self.debug_log_path = Some(path);
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

    /// Admits one transaction through the full policy stack, then mutates
    /// the mempool only through the node's one [`MempoolGateway`].
    ///
    /// `sendrawtransaction` and embedded `Node::broadcast` both use the
    /// gateway's [`MempoolGateway::submit_transaction`] preparation and retry
    /// boundary. [`MempoolGateway::admit_transaction`] evaluates policy under
    /// a pool read and verifies scripts over copied inputs outside pool locks.
    /// Its writer rechecks chain generation, pool sequence and enforced policy
    /// before committing through the gateway's ordered publication seam.
    ///
    /// Membership follows `POL-01` Duplicate submission in
    /// `docs/policies/mempool-policy.md`. The pool read is a best-effort
    /// pre-check; the locked evaluation is authoritative. The RPC lookup
    /// cache is not membership.
    ///
    /// `max_feerate_sat_per_kvb` of `None` disables the max-fee cap,
    /// matching `sendrawtransaction`'s `maxfeerate=0` behavior.
    ///
    /// # Errors
    ///
    /// Returns the policy rejection verbatim (Core rejection strings) or
    /// the failure verbatim; nothing is inserted when this fails.
    // Owned `Tx` is the public call form (`admit_transaction(tx, None)`).
    // Admission only borrows; the value parameter is the compatibility contract.
    #[allow(clippy::needless_pass_by_value)]
    pub fn admit_transaction(
        &self,
        tx: Tx,
        max_feerate_sat_per_kvb: Option<u64>,
    ) -> Result<MutationResult, String> {
        crate::handlers::tx::admit_transaction(self, &tx, max_feerate_sat_per_kvb)
            .map_err(crate::handlers::tx::AdmissionFailure::into_string)
    }
}

impl ChainHandles {
    /// Runs a read while authoritative UTXO and applied-tip transitions are excluded.
    pub fn with_stable_chainstate<R>(&self, read: impl FnOnce() -> R) -> R {
        let _transition = self.chain_transition.lock();
        read()
    }

    fn applied_progress_snapshot(&self) -> (Option<Arc<TipSnapshot>>, Option<u64>) {
        self.with_stable_chainstate(|| (self.applied_tip.load_full(), self.chain_tx_count()))
    }

    /// Returns the pruning state reported by `getblockchaininfo`.
    #[must_use]
    pub fn prune_status(&self) -> PruneStatus {
        self.prune_service
            .as_ref()
            .map_or_else(PruneStatus::default, |service| service.status())
    }

    /// Typed synchronization progress: the `getblockchaininfo` facts without
    /// RPC JSON. Chainwork is the applied tip's when one exists.
    #[must_use]
    pub fn sync_progress(&self) -> SyncProgress {
        let (applied_tip, chain_tx_count) = self.applied_progress_snapshot();
        let applied = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let headers = self.height();
        let (difficulty, time, median_time) =
            applied_tip.as_ref().map_or((0.0, 0_u64, 0_u64), |tip| {
                let tree = self.block_tree.read();
                tree.node(tip.tip_id).map_or((0.0, 0, 0), |node| {
                    (
                        self.difficulty_for_bits(node.header.bits),
                        u64::from(node.header.time),
                        u64::from(tree.median_time_past_at(tip.tip_id, 11).unwrap_or(0)),
                    )
                })
            });
        let now = crate::handlers::chain::unix_now();
        // Core's estimate when the verified-transaction count is known, the
        // height ratio when it is not; `None` is a pre-tracking datadir and
        // means unknown, never zero.
        let verification_progress = chain_tx_count.map_or_else(
            || {
                if headers > 0 {
                    (f64::from(applied) / f64::from(headers)).min(1.0)
                } else {
                    0.0
                }
            },
            |chain_tx_count| {
                crate::handlers::chain::verification_progress(
                    self.chain_network,
                    chain_tx_count,
                    applied,
                    headers,
                    time,
                    now,
                )
            },
        );
        let prune_status = self.prune_status();
        SyncProgress {
            network: self.chain_network,
            blocks: applied,
            headers,
            best_block_hash: applied_tip
                .as_ref()
                .map_or_else(|| self.chain_network.genesis_block_hash(), |tip| tip.hash),
            difficulty,
            time,
            median_time,
            verification_progress,
            initial_block_download: self.ibd.is_active(now),
            chain_work: applied_tip
                .as_deref()
                .map_or_else(|| self.chainwork_hex(), Self::tip_chainwork_hex),
            size_on_disk: self
                .block_storage_disk_usage()
                .unwrap_or_else(|| self.blocks.read().size_on_disk()),
            pruned: prune_status.pruned,
            prune_height: prune_status.pruneheight,
        }
    }

    /// Big-endian hex of one tip snapshot's chainwork.
    fn tip_chainwork_hex(tip: &TipSnapshot) -> String {
        let bytes: [u8; 32] = tip.chainwork.to_be_bytes();
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;

            let _: fmt::Result = write!(&mut out, "{byte:02x}");
        }
        out
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

    /// Publishes a new best-chain tip.
    pub fn set_chain_tip(&self, tip: TipSnapshot) {
        self.chain_tip.store(Some(Arc::new(tip)));
    }

    /// Publishes a new best-applied-block tip.
    pub fn set_applied_tip(&self, tip: TipSnapshot) {
        self.applied_tip.store(Some(Arc::new(tip)));
    }

    /// Stores a block record for block and header RPCs.
    pub fn add_block(&self, record: BlockRecord) {
        self.blocks.write().push(record);
    }

    /// Stores a decoded transaction for transaction lookup RPCs.
    pub fn add_transaction(&self, tx: Tx) -> Txid {
        let txid = tx.txid();
        self.transactions.write().insert(txid, tx);
        txid
    }

    /// Borrows the provisional chain capability shared with P2P admission.
    #[must_use]
    pub(crate) fn admission_chain(&self) -> ChainAdmissionView<'_> {
        ChainAdmissionView::new(
            &self.utxo,
            &self.applied_tip,
            &self.block_tree,
            self.chain_network,
        )
    }

    /// Returns the current tip height, or zero before initial sync publishes one.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.chain_tip.load_full().map_or(0, |tip| tip.height)
    }

    /// Returns the current best-applied-block height (lags `height()` when
    /// headers are ahead of downloaded blocks).
    #[must_use]
    pub fn applied_height(&self) -> u32 {
        self.applied_tip.load_full().map_or(0, |tip| tip.height)
    }

    /// Returns the cumulative transaction count of the applied chain, or `None`
    /// when this node cannot know it.
    ///
    /// This is Bitcoin Core's `CBlockIndex::m_chain_tx_count`, and `None` is its
    /// `HaveNumChainTxs() == false`: a chain whose history was applied before
    /// the node tracked the count cannot recover it without re-reading every
    /// block body. Callers must treat `None` as *unknown*, never as zero — the
    /// two differ by an entire chain.
    #[must_use]
    pub fn chain_tx_count(&self) -> Option<u64> {
        self.applied_tip
            .load_full()
            .and_then(|tip| tip.chain_tx_count.get())
    }

    /// Returns the current best-applied-block hash.
    ///
    /// Before the first applied tip is published the canonical chain is the
    /// genesis-only chain, exactly as `applied_height` already reports `0` and
    /// `block_hash_at_height(0)` answers the genesis hash — callers must never
    /// see an all-zero tip for a chain that always has a height-0 block.
    #[must_use]
    pub fn applied_hash(&self) -> Hash256 {
        self.applied_tip
            .load_full()
            .map_or_else(|| self.chain_network.genesis_block_hash(), |tip| tip.hash)
    }

    /// Returns the current best-chain chainwork as a 64-character lowercase
    /// big-endian hex string. Returns "00" when no tip is published yet (a
    /// 2-char placeholder matching `bitcoind`'s pre-genesis behavior).
    #[must_use]
    pub fn chainwork_hex(&self) -> String {
        let Some(tip) = self.chain_tip.load_full() else {
            return "00".to_owned();
        };
        let bytes: [u8; 32] = tip.chainwork.to_be_bytes();
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;

            let _: fmt::Result = write!(&mut out, "{byte:02x}");
        }
        out
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
        let tip = self.applied_tip.load_full()?;
        self.hash_at_height_from_tip(&tip, height)
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
        if let Some(tip) = self.applied_tip.load_full() {
            let hash = self.hash_at_height_from_tip(&tip, height)?;
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
    pub fn block_storage_disk_usage(&self) -> Option<u64> {
        self.block_body_source.as_ref()?.disk_usage()
    }

    /// Returns lowercase serialized block hex from durable body storage.
    #[must_use]
    pub(crate) fn block_body_hex(&self, record: &BlockRecord) -> Option<String> {
        Some(hex_encode(&self.block_body_bytes(record)?))
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
        tree.median_time_past_at(node_id, 11)
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
        Some(hex_encode(&bytes))
    }

    /// Returns the hash of the block at `height + 1` on the active chain.
    #[must_use]
    pub(crate) fn next_block_hash_for_height(
        &self,
        height: u32,
    ) -> Option<bitcoin_rs_primitives::Hash256> {
        let tree = self.block_tree.read();
        let tip = tree.tip()?;
        let next_height = height.checked_add(1)?;
        let node_id = tree.node_at_height_from(tip.tip_id, next_height)?;
        let node = tree.node(node_id).ok()?;
        Some(node.hash)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// A txindex status source stand-in, so the identity test can prove the
    /// capability travels to `indexes` without a live index runtime.
    struct ReadySource;

    impl crate::capabilities::DerivedIndexCapabilitySource for ReadySource {
        fn capability(&self) -> crate::capabilities::CapabilityStatus {
            crate::capabilities::derived_index_status(
                true,
                crate::capabilities::CapabilityState::Ready,
            )
        }
    }

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
    #[allow(clippy::arc_with_non_send_sync)]
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
    #[allow(clippy::arc_with_non_send_sync)]
    fn from_handles_shares_chain_handles_with_caller() {
        use alloc::sync::Arc;

        let chain_tip = Arc::new(ArcSwapOption::empty());
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let ibd = Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
            Arc::clone(&applied_tip),
            Arc::new(RwLock::new(bitcoin_rs_chain::BlockTree::new())),
            Network::Mainnet,
        ));
        let utxo = Arc::new(bitcoin_rs_utxo::UtxoSet::new());
        let coin_stats = Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        ));
        let block_tree = Arc::new(RwLock::new(bitcoin_rs_chain::BlockTree::new()));
        let banned = Arc::new(RwLock::new(Vec::<bitcoin_rs_p2p::BannedSubnet>::new()));
        let added_nodes = Arc::new(RwLock::new(Vec::new()));
        let network_active = Arc::new(core::sync::atomic::AtomicBool::new(true));
        let status: Arc<dyn crate::capabilities::DerivedIndexCapabilitySource> =
            Arc::new(ReadySource);
        let ctx = Context::from_handles(ContextHandles {
            chain: ChainHandles::new(
                Arc::clone(&chain_tip),
                Arc::clone(&applied_tip),
                Arc::new(RwLock::new(BlockLog::new())),
                Arc::new(RwLock::new(HashMap::new())),
                Arc::clone(&utxo),
                Arc::clone(&coin_stats),
                Arc::clone(&block_tree),
                Network::Mainnet,
                Arc::clone(&ibd),
            ),
            mempool: MempoolHandles {
                mempool: MempoolGateway::shared(Arc::new(RwLock::new(Mempool::new(
                    MempoolLimits::default(),
                )))),
            },
            indexes: IndexHandles {
                derived_index: None,
                esplora_tx_index: None,
                script_index: None,
                derived_index_status: Some(Arc::clone(&status)),
            },
            network: NetworkHandles {
                network: Arc::new(RwLock::new(NetworkState::default())),
                network_active: Arc::clone(&network_active),
                peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
                p2p_outbound_sender: None,
                banned: Arc::clone(&banned),
                added_nodes: Arc::clone(&added_nodes),
            },
            mining: MiningHandles {
                mining_control: None,
            },
        });
        assert!(
            Arc::ptr_eq(&ctx.chain.chain_tip, &chain_tip),
            "chain_tip must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.chain.applied_tip, &applied_tip),
            "applied_tip must be shared with caller"
        );
        // The count travels inside the applied tip: one publication replaces
        // tip and count together, through the cell the caller shares.
        let counted = |count| {
            Arc::new(TipSnapshot {
                tip_id: bitcoin_rs_chain::NodeId::new(0),
                height: 0,
                chainwork: bitcoin_rs_chain::ChainWork::ZERO,
                hash: bitcoin_rs_primitives::Hash256::default(),
                chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(count),
            })
        };
        applied_tip.store(Some(counted(1)));
        assert_eq!(ctx.chain.chain_tx_count(), Some(1));
        applied_tip.store(Some(counted(42)));
        assert_eq!(ctx.chain.chain_tx_count(), Some(42));
        assert!(
            Arc::ptr_eq(&ctx.chain.ibd, &ibd),
            "ibd must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.chain.utxo, &utxo),
            "utxo must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.chain.coin_stats, &coin_stats),
            "coin_stats must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.chain.block_tree, &block_tree),
            "block_tree must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.network.network_active, &network_active),
            "network activity must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.network.banned, &banned),
            "banned must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.network.added_nodes, &added_nodes),
            "added_nodes must be shared with caller"
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

    #[test]
    fn progress_snapshot_waits_for_a_complete_chain_transition() -> anyhow::Result<()> {
        use std::sync::mpsc;
        use std::time::Duration;

        let barrier = Arc::new(Mutex::new(()));
        let ctx = Arc::new(Context::new().with_chain_transition(Arc::clone(&barrier)));
        let genesis = Network::Regtest.genesis_block();
        let tip = {
            let mut tree = ctx.chain.block_tree.write();
            let tip_id = tree.insert_node(
                None,
                genesis.header,
                bitcoin_rs_chain::node::NodeStatus::Active,
            )?;
            let node = tree.node(tip_id)?;
            TipSnapshot {
                tip_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            }
        };

        let tip = TipSnapshot {
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(42),
            ..tip
        };
        let transition = barrier.lock();
        ctx.chain.applied_tip.store(Some(Arc::new(tip.clone())));
        let worker = Arc::clone(&ctx);
        let (tx, rx) = mpsc::channel();
        let join = std::thread::spawn(move || {
            let _ = tx.send(worker.chain.applied_progress_snapshot());
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "RPC progress must not observe a half-published transition"
        );
        drop(transition);

        let (published_tip, published_count) = rx.recv_timeout(Duration::from_secs(1))?;
        join.join()
            .map_err(|_| anyhow::anyhow!("snapshot worker panicked"))?;
        assert_eq!(published_tip.as_deref(), Some(&tip));
        assert_eq!(published_count, Some(42));
        Ok(())
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
        use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};

        let ctx = Context::new();
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[1_u8; 32])), 0);
        let txout = TxOut {
            value: Amount::from_sat(125_000),
            script_pubkey: Script::new(),
        };
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(outpoint, txout, true, 7));

        ctx.chain
            .utxo
            .commit_block(&changes, &Hash256::default())
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
        let ctx = Context::new().with_block_body_source(source);
        ctx.chain.add_block(record.clone());

        assert_eq!(record.body_size, consensus_bytes(&block).len());
        assert_eq!(
            ctx.chain.block_body_bytes(&record).as_deref(),
            Some(body.as_slice())
        );
        let expected_hex = hex_encode(&body);
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
    #[allow(clippy::arc_with_non_send_sync)]
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
            hex_encode(&consensus_bytes(&block.header))
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
    #[allow(clippy::arc_with_non_send_sync)]
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
        assert!(record.header_hex().is_empty());
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
        assert_eq!(record.header_hex(), hex_encode(&consensus_bytes(&header)));
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
            ctx.chain.set_applied_tip((*applied_tip).clone());
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

        ctx.chain.set_applied_tip((*applied_tip).clone());
        ctx.chain.set_chain_tip((*header_tip).clone());
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
}

#[cfg(test)]
mod admission_chain_tests {
    use anyhow::Context as _;
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::{Header, LockTime, Sequence, TxIn, TxOut, Witness};
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
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
                sequence: Sequence::from_consensus(u32::MAX),
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::from_bytes(spendable_script()),
            }],
            lock_time: LockTime::from_consensus(0),
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
        let ctx = Context::new();
        let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[8; 32])), 0);
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
        ctx.chain.utxo.commit_block(&changes, &Hash256::default())?;

        // Stable whole-chain readers hold this mutex without changing the
        // generation. Admission must succeed through its real RPC path while
        // such a reader is active, rather than spending its retry budget on
        // contention that says nothing about stale chain facts.
        let result = ctx
            .chain
            .with_stable_chainstate(|| ctx.admit_transaction(tx, None))
            .map_err(anyhow::Error::msg)?;
        assert_eq!(result.changes.len(), 1);
        assert!(ctx.mempool.read().contains_txid(&txid));
        Ok(())
    }

    #[test]
    fn cached_unconfirmed_transaction_is_still_admitted_from_a_peer() -> anyhow::Result<()> {
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
        ctx.chain.utxo.commit_block(&changes, &Hash256::default())?;
        ctx.chain.add_transaction(tx.clone());
        assert!(
            !ctx.chain
                .admission_chain()
                .snapshot(&tx)
                .context("snapshot")?
                .confirmed
        );
        let result = ctx.mempool.submit_transaction(
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
        assert!(ctx.mempool.read().contains_txid(&txid));
        Ok(())
    }

    #[test]
    fn confirmed_hint_requires_live_chain_outputs_and_survives_no_cache() -> anyhow::Result<()> {
        let ctx = Context::new();
        let tx = spending(OutPoint::new(
            Txid::from(Hash256::from_le_bytes(&[10; 32])),
            0,
        ));
        let output = OutPoint::new(tx.txid(), 0);
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(output, tx.outputs[0].clone(), false, 0));
        ctx.chain.utxo.commit_block(&changes, &Hash256::default())?;
        assert!(ctx.chain.transactions.read().is_empty());
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
        assert!(
            ctx.chain
                .admission_chain()
                .snapshot(&tx)
                .context("empty snapshot")?
                .prevouts
                .is_empty()
        );

        // A borrowed capability observes current handles even in isolated
        // contexts that replace test state after construction.
        ctx.chain.utxo = Arc::new(bitcoin_rs_utxo::UtxoSet::new());
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
        ctx.chain
            .utxo
            .commit_block(&changes, &Hash256::default())
            .context("fund input")?;
        publish_tip(&ctx, 100)?;
        publish_tip(&ctx, 200)?;
        ctx.chain.transactions.write().insert(tx.txid(), tx.clone());

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
            "lookup-cache membership is not chain evidence"
        );
        Ok(())
    }
}
