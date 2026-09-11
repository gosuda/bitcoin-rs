//! Shared node runtime state and capability handles.
//!
//! Construction, recovery, persistence, event publication, pruning, and index
//! lifecycle are isolated below; this facade retains the public handle API.

mod checkpoint;
mod events;
mod index;
mod open;
mod prune;
mod restore;
mod storage;

#[cfg(test)]
pub(crate) use restore::ResumeSource;

use crate::ApplyError;
use crate::NodeConfig;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_rpc::context::BlockLog;
use bitcoin_rs_rpc::context::NetworkState;
use bitcoin_rs_rpc::context::PruneService;
use bitcoin_rs_utxo::UtxoSet;
use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
pub use events::ChainEventHint;
pub use events::ChainEventPublisher;
pub use events::ChainSnapshot;
pub use events::HintKind;
use hashbrown::HashMap;
use index::TxIndexSpawn;
use parking_lot::Mutex;
use parking_lot::RwLock;
pub use prune::NodePruneService;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use storage::NodeStorage;
use storage::StoredBlockBodySource;

// One active generation of outbound requests is enough to keep the drain fed;
// extra backlog is overload and must fail fast at producers.
pub(crate) const P2P_OUTBOUND_QUEUE_LIMIT: usize = 8;

// Bounds transient inbound-block buffering between the per-peer listener
// threads and the single-threaded `BlockSync::tick` drain. Decoded inbound
// blocks carry the full `Block` plus preserved wire bytes (up to ~4 MiB each),
// so an unbounded channel lets a fast or flooding peer accumulate blocks faster
// than they drain — an OOM vector. A full channel applies TCP backpressure to
// the sending peer's listener thread; `tick` drains independently and holds no
// lock a listener needs, so the bound cannot deadlock. Sized well above the
// in-flight request window (`PENDING_BUDGET` = 256) so honest delivery, which
// wakes the drain on every block, is never throttled.
pub(crate) const INBOUND_BLOCK_CHANNEL_LIMIT: usize = 512;

// Bounds chain-event hints between the block-apply commit path and
// reconciliation consumers (#77). Hints are wake-ups, never data: a consumer
// that misses one recovers by reconciling `ChainSnapshot` against its own
// cursor using the chain itself. The bound is single-sourced from the
// inbound-block bound so both channels share the same flood posture; a full
// channel drops the hint and never blocks the commit path.
pub(crate) const CHAIN_HINT_CHANNEL_LIMIT: usize = INBOUND_BLOCK_CHANNEL_LIMIT;

// Bounds inbound peer transactions between the per-peer listener threads and
// the single ingress consumer. A full channel applies TCP backpressure to
// that peer's read loop; other peers keep their own threads. Sized to absorb
// a burst of honest `tx` deliveries without stalling header/block traffic on
// the same connection under normal load.
pub(crate) const INBOUND_TX_CHANNEL_LIMIT: usize = 1_024;

/// Aggregate handle to a running node.
pub struct NodeState {
    /// Height the last clean checkpoint would restore to, 0 when none exists.
    ///
    /// Published by `write_clean_checkpoint` and read by the pruner, which must
    /// not delete an undo record a crash-restore would still need.
    durable_tip_height: Arc<AtomicU32>,
    config: NodeConfig,
    data_dir: PathBuf,
    #[cfg(test)]
    resume_source: ResumeSource,
    storage: NodeStorage,
    block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
    utxo: Arc<UtxoSet>,
    coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    tx_index_runtime: Option<Arc<crate::txindex_worker::TxIndexRuntime>>,
    tx_index_spawn: Option<TxIndexSpawn>,
    tx_index_worker: Option<crate::txindex_worker::TxIndexWorker>,
    tx_index_lifecycle: Option<Arc<arc_swap::ArcSwap<crate::txindex_worker::TxIndexLifecycle>>>,
    /// Stable query adapter for txindex/script-index, constructed before open.
    tx_index_adapter: Option<Arc<crate::txindex_worker::TxIndexQueryAdapter>>,
    /// Live txindex facts for the RPC `getcapabilities` projection.
    txindex_status: Arc<crate::txindex_worker::TxIndexCapability>,
    prune_service: Option<Arc<dyn PruneService>>,
    zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    mempool: Arc<RwLock<Mempool>>,
    /// The single mutation gateway in front of `mempool`.
    mempool_gateway: Arc<bitcoin_rs_mempool::MempoolGateway>,
    /// Template-coordinator wake for authoritative mutations and tip moves.
    mining_generation: Arc<crate::mining::MiningGenerationSignal>,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Cumulative transaction count through `applied_tip`, `0` when unknown.
    /// Shared with `Chainstate`, which maintains it, and with the RPC context.
    chain_tx_count: Arc<AtomicU64>,
    block_tree: Arc<RwLock<bitcoin_rs_chain::BlockTree>>,
    blocks: Arc<RwLock<BlockLog>>,
    transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    network: Arc<RwLock<NetworkState>>,
    /// Shared P2P admission switch controlled by `setnetworkactive`.
    network_active: Arc<AtomicBool>,
    /// Runtime owner of P2P workers, session table, and inbound channels.
    p2p: Arc<bitcoin_rs_p2p::P2pService>,
    peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    banned: Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
    p2p_outbound_tx: crossbeam_channel::Sender<std::net::SocketAddr>,
    p2p_outbound_rx: Arc<Mutex<crossbeam_channel::Receiver<std::net::SocketAddr>>>,
    inbound_headers_tx: Sender<bitcoin_rs_p2p::InboundHeaders>,
    inbound_headers_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundHeaders>>>,
    inbound_blocks_tx: Sender<bitcoin_rs_p2p::InboundBlock>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    inbound_tx_tx: Sender<bitcoin_rs_p2p::InboundTx>,
    inbound_tx_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundTx>>>,
    chain_events: Arc<ChainEventPublisher>,
    chain_event_hints_rx: Arc<Mutex<Receiver<ChainEventHint>>>,
    apply_handles: crate::apply::Chainstate,
    /// Derived consumers of committed chain events. Not held by `Chainstate`.
    followers: crate::chain_effects::ChainFollowers,
    sync: Arc<crate::BlockSync>,
    /// Process-wide rollback-evidence warning snapshot (`ArcSwap`).
    warning_store: Arc<crate::recovery_evidence::WarningStore>,
}

impl Drop for NodeState {
    fn drop(&mut self) {
        let _admission = self.apply_handles.admission.close();
        // Safety net: if `bounded_index_shutdown` was not called (e.g. in
        // tests that drop `NodeState` directly), request shutdown and join
        // any worker not already taken by `bounded_index_shutdown`.
        if let Some(runtime) = &self.tx_index_runtime {
            runtime.request_shutdown();
        }
        if let Some(worker) = self.tx_index_worker.take() {
            worker.join();
        }
    }
}

impl NodeState {
    /// Returns a borrow of the resolved configuration.
    #[must_use]
    pub const fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Returns the node's data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    #[cfg(test)]
    pub(crate) const fn resume_source(&self) -> ResumeSource {
        self.resume_source
    }

    /// Returns the configured storage backend that was opened.
    #[must_use]
    pub const fn storage_kind(&self) -> &'static str {
        self.storage.kind()
    }

    /// Returns the shared UTXO set handle.
    #[must_use]
    pub fn utxo(&self) -> Arc<UtxoSet> {
        Arc::clone(&self.utxo)
    }

    /// Returns the shared coinstats listener handle.
    #[must_use]
    pub fn coin_stats(&self) -> Arc<bitcoin_rs_utxo::stats::CoinStatsListener> {
        Arc::clone(&self.coin_stats)
    }

    /// Returns the manual pruning service when pruning is enabled.
    #[must_use]
    pub fn prune_service(&self) -> Option<Arc<dyn PruneService>> {
        self.prune_service.as_ref().map(Arc::clone)
    }

    /// Returns the configured ZMQ publisher handle (default: `NoOpZmqPublisher`).
    #[must_use]
    pub fn zmq_publisher(&self) -> Arc<dyn crate::ZmqPublisher> {
        Arc::clone(&self.zmq_publisher)
    }

    /// Returns the shared mempool handle.
    #[must_use]
    pub fn mempool(&self) -> Arc<RwLock<Mempool>> {
        Arc::clone(&self.mempool)
    }

    /// Returns the node-owned mutation gateway in front of `mempool`.
    ///
    /// Every mempool mutation in this process — RPC admission, embedded
    /// broadcast, reorg re-admission, block-connect eviction — commits
    /// through this one instance, so observers observe a single ordered
    /// stream.
    #[must_use]
    pub fn mempool_gateway(&self) -> Arc<bitcoin_rs_mempool::MempoolGateway> {
        Arc::clone(&self.mempool_gateway)
    }

    /// Returns the mining generation wake shared with the apply path and the
    /// gateway observer. The template coordinator attaches itself here.
    #[must_use]
    pub fn mining_generation_signal(&self) -> Arc<crate::mining::MiningGenerationSignal> {
        Arc::clone(&self.mining_generation)
    }

    /// Returns the shared best-chain tip handle.
    #[must_use]
    pub fn chain_tip(&self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.chain_tip)
    }

    /// Returns the shared best-applied-block tip handle.
    ///
    /// This handle lags `chain_tip()` when headers are accepted ahead of blocks
    /// being downloaded and applied. RPC consumers showing user-visible state
    /// (best block hash, block count) read this; sync-progress consumers read
    /// `chain_tip()`.
    #[must_use]
    pub fn applied_tip(&self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.applied_tip)
    }

    /// Returns the shared block-tree handle.
    #[must_use]
    pub fn block_tree(&self) -> Arc<RwLock<bitcoin_rs_chain::BlockTree>> {
        Arc::clone(&self.block_tree)
    }

    /// Shares the cumulative chain transaction-count handle with the RPC layer.
    #[must_use]
    pub fn chain_tx_count_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.chain_tx_count)
    }

    /// Shares the chain-transition mutex with the RPC layer.
    ///
    /// The applied tip and the cumulative transaction count are published one
    /// after the other inside a transition. An RPC reader that takes this lock
    /// sees the pair as the transition left it, rather than catching it halfway
    /// through and reporting the new tip's height beside the old tip's count.
    ///
    /// Handing out the lock means an RPC read can wait for a connect to finish.
    /// That is the trade Bitcoin Core already makes -- `getchaintxstats` holds
    /// `cs_main` for its whole body -- and the wait here covers two atomic
    /// loads rather than a whole handler.
    #[must_use]
    pub fn chain_transition_handle(&self) -> Arc<parking_lot::Mutex<()>> {
        Arc::clone(&self.apply_handles.chain_transition)
    }

    /// Returns the shared block-records handle exposed to RPC handlers.
    #[must_use]
    pub fn blocks(&self) -> Arc<RwLock<BlockLog>> {
        Arc::clone(&self.blocks)
    }

    /// Returns a durable block body reader for metadata-only block records.
    #[must_use]
    pub(crate) fn block_body_source(&self) -> Arc<dyn BlockBodySource> {
        Arc::new(StoredBlockBodySource::new(Arc::clone(
            &self.block_body_store,
        )))
    }

    /// Returns the shared txid → transaction map exposed to RPC handlers.
    #[must_use]
    pub fn transactions(&self) -> Arc<RwLock<HashMap<Txid, Tx>>> {
        Arc::clone(&self.transactions)
    }

    /// Returns the shared network-counters handle exposed to RPC handlers.
    #[must_use]
    pub fn network(&self) -> Arc<RwLock<NetworkState>> {
        Arc::clone(&self.network)
    }

    /// Returns the shared P2P admission switch exposed to RPC and P2P workers.
    #[must_use]
    pub fn network_active(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.network_active)
    }

    /// Returns the shared manual IP/subnet ban list exposed to RPC and P2P.
    #[must_use]
    pub fn banned_subnets(&self) -> Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>> {
        Arc::clone(&self.banned)
    }

    /// Returns the P2P runtime that owns workers and the session table.
    #[must_use]
    pub fn p2p(&self) -> Arc<bitcoin_rs_p2p::P2pService> {
        Arc::clone(&self.p2p)
    }

    #[must_use]
    /// Returns the authoritative table of live peer sessions.
    pub fn peer_table(&self) -> Arc<bitcoin_rs_p2p::PeerTable> {
        Arc::clone(&self.peer_table)
    }

    /// Returns the service-owned persistent addnode view.
    #[must_use]
    pub fn added_nodes(&self) -> Arc<RwLock<Vec<std::net::SocketAddr>>> {
        self.p2p.added_nodes_handle()
    }
    /// Returns a cloned sender that RPC `addnode` uses to request outbound P2P connections.
    #[must_use]
    pub fn p2p_outbound_sender(&self) -> crossbeam_channel::Sender<std::net::SocketAddr> {
        self.p2p_outbound_tx.clone()
    }

    /// Returns the shared receiver consumed by the outbound P2P drain worker.
    #[must_use]
    pub fn p2p_outbound_receiver(
        &self,
    ) -> Arc<Mutex<crossbeam_channel::Receiver<std::net::SocketAddr>>> {
        Arc::clone(&self.p2p_outbound_rx)
    }

    /// Returns the rollback-evidence warning store for `getblockchaininfo`.
    #[must_use]
    pub(crate) fn warning_store(&self) -> Arc<crate::recovery_evidence::WarningStore> {
        Arc::clone(&self.warning_store)
    }

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// block headers into. The matching `Receiver` is polled by
    /// `BlockSync::tick` to extend the `BlockTree`.
    pub fn inbound_headers_sender(&self) -> Sender<bitcoin_rs_p2p::InboundHeaders> {
        self.inbound_headers_tx.clone()
    }

    /// Returns the shared receiver handle consumed by `BlockSync::tick`.
    ///
    /// Exposed so tests and `BlockSync::new` can wire the channel; production
    /// code calls `state.sync()` and lets the orchestrator own the drain.
    #[must_use]
    pub fn inbound_headers_rx_handle(
        &self,
    ) -> Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundHeaders>>> {
        Arc::clone(&self.inbound_headers_rx)
    }

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// blocks into for verification and relay.
    pub fn inbound_blocks_sender(&self) -> Sender<bitcoin_rs_p2p::InboundBlock> {
        self.inbound_blocks_tx.clone()
    }

    /// Returns the shared receiver handle consumed by `BlockSync::tick`.
    ///
    /// Exposed so tests and `BlockSync::new` can wire the channel; production
    /// code calls `state.sync()` and lets the orchestrator own the drain.
    #[must_use]
    pub fn inbound_blocks_rx_handle(&self) -> Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>> {
        Arc::clone(&self.inbound_blocks_rx)
    }

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// transactions into for mempool admission.
    pub fn inbound_tx_sender(&self) -> Sender<bitcoin_rs_p2p::InboundTx> {
        self.inbound_tx_tx.clone()
    }

    /// Returns the shared receiver handle drained by the tx-ingress consumer.
    #[must_use]
    pub fn inbound_tx_rx_handle(&self) -> Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundTx>>> {
        Arc::clone(&self.inbound_tx_rx)
    }

    /// Returns the current coherent chain snapshot: the applied tip stamped
    /// with the process epoch and the commit sequence.
    #[must_use]
    pub fn active_chain_snapshot(&self) -> ChainSnapshot {
        self.chain_events.snapshot()
    }

    /// Returns the chain-event publisher. The apply path records committed
    /// connects/disconnects through it; consumers read the snapshot from it.
    #[must_use]
    pub fn chain_event_publisher(&self) -> Arc<ChainEventPublisher> {
        Arc::clone(&self.chain_events)
    }

    /// Returns the shared hint receiver handle for reconciliation consumers.
    #[must_use]
    pub fn chain_event_hints(&self) -> Arc<Mutex<Receiver<ChainEventHint>>> {
        Arc::clone(&self.chain_event_hints_rx)
    }

    /// Returns the shared block-download orchestrator.
    #[must_use]
    pub fn sync(&self) -> Arc<crate::BlockSync> {
        Arc::clone(&self.sync)
    }

    /// Returns the process-wide shutdown signal shared by all runtime workers.
    #[must_use]
    pub fn shutdown(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.apply_handles.shutdown)
    }

    /// Clone of the chainstate facade used by apply, reorg, and sync.
    #[must_use]
    pub fn chainstate(&self) -> crate::apply::Chainstate {
        self.apply_handles.clone()
    }

    /// Clone of the derived-consumer set used after committed transitions.
    #[must_use]
    pub fn chain_followers(&self) -> crate::chain_effects::ChainFollowers {
        self.followers.clone()
    }

    /// Synthetically applies `block` as the next tip after consensus checks.
    ///
    /// Holds the chain transition through follower dispatch (`ARCH-07`).
    pub fn apply_block(&self, block: &Block) -> core::result::Result<TipSnapshot, ApplyError> {
        let outcome = self.followers.apply_connect(&self.apply_handles, block)?;
        Ok(outcome.tip)
    }

    #[cfg(test)]
    pub(crate) fn check_coinbase_maturity(
        &self,
        block: &Block,
        height: u32,
    ) -> core::result::Result<(), ApplyError> {
        crate::apply::check_coinbase_maturity(&self.apply_handles, block, height)
    }
}

#[cfg(test)]
mod tests;
