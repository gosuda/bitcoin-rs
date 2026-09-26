//! Shared node runtime state and capability handles.
//!
//! Shared handles, checkpoint publication, and index lifecycle live with
//! `NodeState`. Construction, recovery, storage, events, and pruning retain
//! separate private implementations.

use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chainstate::ApplyError;
use bitcoin_rs_chainstate::events::ChainEventPublisher;
#[cfg(test)]
pub(crate) use bitcoin_rs_chainstate::recovery::ResumeSource;
use bitcoin_rs_index::block_log::BlockLog;
use bitcoin_rs_index::runtime::DEFAULT_BATCH_LIMITS;
use bitcoin_rs_index::runtime::OpenDerivedIndex;
use bitcoin_rs_index::runtime::REDB_BATCH_LIMITS;
use bitcoin_rs_index::runtime::open_derived_index_store_on_worker;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_rpc::context::NetworkState;
use bitcoin_rs_rpc::context::PruneService;
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_storage::StorageBackend;
use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
use hashbrown::HashMap;
use parking_lot::Mutex;
use parking_lot::RwLock;
pub use prune::NodePruneService;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use storage::NodeStorage;
use storage::StoredBlockBodySource;

#[path = "state_index.rs"]
mod index;
#[path = "state_open.rs"]
mod open;
#[path = "state_prune.rs"]
mod prune;
#[path = "state_storage.rs"]
mod storage;

struct IndexChainCursorSource(Arc<ChainEventPublisher>);

impl bitcoin_rs_index::reconcile::ChainCursorSource for IndexChainCursorSource {
    fn cursor(&self) -> bitcoin_rs_index::reconcile::ConsumerCursor {
        let snapshot = self.0.snapshot();
        bitcoin_rs_index::reconcile::ConsumerCursor {
            epoch: snapshot.epoch,
            sequence: snapshot.sequence,
            height: snapshot.tip_height,
            hash: snapshot.tip_hash,
        }
    }
}

// Outbound full-relay slots, and the one active generation of outbound
// requests that keeps the drain fed: extra backlog is overload and must fail
// fast at producers. Bitcoin Core's `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`.
pub(crate) const P2P_OUTBOUND_FULL_RELAY_SLOTS: usize = 8;

// Outbound block-relay-only slots: connections that relay blocks and nothing
// else. Bitcoin Core's `MAX_BLOCK_RELAY_ONLY_CONNECTIONS`.
pub(crate) const P2P_OUTBOUND_BLOCK_RELAY_SLOTS: usize = 2;

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

// Bounds inbound peer transactions between the per-peer listener threads and
// the single ingress consumer. A full channel applies TCP backpressure to
// that peer's read loop; other peers keep their own threads. Sized to absorb
// a burst of honest `tx` deliveries without stalling header/block traffic on
// the same connection under normal load.
pub(crate) const INBOUND_TX_CHANNEL_LIMIT: usize = 1_024;

/// Aggregate handle to a running node.
pub struct NodeState {
    config: NodeConfig,
    #[cfg(test)]
    resume_source: ResumeSource,
    storage: NodeStorage,
    /// Derived-index host: the always-present status source, the configured
    /// parts, and the one worker state-machine slot.
    derived_index: index::DerivedIndexHost,
    prune_service: Option<Arc<dyn PruneService>>,
    zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    mempool: Arc<RwLock<Mempool>>,
    /// The single mutation gateway in front of `mempool`.
    mempool_gateway: Arc<bitcoin_rs_mempool::MempoolGateway>,
    /// Template-coordinator wake for authoritative mutations and tip moves.
    mining_generation: Arc<crate::mining::MiningGenerationSignal>,
    /// Cumulative transaction count through `applied_tip`, `0` when unknown.
    /// Shared with `Chainstate`, which maintains it, and with the RPC context.
    blocks: Arc<RwLock<BlockLog>>,
    transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    network: Arc<RwLock<NetworkState>>,
    /// Shared P2P admission switch controlled by `setnetworkactive`.
    network_active: Arc<AtomicBool>,
    /// Runtime owner of P2P workers, session table, and inbound channels.
    p2p: Arc<bitcoin_rs_p2p::P2pService>,
    peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    banned: Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
    p2p_outbound_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::OutboundDial>,
    inbound_blocks_tx: Sender<bitcoin_rs_p2p::InboundBlock>,
    inbound_tx_tx: Sender<bitcoin_rs_p2p::InboundTx>,
    inbound_tx_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundTx>>>,
    chainstate: Arc<bitcoin_rs_chainstate::Chainstate>,
    /// Derived consumers of committed chain events. Not held by `Chainstate`.
    followers: crate::chain_effects::ChainFollowers,
    sync: Arc<crate::BlockSync>,
    /// The one initial-block-download latch: chain-owned state shared by the
    /// block-download executor, the RPC context, and the P2P listener, so no
    /// two surfaces can disagree about whether this node is still syncing.
    ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
    /// Process-wide rollback-evidence reporter (warning snapshot + marker).
    recovery_reporter: Arc<crate::recovery_reporter::RecoveryReporter>,
}

impl Drop for NodeState {
    fn drop(&mut self) {
        // Closes chain admission permanently. The derived-index worker stop
        // and join run in `DerivedIndexHost::drop` when that field drops;
        // relative to this admission guard the order is free: `Chainstate::
        // close()` keeps admission closed through the permanent `closed`
        // flag, and the index worker only reads chain handles, so releasing
        // the guard before the join is behavior-identical to holding it.
        let _admission = self.chainstate.close();
        // Close the history boundary first, so a worker still reconciling
        // stops on the owner's shutdown answer instead of pinning rows a
        // process that is leaving will not serve.
        self.chainstate.retention_handle().shutdown();
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
        &self.config.data_dir
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

    /// Returns the undo store that owns disconnect markers: the recovery
    /// evidence the startup path consumes.
    #[must_use]
    /// Crash-recovery test seam: exposes the undo/marker store so harnesses
    /// can arm and inspect disconnect markers. Not a supported mutation
    /// surface for node owners.
    #[doc(hidden)]
    pub fn undo_store(&self) -> Arc<dyn bitcoin_rs_chainstate::UndoStore> {
        self.storage.undo_store()
    }

    /// Returns the durable-head store: the chain's commit point.
    #[must_use]
    /// Crash-recovery test seam: exposes the durable head store so
    /// harnesses can read the commit point. Not a supported mutation
    /// surface for node owners.
    #[doc(hidden)]
    pub fn durable_head(&self) -> Arc<dyn bitcoin_rs_storage::DurableHeadStore> {
        self.storage.durable_head()
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

    /// Returns the shared block-records handle exposed to RPC handlers.
    #[must_use]
    pub fn blocks(&self) -> Arc<RwLock<BlockLog>> {
        Arc::clone(&self.blocks)
    }

    /// Returns a durable block body reader for metadata-only block records.
    pub(crate) fn block_body_source(&self) -> Result<Arc<dyn BlockBodySource>> {
        let store = self
            .chainstate
            .block_body_store_handle()
            .context("running node has no block body store")?;
        Ok(Arc::new(StoredBlockBodySource::new(store)))
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
    pub fn p2p_outbound_sender(&self) -> crossbeam_channel::Sender<bitcoin_rs_p2p::OutboundDial> {
        self.p2p_outbound_tx.clone()
    }

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// blocks into for verification and relay.
    pub fn inbound_blocks_sender(&self) -> Sender<bitcoin_rs_p2p::InboundBlock> {
        self.inbound_blocks_tx.clone()
    }

    /// Returns the rollback-evidence reporter for `getblockchaininfo`.
    #[must_use]
    pub(crate) fn recovery_reporter(&self) -> Arc<crate::recovery_reporter::RecoveryReporter> {
        Arc::clone(&self.recovery_reporter)
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

    /// Returns the shared block-download orchestrator.
    #[must_use]
    pub fn sync(&self) -> Arc<crate::BlockSync> {
        Arc::clone(&self.sync)
    }

    /// Returns the node's one initial-block-download latch.
    #[must_use]
    pub fn ibd(&self) -> Arc<bitcoin_rs_chain::InitialBlockDownload> {
        Arc::clone(&self.ibd)
    }

    /// Returns the process-wide shutdown signal shared by all runtime workers.
    #[must_use]
    pub fn shutdown(&self) -> Arc<AtomicBool> {
        self.chainstate.shutdown_handle()
    }

    /// Clone of the chainstate facade used by apply, reorg, and sync.
    #[must_use]
    pub fn chainstate(&self) -> Arc<bitcoin_rs_chainstate::Chainstate> {
        Arc::clone(&self.chainstate)
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
        let outcome = self.followers.apply_connect(&self.chainstate, block)?;
        Ok(outcome.tip)
    }

    /// Publishes a durable clean checkpoint and returns the published
    /// generation, or an error if there is no applied tip.
    ///
    /// This is the public boundary for the private checkpoint machinery; it
    /// keeps `CheckpointWrite`, `CheckpointError`, and the checkpoint module
    /// internal to the crate.
    pub fn publish_checkpoint(&self) -> Result<u64> {
        self.chainstate
            .publish_checkpoint()?
            .context("checkpoint refused: no applied tip to publish")
    }

    pub(crate) fn write_clean_checkpoint(&self) -> anyhow::Result<Option<u64>> {
        Ok(self.chainstate.publish_checkpoint()?)
    }

    /// Starts chainstate journal and retention maintenance.
    pub fn start_chainstate_maintenance(&self) -> Result<std::thread::JoinHandle<()>> {
        self.chainstate.start_maintenance()
    }

    /// Returns the node-owned complete transaction-index query adapter.
    #[must_use]
    pub fn derived_index_query(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery>> {
        if !self.config.indexes.txindex {
            return None;
        }
        self.derived_index.adapter().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery> = adapter.clone();
            q
        })
    }

    /// Returns transaction lookup for internal Esplora projections.
    ///
    /// `--scriptindex` builds this dependency as well, but that does not
    /// enable or advertise the Core `--txindex` contract.
    #[must_use]
    pub fn esplora_derived_index_query(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery>> {
        self.derived_index.adapter().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery> = adapter.clone();
            q
        })
    }

    /// Returns the node-owned complete generic script-index query adapter.
    #[must_use]
    pub fn script_index_query(&self) -> Option<Arc<dyn bitcoin_rs_rpc::context::ScriptIndexQuery>> {
        if !self.config.indexes.script_index.is_enabled() {
            return None;
        }
        self.derived_index.adapter().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::ScriptIndexQuery> = adapter.clone();
            q
        })
    }

    /// Starts the derived-index workers. Call only once the applied tip is
    /// authoritative — after crash recovery — so the index reconciles against
    /// the real chainstate and never mistakes a recovered gap for a stale branch.
    pub fn start_index_workers(&mut self) -> anyhow::Result<()> {
        self.derived_index.start(&self.chainstate)
    }


    /// Returns the live txindex status source for `getcapabilities`.
    #[must_use]
    pub fn derived_index_status(
        &self,
    ) -> Arc<dyn bitcoin_rs_rpc::capabilities::DerivedIndexCapabilitySource> {
        self.derived_index.status()
    }

    /// Bounded txindex-worker shutdown: requests the worker shutdown, waits up
    /// to `deadline` for a clean join, and detaches on
    /// expiry. On detach, revokes the generation token and publishes
    /// `ShutdownAbandoned` so queries return typed `Unavailable` instead of
    /// hitting a torn reader. An abandoned join is an error: the caller's
    /// teardown records it and suppresses the clean checkpoint.
    pub(crate) fn bounded_index_shutdown(&mut self, deadline: Duration) -> Result<()> {
        self.derived_index.shutdown(deadline)
    }

    /// `true` once the owned index worker's join returned; stays `false` when
    /// the bounded join was abandoned. The lifecycle tests read it at the
    /// checkpoint seam to prove join-before-checkpoint.
    #[cfg(test)]
    pub(crate) fn index_worker_joined(&self) -> Arc<AtomicBool> {
        self.derived_index.worker_joined()
    }
}

fn derived_index_capabilities(config: &NodeConfig) -> bitcoin_rs_index::IndexCapabilities {
    bitcoin_rs_index::IndexCapabilities {
        // Full ScriptIndex-backed Esplora responses need exact historical
        // transactions to render prevouts and calculate fees. `utxo` owns
        // only the compact live-output view and must not pay for TxLookup.
        // `derived_index_query` still exposes TxLookup to Core RPCs only for an
        // explicit --txindex configuration.
        tx_lookup: config.indexes.txindex || config.indexes.script_index.keeps_history(),
        script_history: config.indexes.script_index.keeps_history(),
        script_live: config.indexes.script_index.is_enabled(),
    }
}

fn build_derived_index_open_spec(
    config: &NodeConfig,
    txindex_cache_bytes: u64,
    epoch: u64,
) -> Result<Option<bitcoin_rs_index::runtime::DerivedIndexOpenSpec>> {
    let enabled = derived_index_capabilities(config);
    if enabled.is_empty() {
        return Ok(None);
    }
    if config.storage.prune_target_mb > 0 {
        bail!("transaction and script indexing are not compatible with -prune");
    }
    let canonical_data_root = config
        .data_dir
        .canonicalize()
        .unwrap_or_else(|_| config.data_dir.clone());
    let backend = config.storage.backend;
    let cache_bytes = txindex_cache_bytes;
    Ok(Some(bitcoin_rs_index::runtime::DerivedIndexOpenSpec {
        data_dir: config.data_dir.clone(),
        namespace: "txindex",
        storage_backend: config.storage.backend,
        epoch,
        enabled,
        rollback_rebuild_cutover: bitcoin_rs_index::runtime::DEFAULT_ROLLBACK_REBUILD_CUTOVER,
        canonical_data_root,
        open_store: Arc::new(move |dir| {
            crate::storage_backend::open_txindex(
                backend,
                dir,
                Some(cache_bytes),
                DerivedIndexComposer { backend, epoch },
            )
        }),
        utxo: None,
        chain_transition: None,
    }))
}

struct DerivedIndexComposer {
    backend: StorageBackend,
    epoch: u64,
}

impl crate::storage_backend::StoreConsumer for DerivedIndexComposer {
    type Output = OpenDerivedIndex;
    type Error = bitcoin_rs_index::runtime::DerivedIndexWorkerError;

    fn consume<S>(self, store: Arc<S>) -> Result<Self::Output, Self::Error>
    where
        S: KvStore,
    {
        let batch_limits = match self.backend {
            StorageBackend::RocksDb | StorageBackend::Fjall => DEFAULT_BATCH_LIMITS,
            StorageBackend::Redb => REDB_BATCH_LIMITS,
        };
        open_derived_index_store_on_worker(store, batch_limits, self.epoch)
    }
}

pub(crate) struct TxIndexSpawn {
    spec: bitcoin_rs_index::runtime::DerivedIndexOpenSpec,
    generation: bitcoin_rs_index::runtime::Generation,
    block_source: bitcoin_rs_index::runtime::IndexBlockSource,
    body_source: Arc<dyn BlockBodySource>,
    wake_rx: Receiver<()>,
    recovery_reporter: Arc<crate::recovery_reporter::RecoveryReporter>,
}

#[cfg(test)]
#[path = "../tests/unit/state/tests/mod.rs"]
mod tests;
