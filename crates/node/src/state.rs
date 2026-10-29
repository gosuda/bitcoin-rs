use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use bitcoin_rs_chain::BlockBodySource;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chainstate::events::ChainEventPublisher;
#[cfg(test)]
pub(crate) use bitcoin_rs_chainstate::recovery::ResumeSource;
use bitcoin_rs_index::runtime::DEFAULT_BATCH_LIMITS;
use bitcoin_rs_index::runtime::OpenDerivedIndex;
use bitcoin_rs_index::runtime::REDB_BATCH_LIMITS;
use bitcoin_rs_index::runtime::open_derived_index_store_on_worker;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_rpc::context::PruneService;
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_storage::StorageBackend;
use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
use parking_lot::Mutex;
#[cfg(any(test, feature = "test-seam"))]
use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use storage::NodeStorage;
use storage::StoredBlockBodySource;

mod data_dir_lock;

#[cfg(feature = "pool")]
pub(crate) fn lock_pool_directory(
    path: &std::path::Path,
) -> Result<bitcoin_rs_storage::StoreGuard> {
    Ok(Arc::new(data_dir_lock::DataDirLock::acquire(path)?))
}
mod index;
mod open;
mod storage;

pub use data_dir_lock::DataDirLockError;

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

pub(crate) const P2P_OUTBOUND_FULL_RELAY_SLOTS: usize = 8;

pub(crate) const P2P_OUTBOUND_BLOCK_RELAY_SLOTS: usize = 2;

pub(crate) const INBOUND_BLOCK_CHANNEL_LIMIT: usize = 512;

pub(crate) const INBOUND_TX_CHANNEL_LIMIT: usize = 1_024;

pub(crate) const PACKAGE_INGRESS_MAX_BYTES: u64 =
    1_024 * bitcoin_rs_mempool::standardness::MAX_PACKAGE_WEIGHT;

const _: () = assert!(PACKAGE_INGRESS_MAX_BYTES == 413_696_000);
const _: () = assert!(INBOUND_TX_CHANNEL_LIMIT == 1_024);

pub struct NodeState {
    config: NodeConfig,
    #[cfg(test)]
    resume_source: ResumeSource,
    storage: NodeStorage,
    derived_index: index::DerivedIndexHost,
    prune_service: Option<Arc<dyn PruneService>>,
    mempool_gateway: Arc<bitcoin_rs_mempool::MempoolGateway>,
    p2p: Arc<bitcoin_rs_p2p::P2pService>,
    inbound_tx_tx: Sender<bitcoin_rs_p2p::InboundBody>,
    inbound_tx_rx: Mutex<Option<Receiver<bitcoin_rs_p2p::InboundBody>>>,
    package_capacity: bitcoin_rs_p2p::PackageCapacity,
    transition: bitcoin_rs_chain::TransitionDomain,
    chainstate: Arc<bitcoin_rs_chainstate::Chainstate>,
    followers: crate::chain_effects::ChainFollowers,
    sync: Arc<crate::BlockSync>,
    recovery_reporter: Arc<storage::RecoveryReporter>,
    pub(crate) snapshots: Arc<crate::snapshot::SnapshotControl>,
    block_announce_rx: Mutex<Option<bitcoin_rs_p2p::BlockAnnounceReceiver>>,
}

impl Drop for NodeState {
    fn drop(&mut self) {
        let _admission = self.chainstate.close();
        self.storage.retention().shutdown();
    }
}

impl NodeState {
    #[must_use]
    pub const fn config(&self) -> &NodeConfig {
        &self.config
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.config.data_dir
    }

    #[cfg(test)]
    pub(crate) const fn resume_source(&self) -> ResumeSource {
        self.resume_source
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub const fn storage_kind(&self) -> &'static str {
        self.storage.kind()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[doc(hidden)]
    #[must_use]
    pub fn undo_store(&self) -> Arc<dyn bitcoin_rs_chainstate::UndoStore> {
        self.storage.undo_store()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[doc(hidden)]
    #[must_use]
    pub fn durable_head(&self) -> Arc<dyn bitcoin_rs_storage::DurableHeadStore> {
        self.storage.durable_head()
    }

    #[must_use]
    pub fn prune_service(&self) -> Option<Arc<dyn PruneService>> {
        self.prune_service.as_ref().map(Arc::clone)
    }

    #[must_use]
    pub(crate) fn zmq_publisher(&self) -> Arc<dyn crate::ZmqPublisher> {
        self.followers.zmq_publisher()
    }

    #[must_use]
    pub fn mempool_reader(&self) -> bitcoin_rs_mempool::MempoolReader {
        self.mempool_gateway.reader()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn mempool(&self) -> Arc<RwLock<Mempool>> {
        Arc::clone(self.mempool_gateway.pool())
    }

    #[must_use]
    pub fn mempool_gateway(&self) -> Arc<bitcoin_rs_mempool::MempoolGateway> {
        Arc::clone(&self.mempool_gateway)
    }

    #[must_use]
    pub(crate) fn mining_generation_signal(&self) -> Arc<crate::mining::MiningGenerationSignal> {
        Arc::clone(self.followers.mining())
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn attach_mining_coordinator(&self, coordinator: &Arc<crate::MiningCoordinator>) {
        let signal = self.mining_generation_signal();
        let control: Arc<dyn bitcoin_rs_mining::MiningControl> = coordinator.clone();
        signal.attach(&control);
        let wake: Arc<dyn bitcoin_rs_mining::MempoolSequenceWake> = coordinator.clone();
        signal.attach_sequence_wake(&wake);
    }

    #[must_use]
    pub fn block_log_reader(&self) -> bitcoin_rs_index::BlockLogReader {
        self.followers.block_log_reader()
    }

    pub(crate) fn block_body_source(&self) -> Result<Arc<dyn BlockBodySource>> {
        let store = self
            .chainstate
            .block_body_store_handle()
            .context("running node has no block body store")?;
        Ok(Arc::new(StoredBlockBodySource::new(store)))
    }

    #[must_use]
    pub fn p2p(&self) -> Arc<bitcoin_rs_p2p::P2pService> {
        Arc::clone(&self.p2p)
    }

    #[must_use]
    pub fn peer_table(&self) -> Arc<bitcoin_rs_p2p::PeerTable> {
        self.p2p.table()
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn inbound_blocks_sender(&self) -> Sender<bitcoin_rs_p2p::InboundBlock> {
        self.p2p.inbound_blocks_sender()
    }

    #[must_use]
    pub(crate) fn recovery_reporter(&self) -> Arc<storage::RecoveryReporter> {
        Arc::clone(&self.recovery_reporter)
    }

    pub fn inbound_tx_sender(&self) -> Sender<bitcoin_rs_p2p::InboundBody> {
        self.inbound_tx_tx.clone()
    }

    #[must_use]
    pub fn take_inbound_tx_receiver(&self) -> Option<Receiver<bitcoin_rs_p2p::InboundBody>> {
        self.inbound_tx_rx.lock().take()
    }

    #[must_use]
    pub fn package_capacity(&self) -> bitcoin_rs_p2p::PackageCapacity {
        self.package_capacity.clone()
    }

    #[must_use]
    pub fn take_block_announce_receiver(&self) -> Option<bitcoin_rs_p2p::BlockAnnounceReceiver> {
        self.block_announce_rx.lock().take()
    }

    #[must_use]
    pub fn sync(&self) -> Arc<crate::BlockSync> {
        Arc::clone(&self.sync)
    }

    #[must_use]
    pub(crate) fn ibd(&self) -> Arc<bitcoin_rs_chain::InitialBlockDownload> {
        self.chainstate.ibd_latch()
    }

    #[must_use]
    pub fn shutdown_reader(&self) -> bitcoin_rs_chain::LatchReader {
        self.chainstate.shutdown_reader()
    }

    pub fn request_shutdown(&self) {
        self.chainstate.request_shutdown();
    }

    #[must_use]
    pub fn chainstate(&self) -> Arc<bitcoin_rs_chainstate::Chainstate> {
        Arc::clone(&self.chainstate)
    }

    #[must_use]
    pub fn stable_read(&self) -> bitcoin_rs_chain::StableRead {
        self.transition.stable_read()
    }

    #[must_use]
    pub fn chain_followers(&self) -> crate::chain_effects::ChainFollowers {
        self.followers.clone()
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn apply_block(
        &self,
        payload: &bitcoin_rs_primitives::BlockPayload,
    ) -> core::result::Result<TipSnapshot, crate::chain_effects::ConnectMutationError> {
        let outcome = self.followers.apply_connect(&self.chainstate, payload)?;
        Ok(outcome.tip)
    }

    pub fn publish_checkpoint(&self) -> Result<Option<u64>> {
        Ok(self.chainstate.publish_checkpoint()?)
    }

    pub fn start_chainstate_maintenance(&self) -> Result<std::thread::JoinHandle<()>> {
        self.chainstate.start_maintenance()
    }

    pub fn chainstates_summary(
        &self,
    ) -> Result<bitcoin_rs_chainstate::ChainstatesSummary, bitcoin_rs_chainstate::AssumeUtxoError>
    {
        self.snapshots.manager.chainstates_summary()
    }

    pub fn activate_assumeutxo_snapshot_file(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> anyhow::Result<()> {
        self.snapshots.import_native(path.as_ref())?;
        Ok(())
    }

    #[must_use]
    pub fn derived_index_query(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery>> {
        if !self.config.indexes.txindex {
            return None;
        }
        self.esplora_derived_index_query()
    }

    #[must_use]
    pub(crate) fn esplora_derived_index_query(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery>> {
        self.derived_index.adapter().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery> = adapter.clone();
            q
        })
    }

    pub(crate) fn historical_index_adapter(
        &self,
    ) -> Option<Arc<bitcoin_rs_index::runtime::DerivedIndexQueryAdapter>> {
        self.derived_index.adapter().cloned()
    }

    #[must_use]
    pub fn compact_filter_query(&self) -> Option<Arc<dyn bitcoin_rs_index::CompactFilterQuery>> {
        if !self.config.indexes.blockfilterindex {
            return None;
        }
        self.derived_index.adapter().map(|adapter| {
            let query: Arc<dyn bitcoin_rs_index::CompactFilterQuery> = adapter.clone();
            query
        })
    }

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

    pub fn start_index_workers(&mut self) -> anyhow::Result<()> {
        let history = self.storage.bounded_history();
        self.derived_index.start(&self.chainstate, history)
    }

    #[must_use]
    pub fn derived_index_status(&self) -> Arc<dyn bitcoin_rs_index::DerivedIndexCapabilitySource> {
        self.derived_index.status()
    }

    pub(crate) fn bounded_index_shutdown(&mut self, deadline: Duration) -> Result<()> {
        self.derived_index.shutdown(deadline)
    }

    #[cfg(test)]
    pub(crate) fn index_worker_joined(&self) -> Arc<AtomicBool> {
        self.derived_index.worker_joined()
    }
}

fn derived_index_capabilities(config: &NodeConfig) -> bitcoin_rs_index::IndexCapabilities {
    config
        .indexes
        .script_index
        .enabled_capabilities(config.indexes.txindex)
        .with_compact_filters(config.indexes.blockfilterindex)
}

fn build_derived_index_open_spec(
    config: &NodeConfig,
    txindex_cache_bytes: u64,
    epoch: u64,
    guard: &bitcoin_rs_storage::StoreGuard,
    seed_slot: Option<bitcoin_rs_utxo::SeedOfferCell>,
) -> Result<Option<bitcoin_rs_index::runtime::DerivedIndexOpenSpec>> {
    let enabled = derived_index_capabilities(config);
    if enabled.is_empty() {
        return Ok(None);
    }
    if config.storage.prune_target_mb > 0 {
        bail!("transaction, script and compact-filter indexing are not compatible with -prune");
    }
    let canonical_data_root = config
        .data_dir
        .canonicalize()
        .unwrap_or_else(|_| config.data_dir.clone());
    let backend = config.storage.backend;
    let cache_bytes = txindex_cache_bytes;
    let guard = Arc::clone(guard);
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
                &guard,
                DerivedIndexComposer { backend, epoch },
            )
        }),
        utxo: None,
        chain_transition: None,
        bundle: index_bundle_directive(config)?,
        seed_slot,
    }))
}

fn index_bundle_directive(
    config: &NodeConfig,
) -> Result<bitcoin_rs_index::portable::IndexBundleDirective> {
    use bitcoin_rs_index::portable::{IndexBundleDirective, IndexBundleRequest};
    let request = |dir: &std::path::PathBuf| IndexBundleRequest {
        dir: dir.clone(),
        network: config.network,
    };
    match (&config.indexes.bundle_import, &config.indexes.bundle_export) {
        (None, None) => Ok(IndexBundleDirective::None),
        (Some(dir), None) => Ok(IndexBundleDirective::Restore(request(dir))),
        (None, Some(dir)) => Ok(IndexBundleDirective::Export(request(dir))),
        (Some(_), Some(_)) => {
            bail!("--index-bundle-import and --index-bundle-export are mutually exclusive")
        }
    }
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

struct TxIndexSpawn {
    spec: bitcoin_rs_index::runtime::DerivedIndexOpenSpec,
    generation: bitcoin_rs_index::runtime::Generation,
    body_source: Arc<dyn BlockBodySource>,
    wake_rx: Receiver<()>,
    recovery_reporter: Arc<storage::RecoveryReporter>,
}

#[cfg(test)]
mod tests;
