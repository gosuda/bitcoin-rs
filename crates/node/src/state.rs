use crate::NodeConfig;
use crate::config::ConfigError;
use crate::run::RunError;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_execution::chain::TipSnapshot;
use bitcoin_rs_execution::events::ChainEventPublisher;
#[cfg(test)]
pub(crate) use bitcoin_rs_execution::recovery::ResumeSource;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_projection::runtime::DEFAULT_BATCH_LIMITS;
use bitcoin_rs_projection::runtime::OpenDerivedIndex;
use bitcoin_rs_projection::runtime::open_derived_index_store_with_scratch;
use bitcoin_rs_serving::context::PruneService;
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_storage::StorageBackend;
use bitcoin_rs_storage::block_body::BlockBodySource;
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
) -> core::result::Result<bitcoin_rs_storage::StoreGuard, DataDirLockError> {
    Ok(Arc::new(data_dir_lock::DataDirLock::acquire(path)?))
}
mod index;
pub(crate) mod open;
mod storage;

pub use data_dir_lock::DataDirLockError;
pub use index::IndexWorkerError;

struct IndexChainCursorSource(Arc<ChainEventPublisher>);

impl bitcoin_rs_projection::reconcile::ChainCursorSource for IndexChainCursorSource {
    fn cursor(&self) -> bitcoin_rs_projection::reconcile::ConsumerCursor {
        let snapshot = self.0.snapshot();
        bitcoin_rs_projection::reconcile::ConsumerCursor {
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
pub(crate) const TXINDEX_NAMESPACE: &str = "txindex";

pub(crate) const INBOUND_TX_CHANNEL_LIMIT: usize = 1_024;

pub(crate) const PACKAGE_INGRESS_MAX_BYTES: u64 =
    1_024 * bitcoin_rs_mempool::standardness::MAX_PACKAGE_WEIGHT;

mod bounds_assert {
    use super::*;
    const _: () = assert!(PACKAGE_INGRESS_MAX_BYTES == 413_696_000);
    const _: () = assert!(INBOUND_TX_CHANNEL_LIMIT == 1_024);
}

pub struct NodeState {
    config: NodeConfig,
    #[cfg(test)]
    resume_source: ResumeSource,
    storage: NodeStorage,
    derived_index: index::DerivedIndexHost,
    prune_service: Option<Arc<dyn PruneService>>,
    mempool_gateway: Arc<bitcoin_rs_mempool::MempoolGateway>,
    p2p: Arc<bitcoin_rs_wire::P2pService>,
    inbound_tx_tx: Sender<crate::p2p::tx_policy::ingress::InboundBody>,
    inbound_tx_rx: Mutex<Option<Receiver<crate::p2p::tx_policy::ingress::InboundBody>>>,
    package_capacity: crate::p2p::tx_policy::ingress::PackageCapacity,
    pub tx_policy: Arc<crate::p2p::tx_policy::NodeTxPolicy>,
    transition: bitcoin_rs_execution::chain::TransitionDomain,
    chainstate: Arc<bitcoin_rs_execution::Chainstate>,
    followers: crate::chain_effects::ChainFollowers,
    sync: Arc<crate::p2p::sync::BlockSync>,
    recovery_reporter: Arc<storage::RecoveryReporter>,
    pub(crate) snapshots: Arc<crate::snapshot::SnapshotControl>,
    block_announce_rx: Mutex<Option<crate::p2p::block_announce::BlockAnnounceReceiver>>,
    shutdown: Arc<bitcoin_rs_consensus::latch::LatchWriter>,
    _p2p_shutdown_guard: bitcoin_rs_consensus::latch::HookGuard,
    block_memory: Arc<bitcoin_rs_wire::inbound::block_memory::BlockMemory>,
    #[cfg(any(test, feature = "test-seam"))]
    budget: Arc<crate::budget::NodeBudget>,
}

impl Drop for NodeState {
    fn drop(&mut self) {
        self.shutdown.trigger();
        if let Err(error) = self
            .derived_index
            .shutdown(core::time::Duration::from_secs(5))
        {
            tracing::warn!(%error, "failed to shut down derived index during node state drop");
        }
        self.chainstate.request_shutdown();
        let _admission = self.chainstate.close();
        self.p2p.shutdown();
        if let Err(error) = self.p2p.join() {
            tracing::warn!(%error, "failed to join p2p workers during node state drop");
        }
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

    #[must_use]
    pub fn block_memory(&self) -> Arc<bitcoin_rs_wire::inbound::block_memory::BlockMemory> {
        Arc::clone(&self.block_memory)
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[doc(hidden)]
    #[must_use]
    pub fn budget(&self) -> Arc<crate::budget::NodeBudget> {
        Arc::clone(&self.budget)
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
    pub fn undo_store(&self) -> Arc<dyn bitcoin_rs_execution::UndoStore> {
        self.storage.undo_store()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[doc(hidden)]
    #[must_use]
    pub fn durable_head(&self) -> Arc<dyn bitcoin_rs_storage::DurableHeadStore> {
        self.storage.durable_head()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[doc(hidden)]
    #[must_use]
    pub fn coins(&self) -> Arc<bitcoin_rs_storage::CoinStore> {
        self.storage.coins()
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
        let control: Arc<dyn bitcoin_rs_serving::mining::MiningControl> = coordinator.clone();
        signal.attach(&control);
        let wake: Arc<dyn bitcoin_rs_serving::mining::MempoolSequenceWake> = coordinator.clone();
        signal.attach_sequence_wake(&wake);
    }

    #[must_use]
    pub fn block_log_reader(&self) -> bitcoin_rs_projection::BlockLogReader {
        self.followers.block_log_reader()
    }

    pub(crate) fn block_body_source(
        &self,
    ) -> core::result::Result<Arc<dyn BlockBodySource>, RunError> {
        let store = self
            .chainstate
            .block_body_store_handle()
            .ok_or(RunError::NoBlockBodyStore)?;
        Ok(Arc::new(StoredBlockBodySource::new(store)))
    }

    #[must_use]
    pub fn p2p(&self) -> Arc<bitcoin_rs_wire::P2pService> {
        Arc::clone(&self.p2p)
    }

    #[must_use]
    pub fn peer_table(&self) -> Arc<bitcoin_rs_wire::PeerTable> {
        self.p2p.table()
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn inbound_blocks_sender(&self) -> Sender<bitcoin_rs_wire::InboundBlock> {
        self.p2p.inbound_blocks_sender()
    }

    #[must_use]
    pub(crate) fn recovery_reporter(&self) -> Arc<storage::RecoveryReporter> {
        Arc::clone(&self.recovery_reporter)
    }

    pub fn inbound_tx_sender(&self) -> Sender<crate::p2p::tx_policy::ingress::InboundBody> {
        self.inbound_tx_tx.clone()
    }

    #[must_use]
    pub fn take_inbound_tx_receiver(
        &self,
    ) -> Option<Receiver<crate::p2p::tx_policy::ingress::InboundBody>> {
        self.inbound_tx_rx.lock().take()
    }

    #[must_use]
    pub fn package_capacity(&self) -> crate::p2p::tx_policy::ingress::PackageCapacity {
        self.package_capacity.clone()
    }

    #[must_use]
    pub fn take_block_announce_receiver(
        &self,
    ) -> Option<crate::p2p::block_announce::BlockAnnounceReceiver> {
        self.block_announce_rx.lock().take()
    }

    #[must_use]
    pub fn sync(&self) -> Arc<crate::p2p::sync::BlockSync> {
        Arc::clone(&self.sync)
    }

    #[must_use]
    pub(crate) fn ibd(&self) -> Arc<bitcoin_rs_execution::chain::InitialBlockDownload> {
        self.chainstate.ibd_latch()
    }

    #[must_use]
    pub fn shutdown_reader(&self) -> bitcoin_rs_consensus::latch::LatchReader {
        self.shutdown.reader()
    }

    #[must_use]
    pub fn shutdown_writer(&self) -> Arc<bitcoin_rs_consensus::latch::LatchWriter> {
        Arc::clone(&self.shutdown)
    }

    pub fn request_shutdown(&self) {
        self.shutdown.trigger();
        self.chainstate.request_shutdown();
    }

    #[must_use]
    pub fn chainstate(&self) -> Arc<bitcoin_rs_execution::Chainstate> {
        Arc::clone(&self.chainstate)
    }

    #[must_use]
    pub fn stable_read(&self) -> bitcoin_rs_execution::chain::StableRead {
        self.transition.stable_read()
    }

    #[must_use]
    pub fn chain_followers(&self) -> crate::chain_effects::ChainFollowers {
        self.followers.clone()
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn apply_block(
        &self,
        payload: &bitcoin_rs_consensus::primitives::BlockImage,
    ) -> core::result::Result<TipSnapshot, crate::chain_effects::ConnectMutationError> {
        let outcome = self.followers.apply_connect(&self.chainstate, payload)?;
        Ok(outcome.tip)
    }

    pub fn publish_checkpoint(
        &self,
    ) -> core::result::Result<Option<u64>, bitcoin_rs_execution::CheckpointError> {
        self.chainstate.publish_checkpoint()
    }

    pub fn start_chainstate_maintenance(
        &self,
    ) -> core::result::Result<std::thread::JoinHandle<()>, bitcoin_rs_execution::MaintenanceError>
    {
        self.chainstate.start_maintenance()
    }

    pub fn chainstates_summary(
        &self,
    ) -> Result<bitcoin_rs_execution::ChainstatesSummary, bitcoin_rs_execution::AssumeUtxoError>
    {
        self.snapshots.manager.chainstates_summary()
    }

    pub fn import_manifest(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> core::result::Result<crate::snapshot::SnapshotImport, crate::snapshot::SnapshotImportError>
    {
        self.snapshots.import_manifest(path.as_ref())
    }

    pub fn three_positions(
        &self,
    ) -> core::result::Result<
        crate::snapshot::ThreePositions,
        bitcoin_rs_serving::context::SnapshotControlError,
    > {
        self.snapshots.three_positions()
    }

    #[must_use]
    pub fn derived_index_query(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_serving::context::DerivedIndexQuery>> {
        if !self.config.indexes.txindex {
            return None;
        }
        self.esplora_derived_index_query()
    }

    #[must_use]
    pub(crate) fn esplora_derived_index_query(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_serving::context::DerivedIndexQuery>> {
        self.derived_index.adapter().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_serving::context::DerivedIndexQuery> = adapter.clone();
            q
        })
    }

    pub(crate) fn historical_index_adapter(
        &self,
    ) -> Option<Arc<bitcoin_rs_projection::runtime::DerivedIndexQueryAdapter>> {
        self.derived_index.adapter().cloned()
    }

    #[must_use]
    pub fn compact_filter_query(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_projection::CompactFilterQuery>> {
        if !self.config.indexes.blockfilterindex {
            return None;
        }
        self.derived_index.adapter().map(|adapter| {
            let query: Arc<dyn bitcoin_rs_projection::CompactFilterQuery> = adapter.clone();
            query
        })
    }

    #[must_use]
    pub fn script_index_query(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_serving::context::ScriptIndexQuery>> {
        if !self.config.indexes.script_index.is_enabled() {
            return None;
        }
        self.derived_index.adapter().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_serving::context::ScriptIndexQuery> = adapter.clone();
            q
        })
    }

    pub fn start_index_workers(&mut self) -> core::result::Result<(), IndexWorkerError> {
        let history = self.storage.bounded_history();
        let manager = Arc::clone(&self.snapshots.manager);
        let historical_verified = Arc::new(move || {
            manager
                .status()
                .map(|status| match status {
                    bitcoin_rs_execution::AssumeUtxoDiskStatus::Validating {
                        historical_height,
                        historical_hash,
                        ..
                    } => Some((historical_height, historical_hash)),
                    _ => None,
                })
                .map_err(|error| {
                    bitcoin_rs_projection::TxQueryError::Storage(error.to_string().into())
                })
        });
        self.derived_index
            .start(&self.chainstate, history, historical_verified)
    }

    #[must_use]
    pub fn derived_index_status(
        &self,
    ) -> Arc<dyn bitcoin_rs_projection::DerivedIndexCapabilitySource> {
        self.derived_index.status()
    }

    pub(crate) fn bounded_index_shutdown(
        &mut self,
        deadline: Duration,
    ) -> core::result::Result<(), IndexWorkerError> {
        self.derived_index.shutdown(deadline)
    }

    #[cfg(test)]
    pub(crate) fn index_worker_joined(&self) -> Arc<AtomicBool> {
        self.derived_index.worker_joined()
    }
}

fn derived_index_capabilities(config: &NodeConfig) -> bitcoin_rs_projection::IndexCapabilities {
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
    budget: &Arc<crate::budget::NodeBudget>,
) -> core::result::Result<Option<bitcoin_rs_projection::runtime::DerivedIndexOpenSpec>, ConfigError>
{
    let enabled = derived_index_capabilities(config);
    if enabled.is_empty() {
        return Ok(None);
    }
    if config.storage.prune_target_mb > 0 {
        return Err(ConfigError::PruneWithIndexes);
    }
    let canonical_data_root = config
        .data_dir
        .canonicalize()
        .unwrap_or_else(|_| config.data_dir.clone());
    let backend = config.storage.backend;
    let cache_bytes = txindex_cache_bytes;
    let guard = Arc::clone(guard);
    let seal_scratch = config.data_dir.join("seal-scratch");
    Ok(Some(bitcoin_rs_projection::runtime::DerivedIndexOpenSpec {
        scripthash_limit: config.indexes.scripthash_limit,
        data_dir: config.data_dir.clone(),
        namespace: TXINDEX_NAMESPACE,
        storage_backend: config.storage.backend,
        epoch,
        enabled,
        rollback_rebuild_cutover: bitcoin_rs_projection::runtime::DEFAULT_ROLLBACK_REBUILD_CUTOVER,
        canonical_data_root,
        open_store: Arc::new(move |dir| {
            crate::storage_backend::open_txindex(
                backend,
                dir,
                Some(cache_bytes),
                &guard,
                DerivedIndexComposer {
                    backend,
                    epoch,
                    seal_scratch: seal_scratch.clone(),
                },
            )
        }),
        bundle: index_bundle_directive(config)?,
        facts_rx: None,
        facts_charge: None,
        query_charge: Some(bitcoin_rs_storage::budget::ChargeHandle::new(
            budget.clone(),
            bitcoin_rs_storage::budget::BudgetOwner::QueryViews,
        )),
        facts_gap: None,
        cpu: None,
    }))
}

fn index_bundle_directive(
    config: &NodeConfig,
) -> core::result::Result<bitcoin_rs_projection::portable::IndexBundleDirective, ConfigError> {
    use bitcoin_rs_projection::portable::{IndexBundleDirective, IndexBundleRequest};
    let request = |dir: &std::path::PathBuf| IndexBundleRequest {
        dir: dir.clone(),
        network: config.network,
    };
    match (&config.indexes.bundle_import, &config.indexes.bundle_export) {
        (None, None) => match config.assumeutxo_manifest.as_deref() {
            Some(path) => {
                manifest_attach_directive(path, config.network, derived_index_capabilities(config))
            }
            None => Ok(IndexBundleDirective::None),
        },
        (Some(dir), None) => Ok(IndexBundleDirective::Restore(request(dir))),
        (None, Some(dir)) => Ok(IndexBundleDirective::Export(request(dir))),
        (Some(_), Some(_)) => Err(ConfigError::IndexBundleImportExportExclusive),
    }
}
fn manifest_attach_directive(
    manifest_path: &std::path::Path,
    network: bitcoin_rs_consensus::primitives::Network,
    enabled: bitcoin_rs_projection::IndexCapabilities,
) -> Result<bitcoin_rs_projection::portable::IndexBundleDirective, ConfigError> {
    use bitcoin_rs_consensus::primitives::IndexArtifactCapability;
    use bitcoin_rs_execution::manifest::CapabilityTrust;
    use bitcoin_rs_projection::IndexCapability;
    use bitcoin_rs_projection::portable::{IndexBundleDirective, ManifestArtifactTarget};
    let bytes = match read_bounded_manifest(manifest_path) {
        Ok(b) => b,
        Err(err) => {
            tracing::debug!(path = %manifest_path.display(), %err, "could not read manifest for index directive");
            return Ok(IndexBundleDirective::None);
        }
    };
    let manifest = match bitcoin_rs_execution::manifest::SnapshotManifest::parse(&bytes) {
        Ok(m) => m,
        Err(err) => {
            tracing::debug!(path = %manifest_path.display(), %err, "could not parse manifest for index directive");
            return Ok(IndexBundleDirective::None);
        }
    };
    if manifest.schema != bitcoin_rs_projection::index_format_version() {
        tracing::debug!(
            path = %manifest_path.display(),
            manifest_schema = manifest.schema,
            "manifest schema differs from the node index format; no index artifact attach"
        );
        return Ok(IndexBundleDirective::None);
    }
    let Some(anchor) = network.assume_utxo_for_height(manifest.base_height) else {
        return Ok(IndexBundleDirective::None);
    };
    let genesis = network.genesis_block_hash().to_le_bytes();
    let Ok(trust) = manifest.verify_against_anchor(network, genesis, anchor) else {
        return Ok(IndexBundleDirective::None);
    };
    let dir = manifest_path.parent().unwrap_or(manifest_path);
    let mut attachments = Vec::new();
    for (index, cap_trust) in trust.capability_trust.iter().enumerate() {
        let CapabilityTrust::Trusted(_) = cap_trust else {
            continue;
        };
        let Some(capability) = IndexArtifactCapability::from_index(index) else {
            continue;
        };
        let Ok(artifact_path) = manifest.artifact_path(dir, index + 1) else {
            continue;
        };
        let target = Box::new(ManifestArtifactTarget {
            artifact_path,
            base_height: manifest.base_height,
            base_hash: manifest.base_hash,
            floor: manifest.coverage[index].unwrap_or(0),
            network,
            index_format: manifest.schema,
            sha256: manifest.artifact_sha256(capability),
            size_bytes: manifest.artifact_size(capability),
            chain_tx_count: anchor.chain_tx_count,
        });
        let (projection, directive) = match capability {
            IndexArtifactCapability::TxLookup => (
                IndexCapability::TxLookup,
                IndexBundleDirective::AttachManifestArtifact(target),
            ),
            IndexArtifactCapability::ScriptHistory => (
                IndexCapability::ScriptHistory,
                IndexBundleDirective::AttachManifestScriptHistory(target),
            ),
            IndexArtifactCapability::CompactFilters => (
                IndexCapability::CompactFilters,
                IndexBundleDirective::AttachManifestCompactFilters(target),
            ),
            IndexArtifactCapability::ScriptLive => continue,
        };
        if enabled.contains(projection) {
            attachments.push(directive);
        }
    }
    Ok(IndexBundleDirective::Manifest(attachments))
}

fn read_bounded_manifest(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    const MAX_MANIFEST_BYTES: u64 = 1 << 20;
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_MANIFEST_BYTES) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "manifest is larger than 1 MiB",
        ));
    }
    Ok(bytes)
}

struct DerivedIndexComposer {
    backend: StorageBackend,
    epoch: u64,
    seal_scratch: std::path::PathBuf,
}

impl crate::storage_backend::StoreConsumer for DerivedIndexComposer {
    type Output = OpenDerivedIndex;
    type Error = bitcoin_rs_projection::runtime::DerivedIndexWorkerError;

    fn consume<S>(self, store: Arc<S>) -> Result<Self::Output, Self::Error>
    where
        S: KvStore,
    {
        let _ = self.backend;
        let batch_limits = DEFAULT_BATCH_LIMITS;
        open_derived_index_store_with_scratch(store, batch_limits, self.epoch, self.seal_scratch)
    }
}

struct TxIndexSpawn {
    spec: bitcoin_rs_projection::runtime::DerivedIndexOpenSpec,
    generation: bitcoin_rs_projection::runtime::Generation,
    body_source: Arc<dyn BlockBodySource>,
    wake_rx: Receiver<()>,
    recovery_reporter: Arc<storage::RecoveryReporter>,
}

#[cfg(test)]
mod tests;
