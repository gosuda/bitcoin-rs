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
                let path = config.data_dir.join(path);
                Ok(manifest_attach_directive(
                    &path,
                    config.network,
                    derived_index_capabilities(config),
                ))
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
) -> bitcoin_rs_projection::portable::IndexBundleDirective {
    use bitcoin_rs_consensus::primitives::IndexArtifactCapability;
    use bitcoin_rs_execution::manifest::CapabilityTrust;
    use bitcoin_rs_projection::IndexCapability;
    use bitcoin_rs_projection::portable::{IndexBundleDirective, ManifestArtifactTarget};
    let bytes = match crate::snapshot::read_bounded_manifest(manifest_path) {
        Ok(b) => b,
        Err(err) => {
            tracing::debug!(path = %manifest_path.display(), %err, "could not read manifest for index directive");
            return IndexBundleDirective::None;
        }
    };
    let manifest = match bitcoin_rs_execution::manifest::SnapshotManifest::parse(&bytes) {
        Ok(m) => m,
        Err(err) => {
            tracing::debug!(path = %manifest_path.display(), %err, "could not parse manifest for index directive");
            return IndexBundleDirective::None;
        }
    };
    if manifest.schema != bitcoin_rs_projection::index_format_version() {
        tracing::debug!(
            path = %manifest_path.display(),
            manifest_schema = manifest.schema,
            "manifest schema differs from the node index format; no index artifact attach"
        );
        return IndexBundleDirective::None;
    }
    let Some(anchor) = network.assume_utxo_for_height(manifest.base_height) else {
        return IndexBundleDirective::None;
    };
    let genesis = network.genesis_block_hash().to_le_bytes();
    let Ok(trust) = manifest.verify_against_anchor(network, genesis, anchor) else {
        return IndexBundleDirective::None;
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
    IndexBundleDirective::Manifest(attachments)
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
mod tests {
    mod checkpoint {
        use super::*;
        use crate::test_support::TestError;
        use sonic_rs::JsonValueTrait as _;

        use bitcoin_rs_consensus::primitives::BlockImage;

        #[test]
        fn the_chain_transaction_count_survives_a_checkpoint_restart() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();

            let expected = {
                let state = NodeState::open(config.clone(), None)?;
                assert_eq!(
                    applied_chain_tx_count(&state),
                    bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN,
                    "a node that has applied nothing cannot know the count"
                );

                let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
                let genesis_tx_count = u64::try_from(genesis.txs.len())?;
                let _tip = state.apply_block(&BlockImage::from_local(genesis))?;
                let counted = applied_chain_tx_count(&state);
                assert_eq!(
                    counted,
                    bitcoin_rs_execution::chain::ChainTxCount::established(genesis_tx_count),
                    "genesis establishes the count"
                );

                assert!(state.publish_checkpoint()?.is_some());
                counted
            };

            let resumed = NodeState::open(config, None)?;
            assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
            assert!(
                resumed.block_log_reader().read().is_empty(),
                "the record log really does start empty; the count cannot come from it"
            );
            assert_eq!(applied_chain_tx_count(&resumed), expected);
            Ok(())
        }

        #[test]
        fn clean_checkpoint_reopens_and_applies_the_next_block() -> Result<(), TestError> {
            fn stable_hash(
                view: &bitcoin_rs_storage::utxo::UtxoSetView<'_>,
            ) -> Result<
                bitcoin_rs_consensus::primitives::Hash256,
                bitcoin_rs_storage::utxo::UtxoError,
            > {
                view.hash_serialized_3()
            }
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir.clone();
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;
            let genesis = BlockImage::from_local(
                bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
            );
            let genesis_tip = state.apply_block(&genesis)?;
            let expected_utxo_hash = state
                .chainstate()
                .utxo_reader()
                .with_stable_view(stable_hash)??;
            let expected_stats = state.chainstate().coin_stats_handle().snapshot();
            assert!(state.publish_checkpoint()?.is_some());
            drop(state);

            let mut reopen_config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            reopen_config.data_dir = data_dir.clone();
            reopen_config.p2p.listen.clear();
            let resumed = NodeState::open(reopen_config.clone(), None)?;
            assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
            let applied = resumed
                .chainstate()
                .applied_tip_snapshot()
                .ok_or_else(|| std::io::Error::other("checkpoint did not publish applied tip"))?;
            assert_eq!(applied.height, genesis_tip.height);
            assert_eq!(applied.hash, genesis_tip.hash);
            assert_eq!(
                resumed.chainstate().header_tip().as_deref(),
                Some(applied.as_ref())
            );
            assert_eq!(
                resumed
                    .chainstate()
                    .utxo_reader()
                    .with_stable_view(stable_hash)??,
                expected_utxo_hash
            );
            assert_eq!(
                resumed.chainstate().coin_stats_handle().snapshot(),
                expected_stats
            );
            assert!(resumed.block_log_reader().read().is_empty());
            assert!(resumed.mempool().read().is_empty());

            let next = BlockImage::from_local(regtest_fixture::mined_regtest_child_at(
                genesis.block_hash(),
                1,
            )?);
            let next_tip = resumed.apply_block(&next)?;
            assert_eq!(next_tip.height, 1);
            assert_eq!(
                next_tip.hash.to_le_bytes(),
                next.block_hash().0.to_le_bytes()
            );
            let listener_after_apply = resumed.chainstate().coin_stats_handle().snapshot();
            let mut rescanned = resumed
                .chainstate()
                .utxo_reader()
                .with_stable_view(|view| {
                    bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, next_tip.height, true)
                })??;
            rescanned.tx_count = listener_after_apply.tx_count;
            assert_eq!(
                listener_after_apply.total_amount, rescanned.total_amount,
                "checkpoint resume must keep rolling CoinStats attached to UTXO commits"
            );
            let _ = resumed.publish_checkpoint()?;

            let root = data_dir.join("chainstate-checkpoints");
            let current: sonic_rs::Value =
                sonic_rs::from_slice(&std::fs::read(root.join("CURRENT"))?)?;
            let directory = current
                .get("directory")
                .and_then(|value| value.as_str())
                .ok_or_else(|| std::io::Error::other("CURRENT has no generation directory"))?;
            let manifest_bytes = std::fs::read(root.join(directory).join("manifest-v1.json"))?;
            let manifest: sonic_rs::Value = sonic_rs::from_slice(&manifest_bytes)?;
            assert!(manifest.get("utxo").is_none_or(|v| v.is_null()));
            let inspection_dir = tempfile::tempdir()?;
            for entry in std::fs::read_dir(root.join(directory).join("chainstate"))? {
                let entry = entry?;
                std::fs::copy(entry.path(), inspection_dir.path().join(entry.file_name()))?;
            }
            let image = bitcoin_rs_storage::open_checkpoint_store(inspection_dir.path())?;
            let image_coins = image
                .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
                .collect::<Result<Vec<_>, _>>()?;
            drop(image);
            let committed_coins = resumed
                .chainstate()
                .coins()
                .scan_snapshot()?
                .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
                .collect::<Result<Vec<_>, _>>()?;
            assert!(
                !committed_coins.is_empty(),
                "the committed set must hold the next block's coinbase"
            );
            assert_eq!(
                image_coins, committed_coins,
                "the checkpoint generation must carry exactly the committed coin rows"
            );
            drop(resumed);

            let resumed_again = NodeState::open(reopen_config, None)?;
            assert_eq!(resumed_again.resume_source(), ResumeSource::Checkpoint);
            assert_eq!(
                resumed_again.chainstate().coin_stats_handle().snapshot(),
                rescanned
            );
            Ok(())
        }

        #[test]
        fn clean_checkpoint_lifecycle_is_backend_neutral() -> Result<(), TestError> {
            let backends: Vec<&str> = vec!["rocksdb"];

            for backend in backends {
                let dir = tempfile::tempdir()?;
                let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
                config.data_dir = dir.path().join(backend);
                config.storage.backend = match backend {
                    "rocksdb" => bitcoin_rs_storage::StorageBackend::RocksDb,
                    _ => {
                        return Err(TestError::ExpectationFailed(
                            "a compiled-in storage backend",
                        ));
                    }
                };
                config.p2p.listen.clear();
                let genesis = BlockImage::from_local(
                    bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
                );
                let state = NodeState::open(config.clone(), None)?;
                state.apply_block(&genesis)?;
                let _ = state.publish_checkpoint()?;
                drop(state);

                let resumed = NodeState::open(config, None)?;
                assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
                resumed.apply_block(&BlockImage::from_local(
                    regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?,
                ))?;
            }
            Ok(())
        }

        #[test]
        fn durable_head_replay_restores_state_above_checkpoint() -> Result<(), TestError> {
            fn stable_hash(
                view: &bitcoin_rs_storage::utxo::UtxoSetView<'_>,
            ) -> Result<
                bitcoin_rs_consensus::primitives::Hash256,
                bitcoin_rs_storage::utxo::UtxoError,
            > {
                view.hash_serialized_3()
            }

            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("checkpoint-resume");
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir;
            config.p2p.listen.clear();

            let genesis = BlockImage::from_local(
                bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
            );
            let first = NodeState::open(config.clone(), None)?;
            first.apply_block(&genesis)?;
            let _ = first.publish_checkpoint()?;
            drop(first);

            let base = NodeState::open(config.clone(), None)?;
            assert_eq!(base.resume_source(), ResumeSource::Checkpoint);
            let child = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
            let expected_tip = base.apply_block(&BlockImage::from_local(child))?;
            let expected_utxo = base
                .chainstate()
                .utxo_handle()
                .with_stable_view(stable_hash)?;
            let expected_stats = base.chainstate().coin_stats_handle().snapshot();
            let expected_tx_count = expected_tip.chain_tx_count;
            drop(base);

            let resumed = NodeState::open(config, None)?;
            assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
            let resumed_tip = resumed
                .chainstate()
                .applied_tip_snapshot()
                .ok_or_else(|| std::io::Error::other("checkpoint replay did not publish a tip"))?;
            assert_eq!(resumed_tip.as_ref(), &expected_tip);
            assert_eq!(
                resumed
                    .chainstate()
                    .utxo_handle()
                    .with_stable_view(stable_hash)?,
                expected_utxo
            );
            assert_eq!(
                resumed.chainstate().coin_stats_handle().snapshot(),
                expected_stats
            );
            assert_eq!(resumed_tip.chain_tx_count, expected_tx_count);
            Ok(())
        }

        #[test]
        fn publish_checkpoint_returns_none_when_no_applied_tip() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;
            assert_eq!(
                state.publish_checkpoint()?,
                None,
                "a node that applied no block has no tip to checkpoint"
            );
            Ok(())
        }

        #[test]
        fn publish_checkpoint_returns_generation_and_reopens() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir;
            config.p2p.listen.clear();
            let state = NodeState::open(config.clone(), None)?;
            let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            let tip = state.apply_block(&BlockImage::from_local(genesis))?;
            let generation = state.publish_checkpoint()?;
            assert!(
                generation.is_some_and(|published| published > 0),
                "published checkpoint must have a positive generation"
            );
            drop(state);

            let resumed = NodeState::open(config, None)?;
            assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
            let applied = resumed
                .chainstate()
                .applied_tip_snapshot()
                .ok_or_else(|| std::io::Error::other("checkpoint did not publish applied tip"))?;
            assert_eq!(applied.height, tip.height);
            assert_eq!(applied.hash, tip.hash);
            Ok(())
        }
    }
    mod construction {
        use super::*;
        use crate::state::open::NodeOpenError;
        use crate::test_support::TestError;

        #[test]
        fn runtime_accessors_borrow_their_subsystem_owner() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;
            let p2p = state.p2p();
            let followers = state.chain_followers();

            assert!(Arc::ptr_eq(&state.peer_table(), &p2p.table()));
            assert!(Arc::ptr_eq(&state.p2p(), &p2p));
            assert!(
                state
                    .inbound_blocks_sender()
                    .same_channel(&p2p.inbound_blocks_sender())
            );
            assert!(Arc::ptr_eq(
                state.block_log_reader().raw_handle(),
                followers.block_log()
            ));
            assert!(Arc::ptr_eq(
                &state.mining_generation_signal(),
                followers.mining()
            ));
            assert!(Arc::ptr_eq(&state.ibd(), &state.chainstate().ibd_latch()));
            Ok(())
        }

        #[cfg(feature = "zmq")]
        #[test]
        fn zmq_publisher_handle_reports_active_metadata() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.notifications.zmq = vec![
                bitcoin_rs_serving::zmq::ZmqEndpointConfig {
                    endpoint: "inproc://state-zmq-block".to_owned(),
                    topics: vec![
                        bitcoin_rs_serving::zmq::ZmqTopic::HashBlock,
                        bitcoin_rs_serving::zmq::ZmqTopic::RawBlock,
                    ],
                    hwm: Some(17),
                },
                bitcoin_rs_serving::zmq::ZmqEndpointConfig {
                    endpoint: "inproc://state-zmq-tx".to_owned(),
                    topics: vec![
                        bitcoin_rs_serving::zmq::ZmqTopic::HashTx,
                        bitcoin_rs_serving::zmq::ZmqTopic::RawTx,
                    ],
                    hwm: Some(20),
                },
            ];
            let state = NodeState::open(config, None)?;

            let notifications = state.zmq_publisher().active_notifiers();
            let notification_types: Vec<_> = notifications
                .iter()
                .map(|notification| notification.topic.notifier_type())
                .collect();
            let hwms: Vec<_> = notifications
                .iter()
                .map(|notification| notification.hwm)
                .collect();
            assert_eq!(
                notification_types,
                ["pubhashblock", "pubrawblock", "pubhashtx", "pubrawtx"]
            );
            assert_eq!(hwms, [17, 17, 20, 20]);
            Ok(())
        }

        #[test]
        fn inbound_blocks_channel_is_bounded_against_flood() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;
            let tx = state.inbound_blocks_sender();
            let block = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            for _ in 0..super::INBOUND_BLOCK_CHANNEL_LIMIT {
                tx.try_send(bitcoin_rs_wire::InboundBlock::from_local(block.clone()))
                    .unwrap_or_else(|e| panic!("send within the bound must succeed: {e}"));
            }
            let overflow = tx.try_send(bitcoin_rs_wire::InboundBlock::from_local(block));
            assert!(
                matches!(overflow, Err(crossbeam_channel::TrySendError::Full(_))),
                "channel must reject blocks past INBOUND_BLOCK_CHANNEL_LIMIT, got {overflow:?}",
            );
            Ok(())
        }

        #[test]
        fn inbound_tx_channel_is_bounded_against_flood() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;
            let sender = state.inbound_tx_sender();
            let (lease_tx, _lease_rx) = crossbeam_channel::unbounded();
            let lease = bitcoin_rs_wire::PeerLease::new(lease_tx);
            let source = lease.source_ip(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
            let tx = bitcoin_rs_consensus::primitives::Tx {
                version: 1,
                inputs: Vec::new(),
                outputs: Vec::new(),
                lock_time: LockTime::ZERO,
            };
            for _ in 0..super::INBOUND_TX_CHANNEL_LIMIT {
                sender
                    .try_send(crate::p2p::InboundBody::from(
                        bitcoin_rs_wire::InboundTx::new(tx.clone(), source),
                    ))
                    .unwrap_or_else(|error| panic!("send within the bound must succeed: {error}"));
            }
            let overflow = sender.try_send(crate::p2p::InboundBody::from(
                bitcoin_rs_wire::InboundTx::new(tx, source),
            ));
            assert!(
                matches!(overflow, Err(crossbeam_channel::TrySendError::Full(_))),
                "channel must reject txs past INBOUND_TX_CHANNEL_LIMIT, got {overflow:?}",
            );
            Ok(())
        }

        #[test]
        fn new_datadir_initializes_current_schema_before_storage() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            std::fs::create_dir_all(&config.data_dir)?;
            std::fs::write(config.data_dir.join(".CURRENT_SCHEMA.tmp"), b"partial")?;

            let data_dir = config.data_dir.clone();
            let _state = NodeState::open(config, None)?;
            assert_eq!(
                std::fs::read(
                    data_dir.join(bitcoin_rs_storage::checkpoint::fs::CURRENT_SCHEMA_FILE)
                )?,
                bitcoin_rs_storage::checkpoint::fs::current_schema_bytes()
            );
            assert!(!data_dir.join(".CURRENT_SCHEMA.tmp").exists());
            assert!(data_dir.join("chainstate").exists());
            Ok(())
        }

        // RCV-09
        #[test]
        fn unmarked_nonempty_datadir_is_refused_without_modification() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("legacy-node");
            config.p2p.listen.clear();
            std::fs::create_dir_all(&config.data_dir)?;
            std::fs::write(config.data_dir.join("legacy-state"), b"old")?;

            let data_dir = config.data_dir.clone();
            let Err(NodeOpenError::DataDir(
                bitcoin_rs_execution::events::DataDirError::ValidateSchema { source, .. },
            )) = NodeState::open(config, None)
            else {
                return Err(TestError::ExpectationFailed(
                    "unmarked legacy datadir is refused with ValidateSchema",
                ));
            };
            let error = source.to_string();
            assert!(error.contains("implicitly schema epoch 0"));
            assert!(error.contains("resync"));
            assert!(
                !data_dir
                    .join(bitcoin_rs_storage::checkpoint::fs::CURRENT_SCHEMA_FILE)
                    .exists()
            );
            assert!(!data_dir.join("chainstate").exists());
            assert!(!data_dir.join("process-epoch").exists());
            assert_eq!(std::fs::read(data_dir.join("legacy-state"))?, b"old");
            Ok(())
        }

        #[test]
        fn overlay_identity_dir_is_rooted_in_data_dir() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;

            let mut config_a = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config_a.data_dir = dir.path().join("node-a");
            config_a.p2p.listen.clear();
            let relative = config_a.p2p.overlay.identity_dir.clone();
            assert!(
                relative.is_relative(),
                "overlay identity leaf must stay relative, got {}",
                relative.display()
            );
            let state_a = NodeState::open(config_a, None)?;
            let rooted_a = state_a.p2p().overlay_config().identity_dir.clone();
            assert_eq!(rooted_a, dir.path().join("node-a").join(&relative));

            let mut config_b = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config_b.data_dir = dir.path().join("node-b");
            config_b.p2p.listen.clear();
            let state_b = NodeState::open(config_b, None)?;
            let rooted_b = state_b.p2p().overlay_config().identity_dir.clone();
            assert_eq!(rooted_b, dir.path().join("node-b").join(&relative));
            assert_ne!(
                rooted_a, rooted_b,
                "separate data dirs must not share overlay identities"
            );
            Ok(())
        }

        // RCV-09
        #[test]
        fn mismatched_datadir_schema_is_refused_before_storage_opens() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("old-node");
            config.p2p.listen.clear();
            std::fs::create_dir_all(&config.data_dir)?;
            std::fs::write(
                config
                    .data_dir
                    .join(bitcoin_rs_storage::checkpoint::fs::CURRENT_SCHEMA_FILE),
                b"0\n",
            )?;

            let data_dir = config.data_dir.clone();
            let Err(NodeOpenError::DataDir(
                bitcoin_rs_execution::events::DataDirError::ValidateSchema { source, .. },
            )) = NodeState::open(config, None)
            else {
                return Err(TestError::ExpectationFailed(
                    "mismatched datadir schema is refused with ValidateSchema",
                ));
            };
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::InvalidData,
                "a stale schema epoch is refused as invalid datadir data: {source}"
            );
            assert!(!data_dir.join("chainstate").exists());
            Ok(())
        }

        #[test]
        fn datadir_refusal_when_path_is_a_regular_file_is_typed() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("occupied");
            config.p2p.listen.clear();
            std::fs::write(&config.data_dir, b"not a directory")?;

            let Err(error) = NodeState::open(config, None) else {
                return Err(TestError::message(
                    "a regular file as data_dir must refuse to open",
                ));
            };
            assert!(
                matches!(error, NodeOpenError::CreateDataDir { .. }),
                "datadir creation failure must be NodeOpenError::CreateDataDir, got: {error:?}"
            );
            Ok(())
        }
    }
    mod data_dir_lock {
        use super::*;

        use crate::test_support::TestError;

        use crate::lifecycle::start_node;
        use crate::state::data_dir_lock::{DataDirLock, DataDirLockError};
        use crate::state::open::NodeOpenError;
        use std::net::SocketAddr;

        const CHILD_DIR_ENV: &str = "BITCOIN_RS_TEST_DATA_DIR_LOCK_CHILD_DIR";
        const CHILD_KIND_ENV: &str = "BITCOIN_RS_TEST_DATA_DIR_LOCK_CHILD_KIND";
        const KIND_OPEN: &str = "open";
        const KIND_NODE: &str = "node";
        const CHILD_READY_DEADLINE: std::time::Duration = std::time::Duration::from_mins(1);
        const BASIC_AUTH: &str = "dXNlcjpwYXNzd29yZA==";

        fn lock_config(data_dir: &std::path::Path) -> crate::NodeConfig {
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir.to_path_buf();
            config.rpc.bind = SocketAddr::from(([127, 0, 0, 1], 0));
            config.rpc.auth = crate::Auth::basic("user", "password");
            config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
            config.p2p.listen.clear();
            config.observability.metrics_bind = None;
            config
        }

        fn assert_directory_locked(data_dir: &std::path::Path) {
            match DataDirLock::acquire(data_dir) {
                Err(DataDirLockError::InUse { path }) => assert_eq!(path, data_dir),
                other => panic!("expected the directory to be locked, got: {other:?}"),
            }
        }

        fn assert_in_use(error: &NodeOpenError, expected_dir: &std::path::Path) {
            let NodeOpenError::DataDirLock(lock_error) = error else {
                panic!("expected NodeOpenError::DataDirLock, got: {error:#}");
            };
            match lock_error {
                DataDirLockError::InUse { path } => {
                    assert_eq!(
                        path, expected_dir,
                        "the refusal must name the contended dir"
                    );
                }
                other => panic!("expected InUse, got: {other:?}"),
            }
        }

        #[test]
        fn second_open_while_first_lives_refuses_and_reopen_succeeds_after_drop()
        -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let config = lock_config(&data_dir);

            let first = NodeState::open(config.clone(), None)?;

            let Err(error) = NodeState::open(config.clone(), None) else {
                panic!("the held directory must refuse a second open");
            };
            assert_in_use(&error, &data_dir);

            drop(first);
            let reopened = NodeState::open(config, None)?;
            drop(reopened);
            Ok(())
        }

        #[cfg(unix)]
        #[test]
        fn fork_exec_window_cannot_hold_the_directory_lock() -> Result<(), TestError> {
            use std::io::Read;
            use std::io::Write;
            use std::os::unix::net::UnixStream;

            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            std::fs::create_dir_all(&data_dir)?;

            let first = DataDirLock::acquire(&data_dir)?;

            let (arrived_tx, mut arrived_rx) = UnixStream::pair()?;
            let (mut release_tx, release_rx) = UnixStream::pair()?;
            let spawner = std::thread::spawn(move || {
                let mut command = std::process::Command::new(std::env::current_exe()?);
                command.args(["--list"]);
                let mut arrived = arrived_tx;
                let mut release = release_rx;
                // SAFETY: the closure only writes and reads one byte on inherited sockets.
                unsafe {
                    use std::os::unix::process::CommandExt;
                    command.pre_exec(move || {
                        arrived.write_all(&[1])?;
                        release.read_exact(&mut [0_u8; 1])?;
                        Ok(())
                    });
                }
                command.spawn()
            });

            let mut signal = [0_u8; 1];
            arrived_rx.read_exact(&mut signal)?;

            drop(first);
            let second = DataDirLock::acquire(&data_dir);
            release_tx.write_all(&[1])?;
            let second = second?;
            drop(second);
            let mut child = spawner
                .join()
                .map_err(|_| TestError::ExpectationFailed("child spawner thread panicked"))??;
            let status = child.wait()?;
            assert!(status.success(), "listed child must exit cleanly");
            Ok(())
        }

        #[test]
        fn running_node_refuses_open_until_shutdown_releases() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let config = lock_config(&data_dir);

            let node = start_node(config.clone(), crate::RuntimeInputs::default(), false)?;

            let Err(error) = NodeState::open(config.clone(), None) else {
                panic!("the running node's directory must refuse a second open");
            };
            assert_in_use(&error, &data_dir);

            node.shutdown_blocking()?;
            let reopened = NodeState::open(config, None)?;
            drop(reopened);
            Ok(())
        }

        fn idle_keepalive_rpc_connection(
            addr: SocketAddr,
        ) -> Result<std::net::TcpStream, TestError> {
            use std::io::{BufRead as _, BufReader, Read as _, Write as _};

            let mut stream = std::net::TcpStream::connect(addr)?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
            let body = r#"{"jsonrpc":"1.0","id":"keepalive","method":"uptime","params":[]}"#;
            write!(
                stream,
                "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic {BASIC_AUTH}\r\n\
     Content-Type: application/json\r\nContent-Length: {}\r\n\
     Connection: keep-alive\r\n\r\n{body}",
                body.len()
            )?;
            stream.flush()?;

            let mut reader = BufReader::new(&stream);
            let mut status = String::new();
            reader.read_line(&mut status)?;
            if !status.starts_with("HTTP/1.1 200") {
                return Err(TestError::ExpectationFailed("RPC status is HTTP/1.1 200"));
            }
            let mut content_length = None;
            let mut keep_alive = false;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line)?;
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                let value = value.trim().to_ascii_lowercase();
                match name.trim().to_ascii_lowercase().as_str() {
                    "content-length" => content_length = Some(value.parse::<usize>()?),
                    "connection" => keep_alive = value == "keep-alive",
                    _ => {}
                }
            }
            if !keep_alive {
                return Err(TestError::ExpectationFailed(
                    "the server keeps the connection open",
                ));
            }
            let length = content_length.ok_or(TestError::Missing("RPC Content-Length"))?;
            reader.read_exact(&mut vec![0_u8; length])?;
            drop(reader);
            Ok(stream)
        }

        // EMB-01
        #[test]
        fn idle_keepalive_rpc_connection_releases_the_directory_lock_at_shutdown()
        -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let config = lock_config(&data_dir);
            let node = start_node(config.clone(), crate::RuntimeInputs::default(), false)?;
            let address = node
                .services
                .as_ref()
                .ok_or(TestError::Missing("node services"))?
                .rpc_address(bitcoin_rs_serving::RpcSurface::Shared)
                .ok_or(TestError::Missing("shared rpc address"))?;
            let client = idle_keepalive_rpc_connection(address)?;

            let started = std::time::Instant::now();
            node.shutdown_blocking()?;
            let elapsed = started.elapsed();

            let reopened = NodeState::open(config, None)?;
            drop(reopened);
            drop(client);
            assert!(
                elapsed < crate::lifecycle::DRAIN_DEADLINE * 2,
                "an idle keep-alive reader held the shutdown for {elapsed:?}"
            );
            Ok(())
        }

        #[test]
        fn retained_chainstate_handle_keeps_the_directory_locked_until_dropped()
        -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let config = lock_config(&data_dir);

            let state = NodeState::open(config.clone(), None)?;
            let retained = state.chainstate();
            drop(state);

            let Err(error) = NodeState::open(config.clone(), None) else {
                panic!("a retained chainstate handle must keep the directory locked");
            };
            assert_in_use(&error, &data_dir);

            drop(retained);
            drop(NodeState::open(config, None)?);
            Ok(())
        }

        #[test]
        fn retained_block_body_store_keeps_the_directory_locked_until_dropped()
        -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let config = lock_config(&data_dir);

            let state = NodeState::open(config.clone(), None)?;
            let body_store = state.storage.block_body_store();
            drop(state);

            let Err(error) = NodeState::open(config.clone(), None) else {
                panic!("a retained block-body store must keep the directory locked");
            };
            assert_in_use(&error, &data_dir);

            drop(body_store);
            drop(NodeState::open(config, None)?);
            Ok(())
        }

        #[test]
        fn block_files_alone_keep_the_directory_locked_until_dropped() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let config = lock_config(dir.path());
            let guard: bitcoin_rs_storage::StoreGuard = Arc::new(DataDirLock::acquire(dir.path())?);

            let cache_allocation = bitcoin_rs_storage::split_chainstate_cache_budget(32 << 20);
            let budget = Arc::new(crate::budget::NodeBudget::from_chainstate_cache_budget(
                cache_allocation,
                4,
            ));
            let (storage, block_files) = crate::state::storage::NodeStorage::open(
                &config,
                cache_allocation,
                &guard,
                budget,
            )?;
            drop(storage);
            drop(guard);
            assert_directory_locked(dir.path());

            drop(block_files);
            drop(DataDirLock::acquire(dir.path())?);
            Ok(())
        }

        #[test]
        fn retained_index_query_adapter_keeps_the_directory_locked_until_dropped()
        -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let mut config = lock_config(&data_dir);
            config.indexes.txindex = true;

            let mut state = NodeState::open(config.clone(), None)?;
            state.start_index_workers()?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while state.derived_index.lifecycle_is_opening() {
                if std::time::Instant::now() >= deadline {
                    return Err(TestError::Timeout("txindex lifecycle left Opening"));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if state.derived_index.lifecycle_is_failed() {
                return Err(TestError::ExpectationFailed(
                    "txindex worker serves after opening",
                ));
            }
            let adapter = state
                .derived_index
                .adapter()
                .cloned()
                .ok_or(TestError::Missing("txindex query adapter"))?;
            state.bounded_index_shutdown(std::time::Duration::from_secs(5))?;
            drop(state);

            let Err(error) = NodeState::open(config.clone(), None) else {
                panic!("a retained index query adapter must keep the directory locked");
            };
            assert_in_use(&error, &data_dir);

            drop(adapter);
            let mut reopened = NodeState::open(config, None)?;
            reopened.start_index_workers()?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while reopened.derived_index.lifecycle_is_opening() {
                if std::time::Instant::now() >= deadline {
                    return Err(TestError::Timeout(
                        "replacement txindex worker left Opening",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if reopened.derived_index.lifecycle_is_failed() {
                return Err(TestError::ExpectationFailed(
                    "released index store reopens cleanly",
                ));
            }
            Ok(())
        }

        #[test]
        fn index_open_spec_and_opened_store_each_keep_the_directory_locked() -> Result<(), TestError>
        {
            let dir = tempfile::tempdir()?;
            let mut config = lock_config(dir.path());
            config.indexes.txindex = true;
            let guard: bitcoin_rs_storage::StoreGuard = Arc::new(DataDirLock::acquire(dir.path())?);

            let cache_allocation = bitcoin_rs_storage::split_chainstate_cache_budget(32 << 20);
            let budget = Arc::new(crate::budget::NodeBudget::from_chainstate_cache_budget(
                cache_allocation,
                4,
            ));
            let spec =
                crate::state::build_derived_index_open_spec(&config, 32 << 20, 1, &guard, &budget)?
                    .ok_or(TestError::Missing("txindex open spec"))?;
            drop(guard);
            assert_directory_locked(dir.path());

            let index_dir = dir.path().join("txindex");
            std::fs::create_dir_all(&index_dir)?;
            let opened = (spec.open_store)(&index_dir).map_err(TestError::from)?;
            drop(spec);
            assert_directory_locked(dir.path());

            drop(opened);
            drop(DataDirLock::acquire(dir.path())?);
            Ok(())
        }

        #[test]
        fn symlinked_lock_file_refuses_start_without_following() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            std::fs::create_dir_all(&data_dir)?;
            let outside = dir.path().join("outside.lock");
            std::fs::write(&outside, b"")?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&outside, data_dir.join(".lock"))?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(&outside, data_dir.join(".lock"))?;

            let Err(error) = NodeState::open(lock_config(&data_dir), None) else {
                panic!("a symlinked lock entry must refuse startup");
            };
            let lowered = error.to_string().to_lowercase();
            assert!(
                matches!(
                    error,
                    NodeOpenError::DataDirLock(DataDirLockError::Io { .. })
                ) || lowered.contains("cannot write to directory"),
                "expected the Io refusal for a symlinked lock, got: {error:#}"
            );
            Ok(())
        }

        #[test]
        #[ignore = "spawned explicitly by the contender tests in this file"]
        fn data_dir_lock_subprocess_contender() -> Result<(), TestError> {
            let Some(data_dir) = std::env::var_os(CHILD_DIR_ENV) else {
                return Ok(());
            };
            let data_dir = std::path::PathBuf::from(data_dir);
            let kind = std::env::var(CHILD_KIND_ENV).unwrap_or_else(|_| KIND_OPEN.to_owned());
            let held_marker = data_dir.join("lock-child-held");
            let done_marker = data_dir.join("lock-parent-done");
            if kind == KIND_NODE {
                let node = start_node(
                    lock_config(&data_dir),
                    crate::RuntimeInputs::default(),
                    false,
                )?;
                std::fs::write(&held_marker, b"node")?;
                let deadline = std::time::Instant::now() + CHILD_READY_DEADLINE;
                while !done_marker.exists() {
                    if std::time::Instant::now() >= deadline {
                        return Err(TestError::Timeout("lock child saw the parent release"));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                node.shutdown_blocking()?;
            } else {
                let state = NodeState::open(lock_config(&data_dir), None)?;
                std::fs::write(&held_marker, b"open")?;
                let deadline = std::time::Instant::now() + CHILD_READY_DEADLINE;
                while !done_marker.exists() {
                    if std::time::Instant::now() >= deadline {
                        return Err(TestError::Timeout("lock child saw the parent release"));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                drop(state);
            }
            std::process::exit(0);
        }

        fn wait_for_child_marker(
            child: &mut std::process::Child,
            marker: &std::path::Path,
        ) -> Result<(), TestError> {
            let deadline = std::time::Instant::now() + CHILD_READY_DEADLINE;
            while !marker.exists() {
                if child.try_wait()?.is_some() {
                    return Err(TestError::Timeout("lock child holds the data directory"));
                }
                if std::time::Instant::now() >= deadline {
                    child.kill()?;
                    let _ = child.wait();
                    return Err(TestError::Timeout("lock child writes its held marker"));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Ok(())
        }

        struct LockChild(std::process::Child);

        impl LockChild {
            fn finish(&mut self) -> Result<(), TestError> {
                use std::io::Read as _;
                let mut stderr = String::new();
                if let Some(mut pipe) = self.0.stderr.take() {
                    pipe.read_to_string(&mut stderr)?;
                }
                let status = self.0.wait()?;
                if !status.success() {
                    return Err(TestError::ExpectationFailed(
                        "lock child exits successfully",
                    ));
                }
                Ok(())
            }
        }

        impl Drop for LockChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        #[test]
        fn second_process_is_refused_while_first_holds_its_node() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");

            let test_name = concat!(module_path!(), "::data_dir_lock_subprocess_contender")
                .split("::")
                .skip(1)
                .collect::<Vec<_>>()
                .join("::");
            let exe = std::env::current_exe()?;

            let mut child = LockChild(
                std::process::Command::new(&exe)
                    .args(["--exact", &test_name, "--ignored"])
                    .env(CHILD_DIR_ENV, &data_dir)
                    .env(CHILD_KIND_ENV, KIND_NODE)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?,
            );

            wait_for_child_marker(&mut child.0, &data_dir.join("lock-child-held"))?;

            let Err(error) = NodeState::open(lock_config(&data_dir), None) else {
                panic!("the child process's directory must refuse this open");
            };
            assert_in_use(&error, &data_dir);

            std::fs::write(data_dir.join("lock-parent-done"), b"")?;
            child.finish()?;

            drop(NodeState::open(lock_config(&data_dir), None)?);
            Ok(())
        }
    }
    mod events {
        use super::*;

        use crate::test_support::TestError;
        use bitcoin_rs_consensus::primitives::BlockImage;

        // EVT-01
        #[test]
        fn process_epoch_is_strictly_monotonic_across_restart() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();

            let first = NodeState::open(config.clone(), None)?
                .chainstate()
                .chain_snapshot()
                .epoch;
            let second = NodeState::open(config.clone(), None)?
                .chainstate()
                .chain_snapshot()
                .epoch;
            let third = NodeState::open(config, None)?
                .chainstate()
                .chain_snapshot()
                .epoch;
            assert!(first > 0, "a fresh data dir allocates epoch 1, got {first}");
            assert!(
                second > first,
                "restart must never reuse an epoch: {first} -> {second}"
            );
            assert!(
                third > second,
                "restart must never reuse an epoch: {second} -> {third}"
            );
            Ok(())
        }

        // EVT-01
        #[test]
        fn active_chain_snapshot_starts_at_genesis_on_fresh_node() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();

            let state = NodeState::open(config.clone(), None)?;
            let epoch = state.chainstate().chain_events_handle().epoch();
            assert_eq!(
                state.chainstate().chain_snapshot(),
                ChainSnapshot {
                    epoch,
                    sequence: 0,
                    tip_hash: config.network.genesis_block_hash(),
                    tip_height: 0,
                },
                "a node that committed nothing anchors at genesis with sequence 0"
            );
            Ok(())
        }

        #[test]
        fn active_chain_snapshot_anchors_at_restored_tip_after_restart() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();

            let (tip, first_epoch) = {
                let state = NodeState::open(config.clone(), None)?;
                let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
                let tip = state.apply_block(&BlockImage::from_local(genesis))?;
                assert!(state.publish_checkpoint()?.is_some());
                (tip, state.chainstate().chain_snapshot().epoch)
            };

            let resumed = NodeState::open(config, None)?;
            assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
            let snapshot = resumed.chainstate().chain_snapshot();
            assert_eq!(snapshot.tip_hash, tip.hash);
            assert_eq!(snapshot.tip_height, tip.height);
            assert_eq!(
                snapshot.sequence, 0,
                "a restart resets the sequence, never the epoch"
            );
            assert!(
                snapshot.epoch > first_epoch,
                "restart must advance the epoch: {} -> {}",
                first_epoch,
                snapshot.epoch
            );
            Ok(())
        }

        // EVT-01
        #[test]
        fn record_returns_hints_in_commit_order_and_advances_the_snapshot() {
            let publisher = ChainEventPublisher::detached(7);
            let epoch = publisher.epoch();
            let hash_a = Hash256::from_le_bytes(&[0xAA; 32]);
            let hash_b = Hash256::from_le_bytes(&[0xBB; 32]);

            let first = publisher.record(HintKind::Connected, 1, hash_a);
            let second = publisher.record(HintKind::Disconnected, 0, hash_b);

            let expected_first = ChainEventHint {
                kind: HintKind::Connected,
                height: 1,
                hash: hash_a,
                epoch,
                sequence: 1,
            };
            let expected_second = ChainEventHint {
                kind: HintKind::Disconnected,
                height: 0,
                hash: hash_b,
                epoch,
                sequence: 2,
            };
            assert_eq!(first, expected_first);
            assert_eq!(second, expected_second);
            assert_eq!(
                publisher.snapshot(),
                ChainSnapshot {
                    epoch,
                    sequence: 2,
                    tip_hash: hash_b,
                    tip_height: 0,
                },
                "the last committed event wins the snapshot cell"
            );
        }

        #[test]
        fn corrupt_process_epoch_file_refuses_start() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            std::fs::create_dir_all(&data_dir)?;
            std::fs::write(data_dir.join("process-epoch"), b"seven\n")?;
            std::fs::write(
                data_dir.join("CURRENT_SCHEMA"),
                bitcoin_rs_storage::checkpoint::fs::current_schema_bytes(),
            )?;

            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir;
            config.p2p.listen.clear();

            let Err(error) = NodeState::open(config, None) else {
                return Err(TestError::message(
                    "a corrupt process-epoch file must refuse startup",
                ));
            };
            assert!(
                error.to_string().contains("process-epoch"),
                "the refusal names the corrupt file: {error}"
            );
            assert_eq!(
                std::fs::read(dir.path().join("node").join("process-epoch"))?,
                b"seven\n",
                "the refusal must not reset the persisted epoch"
            );
            Ok(())
        }

        #[cfg(unix)]
        #[test]
        fn symlinked_epoch_lock_refuses_start() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            std::fs::create_dir_all(&data_dir)?;
            std::fs::write(data_dir.join("process-epoch"), b"41\n")?;
            std::fs::write(
                data_dir.join("CURRENT_SCHEMA"),
                bitcoin_rs_storage::checkpoint::fs::current_schema_bytes(),
            )?;
            std::os::unix::fs::symlink("process-epoch", data_dir.join(".process-epoch.lock"))?;

            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir.clone();
            config.p2p.listen.clear();

            let Err(error) = NodeState::open(config, None) else {
                return Err(TestError::message(
                    "a symlinked epoch lock must refuse startup",
                ));
            };
            assert!(
                error.to_string().contains("process epoch lock"),
                "the refusal names the lock target: {error:#}"
            );
            assert_eq!(
                std::fs::read_to_string(data_dir.join("process-epoch"))?,
                "41\n",
                "the symlink must not be followed and the epoch must not reset"
            );
            Ok(())
        }

        #[cfg(all(unix, not(target_vendor = "apple")))]
        #[test]
        #[cfg(not(target_vendor = "apple"))]
        fn non_regular_epoch_lock_refuses_start() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            std::fs::create_dir_all(&data_dir)?;
            std::fs::write(data_dir.join("process-epoch"), b"7\n")?;
            std::fs::write(
                data_dir.join("CURRENT_SCHEMA"),
                bitcoin_rs_storage::checkpoint::fs::current_schema_bytes(),
            )?;
            let lock_dir =
                cap_std::fs::Dir::open_ambient_dir(&data_dir, cap_std::ambient_authority())?;
            rustix::fs::mkfifoat(
                &lock_dir,
                ".process-epoch.lock",
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .map_err(std::io::Error::from)?;

            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir.clone();
            config.p2p.listen.clear();

            let Err(crate::NodeOpenError::DataDir(
                bitcoin_rs_execution::events::DataDirError::LockNotRegularFile,
            )) = NodeState::open(config, None)
            else {
                return Err(TestError::message(
                    "a non-regular epoch lock must refuse startup",
                ));
            };
            assert_eq!(
                std::fs::read_to_string(data_dir.join("process-epoch"))?,
                "7\n",
                "the refusal must not reset the persisted epoch"
            );
            Ok(())
        }
    }
    mod index {
        use super::*;

        use crate::test_support::TestError;

        // IDX-01
        #[test]
        fn script_index_capabilities_match_the_storage_contract() {
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.indexes.txindex = false;

            config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
            assert_eq!(derived_index_capabilities(&config), IndexCapabilities::NONE);
            assert!(!config.indexes.blockfilterindex);
            config.indexes.blockfilterindex = true;
            assert_eq!(
                derived_index_capabilities(&config),
                IndexCapabilities::COMPACT_FILTERS
            );
            config.indexes.blockfilterindex = false;

            config.indexes.script_index = crate::config::ScriptIndexMode::Utxo;
            assert_eq!(
                derived_index_capabilities(&config),
                IndexCapabilities::SCRIPT_LIVE,
                "utxo mode owns only the compact live-output view"
            );

            config.indexes.script_index = crate::config::ScriptIndexMode::Full;
            assert_eq!(
                derived_index_capabilities(&config),
                IndexCapabilities::TX_AND_SCRIPTS
            );

            config.indexes.txindex = true;
            config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
            assert_eq!(
                derived_index_capabilities(&config),
                IndexCapabilities::TX_LOOKUP
            );

            config.indexes.script_index = crate::config::ScriptIndexMode::Utxo;
            assert_eq!(
                derived_index_capabilities(&config),
                IndexCapabilities::TX_LOOKUP_SCRIPT_LIVE
            );
        }

        // IDX-01
        #[test]
        fn open_skips_tx_index_when_disabled() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;

            assert!(state.chain_followers().derived_index().is_none());
            assert!(state.compact_filter_query().is_none());
            assert!(
                state.derived_index_query().is_none(),
                "txindex disabled by default"
            );
            assert!(
                !state.data_dir().join("txindex").exists(),
                "disabled txindex must not create storage"
            );
            Ok(())
        }

        #[test]
        fn index_workers_start_only_when_asked() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.indexes.txindex = true;
            let mut state = NodeState::open(config, None)?;

            assert!(state.chain_followers().derived_index().is_some());
            assert!(state.derived_index.lifecycle_is_opening());
            assert!(
                !state.derived_index.is_running(),
                "no worker may exist before start_index_workers"
            );

            state.start_index_workers()?;
            assert!(state.derived_index.is_running());
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while state.derived_index.lifecycle_is_opening() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "txindex lifecycle remained Opening"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(())
        }

        #[test]
        fn start_index_workers_twice_is_idempotent() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.indexes.txindex = true;
            let mut state = NodeState::open(config, None)?;

            state.start_index_workers()?;
            assert!(state.derived_index.is_running());
            state.start_index_workers()?;
            assert!(
                state.derived_index.is_running(),
                "the second call must leave the one worker running"
            );
            assert_eq!(
                state.derived_index.spawn_count(),
                1,
                "the second call must not have spawned another worker"
            );
            Ok(())
        }

        #[test]
        fn derived_index_status_answers_when_disabled() -> Result<(), TestError> {
            use bitcoin_rs_projection::CapabilityState;

            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.indexes.txindex = false;
            config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
            let state = NodeState::open(config, None)?;

            let status = state.derived_index_status();
            assert_eq!(
                status.capability().state,
                CapabilityState::Disabled,
                "a disabled config must answer a concrete Disabled row"
            );
            Ok(())
        }

        #[test]
        fn bounded_shutdown_stops_the_worker_and_allows_reopen() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.indexes.txindex = true;
            let mut state = NodeState::open(config.clone(), None)?;
            state.start_index_workers()?;
            assert!(state.derived_index.is_running());
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while state.derived_index.lifecycle_is_opening() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "txindex lifecycle remained Opening"
                );
                std::thread::sleep(Duration::from_millis(20));
            }

            state.bounded_index_shutdown(Duration::from_secs(5))?;
            assert!(!state.derived_index.is_running());
            state.bounded_index_shutdown(Duration::from_secs(5))?;
            drop(state);

            let mut reopened = NodeState::open(config, None)?;
            reopened.start_index_workers()?;
            assert!(reopened.derived_index.is_running());
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while reopened.derived_index.lifecycle_is_opening() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "replacement txindex worker remained Opening"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(
                !reopened.derived_index.lifecycle_is_failed(),
                "the replacement worker must open the reclaimed namespace"
            );
            Ok(())
        }

        #[test]
        fn script_index_builds_without_advertising_core_txindex() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.indexes.txindex = false;
            config.indexes.script_index = crate::config::ScriptIndexMode::Full;

            let mut state = NodeState::open(config, None)?;
            state.start_index_workers()?;

            assert!(state.chain_followers().derived_index().is_some());
            assert!(state.derived_index_query().is_none());
            assert!(state.esplora_derived_index_query().is_some());
            assert!(state.script_index_query().is_some());
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while !state.data_dir().join("txindex").exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "script-index worker did not create storage within 30s"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(())
        }

        #[test]
        fn script_index_modes_give_concrete_unspent_outputs_answers() -> Result<(), TestError> {
            use bitcoin_rs_projection::{IndexCapability, ScriptHash};
            use bitcoin_rs_serving::context::{TxQueryError, TxUnavailableCause};

            let scripthash = ScriptHash::from_script_bytes(&[0x51, 0x01]);

            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.indexes.txindex = false;
            config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
            let state = NodeState::open(config, None)?;
            let _ =
                state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    crate::Network::Regtest.genesis_block(),
                ))?;
            assert!(
                state.script_index_query().is_none(),
                "disabled must not hand out a script-index query adapter"
            );
            drop(state);

            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.indexes.txindex = false;
            config.indexes.script_index = crate::config::ScriptIndexMode::Utxo;
            let mut state = NodeState::open(config, None)?;
            state.start_index_workers()?;
            let _ =
                state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    crate::Network::Regtest.genesis_block(),
                ))?;
            let Some(query) = state.script_index_query() else {
                panic!("utxo mode must hand out a script-index query adapter")
            };
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                match query.unspent_outputs(scripthash) {
                    Ok(records) => {
                        assert!(records.is_empty(), "an unfunded script has no outputs");
                        match query.history_snapshot(scripthash) {
                            Err(TxQueryError::Unavailable(
                                TxUnavailableCause::CapabilityDisabled(
                                    IndexCapability::ScriptHistory,
                                ),
                            )) => {}
                            other => {
                                panic!("utxo mode must fail history as disabled, got {other:?}")
                            }
                        }
                        break;
                    }
                    Err(TxQueryError::Retry(_) | TxQueryError::Unavailable(_)) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "utxo mode must converge on the live view"
                        );
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("unexpected script-index error: {error}"),
                }
            }

            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.indexes.txindex = false;
            config.indexes.script_index = crate::config::ScriptIndexMode::Full;
            let mut state = NodeState::open(config, None)?;
            state.start_index_workers()?;
            let _ =
                state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    crate::Network::Regtest.genesis_block(),
                ))?;
            let Some(query) = state.script_index_query() else {
                panic!("full mode must hand out a script-index query adapter")
            };

            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                match query.unspent_outputs(scripthash) {
                    Ok(records) => {
                        assert!(
                            records.is_empty(),
                            "an unfunded script has no unspent outputs"
                        );
                        break;
                    }
                    Err(TxQueryError::Retry(_) | TxQueryError::Unavailable(_)) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "full mode must converge on a concrete answer, not retry forever"
                        );
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("unexpected script-index error: {error}"),
                }
            }
            Ok(())
        }

        #[test]
        fn drop_joins_txindex_worker_before_reopen() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.indexes.txindex = true;

            {
                let mut state = NodeState::open(config.clone(), None)?;
                state.start_index_workers()?;
                assert!(state.derived_index_query().is_some());
            }

            let reopened = NodeState::open(config, None)?;
            assert!(reopened.derived_index_query().is_some());
            Ok(())
        }

        #[test]
        fn open_rejects_txindex_with_pruning() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.indexes.txindex = true;
            config.storage.prune_target_mb = 1;

            let error = match NodeState::open(config, None) {
                Ok(_) => {
                    return Err(TestError::message("txindex with pruning must be rejected"));
                }
                Err(error) => error,
            };
            assert!(
                matches!(
                    error,
                    crate::state::open::NodeOpenError::Config(
                        crate::config::ConfigError::PruneWithIndexes
                    )
                ),
                "unexpected error: {error:#}"
            );
            Ok(())
        }
    }
    mod open {
        use super::*;
        use crate::test_support::TestError;
        // BUD-02
        #[test]
        fn open_wires_peer_outbound_ledger_to_node_budget() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;
            let budget = state.budget();
            let shared = state.p2p().shared_outbound_budget();
            assert_eq!(
                budget.charged_bytes(bitcoin_rs_storage::budget::BudgetOwner::PeerOutbound),
                0
            );
            assert!(shared.test_try_charge(4096));
            assert_eq!(
                budget.charged_bytes(bitcoin_rs_storage::budget::BudgetOwner::PeerOutbound),
                4096
            );
            shared.test_release(4096);
            assert_eq!(
                budget.charged_bytes(bitcoin_rs_storage::budget::BudgetOwner::PeerOutbound),
                0
            );
            Ok(())
        }
    }
    mod pow_valid_hook {
        #![expect(
            clippy::expect_used,
            reason = "poisoned test-recorder locks must fail the test"
        )]

        use super::*;

        use crate::test_support::TestError;
        use std::sync::Mutex;

        type HookFires = Arc<Mutex<Vec<(Hash256, u32)>>>;

        fn open_hook_chain(
            heights: u32,
        ) -> Result<(tempfile::TempDir, NodeState, HookFires), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;
            let fires: HookFires = Arc::new(Mutex::new(Vec::new()));
            let recorder = Arc::clone(&fires);
            state
                .chainstate()
                .set_pow_valid_block(Arc::new(move |_block, hash, height| {
                    recorder
                        .lock()
                        .expect("hook recorder poisoned")
                        .push((hash, height));
                }))
                .map_err(|_| TestError::message("pow-valid hook installs once"))?;
            let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis.clone(),
            ))?;
            let mut previous = genesis.block_hash();
            let mut time = genesis.header.time;
            for height in 1..=heights {
                time += 1;
                let block = regtest_fixture::mined_regtest_child_at_time(previous, time, height)?;
                state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    block.clone(),
                ))?;
                previous = block.block_hash();
            }
            fires.lock().expect("hook recorder poisoned").clear();
            Ok((dir, state, fires))
        }

        #[test]
        fn connect_failure_after_early_send_keeps_tip_and_sends_nothing_more()
        -> Result<(), TestError> {
            let (_dir, state, fires) = open_hook_chain(2)?;
            let tip_before = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or_else(|| TestError::message("no applied tip"))?;

            let valid = regtest_fixture::mined_regtest_child_at_time(
                tip_before.hash.into(),
                tip_before_time(&state)? + 1,
                tip_before.height + 1,
            )?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                valid.clone(),
            ))?;
            let fired = fires.lock().expect("hook recorder poisoned").clone();
            assert_eq!(fired.len(), 1, "one early fire per committed tip child");
            assert_eq!(fired[0].0, Hash256::from(valid.block_hash()));
            assert_eq!(fired[0].1, tip_before.height + 1);

            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or_else(|| TestError::message("no applied tip"))?;
            let mut falling = regtest_fixture::mined_regtest_child_at_time(
                tip.hash.into(),
                tip_before_time(&state)? + 2,
                tip.height + 1,
            )?;
            let coinbase = falling
                .txs
                .first_mut()
                .ok_or_else(|| TestError::message("no coinbase"))?
                .outputs
                .first_mut()
                .ok_or_else(|| TestError::message("no coinbase output"))?;
            coinbase.value = bitcoin_rs_consensus::primitives::Amount::from_sat(
                coinbase
                    .value
                    .to_sat()
                    .checked_add(1)
                    .ok_or_else(|| TestError::message("value overflow"))?,
            );
            falling.header.merkle_root = regtest_fixture::merkle_root(&falling.txs)
                .ok_or_else(|| TestError::message("no root"))?;
            regtest_fixture::mine_block_to_declared_target(&mut falling).map_err(|error| {
                TestError::message(format!("regrind overspend block: {error:?}"))
            })?;
            assert!(
                state
                    .apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                        falling.clone(),
                    ))
                    .is_err(),
                "an overspent coinbase must fail connect after rules"
            );
            let fired = fires.lock().expect("hook recorder poisoned").clone();
            assert_eq!(
                fired.len(),
                2,
                "exactly the rules-boundary fire, nothing after the failure"
            );
            assert_eq!(fired[1].0, Hash256::from(falling.block_hash()));
            let tip_after = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or_else(|| TestError::message("no applied tip"))?;
            assert_eq!(tip_after.height, tip.height);
            assert_eq!(tip_after.hash, tip.hash);
            Ok(())
        }

        fn tip_before_time(state: &NodeState) -> Result<u32, TestError> {
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or_else(|| TestError::message("no applied tip"))?;
            let tree = state.chainstate().block_tree_reader();
            let guard = tree.read();
            let node = guard
                .node(tip.tip_id)
                .map_err(|error| TestError::message(format!("tip node missing: {error:?}")))?;
            Ok(node.header.time)
        }
    }
    mod prune {
        use super::*;

        use crate::test_support::TestError;
        use bitcoin_rs_consensus::primitives::BlockImage;

        #[test]
        fn apply_block_persists_body_under_pruning_key_when_pruning_disabled()
        -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.storage.prune_target_mb = 0;
            let state = NodeState::open(config, None)?;
            let payload = BlockImage::from_local(
                bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
            );
            let hash = Hash256::from_le_bytes(payload.block_hash().as_bytes());

            assert!(state.prune_service().is_none());
            state.apply_block(&payload)?;

            assert_eq!(
                state
                    .block_log_reader()
                    .read()
                    .first()
                    .map(|record| record.body_size),
                Some(payload.bytes().len())
            );
            assert_eq!(
                state
                    .chainstate()
                    .block_body_store()
                    .ok_or_else(|| TestError::message("running node has no body store"))?
                    .load_block_body(0, hash)?
                    .as_deref(),
                Some(payload.bytes().as_ref())
            );
            Ok(())
        }

        #[test]
        fn preserved_bytes_apply_matches_lazy_serialization() -> Result<(), TestError> {
            let local = BlockImage::from_local(
                bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
            );
            let hash = Hash256::from_le_bytes(local.block_hash().as_bytes());
            let preserved = BlockImage::from_raw(local.bytes().clone()).map_err(|error| {
                TestError::message(format!("genesis bytes are canonical: {error}"))
            })?;

            let dir_a = tempfile::tempdir()?;
            let mut config_a = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config_a.data_dir = dir_a.path().join("node-a");
            config_a.p2p.listen.clear();
            config_a.storage.prune_target_mb = 0;
            let state_a = NodeState::open(config_a, None)?;
            state_a.apply_block(&local)?;

            let dir_b = tempfile::tempdir()?;
            let mut config_b = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config_b.data_dir = dir_b.path().join("node-b");
            config_b.p2p.listen.clear();
            config_b.storage.prune_target_mb = 0;
            let state_b = NodeState::open(config_b, None)?;
            state_b.chainstate().apply_block(&preserved)?;

            let body_a = state_a
                .chainstate()
                .block_body_store()
                .ok_or_else(|| TestError::message("running node has no body store"))?
                .load_block_body(0, hash)?
                .ok_or_else(|| TestError::message("apply_block body missing"))?;
            let body_b = state_b
                .chainstate()
                .block_body_store()
                .ok_or_else(|| TestError::message("running node has no body store"))?
                .load_block_body(0, hash)?
                .ok_or_else(|| TestError::message("preserved-byte apply body missing"))?;
            assert_eq!(body_a, body_b);
            Ok(())
        }

        #[test]
        fn prune_waits_for_chain_transition_and_revalidates_applied_tip() -> Result<(), TestError> {
            use std::time::Duration;

            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.storage.prune_target_mb = 1;
            let state = NodeState::open(config.clone(), None)?;
            publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
            let Some(service) = state.prune_service() else {
                return Err(TestError::message(
                    "prune service should exist when prune_target_mb > 0",
                ));
            };

            let handles = state.chainstate();
            let barrier = state.stable_read();
            let transition = barrier.lock();
            let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
            let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
            let (done_while_locked, result) =
                std::thread::scope(|scope| -> Result<_, TestError> {
                    let service = Arc::clone(&service);
                    let worker = scope.spawn(move || {
                        let _ = started_tx.send(());
                        let result = service.prune_to_height(11);
                        let _ = done_tx.send(());
                        result
                    });
                    started_rx.recv_timeout(Duration::from_secs(5))?;
                    let done_while_locked = done_rx.recv_timeout(Duration::from_millis(100));
                    publish_applied_tip_height(&state, 10 + CORE_REORG_SAFETY_MARGIN);
                    drop(transition);
                    let result = worker
                        .join()
                        .map_err(|_| TestError::message("prune worker panicked"))?;
                    Ok((done_while_locked, result))
                })?;
            let status_after = service.status();
            drop(service);
            drop(handles);
            drop(state);
            let reopened = NodeState::open(config, None)?;
            let Some(reopened_service) = reopened.prune_service() else {
                return Err(TestError::message(
                    "prune service should exist after reopen",
                ));
            };

            assert!(
                matches!(
                    done_while_locked,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ),
                "pruning entered while another chain transition held authority"
            );
            assert!(
                matches!(
                    &result,
                    Err(PruneServiceError::Failed(message))
                        if message == "prune height is within reorg safety margin"
                ),
                "pruning did not reject the tip observed under authority: {result:?}"
            );
            assert_eq!(status_after.pruneheight, None);
            assert_eq!(reopened_service.status().pruneheight, None);
            Ok(())
        }

        #[test]
        fn prune_refuses_after_apply_admission_closes() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.storage.prune_target_mb = 1;
            let state = NodeState::open(config, None)?;
            publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
            let Some(service) = state.prune_service() else {
                return Err(TestError::message(
                    "prune service should exist when prune_target_mb > 0",
                ));
            };

            state.chainstate().fail_closed_for_recovery();
            let result = service.prune_to_height(11);

            assert!(
                matches!(
                    &result,
                    Err(PruneServiceError::Failed(message))
                        if message == "block apply rejected because clean shutdown has begun"
                ),
                "pruning ignored closed chain-mutation admission: {result:?}"
            );
            assert_eq!(service.status().pruneheight, None);
            Ok(())
        }

        #[test]
        fn prune_to_height_advances_published_height() -> Result<(), TestError> {
            use bitcoin_rs_serving::context::PruneService;
            use bitcoin_rs_storage::FlatFileBlockStore;
            use bitcoin_rs_storage::KvStore;
            use bitcoin_rs_storage::pruning::load_pruneheight;
            use std::sync::atomic::AtomicU32;

            let dir = tempfile::tempdir()?;
            let mut authority_config =
                crate::NodeConfig::default_for_network(crate::Network::Regtest);
            authority_config.data_dir = dir.path().join("authority");
            authority_config.p2p.listen.clear();
            let authority_state = NodeState::open(authority_config, None)?;
            publish_applied_tip_height(&authority_state, 12 + CORE_REORG_SAFETY_MARGIN);
            let data_dir = dir.path().join("node");
            std::fs::create_dir_all(data_dir.join("chainstate"))?;
            let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
                data_dir.join("chainstate"),
                0,
            )?);
            let block_files = Arc::new(FlatFileBlockStore::open(&data_dir)?);
            let hash = bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[10_u8; 32]);
            let mut seed = store.new_batch();
            seed.put(
                bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
                &bitcoin_rs_storage::pruning::block_body_key(10, hash),
                &bitcoin_rs_storage::BlockFilePosition {
                    file_no: 0,
                    offset: 0,
                    len: 1,
                }
                .encode(),
            );
            seed.put(
                bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
                &bitcoin_rs_storage::block_file_max_height_key(0),
                &bitcoin_rs_storage::encode_block_file_max_height(10),
            );
            store.write(seed)?;
            let service = Arc::new(super::super::storage::NodePruneService::new(
                Arc::clone(&store),
                block_files,
                authority_state.chainstate().prune_authority(),
                Arc::new(AtomicU32::new(11 + CORE_REORG_SAFETY_MARGIN)),
                Arc::new(bitcoin_rs_storage::RetentionRegistry::new()),
            )?);

            let lower_result = service
                .prune_to_height(11)
                .map_err(|err| TestError::message(format!("lower prune failed: {err}")))?;
            let higher_result = service
                .prune_to_height(12)
                .map_err(|err| TestError::message(format!("higher prune failed: {err}")))?;
            assert_eq!(lower_result.pruneheight, 11);
            assert_eq!(higher_result.pruneheight, 12);

            assert_eq!(service.status().pruneheight, Some(12));
            assert_eq!(load_pruneheight(&*store)?, Some(12));
            Ok(())
        }

        #[test]
        fn assumeutxo_validating_blocks_prefix_pruning_even_above_base_height()
        -> Result<(), TestError> {
            use bitcoin_rs_consensus::primitives::Network;
            use bitcoin_rs_execution::AssumeUtxoManager;
            use bitcoin_rs_storage::FlatFileBlockStore;
            use std::sync::atomic::AtomicU32;

            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;
            publish_applied_tip_height(&state, 200 + CORE_REORG_SAFETY_MARGIN);

            let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
                dir.path().join("chainstate"),
                0,
            )?);
            let block_files = Arc::new(FlatFileBlockStore::open(dir.path())?);

            let pinned = Network::Regtest
                .assume_utxo_for_height(110)
                .ok_or_else(|| TestError::message("pinned 110 missing"))?;
            let status = bitcoin_rs_execution::AssumeUtxoDiskStatus::Validating {
                base_height: pinned.height,
                base_hash: pinned.block_hash,
                expected_hash_serialized: pinned.hash_serialized,
                chain_tx_count: pinned.chain_tx_count,
                historical_height: 0,
                historical_hash: Network::Regtest.genesis_block_hash(),
                pending: None,
                checkpoint: None,
            };
            let head_store = state.durable_head();
            let prior = head_store.load()?;
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or_else(|| TestError::message("missing fixture tip"))?;
            state
                .chainstate()
                .commit_authority()
                .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: prior,
                    next_head: bitcoin_rs_storage::DurableHead {
                        assumeutxo: status,
                        commit_id: 1,
                        tip: tip.hash,
                        height: tip.height,
                        chain_tx_count: tip.chain_tx_count.to_wire(),
                        body_extent: None,
                        undo_extent: None,
                    },
                    undo_rows: Vec::new(),
                    body_rows: Vec::new(),
                    attestation: None,
                    coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                })
                .map_err(|error| bitcoin_rs_storage::StorageError::backend(error.to_string()))?;
            let _assumeutxo = AssumeUtxoManager::open(
                Network::Regtest,
                state.chainstate(),
                dir.path().to_path_buf(),
            )?;

            let service = Arc::new(super::super::storage::NodePruneService::new(
                store,
                block_files,
                state.chainstate().prune_authority(),
                Arc::new(AtomicU32::new(200 + CORE_REORG_SAFETY_MARGIN)),
                Arc::new(bitcoin_rs_storage::RetentionRegistry::new()),
            )?);

            for height in [100, 110, 111, 200] {
                let Err(error) = service.prune_to_height(height) else {
                    return Err(TestError::message(format!(
                        "expected prune failure at height {height}"
                    )));
                };
                assert!(
                    error
                        .to_string()
                        .contains("historical validation is required")
                );
                assert_eq!(service.status().pruneheight, None);
            }

            Ok(())
        }
    }
    mod recovery {
        use super::*;
        use crate::state::open::NodeOpenError;
        use crate::test_support::TestError;
        use sonic_rs::JsonValueTrait as _;

        const CRASH_TEST_BACKEND_ENV: &str = "BITCOIN_RS_CRASH_TEST_BACKEND";

        fn crash_test_backend(
            default: bitcoin_rs_storage::StorageBackend,
        ) -> bitcoin_rs_storage::StorageBackend {
            let value = match std::env::var(CRASH_TEST_BACKEND_ENV) {
                Ok(value) => value,
                Err(std::env::VarError::NotPresent) => return default,
                Err(error) => panic!("invalid {CRASH_TEST_BACKEND_ENV}: {error}"),
            };
            let backend: bitcoin_rs_storage::StorageBackend = match value.parse() {
                Ok(backend) => backend,
                Err(error) => panic!("invalid {CRASH_TEST_BACKEND_ENV} {value:?}: {error}"),
            };
            assert!(
                backend.is_compiled_in(),
                "BITCOIN_RS_CRASH_TEST_BACKEND {value:?} is not compiled into this test binary"
            );
            backend
        }

        #[test]
        fn full_revalidation_marker_is_sticky_in_the_datadir() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            std::fs::create_dir_all(&config.data_dir)?;
            let marker = config
                .data_dir
                .join(bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER);
            std::fs::write(&marker, b"force full validation\n")?;

            assert!(requires_full_revalidation(&config.data_dir));
            Ok(())
        }

        #[test]
        fn invalidate_block_settles_disconnect_debt() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir.clone();
            config.p2p.listen.clear();
            config.storage.backend = crash_test_backend(config.storage.backend);
            let state = NodeState::open(config.clone(), None)?;
            let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis.clone(),
            ))?;
            let block_one = regtest_fixture::mined_regtest_child_at_time(
                genesis.block_hash(),
                genesis.header.time + 1,
                1,
            )?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block_one.clone(),
            ))?;
            state.publish_checkpoint()?;

            let block_two = regtest_fixture::mined_regtest_child_at_time(
                block_one.block_hash(),
                genesis.header.time + 2,
                2,
            )?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block_two.clone(),
            ))?;

            crate::reorg::invalidate_block(
                &state.chainstate(),
                &state.chain_followers(),
                Hash256::from(block_two.block_hash()),
            )?;

            let head = state
                .storage
                .durable_head()
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(head.height, 1);
            assert_eq!(head.tip, Hash256::from(block_one.block_hash()));
            assert!(
                state.undo_store().load_disconnect_marker()?.is_none(),
                "settling debt against the engine disarms the disconnect marker"
            );
            let tip = state
                .chainstate()
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("applied tip after invalidation"))?;
            assert_eq!(tip.height, 1);
            assert_eq!(tip.hash, Hash256::from(block_one.block_hash()));

            drop(state);
            let reopened = NodeState::open(config, None)?;
            let reopened_tip = reopened
                .chainstate()
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("reopened tip"))?;
            assert_eq!(reopened_tip.height, 1);
            assert_eq!(reopened_tip.hash, Hash256::from(block_one.block_hash()));
            Ok(())
        }

        #[test]
        fn below_base_invalidate_settles_debt_against_engine() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir.clone();
            config.p2p.listen.clear();
            config.storage.backend = crash_test_backend(config.storage.backend);
            let state = NodeState::open(config.clone(), None)?;
            let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis.clone(),
            ))?;
            let block_one = regtest_fixture::mined_regtest_child_at_time(
                genesis.block_hash(),
                genesis.header.time + 1,
                1,
            )?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block_one.clone(),
            ))?;
            state.publish_checkpoint()?;
            let block_two = regtest_fixture::mined_regtest_child_at_time(
                block_one.block_hash(),
                genesis.header.time + 2,
                2,
            )?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block_two,
            ))?;

            crate::reorg::invalidate_block(
                &state.chainstate(),
                &state.chain_followers(),
                Hash256::from(block_one.block_hash()),
            )?;

            let head = state
                .storage
                .durable_head()
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(
                (head.height, head.tip),
                (0, Hash256::from(genesis.block_hash())),
                "settlement must record the rolled-back head in the engine"
            );
            assert!(
                state.undo_store().load_disconnect_marker()?.is_none(),
                "settling debt against the engine disarms the disconnect marker"
            );
            let tip = state
                .chainstate()
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("applied tip after invalidation"))?;
            assert_eq!(
                (tip.height, tip.hash),
                (0, Hash256::from(genesis.block_hash()))
            );

            let mut previous = genesis.block_hash();
            for height in 1..=2 {
                let replacement = regtest_fixture::mined_regtest_child_at_time(
                    previous,
                    genesis.header.time + 10 + height,
                    height,
                )?;
                previous = replacement.block_hash();
                state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    replacement,
                ))?;
            }
            let tip = state
                .chainstate()
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("rebuilt tip"))?;
            assert_eq!(tip.height, 2);

            drop(state);
            let reopened = NodeState::open(config, None)?;
            let reopened_tip = reopened
                .chainstate()
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("reopened tip"))?;
            assert_eq!(
                (reopened_tip.height, reopened_tip.hash),
                (2, Hash256::from(previous)),
            );
            Ok(())
        }

        #[test]
        fn invalidate_preflights_first_replacement_body_before_disconnect() -> Result<(), TestError>
        {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node-invalidate-preflight");
            config.p2p.listen.clear();
            config.storage.backend = crash_test_backend(config.storage.backend);
            let state = NodeState::open(config, None)?;
            let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis.clone(),
            ))?;
            let block_one = regtest_fixture::mined_regtest_child_at_time(
                genesis.block_hash(),
                genesis.header.time + 1,
                1,
            )?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block_one.clone(),
            ))?;
            let block_two = regtest_fixture::mined_regtest_child_at_time(
                block_one.block_hash(),
                genesis.header.time + 2,
                2,
            )?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block_two,
            ))?;
            let before = state
                .chainstate()
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("active tip"))?;

            let replacement = regtest_fixture::mined_regtest_child_at_time(
                genesis.block_hash(),
                genesis.header.time + 20,
                1,
            )?;
            let genesis_id = state
                .chainstate()
                .block_tree()
                .read()
                .lookup(Hash256::from(genesis.block_hash()))
                .ok_or(TestError::Missing("genesis node"))?;
            crate::sync::fixture_insert_header_node(
                &state.chainstate(),
                genesis_id,
                replacement.header,
                bitcoin_rs_execution::chain::node::NodeStatus::HeaderValid,
            )?;

            let result = crate::reorg::invalidate_block(
                &state.chainstate(),
                &state.chain_followers(),
                Hash256::from(block_one.block_hash()),
            );

            assert!(matches!(
                result,
                Err(crate::reorg::ReorgError::MissingBody {
                    hash,
                    height: 1,
                }) if hash == Hash256::from(replacement.block_hash())
            ));
            assert_eq!(
                state
                    .chainstate()
                    .applied_tip()
                    .load_full()
                    .map(|tip| tip.hash),
                Some(before.hash),
                "missing first replacement body must be discovered before disconnect"
            );
            Ok(())
        }

        #[test]
        fn switch_to_branch_settles_disconnect_debt() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir.clone();
            config.p2p.listen.clear();
            config.storage.backend = crash_test_backend(config.storage.backend);
            let state = NodeState::open(config.clone(), None)?;
            let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis.clone(),
            ))?;
            let block_one = regtest_fixture::mined_regtest_child_at_time(
                genesis.block_hash(),
                genesis.header.time + 1,
                1,
            )?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block_one,
            ))?;
            state.publish_checkpoint()?;

            let genesis_id = state
                .chainstate()
                .block_tree()
                .read()
                .lookup(Hash256::from(genesis.block_hash()))
                .ok_or(TestError::Missing("genesis node"))?;
            let mut parent = genesis_id;
            let mut previous_hash = genesis.block_hash();
            let mut fork_bodies = HashMap::new();
            for height in 1..=2 {
                let block = regtest_fixture::mined_regtest_child_at_time(
                    previous_hash,
                    genesis.header.time + 10 + height,
                    height,
                )?;
                let node_id = crate::sync::fixture_insert_header_node(
                    &state.chainstate(),
                    parent,
                    block.header,
                    bitcoin_rs_execution::chain::node::NodeStatus::HeaderValid,
                )?;
                fork_bodies.insert(
                    Hash256::from(block.block_hash()),
                    bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone()),
                );
                parent = node_id;
                previous_hash = block.block_hash();
            }

            let handles = state.chainstate();
            crate::reorg::switch_to_branch(
                &handles,
                &state.chain_followers(),
                parent,
                |hash| fork_bodies.get(&hash).cloned(),
                |_| {},
            )?;

            let head = state
                .storage
                .durable_head()
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            assert_eq!(head.height, 2);
            assert_eq!(head.tip, Hash256::from(previous_hash));
            assert!(state.undo_store().load_disconnect_marker()?.is_none());
            let tip = handles
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("applied tip after branch switch"))?;
            assert_eq!(tip.height, 2);
            assert_eq!(tip.hash, Hash256::from(previous_hash));

            drop(handles);
            drop(state);
            let reopened = NodeState::open(config, None)?;
            let reopened_tip = reopened
                .chainstate()
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("reopened tip"))?;
            assert_eq!(reopened_tip.height, 2);
            assert_eq!(reopened_tip.hash, Hash256::from(previous_hash));
            Ok(())
        }

        #[test]
        fn witness_is_published_only_after_current_root_sync() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir.clone();
            config.p2p.listen.clear();
            config.storage.backend = crash_test_backend(config.storage.backend);

            let state = NodeState::open(config.clone(), None)?;
            let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            let tip = state.apply_block(
                &bitcoin_rs_consensus::primitives::BlockImage::from_local(genesis),
            )?;

            state.publish_checkpoint()?;
            let witness_path = data_dir.join("applied-tip-witness.json");
            assert!(
                witness_path.exists(),
                "witness file must exist after checkpoint publication"
            );
            let genesis_hex = config.network.genesis_block_hash().to_string_be();
            let witness =
                bitcoin_rs_storage::recovery_evidence::read_witness(&data_dir, &genesis_hex)
                    .ok_or(TestError::Missing("durable witness"))?;
            assert_eq!(witness.height, tip.height);
            assert_eq!(witness.block_hash, tip.hash.to_string_be());
            drop(state);

            Ok(())
        }

        #[test]
        fn stale_checkpoint_restore_surfaces_warning_not_silence() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir.clone();
            config.p2p.listen.clear();
            config.storage.backend = crash_test_backend(config.storage.backend);
            config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;

            let state = NodeState::open(config.clone(), None)?;
            let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis,
            ))?;
            assert!(state.publish_checkpoint()?.is_some());
            drop(state);

            let genesis_hex = config.network.genesis_block_hash().to_string_be();
            let stale_witness = bitcoin_rs_storage::recovery_evidence::AppliedTipWitness::new(
                genesis_hex,
                1,
                5000,
                "cccc",
                1000,
            );
            bitcoin_rs_storage::recovery_evidence::write_witness(&data_dir, &stale_witness)?;

            let resumed = NodeState::open(config.clone(), None)?;
            let warnings = resumed.recovery_reporter().0.warnings();
            assert!(
                !warnings.is_empty(),
                "a stale checkpoint restore 5000 blocks behind the witness must \
     produce at least one rollback warning, not silence"
            );
            assert!(
                warnings.iter().any(|w| w.contains("height 5000")),
                "the warning must name the witness height; got: {warnings:?}"
            );
            assert_eq!(
                resumed.resume_source(),
                ResumeSource::Checkpoint,
                "the checkpoint is still accepted — it is valid, just stale"
            );
            Ok(())
        }

        type ForkFixture = (
            tempfile::TempDir,
            NodeState,
            bitcoin_rs_execution::chain::NodeId,
            HashMap<
                bitcoin_rs_consensus::primitives::Hash256,
                bitcoin_rs_consensus::primitives::BlockImage,
            >,
        );

        fn forked_regtest_state() -> Result<ForkFixture, TestError> {
            let dir = tempfile::tempdir()?;
            let data_dir = dir.path().join("node");
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = data_dir;
            config.p2p.listen.clear();
            config.storage.backend = crash_test_backend(config.storage.backend);
            let state = NodeState::open(config, None)?;
            let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis.clone(),
            ))?;
            let block_one = regtest_fixture::mined_regtest_child_at_time(
                genesis.block_hash(),
                genesis.header.time + 1,
                1,
            )?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block_one,
            ))?;
            state.publish_checkpoint()?;

            let genesis_id = state
                .chainstate()
                .block_tree()
                .read()
                .lookup(Hash256::from(genesis.block_hash()))
                .ok_or(TestError::Missing("genesis node"))?;
            let mut parent = genesis_id;
            let mut previous_hash = genesis.block_hash();
            let mut fork_bodies = HashMap::new();
            for height in 1..=2 {
                let block = regtest_fixture::mined_regtest_child_at_time(
                    previous_hash,
                    genesis.header.time + 10 + height,
                    height,
                )?;
                let node_id = crate::sync::fixture_insert_header_node(
                    &state.chainstate(),
                    parent,
                    block.header,
                    bitcoin_rs_execution::chain::node::NodeStatus::HeaderValid,
                )?;
                fork_bodies.insert(
                    Hash256::from(block.block_hash()),
                    bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone()),
                );
                parent = node_id;
                previous_hash = block.block_hash();
            }
            Ok((dir, state, parent, fork_bodies))
        }

        #[test]
        fn switch_to_branch_releases_retention_authority_once() -> Result<(), TestError> {
            let (_dir, state, fork_tip, fork_bodies) = forked_regtest_state()?;
            let handles = state.chainstate();
            assert_eq!(state.storage.retention().active_leases(), 0);

            crate::reorg::switch_to_branch(
                &handles,
                &state.chain_followers(),
                fork_tip,
                |hash| fork_bodies.get(&hash).cloned(),
                |_| {},
            )?;

            assert_eq!(state.storage.retention().active_leases(), 0);
            Ok(())
        }

        #[test]
        fn switch_to_branch_refuses_history_the_prune_line_crossed() -> Result<(), TestError> {
            let (_dir, state, fork_tip, fork_bodies) = forked_regtest_state()?;
            let handles = state.chainstate();
            let tip_before = handles.applied_tip().load_full().map(|tip| tip.hash);
            let reservation = state.storage.retention().reserve(5);
            reservation.commit(5);

            let outcome = crate::reorg::switch_to_branch(
                &handles,
                &state.chain_followers(),
                fork_tip,
                |hash| fork_bodies.get(&hash).cloned(),
                |_| {},
            );

            assert!(matches!(
                outcome,
                Err(crate::reorg::ReorgError::RetentionUnavailable { floor: 1, .. })
            ));
            assert_eq!(
                handles.applied_tip().load_full().map(|tip| tip.hash),
                tip_before
            );
            assert_eq!(state.storage.retention().active_leases(), 0);
            assert!(handles.lock_transition().is_ok());
            Ok(())
        }

        fn applied_regtest_chain(
            heights: u32,
            checkpoint_height: u32,
        ) -> Result<(tempfile::TempDir, NodeState, crate::NodeConfig), TestError> {
            assert!((1..=heights).contains(&checkpoint_height));
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            config.storage.backend = crash_test_backend(config.storage.backend);
            config.storage.prune_target_mb = 1;
            let state = NodeState::open(config.clone(), None)?;
            let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis.clone(),
            ))?;
            let mut previous = genesis.block_hash();
            let mut time = genesis.header.time;
            for height in 1..=heights {
                time += 1;
                let block = regtest_fixture::mined_regtest_child_at_time(previous, time, height)?;
                state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    block.clone(),
                ))?;
                previous = block.block_hash();
                if height == checkpoint_height {
                    state.publish_checkpoint()?;
                }
            }
            Ok((dir, state, config))
        }

        #[test]
        fn missing_checkpoint_replays_durable_head_chain_at_startup() -> Result<(), TestError> {
            let (_dir, state, config) = applied_regtest_chain(2, 1)?;
            let remembered_tip = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("applied tip"))?;
            let committed_coins = state
                .chainstate()
                .coins()
                .scan_snapshot()?
                .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
                .collect::<Result<Vec<_>, _>>()?;
            let root = config.data_dir.join("chainstate-checkpoints");
            let current: sonic_rs::Value =
                sonic_rs::from_slice(&std::fs::read(root.join("CURRENT"))?)?;
            let directory = current
                .get("directory")
                .and_then(|value| value.as_str())
                .ok_or_else(|| std::io::Error::other("CURRENT has no generation directory"))?;
            let image = root.join(directory).join("chainstate");
            let missing_image = root.join(directory).join("chainstate.missing");
            std::fs::rename(&image, &missing_image)?;
            drop(state);

            let open_result = NodeState::open(config.clone(), None);
            std::fs::rename(&missing_image, &image)?;
            let error = open_result.err().ok_or(TestError::UnexpectedSuccess(
                "missing checkpoint engine image was accepted",
            ))?;
            assert!(
                matches!(
                    &error,
                    NodeOpenError::Recovery(source)
                        if matches!(
                            source.as_ref(),
                            bitcoin_rs_execution::recovery::RecoveryError::CheckpointEngineImageMissing
                        )
                ),
                "unexpected missing-image refusal: {error:#}"
            );

            std::fs::remove_dir_all(root)?;
            let reopened = NodeState::open(config, None)?;
            let tip = reopened
                .chainstate()
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("replayed applied tip"))?;
            assert_eq!(
                (tip.hash, tip.height),
                (remembered_tip.hash, remembered_tip.height),
                "a missing checkpoint must replay the durable head chain from genesis"
            );
            let reopened_coins = reopened
                .chainstate()
                .coins()
                .scan_snapshot()?
                .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(
                reopened_coins, committed_coins,
                "newer committed coin rows must survive the missing-image refusal"
            );
            Ok(())
        }

        #[test]
        fn committed_frame_corruption_refuses_startup_and_preserves_all_bytes()
        -> Result<(), TestError> {
            for keep_checkpoint in [false, true] {
                for corrupt_length in [false, true] {
                    let (_dir, state, config) = applied_regtest_chain(2, 2)?;
                    drop(state);
                    if !keep_checkpoint {
                        std::fs::remove_dir_all(config.data_dir.join("chainstate-checkpoints"))?;
                    }
                    let path = config.data_dir.join("blocks/blk00000.dat");
                    let mut damaged = std::fs::read(&path)?;
                    let genesis_len = u32::from_le_bytes(damaged[4..8].try_into()?);
                    let middle = 44 + usize::try_from(genesis_len)?;
                    assert_eq!(&damaged[middle..middle + 4], b"BRSB");
                    if corrupt_length {
                        damaged[middle + 4..middle + 8].copy_from_slice(&u32::MAX.to_le_bytes());
                    } else {
                        damaged[middle] ^= 0xff;
                    }
                    std::fs::write(&path, &damaged)?;
                    let error =
                        NodeState::open(config, None)
                            .err()
                            .ok_or(TestError::UnexpectedSuccess(
                                "committed corruption was accepted",
                            ))?;
                    assert!(
                        matches!(
                            error,
                            NodeOpenError::Storage(
                                bitcoin_rs_storage::StorageError::IncompatibleData(_)
                            )
                        ),
                        "unexpected refusal: {error:#}"
                    );
                    assert_eq!(std::fs::read(path)?, damaged);
                }
            }
            Ok(())
        }

        #[test]
        fn startup_verification_refuses_a_corrupt_tip_body() -> Result<(), TestError> {
            use bitcoin_rs_execution::verify::VerifyError;

            let (_dir, state, config) = applied_regtest_chain(2, 2)?;
            drop(state);
            let data_dir = config.data_dir.clone();
            let path = data_dir.join("blocks/blk00000.dat");
            let mut damaged = std::fs::read(&path)?;
            *damaged.last_mut().ok_or(TestError::Missing("block file"))? ^= 0xff;
            std::fs::write(&path, &damaged)?;

            let error = NodeState::open(config, None)
                .err()
                .ok_or(TestError::UnexpectedSuccess(
                    "a damaged tip body was accepted",
                ))?;
            let NodeOpenError::StartupVerification { paths, source, .. } = &error else {
                return Err(TestError::ExpectationFailed(
                    "a damaged tip body must refuse startup verification",
                ));
            };
            assert!(
                matches!(source, VerifyError::Binding { height: 2, .. }),
                "unexpected refusal: {error:#}"
            );
            assert_eq!(
                paths.checkpoints,
                data_dir.join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT),
                "the operator must be pointed at the checkpoint root that holds the files"
            );
            assert!(
                paths.checkpoints.is_dir(),
                "the named checkpoint directory must exist: {}",
                paths.checkpoints.display()
            );
            assert_eq!(
                paths.txindex,
                data_dir.join(crate::state::TXINDEX_NAMESPACE),
                "the operator must be pointed at the txindex namespace directory"
            );
            assert_eq!(
                std::fs::read(&path)?,
                damaged,
                "refusing to start must not repair or truncate the block file"
            );
            Ok(())
        }

        #[test]
        fn checkpoint_resume_discards_only_incomplete_uncommitted_tail() -> Result<(), TestError> {
            use std::io::Write as _;

            let (_dir, state, config) = applied_regtest_chain(2, 2)?;
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("fixture tip"))?;
            drop(state);
            let path = config.data_dir.join("blocks/blk00000.dat");
            let committed = std::fs::read(&path)?;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)?
                .write_all(b"BR")?;
            let reopened = NodeState::open(config, None)?;
            assert_eq!(std::fs::read(&path)?, committed);
            assert_eq!(
                reopened
                    .chainstate()
                    .applied_tip_snapshot()
                    .map(|tip| tip.hash),
                Some(tip.hash)
            );
            Ok(())
        }

        #[test]
        fn full_revalidation_marker_resumes_on_durable_head() -> Result<(), TestError> {
            let (_dir, state, config) = applied_regtest_chain(2, 1)?;
            let remembered_tip = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("applied tip"))?;
            drop(state);
            std::fs::write(
                config
                    .data_dir
                    .join(bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER),
                b"force full validation\n",
            )?;

            let reopened = NodeState::open(config, None)?;
            let tip = reopened
                .chainstate()
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("replayed applied tip"))?;
            assert_eq!(
                (tip.hash, tip.height),
                (remembered_tip.hash, remembered_tip.height),
                "forced full revalidation must rebuild on the durable head chain"
            );
            Ok(())
        }
        // SYNC-05
        #[test]
        fn full_revalidation_cold_open_wipes_stale_engine_coins() -> Result<(), TestError> {
            let (_dir, state, config) = applied_regtest_chain(2, 1)?;
            let remembered_tip = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("applied tip"))?;
            let stale = bitcoin_rs_storage::CoinKey([0xA5; 32]);
            assert!(
                state.chainstate().coins().get(&stale)?.is_none(),
                "the probe key must start absent from the engine coin namespace"
            );
            state.chainstate().coins().ingest_sorted(std::iter::once((
                stale,
                bitcoin_rs_storage::Bytes::from_static(b"stale"),
            )))?;
            assert!(
                state.chainstate().coins().get(&stale)?.is_some(),
                "the seeded row must read back before the cold reopen"
            );
            drop(state);
            std::fs::write(
                config
                    .data_dir
                    .join(bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER),
                b"force full validation\n",
            )?;
            let reopened = NodeState::open(config, None)?;
            assert!(
                reopened.chainstate().coins().get(&stale)?.is_none(),
                "a cold open with no engine image must wipe stale engine coin rows before replay"
            );
            let tip = reopened
                .chainstate()
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("replayed applied tip"))?;
            assert_eq!(
                (tip.hash, tip.height),
                (remembered_tip.hash, remembered_tip.height),
                "the wipe must keep the durable head chain that replay rebuilds"
            );
            Ok(())
        }

        type ForkPlan = (
            bitcoin_rs_execution::chain::NodeId,
            HashMap<
                bitcoin_rs_consensus::primitives::Hash256,
                bitcoin_rs_consensus::primitives::BlockImage,
            >,
            Vec<(u32, bitcoin_rs_consensus::primitives::Hash256)>,
        );

        fn plan_fork(
            state: &NodeState,
            fork_height: u32,
            depth: u32,
            time_base: u32,
        ) -> Result<ForkPlan, TestError> {
            let ancestor = {
                let tree = state.chainstate().block_tree_reader();
                let tree = tree.read();
                let tip = tree.tip().ok_or(TestError::Missing("chain tip"))?;
                tree.node_at_height_from(tip.tip_id, fork_height)
                    .ok_or(TestError::Missing("active node at the fork height"))?
            };
            let ancestor_hash = state.chainstate().block_tree().read().node(ancestor)?.hash;
            let mut parent = ancestor;
            let mut previous = BlockHash::from(ancestor_hash);
            let mut bodies = HashMap::new();
            let mut ordered = Vec::new();
            for height in fork_height + 1..=fork_height + depth {
                let block = regtest_fixture::mined_regtest_child_at_time(
                    previous,
                    time_base.wrapping_add(height),
                    height,
                )?;
                let hash = Hash256::from(block.block_hash());
                let node_id = crate::sync::fixture_insert_header_node(
                    &state.chainstate(),
                    parent,
                    block.header,
                    bitcoin_rs_execution::chain::node::NodeStatus::HeaderValid,
                )?;
                bodies.insert(
                    hash,
                    bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone()),
                );
                ordered.push((height, hash));
                parent = node_id;
                previous = block.block_hash();
            }
            Ok((parent, bodies, ordered))
        }

        #[test]
        fn prune_then_reorg_refuses_deleted_history_but_keeps_retained_reorgs()
        -> Result<(), TestError> {
            let (_dir, state, _config) = applied_regtest_chain(620, 320)?;
            let (deep_tip, deep_bodies, _deep_order) = plan_fork(&state, 20, 2, 1_400_000_000)?;
            let (shallow_tip, shallow_bodies, _shallow_order) =
                plan_fork(&state, 400, 2, 1_500_000_000)?;
            let Some(service) = state.prune_service() else {
                return Err(TestError::Missing("prune service with prune_target_mb > 0"));
            };

            service.prune_to_height(30).map_err(TestError::from)?;
            let handles = state.chainstate();
            assert_eq!(state.storage.retention().pruned_below(), 30);

            let outcome = crate::reorg::switch_to_branch(
                &handles,
                &state.chain_followers(),
                deep_tip,
                |hash| deep_bodies.get(&hash).cloned(),
                |_| {},
            );
            let Err(error) = outcome else {
                panic!("a reorg rooted in pruned history must be refused");
            };
            assert!(
                matches!(
                    &error,
                    crate::reorg::ReorgError::RetentionUnavailable { floor: 21, .. }
                ),
                "deep reorg must refuse deleted history, got: {error:?}"
            );
            assert_eq!(state.storage.retention().active_leases(), 0);

            crate::reorg::switch_to_branch(
                &handles,
                &state.chain_followers(),
                shallow_tip,
                |hash| shallow_bodies.get(&hash).cloned(),
                |_| {},
            )?;
            let landed = handles
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("reorg-published tip"))?;
            assert_eq!(landed.height, 402);
            assert_eq!(state.storage.retention().active_leases(), 0);
            Ok(())
        }

        #[test]
        fn deep_reorg_streams_bounded_prefixes_to_the_exact_reference() -> Result<(), TestError> {
            const STAGED_PREFIX: u32 = 16;
            let (_dir, state, _config) = applied_regtest_chain(320, 1)?;
            let (fork_tip, fork_bodies, ordered) = plan_fork(&state, 20, 300, 1_600_000_000)?;
            let height_of: HashMap<bitcoin_rs_consensus::primitives::Hash256, u32> = ordered
                .iter()
                .map(|(height, hash)| (*hash, *height))
                .collect();
            let height_of = std::sync::Arc::new(height_of);

            let (_ref_dir, reference, _ref_config) = applied_regtest_chain(20, 1)?;
            for (_height, hash) in &ordered {
                let block = fork_bodies
                    .get(hash)
                    .ok_or(TestError::Missing("fork body in the plan"))?;
                reference.apply_block(block)?;
            }

            let handles = state.chainstate();
            let served_through = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(20));
            let mut switches = 0_u32;
            loop {
                switches += 1;
                assert!(
                    switches <= 48,
                    "bounded stepping did not converge after {switches} switches"
                );
                let served = served_through.clone();
                let reporter = served_through.clone();
                let reporter_heights = std::sync::Arc::clone(&height_of);
                let outcome = crate::reorg::switch_to_branch(
                    &handles,
                    &state.chain_followers(),
                    fork_tip,
                    |hash| match height_of.get(&hash) {
                        Some(height)
                            if *height <= served.load(Ordering::Acquire) + STAGED_PREFIX =>
                        {
                            fork_bodies.get(&hash).cloned()
                        }
                        _ => None,
                    },
                    move |hash| {
                        if let Some(height) = reporter_heights.get(&hash) {
                            reporter.store(*height, Ordering::Release);
                        }
                    },
                );
                match outcome {
                    Ok(()) => break,
                    Err(crate::reorg::ReorgError::MissingBody { .. }) => continue,
                    Err(error) => return Err(error.into()),
                }
            }

            let landed = handles
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("reorg-published tip"))?;
            let reference_tip = reference
                .chainstate()
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("reference-published tip"))?;
            assert_eq!(landed.hash, reference_tip.hash);
            assert_eq!(landed.height, reference_tip.height);
            let restored = state
                .chainstate()
                .applied_tip_reader()
                .load_full()
                .ok_or(TestError::Missing("restored-node published tip"))?;
            assert_eq!(restored.chain_tx_count, reference_tip.chain_tx_count);
            assert_eq!(state.storage.retention().active_leases(), 0);
            Ok(())
        }

        #[test]
        fn restart_without_periodic_publication_restores_tip_and_commit_id() -> Result<(), TestError>
        {
            let (_dir, state, config) = applied_regtest_chain(4, 1)?;
            let head = state
                .storage
                .durable_head()
                .load()?
                .ok_or(TestError::Missing("durable head"))?;
            let pre_tip = state
                .chainstate()
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("applied tip before restart"))?;
            assert_eq!(pre_tip.height, 4);
            drop(state);

            let reopened = NodeState::open(config.clone(), None)?;
            let landed = reopened
                .chainstate()
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("restart-published tip"))?;
            assert_eq!(landed.as_ref(), pre_tip.as_ref());
            assert_eq!(landed.height, head.height);
            let restored = reopened
                .storage
                .durable_head()
                .load()?
                .ok_or(TestError::Missing("surviving durable head"))?;
            assert_eq!(restored.tip, head.tip);
            assert_eq!(restored.commit_id, head.commit_id);
            assert!(matches!(reopened.resume_source(), ResumeSource::Checkpoint));

            drop(reopened);
            let second = NodeState::open(config, None)?;
            let landed = second
                .chainstate()
                .applied_tip()
                .load_full()
                .ok_or(TestError::Missing("second-restart published tip"))?;
            assert_eq!(landed.hash, head.tip);
            assert_eq!(landed.height, head.height);
            Ok(())
        }

        // RCV-02
        #[test]
        fn stored_prune_height_comes_from_the_datadir_not_the_config() -> Result<(), TestError> {
            let (_dir, state, config) = applied_regtest_chain(620, 320)?;
            let service = state
                .prune_service()
                .ok_or(TestError::Missing("prune service with prune_target_mb > 0"))?;
            service.prune_to_height(30).map_err(TestError::from)?;
            drop(service);
            drop(state);

            let mut reopen = config;
            reopen.storage.prune_target_mb = 0;
            let state = NodeState::open(reopen, None)?;
            assert_eq!(
                state.storage.stored_prune_height(),
                Some(30),
                "a datadir pruned before keeps its prune height after the config drops it"
            );
            Ok(())
        }
    }

    use crate::test_support::TestError;

    use bitcoin_rs_execution::chain::{TipSnapshot, regtest_fixture};

    use bitcoin_rs_consensus::primitives::{Hash256, chain_constants::CORE_REORG_SAFETY_MARGIN};

    use bitcoin_rs_serving::context::PruneServiceError;

    use core::mem::size_of;

    use hashbrown::HashMap;

    use bitcoin_rs_execution::{events::*, recovery::*};

    use std::{
        sync::{Arc, atomic::Ordering},
        time::Duration,
    };

    use super::*;
    use bitcoin_rs_consensus::primitives::LockTime;

    fn applied_chain_tx_count(state: &NodeState) -> bitcoin_rs_execution::chain::ChainTxCount {
        state
            .chainstate()
            .applied_tip_reader()
            .load_full()
            .map_or(bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN, |tip| {
                tip.chain_tx_count
            })
    }

    use bitcoin_rs_projection::IndexCapabilities;

    use bitcoin_rs_consensus::primitives::BlockHash;

    fn publish_applied_tip_height(state: &NodeState, height: u32) {
        let mut hash = [0_u8; 32];
        hash[..size_of::<u32>()].copy_from_slice(&height.to_le_bytes());
        state
            .chainstate()
            .applied_tip()
            .store(Some(Arc::new(TipSnapshot {
                tip_id: bitcoin_rs_execution::chain::node::NodeId::new(height),
                height,
                chainwork: bitcoin_rs_consensus::header_rules::ChainWork::ZERO,
                hash: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&hash),
                chain_tx_count: bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN,
            })));
    }

    fn dir_listing(data_dir: &std::path::Path) -> String {
        match std::fs::read_dir(data_dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(","),
            Err(error) => format!("(listing failed: {error})"),
        }
    }

    #[test]
    fn process_epoch_allocation_is_unique_across_processes() -> Result<(), TestError> {
        const CHILD_DIR_ENV: &str = "BITCOIN_RS_TEST_EPOCH_CHILD_DIR";
        const CHILDREN: usize = 8;
        if let Ok(data_dir) = std::env::var(CHILD_DIR_ENV) {
            let data_dir = std::path::PathBuf::from(data_dir);
            let dir = cap_std::fs::Dir::open_ambient_dir(&data_dir, cap_std::ambient_authority())?;
            std::fs::write(data_dir.join(format!("ready-{}", std::process::id())), b"")?;
            let go = data_dir.join("go");
            let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
            while !go.exists() {
                if std::time::Instant::now() >= deadline {
                    return Err(TestError::message(
                        "epoch child never saw the start barrier",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let epoch = allocate_process_epoch(&dir)?;
            std::fs::write(
                data_dir.join(format!("epoch-{}", std::process::id())),
                format!("{epoch}\n"),
            )?;
            std::process::exit(0);
        }

        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        std::fs::create_dir_all(&data_dir)?;

        let test_name = concat!(
            module_path!(),
            "::process_epoch_allocation_is_unique_across_processes"
        )
        .split("::")
        .skip(1)
        .collect::<Vec<_>>()
        .join("::");
        let exe = std::env::current_exe()?;
        let mut children = Vec::new();
        for _ in 0..CHILDREN {
            children.push(
                std::process::Command::new(&exe)
                    .args(["--exact", &test_name])
                    .env(CHILD_DIR_ENV, &data_dir)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?,
            );
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
        loop {
            let ready = std::fs::read_dir(&data_dir)?
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("ready-"))
                .count();
            if ready == CHILDREN {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(TestError::message(format!(
                    "epoch children never became ready: {ready}/{CHILDREN}"
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        std::fs::write(data_dir.join("go"), b"")?;

        let mut epochs = Vec::new();
        for (index, child) in children.into_iter().enumerate() {
            let output = child.wait_with_output()?;
            if !output.status.success() {
                return Err(TestError::message(format!(
                    "epoch child {index} failed: data_dir={data_dir:?} listing={} stderr={}",
                    dir_listing(&data_dir),
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        }
        for entry in std::fs::read_dir(&data_dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("epoch-") {
                let text = std::fs::read_to_string(entry.path())?;
                epochs.push(text.trim().parse::<u64>()?);
            }
        }
        epochs.sort_unstable();
        assert_eq!(
            epochs.len(),
            CHILDREN,
            "each child reports exactly one epoch"
        );
        for (index, epoch) in epochs.iter().enumerate() {
            assert_eq!(
                *epoch,
                u64::try_from(index)? + 1,
                "concurrent children must each own one distinct epoch: {epochs:?}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(data_dir.join("process-epoch"))?,
            format!("{}\n", epochs[CHILDREN - 1]),
            "the persisted file must name the highest allocated epoch"
        );
        Ok(())
    }
}
