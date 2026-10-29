use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_primitives::BlockBodyMetadata;
use bitcoin_rs_rpc::context::{PruneResult, PruneService, PruneServiceError, PruneStatus};
use bitcoin_rs_storage::DurableHeadStore as _;
use bitcoin_rs_storage::FlatFileBlockStore;
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_storage::StorageBackend;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::StoreGuard;
use bitcoin_rs_storage::pruning::PruneError;
use bitcoin_rs_storage::recovery_evidence::RecoveryEvidencePublisher;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

pub(super) struct NodeStorage {
    backend: StorageBackend,
    undo_store: Arc<dyn bitcoin_rs_chainstate::UndoStore>,
    durable_head: Arc<dyn bitcoin_rs_storage::DurableHeadStore>,
    block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
    retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    pub(super) deferred: Arc<dyn DeferredChainstateServices>,
}

struct ChainstateComposer<'a> {
    backend: StorageBackend,
    data_dir: &'a std::path::Path,
    guard: &'a StoreGuard,
}

impl crate::storage_backend::StoreConsumer for ChainstateComposer<'_> {
    type Output = (NodeStorage, Arc<FlatFileBlockStore>);
    type Error = bitcoin_rs_storage::StorageError;

    fn consume<S>(
        self,
        store: Arc<S>,
    ) -> core::result::Result<Self::Output, bitcoin_rs_storage::StorageError>
    where
        S: KvStore,
    {
        let durable_head = Arc::new(bitcoin_rs_storage::KvDurableHeadStore::new(Arc::clone(
            &store,
        )));
        let committed = durable_head.load()?.and_then(|head| head.body_extent);
        let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::seeded(
            bitcoin_rs_storage::pruning::ExecutedFrontier::reconstruct(&*store)?,
        ));
        let block_files = Arc::new(
            match committed {
                Some(extent) => {
                    FlatFileBlockStore::open_with_committed_extent(self.data_dir, extent)?
                }
                None => FlatFileBlockStore::open(self.data_dir)?,
            }
            .guarded_by(Arc::clone(self.guard)),
        );
        let deferred: Arc<dyn DeferredChainstateServices> = Arc::new(ChainstateStoreServices {
            store: Arc::clone(&store),
        });
        let storage = NodeStorage {
            backend: self.backend,
            undo_store: Arc::new(bitcoin_rs_chainstate::KvUndoStore::new(Arc::clone(&store))),
            durable_head,
            block_body_store: Arc::new(bitcoin_rs_storage::block_body::IndexedBlockBodyStore::new(
                Arc::clone(&store),
                Arc::clone(&block_files),
            )),
            retention,
            deferred,
        };
        Ok((storage, block_files))
    }
}

impl NodeStorage {
    pub(super) fn open(
        config: &NodeConfig,
        chainstate_cache_bytes: u64,
        guard: &StoreGuard,
    ) -> Result<(Self, Arc<FlatFileBlockStore>)> {
        let chainstate_dir = config.data_dir.join("chainstate");
        std::fs::create_dir_all(&chainstate_dir)
            .with_context(|| format!("create chainstate_dir {}", chainstate_dir.display()))?;

        let backend = config.storage.backend;
        crate::storage_backend::open_generic(
            "chainstate",
            backend,
            &chainstate_dir,
            Some(chainstate_cache_bytes),
            guard,
            ChainstateComposer {
                backend,
                data_dir: &config.data_dir,
                guard,
            },
        )
        .map_err(anyhow::Error::new)
    }

    pub(super) const fn kind(&self) -> &'static str {
        self.backend.as_str()
    }

    pub(super) fn block_body_store(
        &self,
    ) -> Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore> {
        Arc::clone(&self.block_body_store)
    }

    pub(super) fn undo_store(&self) -> Arc<dyn bitcoin_rs_chainstate::UndoStore> {
        Arc::clone(&self.undo_store)
    }

    pub(super) fn durable_head(&self) -> Arc<dyn bitcoin_rs_storage::DurableHeadStore> {
        Arc::clone(&self.durable_head)
    }

    pub(super) fn retention(&self) -> Arc<bitcoin_rs_storage::RetentionRegistry> {
        Arc::clone(&self.retention)
    }

    pub(super) fn mandatory_retention(&self) -> bitcoin_rs_storage::MandatoryRetention {
        bitcoin_rs_storage::MandatoryRetention::new(Arc::clone(&self.retention))
    }

    pub(super) fn bounded_history(&self) -> bitcoin_rs_storage::pruning::HistoryAccess {
        bitcoin_rs_storage::pruning::HistoryAccess::new(
            Arc::clone(&self.retention),
            bitcoin_rs_storage::pruning::RetentionBudget::from_blocks(
                bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN,
            ),
        )
    }
}

pub(super) trait DeferredChainstateServices: Send + Sync {
    fn prune_service(
        &self,
        block_files: Arc<FlatFileBlockStore>,
        authority: bitcoin_rs_chainstate::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
        retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    ) -> Result<Arc<dyn PruneService>>;
    fn journal_writer(
        &self,
        dir: cap_std::fs::Dir,
        bootstrap: bitcoin_rs_chainstate::JournalBootstrap,
    ) -> Result<bitcoin_rs_storage::chainstate_journal::SharedJournalWriter>;
}

struct ChainstateStoreServices<S> {
    store: Arc<S>,
}

impl<S: KvStore> DeferredChainstateServices for ChainstateStoreServices<S> {
    fn prune_service(
        &self,
        block_files: Arc<FlatFileBlockStore>,
        authority: bitcoin_rs_chainstate::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
        retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    ) -> Result<Arc<dyn PruneService>> {
        Ok(Arc::new(NodePruneService::new(
            Arc::clone(&self.store),
            block_files,
            authority,
            durable_tip_height,
            retention,
        )?))
    }

    fn journal_writer(
        &self,
        dir: cap_std::fs::Dir,
        bootstrap: bitcoin_rs_chainstate::JournalBootstrap,
    ) -> Result<bitcoin_rs_storage::chainstate_journal::SharedJournalWriter> {
        build_journal_writer(dir, Arc::clone(&self.store), &bootstrap)
    }
}

fn build_journal_writer<S: KvStore + 'static>(
    dir: cap_std::fs::Dir,
    store: Arc<S>,
    bootstrap: &bitcoin_rs_chainstate::JournalBootstrap,
) -> Result<bitcoin_rs_storage::chainstate_journal::SharedJournalWriter> {
    let mut writer = if bootstrap.open_existing {
        bitcoin_rs_storage::chainstate_journal::JournalWriter::open(dir, store)?
    } else {
        bitcoin_rs_storage::chainstate_journal::JournalWriter::initialize(
            dir,
            store,
            bootstrap.base_generation,
            (0, 0),
            bootstrap.height,
            bootstrap.block_hash,
            bootstrap.prev_hash,
            bootstrap.chain_tx_count,
        )?
    };
    writer.configure(bitcoin_rs_storage::chainstate_journal::JournalPolicy {
        batch_blocks: bootstrap.config.blocks,
        batch_seconds: Duration::from_secs(bootstrap.config.seconds),
        rotate_mib: bootstrap.config.rotate_mib,
        max_journal_mib: bootstrap.config.max_journal_mib,
        max_lag_blocks: bootstrap.config.max_lag_blocks,
        max_lag_seconds: Duration::from_secs(bootstrap.config.max_lag_seconds),
    })?;
    Ok(bitcoin_rs_storage::chainstate_journal::shared_journal_writer(writer))
}

pub(super) struct StoredBlockBodySource {
    store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
}

impl StoredBlockBodySource {
    pub(super) fn new(store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>) -> Self {
        Self { store }
    }
}

impl BlockBodySource for StoredBlockBodySource {
    fn block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        self.store
            .load_block_body_for_verification(height, hash.0)
            .map_err(|error| match error {
                StorageError::CorruptBlockFrame(_) => {
                    bitcoin_rs_chain::BlockBodyReadError::Corrupt(error.to_string())
                }
                _ => bitcoin_rs_chain::BlockBodyReadError::Read(error.to_string()),
            })
    }

    fn disk_usage(&self) -> Option<u64> {
        self.store.disk_usage()
    }

    fn block_body_range(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::BlockHash,
        offset: u32,
        len: u32,
    ) -> Option<Vec<u8>> {
        match self
            .store
            .load_block_body_range(height, hash.0, offset, len)
        {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::debug!(
                    %error,
                    height,
                    offset,
                    len,
                    "ranged block body read failed; falling back to the whole body"
                );
                None
            }
        }
    }

    fn block_body_metadata(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::BlockHash,
    ) -> Option<BlockBodyMetadata> {
        self.store
            .block_body_metadata(height, hash.0)
            .ok()
            .flatten()
    }
}

pub(super) struct NodePruneService<S: KvStore> {
    store: Arc<S>,
    block_files: Arc<FlatFileBlockStore>,
    authority: bitcoin_rs_chainstate::PruneAuthority,
    pruneheight: Mutex<Option<u32>>,
    durable_tip_height: Arc<AtomicU32>,
    retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
}

impl<S: KvStore> NodePruneService<S> {
    pub(super) fn new(
        store: Arc<S>,
        block_files: Arc<FlatFileBlockStore>,
        authority: bitcoin_rs_chainstate::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
        retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    ) -> anyhow::Result<Self> {
        let pruneheight = bitcoin_rs_storage::pruning::load_pruneheight(&*store)?;
        Ok(Self {
            store,
            block_files,
            authority,
            pruneheight: Mutex::new(pruneheight),
            durable_tip_height,
            retention,
        })
    }
}

impl<S: KvStore> PruneService for NodePruneService<S> {
    fn prune_to_height(
        &self,
        requested_height: u32,
    ) -> core::result::Result<PruneResult, PruneServiceError> {
        let authority = self
            .authority
            .begin()
            .map_err(|error| PruneServiceError::failed(error.to_string()))?;
        let applied_tip_height = authority
            .applied_tip_height()
            .ok_or_else(|| PruneServiceError::failed("applied tip is unavailable"))?;
        let updated_pruneheight = self
            .pruneheight
            .lock()
            .map_or(requested_height, |height| height.max(requested_height));
        let durable_tip_height = self.durable_tip_height.load(Ordering::Acquire);
        bitcoin_rs_storage::pruning::prune_to_height(
            &*self.store,
            &self.block_files,
            &self.retention,
            applied_tip_height,
            durable_tip_height,
            updated_pruneheight,
            |_pruned_below| Ok(()),
        )
        .map_err(|err| match err {
            PruneError::Storage(StorageError::InvalidOperation(message)) => {
                PruneServiceError::failed(message)
            }
            other => PruneServiceError::failed(other.to_string()),
        })?;

        {
            let mut published = self.pruneheight.lock();
            *published = Some(published.map_or(updated_pruneheight, |height| {
                height.max(updated_pruneheight)
            }));
        }

        Ok(PruneResult {
            pruneheight: updated_pruneheight,
        })
    }

    fn status(&self) -> PruneStatus {
        PruneStatus {
            pruned: true,
            pruneheight: *self.pruneheight.lock(),
        }
    }
}

pub(crate) struct RecoveryReporter(pub(crate) RecoveryEvidencePublisher);

impl bitcoin_rs_index::runtime::IndexAheadSink for RecoveryReporter {
    fn report_index_ahead(
        &self,
        capability: &str,
        index_height: u32,
        tip_height: u32,
        tip_hash_be: &str,
        index_hash_be: &str,
        depth: u32,
        unix_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.0
            .publish_index_ahead(
                capability,
                index_height,
                tip_height,
                tip_hash_be,
                index_hash_be,
                depth,
                unix_secs,
            )
            .map_err(Into::into)
    }
}

impl bitcoin_rs_index::RollbackWarningSource for RecoveryReporter {
    fn rollback_warnings(&self) -> Vec<String> {
        self.0.warnings()
    }
}

#[cfg(test)]
mod body_read_tests {
    use super::*;
    use bitcoin_rs_primitives::Hash256;
    use bitcoin_rs_storage::block_body::BlockBodyStore;

    struct UnreadableStore;

    impl BlockBodyStore for UnreadableStore {
        fn persist_block_body(&self, _: u32, _: Hash256, _: &[u8]) -> Result<(), StorageError> {
            panic!("a read must not repair or rewrite storage");
        }

        fn load_block_body(&self, _: u32, _: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
            Err(StorageError::InvalidOperation("injected body read failure"))
        }

        fn sync(&self) -> Result<(), StorageError> {
            panic!("a read must not commit storage");
        }
    }

    #[test]
    fn stored_body_read_preserves_failure_instead_of_reporting_absence() {
        let source = StoredBlockBodySource::new(Arc::new(UnreadableStore));
        match source.block_body(1, Hash256::default().into()) {
            Err(bitcoin_rs_chain::BlockBodyReadError::Read(error)) => {
                assert!(error.contains("injected body read failure"));
            }
            _ => panic!("I/O failure proves neither corruption, absence nor a successful read"),
        }
    }
}
