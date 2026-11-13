use crate::NodeConfig;
use bitcoin_rs_consensus::primitives::BlockBodyMetadata;
use bitcoin_rs_serving::context::{PruneResult, PruneService, PruneServiceError, PruneStatus};
use bitcoin_rs_storage::DurableHeadStore as _;
use bitcoin_rs_storage::FlatFileBlockStore;
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_storage::StorageBackend;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::StoreGuard;
use bitcoin_rs_storage::block_body::BlockBodySource;
use bitcoin_rs_storage::pruning::PruneError;
use bitcoin_rs_storage::recovery_evidence::RecoveryEvidencePublisher;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use super::open::NodeOpenError;

pub(super) struct NodeStorage {
    backend: StorageBackend,
    undo_store: Arc<dyn bitcoin_rs_execution::UndoStore>,
    durable_head: Arc<dyn bitcoin_rs_storage::DurableHeadStore>,
    block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
    retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    prune_height: Option<u32>,
    pub(super) deferred: Arc<dyn DeferredChainstateServices>,
    pub(super) coins: Arc<bitcoin_rs_storage::CoinStore>,
    pub(super) commit_authority: Arc<bitcoin_rs_storage::CommitAuthority>,
}

struct ChainstateComposer<'a> {
    backend: StorageBackend,
    data_dir: &'a std::path::Path,
    guard: &'a StoreGuard,
    cache_allocation: bitcoin_rs_storage::ChainstateCacheBudget,
}

impl crate::storage_backend::StoreConsumer for ChainstateComposer<'_> {
    type Output = (NodeStorage, Arc<FlatFileBlockStore>);
    type Error = bitcoin_rs_storage::StorageError;

    fn consume<S>(
        self,
        store: Arc<S>,
    ) -> core::result::Result<Self::Output, bitcoin_rs_storage::StorageError>
    where
        S: KvStore + 'static,
    {
        let durable_head = Arc::new(bitcoin_rs_storage::KvDurableHeadStore::new(Arc::clone(
            &store,
        )));
        let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = store.clone();
        let coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
            Arc::clone(&dyn_store),
            self.cache_allocation.coin_bytes,
        ));
        let commit_authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(
            dyn_store,
            Arc::clone(&coins),
        ));
        let committed = durable_head.load()?.and_then(|head| head.body_extent);
        let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::seeded(
            bitcoin_rs_storage::pruning::ExecutedFrontier::reconstruct(&*store)?,
        ));
        let prune_height = bitcoin_rs_storage::pruning::load_pruneheight(&*store)?;
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
            undo_store: Arc::new(bitcoin_rs_execution::KvUndoStore::new(Arc::clone(&store))),
            durable_head,
            block_body_store: Arc::new(bitcoin_rs_storage::block_body::IndexedBlockBodyStore::new(
                Arc::clone(&store),
                Arc::clone(&block_files),
            )),
            retention,
            prune_height,
            deferred,
            coins,
            commit_authority,
        };
        Ok((storage, block_files))
    }
}

impl NodeStorage {
    pub(super) fn open(
        config: &NodeConfig,
        cache_allocation: bitcoin_rs_storage::ChainstateCacheBudget,
        guard: &StoreGuard,
    ) -> Result<(Self, Arc<FlatFileBlockStore>), NodeOpenError> {
        let chainstate_dir = config.data_dir.join("chainstate");
        std::fs::create_dir_all(&chainstate_dir).map_err(|source| {
            NodeOpenError::CreateChainstateDir {
                path: chainstate_dir.clone(),
                source,
            }
        })?;

        let backend = config.storage.backend;
        let opened = crate::storage_backend::open_generic(
            "chainstate",
            backend,
            &chainstate_dir,
            Some(cache_allocation.engine_bytes),
            guard,
            ChainstateComposer {
                backend,
                data_dir: &config.data_dir,
                guard,
                cache_allocation,
            },
        )?;
        Ok(opened)
    }

    pub(super) const fn kind(&self) -> &'static str {
        self.backend.as_str()
    }

    pub(super) const fn stored_prune_height(&self) -> Option<u32> {
        self.prune_height
    }

    pub(super) fn block_body_store(
        &self,
    ) -> Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore> {
        Arc::clone(&self.block_body_store)
    }

    pub(super) fn undo_store(&self) -> Arc<dyn bitcoin_rs_execution::UndoStore> {
        Arc::clone(&self.undo_store)
    }

    pub(super) fn durable_head(&self) -> Arc<dyn bitcoin_rs_storage::DurableHeadStore> {
        Arc::clone(&self.durable_head)
    }

    pub(super) fn coins(&self) -> Arc<bitcoin_rs_storage::CoinStore> {
        Arc::clone(&self.coins)
    }

    pub(super) fn commit_authority(&self) -> Arc<bitcoin_rs_storage::CommitAuthority> {
        Arc::clone(&self.commit_authority)
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
                bitcoin_rs_consensus::primitives::chain_constants::CORE_REORG_SAFETY_MARGIN,
            ),
        )
    }
}

pub(super) trait DeferredChainstateServices: Send + Sync {
    fn prune_service(
        &self,
        block_files: Arc<FlatFileBlockStore>,
        authority: bitcoin_rs_execution::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
        retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    ) -> Result<Arc<dyn PruneService>, NodeOpenError>;
}

struct ChainstateStoreServices<S> {
    store: Arc<S>,
}

impl<S: KvStore> DeferredChainstateServices for ChainstateStoreServices<S> {
    fn prune_service(
        &self,
        block_files: Arc<FlatFileBlockStore>,
        authority: bitcoin_rs_execution::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
        retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    ) -> Result<Arc<dyn PruneService>, NodeOpenError> {
        Ok(Arc::new(NodePruneService::new(
            Arc::clone(&self.store),
            block_files,
            authority,
            durable_tip_height,
            retention,
        )?))
    }
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
        hash: bitcoin_rs_consensus::primitives::BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
        self.store
            .load_block_body_for_verification(height, hash.0)
            .map_err(|error| match error {
                StorageError::CorruptBlockFrame(_) => {
                    bitcoin_rs_storage::block_body::BlockBodyReadError::Corrupt(error.to_string())
                }
                _ => bitcoin_rs_storage::block_body::BlockBodyReadError::Read(error.to_string()),
            })
    }

    fn disk_usage(&self) -> Option<u64> {
        self.store.disk_usage()
    }

    fn block_body_range(
        &self,
        height: u32,
        hash: bitcoin_rs_consensus::primitives::BlockHash,
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
        hash: bitcoin_rs_consensus::primitives::BlockHash,
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
    authority: bitcoin_rs_execution::PruneAuthority,
    pruneheight: Mutex<Option<u32>>,
    durable_tip_height: Arc<AtomicU32>,
    retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
}

impl<S: KvStore> NodePruneService<S> {
    pub(super) fn new(
        store: Arc<S>,
        block_files: Arc<FlatFileBlockStore>,
        authority: bitcoin_rs_execution::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
        retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    ) -> Result<Self, NodeOpenError> {
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

impl bitcoin_rs_projection::runtime::IndexAheadSink for RecoveryReporter {
    fn report_index_ahead(
        &self,
        capability: &str,
        index_height: u32,
        tip_height: u32,
        tip_hash_be: &str,
        index_hash_be: &str,
        depth: u32,
        unix_secs: u64,
    ) -> Result<(), bitcoin_rs_projection::runtime::IndexAheadError> {
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

impl bitcoin_rs_projection::RollbackWarningSource for RecoveryReporter {
    fn rollback_warnings(&self) -> Vec<String> {
        self.0.warnings()
    }
}

#[cfg(test)]
mod body_read_tests {
    use super::*;
    use bitcoin_rs_consensus::primitives::Hash256;
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
            Err(bitcoin_rs_storage::block_body::BlockBodyReadError::Read(error)) => {
                assert!(error.contains("injected body read failure"));
            }
            _ => panic!("I/O failure proves neither corruption, absence nor a successful read"),
        }
    }
}
