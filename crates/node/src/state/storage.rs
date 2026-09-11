//! Chainstate storage composition; backend-neutral capabilities share one store.

#[cfg(test)]
use bitcoin_rs_storage::{ColumnFamily, WriteBatch};

use super::prune::NodePruneService;
use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;
use bitcoin_rs_chain::BlockBodyMetadata;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_rpc::context::BlockLog;
use bitcoin_rs_rpc::context::PruneService;
use bitcoin_rs_storage::FlatFileBlockStore;
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_storage::StorageBackend;
use hashbrown::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

pub(super) struct NodeStorage {
    backend: StorageBackend,
    undo_store: Arc<dyn crate::apply::UndoStore>,
    block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
    deferred: Arc<dyn DeferredChainstateServices>,
    #[cfg(test)]
    test_store: Arc<dyn TestStoreAccess>,
}

struct ChainstateComposer {
    backend: StorageBackend,
    block_files: Arc<FlatFileBlockStore>,
}

impl crate::storage_backend::StoreConsumer for ChainstateComposer {
    type Output = NodeStorage;
    type Error = bitcoin_rs_storage::StorageError;

    fn consume<S>(
        self,
        store: Arc<S>,
    ) -> core::result::Result<Self::Output, bitcoin_rs_storage::StorageError>
    where
        S: KvStore,
    {
        let deferred: Arc<dyn DeferredChainstateServices> = Arc::new(ChainstateStoreServices {
            store: Arc::clone(&store),
        });
        Ok(NodeStorage {
            backend: self.backend,
            undo_store: Arc::new(crate::apply::KvUndoStore::new(Arc::clone(&store))),
            block_body_store: Arc::new(bitcoin_rs_storage::block_body::IndexedBlockBodyStore::new(
                Arc::clone(&store),
                self.block_files,
            )),
            deferred,
            #[cfg(test)]
            test_store: Arc::new(TestStore { store }),
        })
    }
}

impl NodeStorage {
    /// Opens the configured backend for the chainstate namespace with its
    /// cache share from the process budget.
    pub(super) fn open(
        config: &NodeConfig,
        chainstate_cache_bytes: u64,
        block_files: Arc<FlatFileBlockStore>,
    ) -> Result<Self> {
        let chainstate_dir = config.data_dir.join("chainstate");
        std::fs::create_dir_all(&chainstate_dir)
            .with_context(|| format!("create chainstate_dir {}", chainstate_dir.display()))?;

        let backend = config.storage.backend;
        crate::storage_backend::open_chainstate(
            backend,
            &chainstate_dir,
            Some(chainstate_cache_bytes),
            ChainstateComposer {
                backend,
                block_files,
            },
        )
        .map_err(anyhow::Error::new)
    }

    pub(super) const fn kind(&self) -> &'static str {
        self.backend.as_str()
    }

    pub(super) fn prune_service(
        &self,
        block_files: &Arc<FlatFileBlockStore>,
        block_body_store: &Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
        authority: crate::apply::PruneAuthority,
        durable_tip_height: &Arc<AtomicU32>,
    ) -> Result<Arc<dyn PruneService>> {
        self.deferred.prune_service(
            Arc::clone(block_files),
            Arc::clone(block_body_store),
            blocks,
            transactions,
            authority,
            Arc::clone(durable_tip_height),
        )
    }

    pub(super) fn block_body_store(
        &self,
    ) -> Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore> {
        Arc::clone(&self.block_body_store)
    }

    /// Builds the undo store for the configured backend.
    ///
    /// Mandatory rather than optional: without undo records the node cannot
    /// disconnect a block, so it could advance its tip into a chain it is
    /// unable to leave.
    pub(super) fn undo_store(&self) -> Arc<dyn crate::apply::UndoStore> {
        Arc::clone(&self.undo_store)
    }

    pub(super) fn journal_writer(
        &self,
        dir: cap_std::fs::Dir,
        bootstrap: JournalBootstrap,
    ) -> Result<crate::chainstate_journal::SharedJournalWriter> {
        self.deferred.journal_writer(dir, bootstrap)
    }

    #[cfg(test)]
    pub(super) fn stored_prune_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>> {
        let key = bitcoin_rs_storage::pruning::block_body_key(height, hash);
        Ok(self
            .test_store
            .get(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key)?)
    }

    #[cfg(test)]
    pub(super) fn stored_prune_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>> {
        let key = bitcoin_rs_storage::pruning::block_undo_key(height, hash);
        Ok(self.test_store.get(ColumnFamily::UndoData, &key)?)
    }

    #[cfg(test)]
    pub(super) fn write_test_rows(&self, rows: &[(ColumnFamily, Vec<u8>, Vec<u8>)]) -> Result<()> {
        self.test_store.write_rows(rows).map_err(anyhow::Error::new)
    }

    #[cfg(test)]
    pub(super) fn read_test_row(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.test_store.get(cf, key).map_err(anyhow::Error::new)
    }
}

#[derive(Clone, Copy)]
pub(super) struct JournalBootstrap {
    pub(super) open_existing: bool,
    pub(super) base_generation: u64,
    pub(super) height: u32,
    pub(super) block_hash: [u8; 32],
    pub(super) prev_hash: [u8; 32],
    pub(super) chain_tx_count: u64,
    pub(super) config: crate::config::ChainstateJournalConfig,
}

/// Capabilities whose inputs become available after the chainstate store is
/// opened. This is a composition seam, not a storage API: concrete reads,
/// batches, and durability remain generic over `KvStore` below it.
trait DeferredChainstateServices: Send + Sync {
    fn prune_service(
        &self,
        block_files: Arc<FlatFileBlockStore>,
        block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
        authority: crate::apply::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
    ) -> Result<Arc<dyn PruneService>>;

    fn journal_writer(
        &self,
        dir: cap_std::fs::Dir,
        bootstrap: JournalBootstrap,
    ) -> Result<crate::chainstate_journal::SharedJournalWriter>;
}

struct ChainstateStoreServices<S> {
    store: Arc<S>,
}

impl<S: KvStore> DeferredChainstateServices for ChainstateStoreServices<S> {
    fn prune_service(
        &self,
        block_files: Arc<FlatFileBlockStore>,
        block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
        authority: crate::apply::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
    ) -> Result<Arc<dyn PruneService>> {
        Ok(Arc::new(NodePruneService::new(
            Arc::clone(&self.store),
            block_files,
            block_body_store,
            blocks,
            transactions,
            authority,
            durable_tip_height,
        )?))
    }

    fn journal_writer(
        &self,
        dir: cap_std::fs::Dir,
        bootstrap: JournalBootstrap,
    ) -> Result<crate::chainstate_journal::SharedJournalWriter> {
        build_journal_writer(dir, Arc::clone(&self.store), bootstrap)
    }
}

#[cfg(test)]
trait TestStoreAccess: Send + Sync {
    fn get(
        &self,
        cf: ColumnFamily,
        key: &[u8],
    ) -> core::result::Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError>;

    fn write_rows(
        &self,
        rows: &[(ColumnFamily, Vec<u8>, Vec<u8>)],
    ) -> core::result::Result<(), bitcoin_rs_storage::StorageError>;
}

#[cfg(test)]
struct TestStore<S> {
    store: Arc<S>,
}

#[cfg(test)]
impl<S: KvStore> TestStoreAccess for TestStore<S> {
    fn get(
        &self,
        cf: ColumnFamily,
        key: &[u8],
    ) -> core::result::Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
        self.store.get(cf, key)
    }

    fn write_rows(
        &self,
        rows: &[(ColumnFamily, Vec<u8>, Vec<u8>)],
    ) -> core::result::Result<(), bitcoin_rs_storage::StorageError> {
        let mut batch = self.store.new_batch();
        for (cf, key, value) in rows {
            batch.put(*cf, key, value);
        }
        self.store.write(batch)
    }
}

fn build_journal_writer<S: KvStore + 'static>(
    dir: cap_std::fs::Dir,
    store: Arc<S>,
    bootstrap: JournalBootstrap,
) -> Result<crate::chainstate_journal::SharedJournalWriter> {
    let mut writer = if bootstrap.open_existing {
        crate::chainstate_journal::JournalWriter::open(dir, store)?
    } else {
        crate::chainstate_journal::JournalWriter::initialize(
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
    writer.configure(
        bootstrap.config.blocks,
        Duration::from_secs(bootstrap.config.seconds),
        bootstrap.config.rotate_mib,
        bootstrap.config.max_journal_mib,
        bootstrap.config.max_lag_blocks,
        Duration::from_secs(bootstrap.config.max_lag_seconds),
    )?;
    Ok(crate::chainstate_journal::shared_journal_writer(writer))
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
    fn block_body(&self, height: u32, hash: bitcoin_rs_primitives::BlockHash) -> Option<Vec<u8>> {
        self.store.load_block_body(height, hash.0).ok().flatten()
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
        // `None` is overloaded here: it means both "this store cannot slice"
        // and "the read failed". Callers must treat either as a reason to fall
        // back to the whole body, so the return type stays — but this is the
        // hot path for every ScriptIndex history call now, and an I/O error that
        // silently degrades into a full block scan is exactly the failure that
        // would otherwise show up only as unexplained latency.
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
