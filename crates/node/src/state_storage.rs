//! Chainstate storage composition; backend-neutral capabilities share one store.

use super::prune::NodePruneService;
use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;
use bitcoin_rs_chain::BlockBodyMetadata;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_index::block_log::BlockLog;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_rpc::context::PruneService;
use bitcoin_rs_storage::DurableHeadStore as _;
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
    undo_store: Arc<dyn bitcoin_rs_chainstate::UndoStore>,
    durable_head: Arc<dyn bitcoin_rs_storage::DurableHeadStore>,
    block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
    pub(super) deferred: Arc<dyn DeferredChainstateServices>,
}

struct ChainstateComposer<'a> {
    backend: StorageBackend,
    data_dir: &'a std::path::Path,
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
        // Load the commit point before block-file recovery can change bytes.
        // A clean checkpoint does not make a damaged committed frame an orphan.
        let committed = durable_head.load()?.and_then(|head| head.body_extent);
        let block_files = Arc::new(match committed {
            Some(extent) => FlatFileBlockStore::open_with_committed_extent(self.data_dir, extent)?,
            None => FlatFileBlockStore::open(self.data_dir)?,
        });
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
            deferred,
        };
        Ok((storage, block_files))
    }
}

impl NodeStorage {
    /// Opens the configured backend for the chainstate namespace with its
    /// cache share from the process budget.
    pub(super) fn open(
        config: &NodeConfig,
        chainstate_cache_bytes: u64,
    ) -> Result<(Self, Arc<FlatFileBlockStore>)> {
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
                data_dir: &config.data_dir,
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

    /// Builds the undo store for the configured backend.
    ///
    /// Mandatory rather than optional: without undo records the node cannot
    /// disconnect a block, so it could advance its tip into a chain it is
    /// unable to leave.
    pub(super) fn undo_store(&self) -> Arc<dyn bitcoin_rs_chainstate::UndoStore> {
        Arc::clone(&self.undo_store)
    }

    pub(super) fn durable_head(&self) -> Arc<dyn bitcoin_rs_storage::DurableHeadStore> {
        Arc::clone(&self.durable_head)
    }
}

/// Capabilities whose inputs become available after the chainstate store is
/// opened. This is a composition seam, not a storage API: concrete reads,
/// batches, and durability remain generic over `KvStore` below it.
pub(super) trait DeferredChainstateServices: Send + Sync {
    fn prune_service(
        &self,
        block_files: Arc<FlatFileBlockStore>,
        block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
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
        block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
        authority: bitcoin_rs_chainstate::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
        retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    ) -> Result<Arc<dyn PruneService>> {
        Ok(Arc::new(NodePruneService::new(
            Arc::clone(&self.store),
            block_files,
            block_body_store,
            blocks,
            transactions,
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
        build_journal_writer(dir, Arc::clone(&self.store), bootstrap)
    }
}

fn build_journal_writer<S: KvStore + 'static>(
    dir: cap_std::fs::Dir,
    store: Arc<S>,
    bootstrap: bitcoin_rs_chainstate::JournalBootstrap,
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
