//! Shared node state aggregating subsystem handles.
//!
//! V1 keeps this deliberately minimal: it owns the resolved [`Config`], the
//! data-directory path, the open chainstate storage backend, and the replay log
//! used by [`crate::crash_recovery`]. Subsystem wiring (chain / utxo / mempool
//! / index / p2p / rpc / electrum) parks here as the integration point matures.

use arc_swap::{ArcSwap, ArcSwapOption};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hex::FromHex as _;
use bitcoin::{Transaction, Txid, block::Header};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_rpc::{
    BlockBodySource, BlockRecord, NetworkState, PruneResult, PruneService, PruneServiceError,
    PruneStatus, ZmqNotification,
};
use compact_str::CompactString;
use core::fmt;
use core::mem::size_of;
use crossbeam_channel::{Receiver, Sender};
use hashbrown::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_pruning::policy::CORE_REORG_SAFETY_MARGIN;
use bitcoin_rs_pruning::{PrunePolicy, stage_block_and_undo_prune};
use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch};
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::{Mutex, RwLock};

use crate::Config;

type TxIndexHandle = Arc<Mutex<Box<dyn bitcoin_rs_index::IndexerLike>>>;
type FilterIndexHandle = Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>;

// One active generation of outbound requests is enough to keep the drain fed;
// extra backlog is overload and must fail fast at producers.
pub(crate) const P2P_OUTBOUND_QUEUE_LIMIT: usize = 8;

/// Errors produced when applying a block to the node state.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The block's previous header hash does not match the current tip's hash.
    #[error("prev hash mismatch: tip {tip}, block prev {prev}")]
    PrevHashMismatch {
        /// Current tip header hash, big-endian hex.
        tip: bitcoin_rs_primitives::Hash256,
        /// Block's previous header hash, big-endian hex.
        prev: bitcoin_rs_primitives::Hash256,
    },
    /// Height arithmetic overflowed `u32::MAX`.
    #[error("height overflow at tip {0}")]
    HeightOverflow(u32),
    /// The block header hash does not satisfy its declared proof-of-work target.
    #[error("proof-of-work: header hash {hash} exceeds declared target")]
    ProofOfWork {
        /// Block header hash, big-endian display.
        hash: bitcoin_rs_primitives::Hash256,
    },
    /// Declared target exceeds the network's proof-of-work limit.
    #[error("declared target exceeds network max_target")]
    TargetAboveLimit,
    /// Declared `nBits` does not match the parent block's `nBits` at a non-retarget height.
    #[error(
        "nBits {actual:08x} does not match parent {expected:08x} at non-retarget height {height}"
    )]
    NbitsNonRetargetMismatch {
        /// This block's `nBits`.
        actual: u32,
        /// Parent block's `nBits`.
        expected: u32,
        /// Block height.
        height: u32,
    },
    /// Consensus validation rejected the block.
    #[error("consensus: {0}")]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    /// Block-tree insertion rejected the header.
    #[error("chain: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    /// UTXO commit failed during block apply.
    #[error("utxo commit: {0}")]
    UtxoCommit(#[from] bitcoin_rs_utxo::UtxoError),
    /// Persisting the canonical prunable block body failed.
    #[error("block body persistence: {0}")]
    BlockBodyPersistence(#[from] bitcoin_rs_storage::StorageError),
}

enum NodeStorage {
    #[cfg(feature = "rocksdb")]
    RocksDb(Arc<bitcoin_rs_storage::RocksDbStore>),
    #[cfg(feature = "fjall")]
    Fjall(Arc<bitcoin_rs_storage::FjallStore>),
    #[cfg(feature = "redb")]
    Redb(Arc<bitcoin_rs_storage::RedbStore>),
    #[cfg(feature = "mdbx")]
    Mdbx(Arc<bitcoin_rs_storage::MdbxStore>),
}

impl NodeStorage {
    fn open(config: &Config) -> Result<Self> {
        let chainstate_dir = config.data_dir.join("chainstate");
        std::fs::create_dir_all(&chainstate_dir)
            .with_context(|| format!("create chainstate_dir {}", chainstate_dir.display()))?;

        match config.storage_backend.as_str() {
            #[cfg(feature = "rocksdb")]
            "rocksdb" => Ok(Self::RocksDb(Arc::new(
                bitcoin_rs_storage::RocksDbStore::open(&chainstate_dir)
                    .map_err(anyhow::Error::new)?,
            ))),
            #[cfg(feature = "fjall")]
            "fjall" => Ok(Self::Fjall(Arc::new(
                bitcoin_rs_storage::FjallStore::open(&chainstate_dir)
                    .map_err(anyhow::Error::new)?,
            ))),
            #[cfg(feature = "redb")]
            "redb" => Ok(Self::Redb(Arc::new(
                bitcoin_rs_storage::RedbStore::open(&chainstate_dir).map_err(anyhow::Error::new)?,
            ))),
            #[cfg(feature = "mdbx")]
            "mdbx" => Ok(Self::Mdbx(Arc::new(
                bitcoin_rs_storage::MdbxStore::open(&chainstate_dir).map_err(anyhow::Error::new)?,
            ))),
            other => bail!(
                "unsupported storage backend: {other} (compiled features = {CompiledStorageFeatures})"
            ),
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => {
                let _ = store;
                "rocksdb"
            }
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => {
                let _ = store;
                "fjall"
            }
            #[cfg(feature = "redb")]
            Self::Redb(store) => {
                let _ = store;
                "redb"
            }
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => {
                let _ = store;
                "mdbx"
            }
        }
    }

    fn prune_service(
        &self,
        blocks: Arc<RwLock<Vec<BlockRecord>>>,
        transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    ) -> Result<Arc<dyn PruneService>> {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                blocks,
                transactions,
            )?)),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                blocks,
                transactions,
            )?)),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                blocks,
                transactions,
            )?)),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                blocks,
                transactions,
            )?)),
        }
    }

    fn block_body_store(&self) -> Arc<dyn crate::apply::PruneBodyStore> {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => {
                let store: Arc<dyn crate::apply::PruneBodyStore> = store.clone();
                store
            }
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => {
                let store: Arc<dyn crate::apply::PruneBodyStore> = store.clone();
                store
            }
            #[cfg(feature = "redb")]
            Self::Redb(store) => {
                let store: Arc<dyn crate::apply::PruneBodyStore> = store.clone();
                store
            }
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => {
                let store: Arc<dyn crate::apply::PruneBodyStore> = store.clone();
                store
            }
        }
    }

    #[cfg(test)]
    fn seed_prune_rows(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: &[u8],
        undo: &[u8],
    ) -> Result<()> {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => seed_prune_rows(&**store, height, hash, body, undo),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => seed_prune_rows(&**store, height, hash, body, undo),
            #[cfg(feature = "redb")]
            Self::Redb(store) => seed_prune_rows(&**store, height, hash, body, undo),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => seed_prune_rows(&**store, height, hash, body, undo),
        }
    }

    #[cfg(test)]
    fn stored_prune_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>> {
        let key = bitcoin_rs_pruning::block_body_key(height, hash);
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => Ok(store.get(ColumnFamily::BlockTree, &key)?),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Ok(store.get(ColumnFamily::BlockTree, &key)?),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Ok(store.get(ColumnFamily::BlockTree, &key)?),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Ok(store.get(ColumnFamily::BlockTree, &key)?),
        }
    }

    #[cfg(test)]
    fn stored_prune_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>> {
        let key = bitcoin_rs_pruning::block_undo_key(height, hash);
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => Ok(store.get(ColumnFamily::BlockTree, &key)?),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Ok(store.get(ColumnFamily::BlockTree, &key)?),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Ok(store.get(ColumnFamily::BlockTree, &key)?),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Ok(store.get(ColumnFamily::BlockTree, &key)?),
        }
    }
}

struct StoredBlockBodySource {
    store: Arc<dyn crate::apply::PruneBodyStore>,
}

impl StoredBlockBodySource {
    fn new(store: Arc<dyn crate::apply::PruneBodyStore>) -> Self {
        Self { store }
    }
}

impl BlockBodySource for StoredBlockBodySource {
    fn block_body(&self, height: u32, hash: bitcoin_rs_primitives::Hash256) -> Option<Vec<u8>> {
        self.store.load_block_body(height, hash).ok().flatten()
    }
}

const PRUNEHEIGHT_METADATA_KEY: &[u8] = b"node:pruneheight";

fn load_pruneheight<S: KvStore>(store: &S) -> Result<Option<u32>> {
    let Some(bytes) = store.get(ColumnFamily::UtxoMeta, PRUNEHEIGHT_METADATA_KEY)? else {
        return Ok(None);
    };
    if bytes.len() != size_of::<u32>() {
        bail!("invalid persisted pruneheight length {}", bytes.len());
    }
    let mut encoded = [0_u8; size_of::<u32>()];
    encoded.copy_from_slice(&bytes);
    Ok(Some(u32::from_be_bytes(encoded)))
}

/// Storage-backed implementation of RPC manual pruning.
pub struct NodePruneService<S: KvStore> {
    store: Arc<S>,
    blocks: Arc<RwLock<Vec<BlockRecord>>>,
    transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    pruneheight: Mutex<Option<u32>>,
}

impl<S: KvStore> NodePruneService<S> {
    /// Creates a manual pruning service over the chainstate store and RPC block cache.
    pub fn new(
        store: Arc<S>,
        blocks: Arc<RwLock<Vec<BlockRecord>>>,
        transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    ) -> Result<Self> {
        let pruneheight = load_pruneheight(&*store)?;
        Ok(Self {
            store,
            blocks,
            transactions,
            pruneheight: Mutex::new(pruneheight),
        })
    }
}

impl<S: KvStore> PruneService for NodePruneService<S> {
    fn prune_to_height(
        &self,
        requested_height: u32,
    ) -> core::result::Result<PruneResult, PruneServiceError> {
        let mut blocks = self.blocks.write();
        let mut pruneheight = self.pruneheight.lock();
        let policy = PrunePolicy {
            target_size_mb: 0,
            keep_below_tip: CORE_REORG_SAFETY_MARGIN,
        };
        let updated_pruneheight =
            pruneheight.map_or(requested_height, |height| height.max(requested_height));
        let pruner_tip = updated_pruneheight
            .checked_add(policy.retention_depth())
            .ok_or_else(|| PruneServiceError::failed("prune height overflow"))?;
        let mut batch = self.store.new_batch();
        let (block_outcome, undo_outcome) =
            stage_block_and_undo_prune(&*self.store, &mut batch, pruner_tip, policy)
                .map_err(|err| PruneServiceError::failed(err.to_string()))?;
        batch.put(
            ColumnFamily::UtxoMeta,
            PRUNEHEIGHT_METADATA_KEY,
            &updated_pruneheight.to_be_bytes(),
        );

        let mut pruned_txids = Vec::new();
        for record in blocks
            .iter()
            .filter(|record| record.height < updated_pruneheight)
        {
            if record.tx_count == 0 {
                continue;
            }
            let bytes = if record.block_hex.is_empty() {
                <S as crate::apply::PruneBodyStore>::load_block_body(
                    &*self.store,
                    record.height,
                    record.hash,
                )
                .map_err(|error| PruneServiceError::failed(error.to_string()))?
                .unwrap_or_default()
            } else {
                Vec::<u8>::from_hex(&record.block_hex).map_err(|error| {
                    PruneServiceError::failed(format!(
                        "cached block body at height {} is not valid hex: {error}",
                        record.height
                    ))
                })?
            };
            if bytes.is_empty() {
                continue;
            }
            let block = deserialize::<bitcoin::Block>(&bytes).map_err(|error| {
                PruneServiceError::failed(format!(
                    "cached block body at height {} failed decode: {error}",
                    record.height
                ))
            })?;
            pruned_txids.extend(block.txdata.iter().map(Transaction::compute_txid));
        }
        self.store
            .write(batch)
            .map_err(|err| PruneServiceError::failed(err.to_string()))?;

        if !pruned_txids.is_empty() {
            let mut transactions = self.transactions.write();
            for txid in pruned_txids {
                transactions.remove(&txid);
            }
        }

        for record in blocks.iter_mut() {
            if record.height < updated_pruneheight {
                record.block_hex = String::new();
            }
        }
        *pruneheight = Some(updated_pruneheight);

        Ok(PruneResult {
            requested_height,
            pruneheight: updated_pruneheight,
            block_rows_removed: block_outcome.blocks_removed,
            undo_rows_removed: undo_outcome.blocks_removed,
            bytes_freed: block_outcome
                .bytes_freed
                .saturating_add(undo_outcome.bytes_freed),
        })
    }

    fn status(&self) -> PruneStatus {
        PruneStatus {
            pruned: true,
            pruneheight: *self.pruneheight.lock(),
        }
    }
}

#[cfg(test)]
fn seed_prune_rows<S: KvStore>(
    store: &S,
    height: u32,
    hash: bitcoin_rs_primitives::Hash256,
    body: &[u8],
    undo: &[u8],
) -> Result<()> {
    use bitcoin_rs_storage::WriteBatch as _;

    let mut batch = store.new_batch();
    batch.put(
        ColumnFamily::BlockTree,
        &bitcoin_rs_pruning::block_body_key(height, hash),
        body,
    );
    batch.put(
        ColumnFamily::BlockTree,
        &bitcoin_rs_pruning::block_undo_key(height, hash),
        undo,
    );
    store.write(batch)?;
    Ok(())
}

/// Concrete txindex store handles retained per backend.
///
/// Mirrors `NodeStorage` but for the txindex sub-database. Kept alongside the
/// erased `Arc<Mutex<Box<dyn IndexerLike>>>` so the Electrum `IndexHandle` can
/// observe the live `KvStore` for header reads.
enum TxIndexStorage {
    #[cfg(feature = "rocksdb")]
    RocksDb(Arc<bitcoin_rs_storage::RocksDbStore>),
    #[cfg(feature = "fjall")]
    Fjall(Arc<bitcoin_rs_storage::FjallStore>),
    #[cfg(feature = "redb")]
    Redb(Arc<bitcoin_rs_storage::RedbStore>),
    #[cfg(feature = "mdbx")]
    Mdbx(Arc<bitcoin_rs_storage::MdbxStore>),
}

impl TxIndexStorage {
    fn electrum_index_handle(&self) -> bitcoin_rs_electrum::IndexHandle {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => bitcoin_rs_electrum::IndexHandle::from_store(Arc::clone(store)),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => bitcoin_rs_electrum::IndexHandle::from_store(Arc::clone(store)),
            #[cfg(feature = "redb")]
            Self::Redb(store) => bitcoin_rs_electrum::IndexHandle::from_store(Arc::clone(store)),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => bitcoin_rs_electrum::IndexHandle::from_store(Arc::clone(store)),
        }
    }

    fn electrum_history_reader(
        &self,
        blocks: Arc<RwLock<Vec<bitcoin_rs_rpc::BlockRecord>>>,
        block_body_source: Arc<dyn BlockBodySource>,
    ) -> Arc<dyn bitcoin_rs_electrum::methods::ConfirmedHistoryReader> {
        let block_source =
            crate::NodeBlockSource::new(blocks).with_block_body_source(block_body_source);
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => {
                let indexer = Arc::new(bitcoin_rs_index::Indexer::new(Arc::clone(store)));
                Arc::new(bitcoin_rs_electrum::methods::IndexerHistoryReader::new(
                    indexer,
                    block_source,
                ))
            }
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => {
                let indexer = Arc::new(bitcoin_rs_index::Indexer::new(Arc::clone(store)));
                Arc::new(bitcoin_rs_electrum::methods::IndexerHistoryReader::new(
                    indexer,
                    block_source,
                ))
            }
            #[cfg(feature = "redb")]
            Self::Redb(store) => {
                let indexer = Arc::new(bitcoin_rs_index::Indexer::new(Arc::clone(store)));
                Arc::new(bitcoin_rs_electrum::methods::IndexerHistoryReader::new(
                    indexer,
                    block_source,
                ))
            }
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => {
                let indexer = Arc::new(bitcoin_rs_index::Indexer::new(Arc::clone(store)));
                Arc::new(bitcoin_rs_electrum::methods::IndexerHistoryReader::new(
                    indexer,
                    block_source,
                ))
            }
        }
    }
}

const COMPILED_STORAGE_FEATURES: &[&str] = &[
    #[cfg(feature = "rocksdb")]
    "rocksdb",
    #[cfg(feature = "fjall")]
    "fjall",
    #[cfg(feature = "redb")]
    "redb",
    #[cfg(feature = "mdbx")]
    "mdbx",
];

struct CompiledStorageFeatures;

impl fmt::Display for CompiledStorageFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some((first, rest)) = COMPILED_STORAGE_FEATURES.split_first() else {
            return f.write_str("none");
        };

        f.write_str(first)?;
        for feature in rest {
            f.write_str(",")?;
            f.write_str(feature)?;
        }
        Ok(())
    }
}

fn open_tx_index(config: &Config) -> Result<Option<(TxIndexHandle, TxIndexStorage)>> {
    if !config.txindex {
        return Ok(None);
    }

    let txindex_dir = config.data_dir.join("txindex");
    std::fs::create_dir_all(&txindex_dir)
        .with_context(|| format!("create txindex_dir {}", txindex_dir.display()))?;
    match config.storage_backend.as_str() {
        #[cfg(feature = "rocksdb")]
        "rocksdb" => {
            let store = Arc::new(
                bitcoin_rs_storage::RocksDbStore::open(&txindex_dir).map_err(anyhow::Error::new)?,
            );
            let indexer: Box<dyn bitcoin_rs_index::IndexerLike> =
                Box::new(bitcoin_rs_index::Indexer::new(Arc::clone(&store)));
            Ok(Some((
                Arc::new(Mutex::new(indexer)),
                TxIndexStorage::RocksDb(store),
            )))
        }
        #[cfg(feature = "fjall")]
        "fjall" => {
            let store = Arc::new(
                bitcoin_rs_storage::FjallStore::open(&txindex_dir).map_err(anyhow::Error::new)?,
            );
            let indexer: Box<dyn bitcoin_rs_index::IndexerLike> =
                Box::new(bitcoin_rs_index::Indexer::new(Arc::clone(&store)));
            Ok(Some((
                Arc::new(Mutex::new(indexer)),
                TxIndexStorage::Fjall(store),
            )))
        }
        #[cfg(feature = "redb")]
        "redb" => {
            let store = Arc::new(
                bitcoin_rs_storage::RedbStore::open(&txindex_dir).map_err(anyhow::Error::new)?,
            );
            let indexer: Box<dyn bitcoin_rs_index::IndexerLike> =
                Box::new(bitcoin_rs_index::Indexer::new(Arc::clone(&store)));
            Ok(Some((
                Arc::new(Mutex::new(indexer)),
                TxIndexStorage::Redb(store),
            )))
        }
        #[cfg(feature = "mdbx")]
        "mdbx" => {
            let store = Arc::new(
                bitcoin_rs_storage::MdbxStore::open(&txindex_dir).map_err(anyhow::Error::new)?,
            );
            let indexer: Box<dyn bitcoin_rs_index::IndexerLike> =
                Box::new(bitcoin_rs_index::Indexer::new(Arc::clone(&store)));
            Ok(Some((
                Arc::new(Mutex::new(indexer)),
                TxIndexStorage::Mdbx(store),
            )))
        }
        other => bail!("unsupported storage backend for txindex: {other}"),
    }
}

fn open_filter_index(config: &Config) -> Result<FilterIndexHandle> {
    let filters_dir = config.data_dir.join("filters");
    std::fs::create_dir_all(&filters_dir)
        .with_context(|| format!("create filters_dir {}", filters_dir.display()))?;
    let filter_index: Box<dyn bitcoin_rs_filters::FilterIndexLike> =
        match config.storage_backend.as_str() {
            #[cfg(feature = "rocksdb")]
            "rocksdb" => Box::new(bitcoin_rs_filters::FilterIndex::new(
                bitcoin_rs_storage::RocksDbStore::open(&filters_dir).map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "fjall")]
            "fjall" => Box::new(bitcoin_rs_filters::FilterIndex::new(
                bitcoin_rs_storage::FjallStore::open(&filters_dir).map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "redb")]
            "redb" => Box::new(bitcoin_rs_filters::FilterIndex::new(
                bitcoin_rs_storage::RedbStore::open(&filters_dir).map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "mdbx")]
            "mdbx" => Box::new(bitcoin_rs_filters::FilterIndex::new(
                bitcoin_rs_storage::MdbxStore::open(&filters_dir).map_err(anyhow::Error::new)?,
            )),
            other => bail!("unsupported storage backend for filter index: {other}"),
        };
    Ok(Arc::new(filter_index))
}

/// Aggregate handle to a running node.
pub struct NodeState {
    config: Config,
    data_dir: PathBuf,
    storage: NodeStorage,
    utxo: Arc<UtxoSet>,
    coin_stats: Arc<bitcoin_rs_coinstats::CoinStatsListener>,
    tx_index: Option<TxIndexHandle>,
    tx_index_storage: Option<Arc<TxIndexStorage>>,
    filter_index: FilterIndexHandle,
    prune_service: Option<Arc<dyn PruneService>>,
    zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    active_zmq_notifications: Vec<ZmqNotification>,
    g2_muhash_sampler: Option<Arc<crate::g2_muhash::G2MuhashSampler>>,
    mempool: Arc<RwLock<Mempool>>,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<bitcoin_rs_chain::BlockTree>>,
    blocks: Arc<RwLock<Vec<BlockRecord>>>,
    transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    network: Arc<RwLock<NetworkState>>,
    peers: Arc<RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>>,
    /// Per-peer outbound message senders, keyed by remote socket address.
    /// External code pushes messages here; the per-connection thread drains
    /// and writes them to the peer's TCP stream.
    peer_outbound: Arc<
        RwLock<HashMap<std::net::SocketAddr, crossbeam_channel::Sender<bitcoin_rs_p2p::Message>>>,
    >,
    banned: Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
    p2p_outbound_tx: crossbeam_channel::Sender<std::net::SocketAddr>,
    p2p_outbound_rx: Arc<Mutex<crossbeam_channel::Receiver<std::net::SocketAddr>>>,
    inbound_headers_tx: Sender<Vec<Header>>,
    inbound_headers_rx: Arc<Mutex<Receiver<Vec<Header>>>>,
    inbound_blocks_tx: Sender<bitcoin::Block>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin::Block>>>,
    sync: Arc<crate::BlockSync>,
    mining_template_id: Arc<ArcSwap<CompactString>>,
    replayed: Mutex<Vec<u32>>,
}

impl NodeState {
    /// Opens (or creates) the node's data directory and configured storage
    /// backend.
    #[allow(clippy::arc_with_non_send_sync)]
    #[allow(clippy::too_many_lines)]
    pub fn open(config: Config) -> Result<Self> {
        config.validate()?;
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("create data_dir {}", config.data_dir.display()))?;
        let g2_muhash_sampler = config
            .g2_muhash_samples
            .clone()
            .map(|path| crate::g2_muhash::G2MuhashSampler::open(path, config.g2_muhash_tip_height))
            .transpose()
            .context("open G2 MuHash sample writer")?
            .map(Arc::new);
        let storage = NodeStorage::open(&config)?;
        let tx_index_pair = open_tx_index(&config)?;
        let (tx_index, tx_index_storage) = tx_index_pair
            .map_or((None, None), |(tx_index, tx_index_storage)| {
                (Some(tx_index), Some(Arc::new(tx_index_storage)))
            });
        let filter_index = open_filter_index(&config)?;
        let zmq_publications = config.zmq_publications();
        let active_zmq_notifications: Vec<_> = zmq_publications
            .iter()
            .map(|publication| {
                ZmqNotification::new(
                    publication.topic.notifier_type(),
                    publication.endpoint.clone(),
                    publication.hwm,
                )
            })
            .collect();
        let zmq_publisher: Arc<dyn crate::ZmqPublisher> = if zmq_publications.is_empty() {
            Arc::new(crate::NoOpZmqPublisher)
        } else {
            Arc::new(crate::SocketZmqPublisher::bind(&zmq_publications)?)
        };
        let mut utxo_set = bitcoin_rs_utxo::UtxoSet::new();
        let coin_stats_listener = bitcoin_rs_coinstats::CoinStatsListener::new(
            bitcoin_rs_coinstats::CoinStats::default(),
        );
        utxo_set.set_listener(Box::new(coin_stats_listener.clone()));
        let utxo = Arc::new(utxo_set);
        let coin_stats = Arc::new(coin_stats_listener);
        let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let block_tree = Arc::new(RwLock::new(bitcoin_rs_chain::BlockTree::new()));
        let chain_tip = block_tree.read().tip_handle();
        let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
        let blocks = Arc::new(RwLock::new(Vec::new()));
        let transactions = Arc::new(RwLock::new(HashMap::new()));
        let network = Arc::new(RwLock::new(NetworkState::default()));
        let peers = Arc::new(RwLock::new(Vec::new()));
        let banned = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (p2p_outbound_tx, p2p_outbound_rx_raw) =
            crossbeam_channel::bounded(P2P_OUTBOUND_QUEUE_LIMIT);
        let p2p_outbound_rx = Arc::new(Mutex::new(p2p_outbound_rx_raw));
        let mining_template_id = Arc::new(ArcSwap::from_pointee(CompactString::new("0")));
        let (inbound_headers_tx, inbound_headers_rx_raw) =
            crossbeam_channel::unbounded::<Vec<Header>>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            crossbeam_channel::unbounded::<bitcoin::Block>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let sync = Arc::new(crate::BlockSync::new(
            crate::apply::ApplyHandles {
                network: config.network,
                chain_tip: Arc::clone(&chain_tip),
                applied_tip: Arc::clone(&applied_tip),
                block_tree: Arc::clone(&block_tree),
                utxo: Arc::clone(&utxo),
                coin_stats: Arc::clone(&coin_stats),
                tx_index: tx_index.as_ref().map(Arc::clone),
                filter_index: Arc::clone(&filter_index),
                mempool: Arc::clone(&mempool),
                blocks: Arc::clone(&blocks),
                transactions: Arc::clone(&transactions),
                zmq_publisher: Arc::clone(&zmq_publisher),
                cache_block_bodies_in_memory: false,
                block_body_store: Some(storage.block_body_store()),
                g2_muhash_sampler: g2_muhash_sampler.clone(),
            },
            Arc::clone(&peers),
            Arc::clone(&peer_outbound),
            Arc::clone(&inbound_headers_rx),
            Arc::clone(&inbound_blocks_rx),
        ));
        let prune_service = if config.prune_target_mb > 0 {
            Some(storage.prune_service(Arc::clone(&blocks), Arc::clone(&transactions))?)
        } else {
            None
        };
        tracing::info!(
            backend = storage.kind(),
            chainstate_dir = %config.data_dir.join("chainstate").display(),
            "opened storage backend"
        );
        let data_dir = config.data_dir.clone();
        Ok(Self {
            config,
            data_dir,
            storage,
            utxo,
            coin_stats,
            tx_index,
            tx_index_storage,
            filter_index,
            prune_service,
            zmq_publisher,
            active_zmq_notifications,
            g2_muhash_sampler,
            mempool,
            chain_tip,
            applied_tip,
            block_tree,
            blocks,
            transactions,
            network,
            peers,
            peer_outbound,
            banned,
            p2p_outbound_tx,
            p2p_outbound_rx,
            inbound_headers_tx,
            inbound_headers_rx,
            inbound_blocks_tx,
            inbound_blocks_rx,
            mining_template_id,
            sync,
            replayed: Mutex::new(Vec::new()),
        })
    }

    /// Returns a borrow of the resolved configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the node's data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
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
    pub fn coin_stats(&self) -> Arc<bitcoin_rs_coinstats::CoinStatsListener> {
        Arc::clone(&self.coin_stats)
    }

    /// Returns the shared block indexer handle, when txindex is enabled.
    #[must_use]
    pub fn tx_index(&self) -> Option<Arc<Mutex<Box<dyn bitcoin_rs_index::IndexerLike>>>> {
        self.tx_index.as_ref().map(Arc::clone)
    }

    /// Builds an Electrum `IndexHandle` backed by the live txindex store.
    ///
    /// The handle observes the same `KvStore` the writer side ingests into via
    /// `apply_block`, so `blockchain.block.headers` returns real data once IBD
    /// is underway.
    #[must_use]
    pub fn electrum_index_handle(&self) -> Option<bitcoin_rs_electrum::IndexHandle> {
        self.tx_index_storage
            .as_ref()
            .map(|storage| storage.electrum_index_handle())
    }

    /// Builds an Electrum-side history reader wired through the live txindex store
    /// and the in-memory block log. The handle can be attached to `IndexHandle`
    /// via `with_history_reader`.
    #[must_use]
    pub fn electrum_history_reader(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_electrum::methods::ConfirmedHistoryReader>> {
        self.tx_index_storage
            .as_ref()
            .map(|storage| storage.electrum_history_reader(self.blocks(), self.block_body_source()))
    }

    /// Returns the shared compact-filter index handle.
    #[must_use]
    pub fn filter_index(&self) -> FilterIndexHandle {
        Arc::clone(&self.filter_index)
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

    /// Returns active ZMQ notification metadata for RPC reporting.
    #[must_use]
    pub fn active_zmq_notifications(&self) -> Vec<ZmqNotification> {
        self.active_zmq_notifications.clone()
    }

    /// Returns the shared mempool handle.
    #[must_use]
    pub fn mempool(&self) -> Arc<RwLock<Mempool>> {
        Arc::clone(&self.mempool)
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

    /// Returns the shared block-records handle exposed to RPC handlers.
    #[must_use]
    pub fn blocks(&self) -> Arc<RwLock<Vec<BlockRecord>>> {
        Arc::clone(&self.blocks)
    }

    /// Returns a durable block body reader for metadata-only block records.
    #[must_use]
    pub(crate) fn block_body_source(&self) -> Arc<dyn BlockBodySource> {
        Arc::new(StoredBlockBodySource::new(self.storage.block_body_store()))
    }

    /// Returns the shared txid → transaction map exposed to RPC handlers.
    #[must_use]
    pub fn transactions(&self) -> Arc<RwLock<HashMap<Txid, Transaction>>> {
        Arc::clone(&self.transactions)
    }

    /// Returns the shared network-counters handle exposed to RPC handlers.
    #[must_use]
    pub fn network(&self) -> Arc<RwLock<NetworkState>> {
        Arc::clone(&self.network)
    }

    /// Returns the shared registry of currently-handshook peers.
    #[must_use]
    pub fn peers(&self) -> Arc<RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>> {
        Arc::clone(&self.peers)
    }

    /// Returns the shared manual IP/subnet ban list exposed to RPC and P2P.
    #[must_use]
    pub fn banned_subnets(&self) -> Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>> {
        Arc::clone(&self.banned)
    }

    /// Returns the shared per-peer outbound message-sender map.
    ///
    /// External callers can look up a peer's `Sender<Message>` by socket
    /// address and send a message into that peer's outbound queue. The
    /// per-connection thread drains the receiver each iteration of
    /// `run_message_loop` and writes the message via `peer.send`.
    #[must_use]
    pub fn peer_outbound(
        &self,
    ) -> Arc<
        RwLock<HashMap<std::net::SocketAddr, crossbeam_channel::Sender<bitcoin_rs_p2p::Message>>>,
    > {
        Arc::clone(&self.peer_outbound)
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

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// `Headers` batches into. The matching `Receiver` is consumed by
    /// `BlockSync::tick` to extend the `BlockTree`.
    #[must_use]
    pub fn inbound_headers_sender(&self) -> Sender<Vec<Header>> {
        self.inbound_headers_tx.clone()
    }

    /// Returns the shared receiver handle consumed by `BlockSync::tick`.
    ///
    /// Exposed so tests and `BlockSync::new` can wire the channel; production
    /// code calls `state.sync()` and lets the orchestrator own the drain.
    #[must_use]
    pub fn inbound_headers_rx_handle(&self) -> Arc<Mutex<Receiver<Vec<Header>>>> {
        Arc::clone(&self.inbound_headers_rx)
    }

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// `Block` messages into. The matching `Receiver` is consumed by
    /// `BlockSync::tick` to apply downloaded blocks.
    #[must_use]
    pub fn inbound_blocks_sender(&self) -> Sender<bitcoin::Block> {
        self.inbound_blocks_tx.clone()
    }

    /// Returns the shared receiver handle consumed by `BlockSync::tick`.
    ///
    /// Exposed so tests and `BlockSync::new` can wire the channel; production
    /// code calls `state.sync()` and lets the orchestrator own the drain.
    #[must_use]
    pub fn inbound_blocks_rx_handle(&self) -> Arc<Mutex<Receiver<bitcoin::Block>>> {
        Arc::clone(&self.inbound_blocks_rx)
    }

    /// Returns the shared block-download orchestrator.
    #[must_use]
    pub fn sync(&self) -> Arc<crate::BlockSync> {
        Arc::clone(&self.sync)
    }

    /// Returns the shared getblocktemplate long-poll id.
    #[must_use]
    pub fn mining_template_id(&self) -> Arc<ArcSwap<CompactString>> {
        Arc::clone(&self.mining_template_id)
    }

    /// Heights walked by the most recent crash-recovery replay.
    #[must_use]
    pub fn replayed_heights(&self) -> Vec<u32> {
        self.replayed.lock().clone()
    }

    /// Records a height in the in-memory replay log.
    pub(crate) fn push_replayed(&self, height: u32) {
        self.replayed.lock().push(height);
    }

    /// Test helper: writes the recovery metadata as if a block at `height`
    /// had just been fully committed. Real block commits flow through the
    /// `crates/utxo` listener; this helper exists so crash-recovery tests
    /// can simulate a chain without bringing up the full subsystem stack.
    pub fn record_synthetic_block_for_recovery(&self, height: u32) -> Result<()> {
        let meta = crate::crash_recovery::Meta {
            height,
            last_committed_height: height,
        };
        crate::crash_recovery::write_meta(self, &meta)
    }

    /// Snapshot of the handle set needed by `crate::apply::apply_block`.
    #[must_use]
    pub fn apply_handles(&self) -> crate::apply::ApplyHandles {
        crate::apply::ApplyHandles {
            network: self.config.network,
            chain_tip: Arc::clone(&self.chain_tip),
            applied_tip: Arc::clone(&self.applied_tip),
            block_tree: Arc::clone(&self.block_tree),
            utxo: Arc::clone(&self.utxo),
            coin_stats: Arc::clone(&self.coin_stats),
            tx_index: self.tx_index.as_ref().map(Arc::clone),
            filter_index: Arc::clone(&self.filter_index),
            mempool: Arc::clone(&self.mempool),
            blocks: Arc::clone(&self.blocks),
            transactions: Arc::clone(&self.transactions),
            zmq_publisher: Arc::clone(&self.zmq_publisher),
            cache_block_bodies_in_memory: false,
            block_body_store: Some(self.storage.block_body_store()),
            g2_muhash_sampler: self.g2_muhash_sampler.clone(),
        }
    }

    /// Synthetically applies `block` as the next tip after consensus checks.
    ///
    /// Delegates to `crate::apply::apply_block` over the shared handles.
    pub fn apply_block(
        &self,
        block: &bitcoin::Block,
    ) -> core::result::Result<TipSnapshot, ApplyError> {
        crate::apply::apply_block(&self.apply_handles(), block)
    }

    #[cfg(test)]
    pub(crate) fn check_coinbase_maturity(
        &self,
        block: &bitcoin::Block,
        height: u32,
    ) -> core::result::Result<(), ApplyError> {
        crate::apply::check_coinbase_maturity(&self.apply_handles(), block, height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_constructs_empty_handles() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let config = crate::Config {
            data_dir: dir.path().join("node"),
            ..crate::Config::default()
        };

        let state = NodeState::open(config)?;
        let utxo = state.utxo();
        let mempool = state.mempool();

        assert!(
            Arc::strong_count(&utxo) >= 2,
            "caller and NodeState should both hold a strong ref"
        );
        assert!(Arc::strong_count(&mempool) >= 2);
        assert_eq!(mempool.read().len(), 0, "fresh mempool must be empty");

        Ok(())
    }

    #[test]
    fn open_constructs_empty_block_tree() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let tree = state.block_tree();

        assert!(
            tree.read().is_empty(),
            "freshly opened tree has zero headers"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_coin_stats_listener() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let snapshot = state.coin_stats().snapshot();
        assert_eq!(
            snapshot.tx_count, 0,
            "freshly opened coin_stats has zero txs"
        );
        Ok(())
    }

    #[test]
    fn open_skips_tx_index_when_disabled() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        assert!(state.tx_index().is_none(), "txindex disabled by default");
        assert!(
            !state.data_dir().join("txindex").exists(),
            "disabled txindex must not create storage"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_tx_index_when_enabled() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = true;
        let state = NodeState::open(config)?;
        let (Some(a), Some(b)) = (state.tx_index(), state.tx_index()) else {
            panic!("txindex handle missing when enabled");
        };
        assert!(Arc::ptr_eq(&a, &b), "tx_index handle stable across calls");
        assert!(
            state.data_dir().join("txindex").exists(),
            "enabled txindex must create storage"
        );
        Ok(())
    }

    #[test]
    fn electrum_index_handle_constructs_with_real_txindex_store() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = true;
        let state = NodeState::open(config)?;
        let Some(handle) = state.electrum_index_handle() else {
            panic!("electrum index handle missing when txindex enabled");
        };

        assert!(!format!("{handle:?}").is_empty());
        Ok(())
    }

    #[test]
    fn open_constructs_filter_index() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let a = state.filter_index();
        let b = state.filter_index();
        assert!(
            Arc::ptr_eq(&a, &b),
            "filter_index handle stable across calls"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_block_sync_orchestrator() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let sync_a = state.sync();
        let sync_b = state.sync();
        assert!(
            Arc::ptr_eq(&sync_a, &sync_b),
            "sync handle is stable across calls"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_empty_applied_tip() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        assert!(
            state.applied_tip().load_full().is_none(),
            "freshly opened applied_tip is empty"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_empty_peer_registry() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        assert!(
            state.peers().read().is_empty(),
            "freshly opened registry is empty"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_empty_peer_outbound_map() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        assert!(state.peer_outbound().read().is_empty());
        Ok(())
    }

    #[test]
    fn zmq_publisher_handle_defaults_to_noop() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let publisher = state.zmq_publisher();
        // No-op publisher accepts publish calls silently.
        publisher.publish_hashblock(bitcoin_rs_primitives::Hash256::default());
        Ok(())
    }

    #[test]
    fn zmq_publisher_handle_reports_active_metadata() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.zmqpubhashblock = vec!["inproc://state-zmq-pubhashblock".to_owned()];
        config.zmqpubhashtx = vec!["inproc://state-zmq-pubhashtx".to_owned()];
        config.zmqpubrawblock = vec!["inproc://state-zmq-pubrawblock".to_owned()];
        config.zmqpubrawtx = vec!["inproc://state-zmq-pubrawtx".to_owned()];
        config.zmqpubhashblockhwm = Some(17);
        config.zmqpubhashtxhwm = Some(18);
        config.zmqpubrawblockhwm = Some(19);
        config.zmqpubrawtxhwm = Some(20);
        let state = NodeState::open(config)?;

        let notifications = state.active_zmq_notifications();
        let notification_types: Vec<_> = notifications
            .iter()
            .map(|notification| notification.notification_type.as_str())
            .collect();
        let hwms: Vec<_> = notifications
            .iter()
            .map(|notification| notification.hwm)
            .collect();
        assert_eq!(
            notification_types,
            ["pubhashblock", "pubhashtx", "pubrawblock", "pubrawtx"]
        );
        assert_eq!(hwms, [17, 18, 19, 20]);
        Ok(())
    }

    #[test]
    fn inbound_headers_sender_is_unbounded_clone_target() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let tx1 = state.inbound_headers_sender();
        let tx2 = state.inbound_headers_sender();
        tx1.send(Vec::new())
            .map_err(|err| anyhow::anyhow!("send via tx1 failed: {err}"))?;
        tx2.send(Vec::new())
            .map_err(|err| anyhow::anyhow!("send via tx2 failed: {err}"))?;
        Ok(())
    }

    #[test]
    fn inbound_blocks_sender_is_clonable_into_listener_threads() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let _tx1 = state.inbound_blocks_sender();
        let _tx2 = state.inbound_blocks_sender();
        Ok(())
    }

    #[test]
    fn open_constructs_full_rpc_handle_set() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let config = crate::Config {
            data_dir: dir.path().join("node"),
            ..crate::Config::default()
        };

        let state = NodeState::open(config)?;
        let chain_tip = state.chain_tip();
        let blocks = state.blocks();
        let transactions = state.transactions();
        let network = state.network();
        let mining_template_id = state.mining_template_id();

        assert!(chain_tip.load().is_none(), "fresh chain tip must be empty");
        assert!(blocks.read().is_empty(), "fresh blocks must be empty");
        assert!(
            transactions.read().is_empty(),
            "fresh transactions must be empty"
        );
        assert_eq!(network.read().connection_count, 0);
        assert_eq!(mining_template_id.load().as_str(), "0");

        Ok(())
    }

    #[test]
    fn apply_handles_follow_txindex_availability() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("without-txindex");
        config.p2p_listen.clear();
        config.txindex = false;
        let state = NodeState::open(config)?;
        assert!(state.apply_handles().tx_index.is_none());

        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("with-txindex");
        config.p2p_listen.clear();
        config.txindex = true;
        let state = NodeState::open(config)?;
        assert!(state.apply_handles().tx_index.is_some());
        Ok(())
    }

    #[test]
    fn prune_service_is_absent_when_config_disables_pruning() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 0;

        let state = NodeState::open(config)?;

        assert!(state.prune_service().is_none());
        Ok(())
    }

    #[test]
    fn apply_block_persists_body_under_pruning_key_when_pruning_disabled() -> anyhow::Result<()> {
        use bitcoin::blockdata::constants::genesis_block;
        use bitcoin::consensus::encode::serialize;
        use bitcoin::hashes::Hash as _;

        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 0;
        let state = NodeState::open(config)?;
        let block = genesis_block(bitcoin::Network::Regtest);
        let hash =
            bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_byte_array());

        assert!(state.prune_service().is_none());
        state.apply_block(&block)?;

        assert_eq!(
            state
                .blocks
                .read()
                .first()
                .map(|record| record.block_hex.as_str()),
            Some("")
        );
        assert_eq!(
            state.storage.stored_prune_body(0, hash)?.as_deref(),
            Some(serialize(&block).as_slice())
        );
        Ok(())
    }

    #[test]
    fn prune_service_deletes_seeded_storage_rows_and_clears_cached_bodies() -> anyhow::Result<()> {
        fn hash(height: u32) -> anyhow::Result<bitcoin_rs_primitives::Hash256> {
            let byte = u8::try_from(height)
                .map_err(|_| anyhow::anyhow!("test height {height} exceeds u8"))?;
            Ok(bitcoin_rs_primitives::Hash256::from_le_bytes(&[byte; 32]))
        }

        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let state = NodeState::open(config)?;

        for height in 10_u32..=12 {
            let hash = hash(height)?;
            state
                .storage
                .seed_prune_rows(height, hash, b"block-body", b"undo-body")?;
            state.blocks.write().push(BlockRecord {
                hash,
                height,
                block_hex: "00".to_owned(),
                body_size: 1,
                header_hex: String::new(),
                tx_count: 0,
                time: 0,
            });
        }

        let Some(service) = state.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        let result = service
            .prune_to_height(11)
            .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;

        assert_eq!(result.pruneheight, 11);
        assert_eq!(result.block_rows_removed, 1);
        assert_eq!(result.undo_rows_removed, 1);
        assert!(state.storage.stored_prune_body(10, hash(10)?)?.is_none());
        assert!(state.storage.stored_prune_undo(10, hash(10)?)?.is_none());
        assert!(state.storage.stored_prune_body(11, hash(11)?)?.is_some());
        assert!(state.storage.stored_prune_undo(11, hash(11)?)?.is_some());
        assert!(state.storage.stored_prune_body(12, hash(12)?)?.is_some());
        assert!(state.storage.stored_prune_undo(12, hash(12)?)?.is_some());

        let blocks = state.blocks.read();
        assert_eq!(
            blocks
                .iter()
                .find(|record| record.height == 10)
                .map(|record| record.block_hex.as_str()),
            Some("")
        );
        assert_eq!(
            blocks
                .iter()
                .find(|record| record.height == 10)
                .map(|record| record.block_hex.capacity()),
            Some(0)
        );
        assert_eq!(
            blocks
                .iter()
                .find(|record| record.height == 11)
                .map(|record| record.block_hex.as_str()),
            Some("00")
        );

        Ok(())
    }

    #[test]
    fn manual_prune_removes_pruned_block_transactions_from_cache() -> anyhow::Result<()> {
        use bitcoin::blockdata::constants::genesis_block;
        use bitcoin::consensus::encode::serialize;
        use bitcoin::hashes::Hash as _;

        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let state = NodeState::open(config)?;

        let pruned_block = genesis_block(bitcoin::Network::Regtest);
        let pruned_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(
            pruned_block.block_hash().as_byte_array(),
        );
        state
            .storage
            .seed_prune_rows(10, pruned_hash, &serialize(&pruned_block), b"undo-body")?;
        state
            .blocks
            .write()
            .push(BlockRecord::from_block_metadata(10, &pruned_block));

        let pruned_tx = pruned_block.txdata[0].clone();
        let pruned_txid = pruned_tx.compute_txid();
        let unrelated_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let unrelated_txid = unrelated_tx.compute_txid();

        {
            let mut transactions = state.transactions.write();
            transactions.insert(pruned_txid, pruned_tx);
            transactions.insert(unrelated_txid, unrelated_tx);
        }

        let Some(service) = state.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        service
            .prune_to_height(11)
            .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;

        let transactions = state.transactions.read();
        assert!(!transactions.contains_key(&pruned_txid));
        assert!(transactions.contains_key(&unrelated_txid));
        Ok(())
    }

    #[test]
    fn prune_service_restores_persisted_pruneheight_on_reopen() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;

        {
            let state = NodeState::open(config.clone())?;
            let Some(service) = state.prune_service() else {
                anyhow::bail!("prune service should exist when prune_target_mb > 0");
            };
            let result = service
                .prune_to_height(11)
                .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;
            assert_eq!(result.pruneheight, 11);
        }

        let reopened = NodeState::open(config)?;
        let Some(service) = reopened.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        assert_eq!(service.status().pruneheight, Some(11));

        Ok(())
    }
}
