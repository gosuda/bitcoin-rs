//! Shared node state aggregating subsystem handles.
//!
//! V1 keeps this deliberately minimal: it owns the resolved [`Config`], the
//! data-directory path, the open chainstate storage backend, and the replay log
//! used by [`crate::crash_recovery`]. Subsystem wiring (chain / utxo / mempool
//! / index / p2p / rpc / electrum) parks here as the integration point matures.

use arc_swap::{ArcSwap, ArcSwapOption};
use bitcoin::{Transaction, Txid, block::Header};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_rpc::{BlockRecord, NetworkState};
use compact_str::CompactString;
use core::fmt;
use crossbeam_channel::{Receiver, Sender};
use hashbrown::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::{Mutex, RwLock};

use crate::Config;

type TxIndexHandle = Arc<Mutex<Box<dyn bitcoin_rs_index::IndexerLike>>>;
type FilterIndexHandle = Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>;

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
}

enum NodeStorage {
    #[cfg(feature = "rocksdb")]
    RocksDb(bitcoin_rs_storage::RocksDbStore),
    #[cfg(feature = "fjall")]
    Fjall(bitcoin_rs_storage::FjallStore),
    #[cfg(feature = "redb")]
    Redb(bitcoin_rs_storage::RedbStore),
    #[cfg(feature = "mdbx")]
    Mdbx(bitcoin_rs_storage::MdbxStore),
}

impl NodeStorage {
    fn open(config: &Config) -> Result<Self> {
        let chainstate_dir = config.data_dir.join("chainstate");
        std::fs::create_dir_all(&chainstate_dir)
            .with_context(|| format!("create chainstate_dir {}", chainstate_dir.display()))?;

        match config.storage_backend.as_str() {
            #[cfg(feature = "rocksdb")]
            "rocksdb" => Ok(Self::RocksDb(
                bitcoin_rs_storage::RocksDbStore::open(&chainstate_dir)
                    .map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "fjall")]
            "fjall" => Ok(Self::Fjall(
                bitcoin_rs_storage::FjallStore::open(&chainstate_dir)
                    .map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "redb")]
            "redb" => Ok(Self::Redb(
                bitcoin_rs_storage::RedbStore::open(&chainstate_dir).map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "mdbx")]
            "mdbx" => Ok(Self::Mdbx(
                bitcoin_rs_storage::MdbxStore::open(&chainstate_dir).map_err(anyhow::Error::new)?,
            )),
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
    ) -> Arc<dyn bitcoin_rs_electrum::methods::ConfirmedHistoryReader> {
        let block_source = crate::NodeBlockSource::new(blocks);
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

fn open_tx_index(config: &Config) -> Result<(TxIndexHandle, TxIndexStorage)> {
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
            Ok((
                Arc::new(Mutex::new(indexer)),
                TxIndexStorage::RocksDb(store),
            ))
        }
        #[cfg(feature = "fjall")]
        "fjall" => {
            let store = Arc::new(
                bitcoin_rs_storage::FjallStore::open(&txindex_dir).map_err(anyhow::Error::new)?,
            );
            let indexer: Box<dyn bitcoin_rs_index::IndexerLike> =
                Box::new(bitcoin_rs_index::Indexer::new(Arc::clone(&store)));
            Ok((Arc::new(Mutex::new(indexer)), TxIndexStorage::Fjall(store)))
        }
        #[cfg(feature = "redb")]
        "redb" => {
            let store = Arc::new(
                bitcoin_rs_storage::RedbStore::open(&txindex_dir).map_err(anyhow::Error::new)?,
            );
            let indexer: Box<dyn bitcoin_rs_index::IndexerLike> =
                Box::new(bitcoin_rs_index::Indexer::new(Arc::clone(&store)));
            Ok((Arc::new(Mutex::new(indexer)), TxIndexStorage::Redb(store)))
        }
        #[cfg(feature = "mdbx")]
        "mdbx" => {
            let store = Arc::new(
                bitcoin_rs_storage::MdbxStore::open(&txindex_dir).map_err(anyhow::Error::new)?,
            );
            let indexer: Box<dyn bitcoin_rs_index::IndexerLike> =
                Box::new(bitcoin_rs_index::Indexer::new(Arc::clone(&store)));
            Ok((Arc::new(Mutex::new(indexer)), TxIndexStorage::Mdbx(store)))
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
    tx_index: TxIndexHandle,
    tx_index_storage: Arc<TxIndexStorage>,
    filter_index: FilterIndexHandle,
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
    pub fn open(config: Config) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("create data_dir {}", config.data_dir.display()))?;
        let storage = NodeStorage::open(&config)?;
        let (tx_index, tx_index_storage) = open_tx_index(&config)?;
        let tx_index_storage = Arc::new(tx_index_storage);
        let filter_index = open_filter_index(&config)?;
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
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (p2p_outbound_tx, p2p_outbound_rx_raw) = crossbeam_channel::unbounded();
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
                tx_index: Arc::clone(&tx_index),
                filter_index: Arc::clone(&filter_index),
                mempool: Arc::clone(&mempool),
                blocks: Arc::clone(&blocks),
                transactions: Arc::clone(&transactions),
            },
            Arc::clone(&peers),
            Arc::clone(&peer_outbound),
            Arc::clone(&inbound_headers_rx),
            Arc::clone(&inbound_blocks_rx),
        ));
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
            tx_index_storage: Arc::clone(&tx_index_storage),
            filter_index,
            mempool,
            chain_tip,
            applied_tip,
            block_tree,
            blocks,
            transactions,
            network,
            peers,
            peer_outbound,
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

    /// Returns the shared block indexer handle.
    #[must_use]
    pub fn tx_index(&self) -> Arc<Mutex<Box<dyn bitcoin_rs_index::IndexerLike>>> {
        Arc::clone(&self.tx_index)
    }

    /// Builds an Electrum `IndexHandle` backed by the live txindex store.
    ///
    /// The handle observes the same `KvStore` the writer side ingests into via
    /// `apply_block`, so `blockchain.block.headers` returns real data once IBD
    /// is underway.
    #[must_use]
    pub fn electrum_index_handle(&self) -> bitcoin_rs_electrum::IndexHandle {
        self.tx_index_storage.electrum_index_handle()
    }

    /// Builds an Electrum-side history reader wired through the live txindex store
    /// and the in-memory block log. The handle can be attached to `IndexHandle`
    /// via `with_history_reader`.
    #[must_use]
    pub fn electrum_history_reader(
        &self,
    ) -> Arc<dyn bitcoin_rs_electrum::methods::ConfirmedHistoryReader> {
        self.tx_index_storage.electrum_history_reader(self.blocks())
    }

    /// Returns the shared compact-filter index handle.
    #[must_use]
    pub fn filter_index(&self) -> FilterIndexHandle {
        Arc::clone(&self.filter_index)
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
            tx_index: Arc::clone(&self.tx_index),
            filter_index: Arc::clone(&self.filter_index),
            mempool: Arc::clone(&self.mempool),
            blocks: Arc::clone(&self.blocks),
            transactions: Arc::clone(&self.transactions),
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
    fn open_constructs_tx_index() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let a = state.tx_index();
        let b = state.tx_index();
        assert!(Arc::ptr_eq(&a, &b), "tx_index handle stable across calls");
        Ok(())
    }

    #[test]
    fn electrum_index_handle_constructs_with_real_txindex_store() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let handle = state.electrum_index_handle();

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
}
