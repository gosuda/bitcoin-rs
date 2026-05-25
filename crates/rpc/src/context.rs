use alloc::sync::Arc;
use core::fmt;

use arc_swap::{ArcSwap, ArcSwapOption};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::{Block, Transaction, Txid};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_primitives::{Hash256, Network};
use compact_str::CompactString;
use crossbeam_channel::{Receiver, Sender, unbounded};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

/// Block data made available to RPC handlers without forcing storage I/O.
#[derive(Clone, Debug)]
pub struct BlockRecord {
    /// Block hash in conventional big-endian hex order.
    pub hash: Hash256,
    /// Height in the active chain.
    pub height: u32,
    /// Serialized block bytes as lowercase hex.
    pub block_hex: String,
    /// Serialized block header bytes as lowercase hex.
    pub header_hex: String,
    /// Transaction count in the block.
    pub tx_count: usize,
    /// Block header timestamp (UNIX seconds).
    pub time: u32,
}

impl BlockRecord {
    /// Builds a record from a decoded Bitcoin block.
    #[must_use]
    pub fn from_block(height: u32, block: &Block) -> Self {
        let block_hash = block.block_hash();
        let hash = Hash256::from_le_bytes(block_hash.as_byte_array());
        let header_hex = serialize(&block.header).to_lower_hex_string();
        let block_hex = serialize(block).to_lower_hex_string();
        Self {
            hash,
            height,
            block_hex,
            header_hex,
            tx_count: block.txdata.len(),
            time: block.header.time,
        }
    }

    /// Builds a synthetic record used by tests and empty-state scaffolds.
    #[must_use]
    pub fn synthetic(height: u32, hash: Hash256) -> Self {
        Self {
            hash,
            height,
            block_hex: String::new(),
            header_hex: String::new(),
            tx_count: 0,
            time: 0,
        }
    }
}

/// Network counters and peer metadata exposed by network RPCs.
#[derive(Clone, Debug, Default)]
pub struct NetworkState {
    /// Number of connected peers.
    pub connection_count: u64,
    /// Total bytes received since startup.
    pub bytes_recv: u64,
    /// Total bytes sent since startup.
    pub bytes_sent: u64,
    /// Unix timestamp for the counters.
    pub timestamp: u64,
}

/// Current pruning state reported by chain RPCs.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneStatus {
    /// Whether block pruning is enabled for this node.
    pub pruned: bool,
    /// Highest manual prune height completed by the backing service.
    pub pruneheight: Option<u32>,
}

/// Summary of one completed manual prune request.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneResult {
    /// Height requested by the RPC caller.
    pub requested_height: u32,
    /// Highest prune height now recorded by the service.
    pub pruneheight: u32,
    /// Serialized block-body rows removed from storage.
    pub block_rows_removed: u64,
    /// Serialized undo rows removed from storage.
    pub undo_rows_removed: u64,
    /// Payload bytes removed from storage.
    pub bytes_freed: u64,
}

/// One active ZMQ notification reported by `getzmqnotifications`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZmqNotification {
    /// Core notifier type (`pubhashblock`, `pubhashtx`, `pubrawblock`, `pubrawtx`).
    pub notification_type: CompactString,
    /// Bound ZMQ endpoint address.
    pub address: String,
    /// PUB socket high-water mark.
    pub hwm: u32,
}

impl ZmqNotification {
    /// Builds immutable RPC metadata for an active ZMQ publisher.
    #[must_use]
    pub fn new(
        notification_type: impl Into<CompactString>,
        address: impl Into<String>,
        hwm: u32,
    ) -> Self {
        Self {
            notification_type: notification_type.into(),
            address: address.into(),
            hwm,
        }
    }
}

/// Error returned by the node-owned pruning implementation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PruneServiceError {
    /// Storage or backend-specific pruning failure.
    #[error("{0}")]
    Failed(String),
}

impl PruneServiceError {
    /// Wraps a concrete backend error message without coupling RPC to a storage crate.
    #[must_use]
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }
}

/// Node-owned storage mutator used by `pruneblockchain`.
pub trait PruneService: Send + Sync {
    /// Deletes persisted block/undo data below `requested_height`.
    fn prune_to_height(&self, requested_height: u32) -> Result<PruneResult, PruneServiceError>;

    /// Reports whether pruning is enabled and the highest completed prune height.
    fn status(&self) -> PruneStatus;
}
/// Shared state consumed by JSON-RPC handlers.
pub struct Context {
    /// Best-chain tip snapshot published by chain validation.
    pub chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Best-applied-block tip snapshot published after block application.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// In-memory mempool handle.
    pub mempool: Arc<RwLock<Mempool>>,
    /// Block records already available without blocking storage readers.
    pub blocks: Arc<RwLock<Vec<BlockRecord>>>,
    /// Raw transactions indexed by txid for Core transaction RPCs.
    pub transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    /// UTXO set snapshot handle used by chain metadata RPCs.
    pub utxo: Arc<bitcoin_rs_utxo::UtxoSet>,
    /// Incremental UTXO-set statistics.
    pub coin_stats: Arc<bitcoin_rs_coinstats::CoinStatsListener>,
    /// BIP157/158 compact-filter index used by filter RPCs when enabled.
    pub filter_index: Option<Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>>,
    /// Optional storage pruning mutator.
    pub prune_service: Option<Arc<dyn PruneService>>,
    /// Optional shared confirmed-block indexer used to resolve prevout values for fee statistics.
    /// `None` for embedded/test callers without txindex.
    pub indexer: Option<Arc<Mutex<Box<dyn bitcoin_rs_index::IndexerLike>>>>,
    /// Network counters and peers.
    pub network: Arc<RwLock<NetworkState>>,
    /// Network selector used by handlers needing consensus parameters (e.g.
    /// difficulty calculation).
    pub chain_network: Network,
    /// Shared registry of currently-handshook peers.
    pub peers: Arc<RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>>,
    /// Shared in-memory block tree.
    pub block_tree: Arc<parking_lot::RwLock<bitcoin_rs_chain::BlockTree>>,
    /// Current getblocktemplate long-poll id.
    pub mining_template_id: Arc<ArcSwap<CompactString>>,
    /// Receiver notified when mining template inputs change.
    pub mining_notifications: Receiver<()>,
    /// Optional outbound channel that submits decoded blocks back to the node's
    /// `BlockSync::tick` for the canonical apply path. `None` when no node is
    /// wired (tests, embedded callers).
    pub inbound_blocks_sender: Option<crossbeam_channel::Sender<bitcoin::Block>>,
    /// Optional outbound channel for `addnode` to request new P2P connections.
    /// `None` for embedded/test callers without a live P2P listener.
    pub p2p_outbound_sender: Option<crossbeam_channel::Sender<std::net::SocketAddr>>,
    /// Manual IP/CIDR bans shared with P2P enforcement.
    pub banned: Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
    /// Persisted `addnode add` entries.
    pub added_nodes: Arc<parking_lot::RwLock<Vec<std::net::SocketAddr>>>,
    /// Active ZMQ PUB notifications.
    pub zmq_notifications: Arc<[ZmqNotification]>,
    mining_sender: Sender<()>,
}
// SAFETY: `Context` is shared by RPC worker threads. Each mutable subsystem
// handle behind it uses atomics, channels, or locks for interior mutation.
// `UtxoSet` is likewise internally sharded behind locks; RPC currently only
// calls read-only aggregate counters through this handle.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for Context {}

// SAFETY: See the `Send` impl above. Shared access to all contained mutable
// state is mediated by thread-safe primitives or UTXO shard locks.
unsafe impl Sync for Context {}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context").finish_non_exhaustive()
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    /// Builds an empty context suitable for tests and early startup.
    #[must_use]
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn new() -> Self {
        let (mining_sender, mining_notifications) = unbounded();
        let coin_stats_listener = bitcoin_rs_coinstats::CoinStatsListener::new(
            bitcoin_rs_coinstats::CoinStats::default(),
        );
        let mut utxo = bitcoin_rs_utxo::UtxoSet::new();
        utxo.set_listener(Box::new(coin_stats_listener.clone()));
        let coin_stats = Arc::new(coin_stats_listener);
        Self {
            chain_tip: Arc::new(ArcSwapOption::empty()),
            applied_tip: Arc::new(ArcSwapOption::empty()),
            mempool: Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            blocks: Arc::new(RwLock::new(Vec::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            utxo: Arc::new(utxo),
            coin_stats,
            filter_index: None,
            indexer: None,
            prune_service: None,
            network: Arc::new(RwLock::new(NetworkState::default())),
            chain_network: Network::Mainnet,
            peers: Arc::new(RwLock::new(Vec::new())),
            block_tree: Arc::new(parking_lot::RwLock::new(bitcoin_rs_chain::BlockTree::new())),
            mining_template_id: Arc::new(ArcSwap::from_pointee(CompactString::new("0"))),
            mining_notifications,
            inbound_blocks_sender: None,
            p2p_outbound_sender: None,
            banned: Arc::new(parking_lot::RwLock::new(Vec::new())),
            added_nodes: Arc::new(parking_lot::RwLock::new(Vec::new())),
            zmq_notifications: Arc::from(Vec::<ZmqNotification>::new()),
            mining_sender,
        }
    }
    /// Builds a context that shares pre-existing handles owned elsewhere
    /// (typically by `bitcoin-rs-node::state::NodeState`).
    ///
    /// This is the wiring path for the integration layer: subsystem owners
    /// pass in their authoritative Arc handles, and RPC handlers observe
    /// the same state.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_handles(
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        mempool: Arc<RwLock<Mempool>>,
        blocks: Arc<RwLock<Vec<BlockRecord>>>,
        transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
        utxo: Arc<bitcoin_rs_utxo::UtxoSet>,
        coin_stats: Arc<bitcoin_rs_coinstats::CoinStatsListener>,
        filter_index: Option<Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>>,
        network: Arc<RwLock<NetworkState>>,
        mining_template_id: Arc<ArcSwap<CompactString>>,
        peers: Arc<RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>>,
        block_tree: Arc<parking_lot::RwLock<bitcoin_rs_chain::BlockTree>>,
        chain_network: Network,
        inbound_blocks_sender: Option<crossbeam_channel::Sender<bitcoin::Block>>,
        p2p_outbound_sender: Option<crossbeam_channel::Sender<std::net::SocketAddr>>,
        banned: Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
        added_nodes: Arc<parking_lot::RwLock<Vec<std::net::SocketAddr>>>,
        indexer: Option<Arc<Mutex<Box<dyn bitcoin_rs_index::IndexerLike>>>>,
    ) -> Self {
        let (mining_sender, mining_notifications) = unbounded();
        Self {
            chain_tip,
            applied_tip,
            mempool,
            blocks,
            transactions,
            utxo,
            coin_stats,
            filter_index,
            indexer,
            network,
            chain_network,
            peers,
            block_tree,
            mining_template_id,
            mining_notifications,
            inbound_blocks_sender,
            p2p_outbound_sender,
            banned,
            added_nodes,
            prune_service: None,
            zmq_notifications: Arc::from(Vec::<ZmqNotification>::new()),
            mining_sender,
        }
    }

    /// Attaches the node-owned pruning mutator used by `pruneblockchain`.
    #[must_use]
    pub fn with_prune_service(mut self, prune_service: Arc<dyn PruneService>) -> Self {
        self.prune_service = Some(prune_service);
        self
    }

    /// Attaches active ZMQ notification metadata reported by `getzmqnotifications`.
    #[must_use]
    pub fn with_zmq_notifications(mut self, notifications: Vec<ZmqNotification>) -> Self {
        self.zmq_notifications = Arc::from(notifications);
        self
    }

    /// Returns active ZMQ notification metadata.
    #[must_use]
    pub fn zmq_notifications(&self) -> &[ZmqNotification] {
        self.zmq_notifications.as_ref()
    }

    /// Returns the pruning state reported by `getblockchaininfo`.
    #[must_use]
    pub fn prune_status(&self) -> PruneStatus {
        self.prune_service
            .as_ref()
            .map_or_else(PruneStatus::default, |service| service.status())
    }

    /// Returns the f64 difficulty for `bits`, computed against the network's
    /// `PoW` limit. Returns `0.0` on any conversion failure.
    #[must_use]
    pub fn difficulty_for_bits(&self, bits: bitcoin::CompactTarget) -> f64 {
        let params = bitcoin::params::Params::new(bitcoin_network(self.chain_network));
        let current_target = bitcoin::pow::Target::from_compact(bits);
        if current_target == bitcoin::pow::Target::ZERO {
            return 0.0;
        }

        target_to_f64(params.max_attainable_target) / target_to_f64(current_target)
    }

    /// Publishes a new best-chain tip and wakes getblocktemplate long polls.
    pub fn set_chain_tip(&self, tip: TipSnapshot) {
        self.mining_template_id
            .store(Arc::new(CompactString::from(tip.hash.to_string_be())));
        self.chain_tip.store(Some(Arc::new(tip)));
        let _ignored = self.mining_sender.send(());
    }

    /// Publishes a new best-applied-block tip.
    pub fn set_applied_tip(&self, tip: TipSnapshot) {
        self.applied_tip.store(Some(Arc::new(tip)));
    }

    /// Stores a block record for block and header RPCs.
    pub fn add_block(&self, record: BlockRecord) {
        self.blocks.write().push(record);
    }

    /// Stores a decoded transaction for transaction lookup RPCs.
    pub fn add_transaction(&self, tx: Transaction) -> Txid {
        let txid = tx.compute_txid();
        self.transactions.write().insert(txid, tx);
        txid
    }

    /// Returns the current tip height, or zero before initial sync publishes one.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.chain_tip.load_full().map_or(0, |tip| tip.height)
    }

    /// Returns the current best-applied-block height (lags `height()` when
    /// headers are ahead of downloaded blocks).
    #[must_use]
    pub fn applied_height(&self) -> u32 {
        self.applied_tip.load_full().map_or(0, |tip| tip.height)
    }

    /// Returns the current best-applied-block hash.
    #[must_use]
    pub fn applied_hash(&self) -> Hash256 {
        self.applied_tip
            .load_full()
            .map_or_else(Hash256::default, |tip| tip.hash)
    }

    /// Returns the current best block hash, or all-zero before initial sync.
    #[must_use]
    pub fn best_hash(&self) -> Hash256 {
        self.chain_tip
            .load_full()
            .map_or_else(Hash256::default, |tip| tip.hash)
    }

    /// Returns the current best-chain chainwork as a 64-character lowercase
    /// big-endian hex string. Returns "00" when no tip is published yet (a
    /// 2-char placeholder matching `bitcoind`'s pre-genesis behavior).
    #[must_use]
    pub fn chainwork_hex(&self) -> String {
        let Some(tip) = self.chain_tip.load_full() else {
            return "00".to_owned();
        };
        let bytes: [u8; 32] = tip.chainwork.to_be_bytes();
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;

            let _: fmt::Result = write!(&mut out, "{byte:02x}");
        }
        out
    }

    /// Returns the block hash for `height` when known without blocking I/O.
    #[must_use]
    pub fn block_hash_at_height(&self, height: u32) -> Option<Hash256> {
        self.blocks
            .read()
            .iter()
            .find(|record| record.height == height)
            .map(|record| record.hash)
            .or_else(|| {
                self.chain_tip.load_full().and_then(|tip| {
                    if tip.height == height {
                        Some(tip.hash)
                    } else {
                        None
                    }
                })
            })
    }

    /// Returns a known block by hash.
    #[must_use]
    pub fn block_by_hash(&self, hash: Hash256) -> Option<BlockRecord> {
        self.blocks
            .read()
            .iter()
            .find(|record| record.hash == hash)
            .cloned()
    }

    /// Returns the `BlockRecord` at the given height, if known.
    ///
    /// Linear scan over the in-memory block log. Returns the first matching
    /// record. Suitable for handlers and Electrum resolvers needing a block
    /// reference; not a hot path on an indexed store.
    #[must_use]
    pub fn block_by_height(&self, height: u32) -> Option<BlockRecord> {
        self.blocks
            .read()
            .iter()
            .find(|record| record.height == height)
            .cloned()
    }

    /// Returns the median-time-past at the block with `hash`, or `None` if the
    /// block is not in the tree.
    #[must_use]
    pub fn median_time_past_for_hash(&self, hash: bitcoin_rs_primitives::Hash256) -> Option<u32> {
        let tree = self.block_tree.read();
        let node_id = tree.lookup(hash)?;
        tree.median_time_past_at(node_id, 11)
    }

    /// Returns the block height for `hash` via the in-memory `BlockTree`, or
    /// `None` if no node with that hash is known to the tree.
    ///
    /// Composes `BlockTree::height_of_hash` (chain crate commit `ef9ff41`).
    #[must_use]
    pub fn height_for_hash(&self, hash: bitcoin_rs_primitives::Hash256) -> Option<u32> {
        self.block_tree.read().height_of_hash(hash)
    }

    /// Returns the 64-char lowercase hex chainwork at the block with `hash`.
    #[must_use]
    pub fn chain_work_hex_for_hash(&self, hash: bitcoin_rs_primitives::Hash256) -> Option<String> {
        let tree = self.block_tree.read();
        let node = tree.node_by_hash(hash)?;
        let bytes: [u8; 32] = node.chainwork.to_be_bytes();
        Some(bytes.to_lower_hex_string())
    }

    /// Returns the hash of the block at `height + 1` on the active chain.
    #[must_use]
    pub fn next_block_hash_for_height(
        &self,
        height: u32,
    ) -> Option<bitcoin_rs_primitives::Hash256> {
        let tree = self.block_tree.read();
        let tip = tree.tip()?;
        let next_height = height.checked_add(1)?;
        let node_id = tree.node_at_height_from(tip.tip_id, next_height)?;
        let node = tree.node(node_id).ok()?;
        Some(node.hash)
    }
}

impl bitcoin_rs_index::BlockSource for Context {
    fn block_at_height(&self, height: u32) -> Option<bitcoin::Block> {
        let block_hex = self
            .blocks
            .read()
            .iter()
            .find(|record| record.height == height)
            .map(|record| record.block_hex.clone())?;
        if block_hex.is_empty() {
            return None;
        }
        let bytes = Vec::<u8>::from_hex(&block_hex).ok()?;
        bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&bytes).ok()
    }
}

fn bitcoin_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet3 => bitcoin::Network::Testnet,
        Network::Testnet4 => bitcoin::Network::Testnet4,
        Network::Signet => bitcoin::Network::Signet,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}

fn target_to_f64(target: bitcoin::pow::Target) -> f64 {
    target
        .to_be_bytes()
        .iter()
        .fold(0.0_f64, |acc, &byte| acc.mul_add(256.0, f64::from(byte)))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopFilterIndex;

    impl bitcoin_rs_filters::FilterIndexLike for NoopFilterIndex {
        fn put_filter(
            &self,
            _block_hash: bitcoin_rs_primitives::Hash256,
            prev_header: bitcoin_rs_primitives::Hash256,
            _filter_bytes: &[u8],
        ) -> Result<bitcoin_rs_primitives::Hash256, bitcoin_rs_filters::FilterIndexError> {
            Ok(prev_header)
        }

        fn filter_header(
            &self,
            _block_hash: bitcoin_rs_primitives::Hash256,
        ) -> Result<Option<bitcoin_rs_primitives::Hash256>, bitcoin_rs_filters::FilterIndexError>
        {
            Ok(None)
        }
    }

    fn noop_filter_index() -> Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>> {
        Arc::new(Box::new(NoopFilterIndex))
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn from_handles_shares_tip_handles_with_caller() {
        use alloc::sync::Arc;

        let chain_tip = Arc::new(ArcSwapOption::empty());
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let utxo = Arc::new(bitcoin_rs_utxo::UtxoSet::new());
        let coin_stats = Arc::new(bitcoin_rs_coinstats::CoinStatsListener::new(
            bitcoin_rs_coinstats::CoinStats::default(),
        ));
        let filter_index = noop_filter_index();
        let block_tree = Arc::new(RwLock::new(bitcoin_rs_chain::BlockTree::new()));
        let banned = Arc::new(RwLock::new(Vec::<bitcoin_rs_p2p::BannedSubnet>::new()));
        let added_nodes = Arc::new(RwLock::new(Vec::new()));
        let ctx = Context::from_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::clone(&utxo),
            Arc::clone(&coin_stats),
            Some(Arc::clone(&filter_index)),
            Arc::new(RwLock::new(NetworkState::default())),
            Arc::new(ArcSwap::from_pointee(CompactString::new("0"))),
            Arc::new(RwLock::new(Vec::new())),
            Arc::clone(&block_tree),
            Network::Mainnet,
            None,
            None,
            Arc::clone(&banned),
            Arc::clone(&added_nodes),
            None,
        );
        assert!(
            Arc::ptr_eq(&ctx.chain_tip, &chain_tip),
            "chain_tip must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.applied_tip, &applied_tip),
            "applied_tip must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.utxo, &utxo),
            "utxo must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.coin_stats, &coin_stats),
            "coin_stats must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(
                ctx.filter_index
                    .as_ref()
                    .expect("filter_index must be wired"),
                &filter_index
            ),
            "filter_index must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.block_tree, &block_tree),
            "block_tree must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.banned, &banned),
            "banned must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.added_nodes, &added_nodes),
            "added_nodes must be shared with caller"
        );
    }

    #[test]
    fn new_context_wires_utxo_commits_to_coin_stats() {
        use bitcoin::{Amount, ScriptBuf};
        use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
        use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};

        let ctx = Context::new();
        let outpoint = OutPoint::new(Hash256::from_le_bytes(&[1_u8; 32]), 0);
        let txout = TxOut {
            value: Amount::from_sat(125_000),
            script_pubkey: ScriptBuf::new(),
        };
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(outpoint, txout, true, 7));

        ctx.utxo
            .commit_block(&changes, &Hash256::default())
            .unwrap_or_else(|err| panic!("commit_block failed: {err}"));

        let snapshot = ctx.coin_stats.snapshot();
        assert_eq!(snapshot.utxo_count, 1);
        assert_eq!(snapshot.total_amount, 125_000);
    }

    #[test]
    fn block_by_height_returns_record_after_add_block() {
        use bitcoin_rs_primitives::Hash256;

        let ctx = Context::new();
        let record = BlockRecord::synthetic(42, Hash256::default());
        ctx.add_block(record);

        let Some(found) = ctx.block_by_height(42) else {
            panic!("expected record at height 42");
        };
        assert_eq!(found.height, 42);
    }

    #[test]
    fn height_for_hash_returns_none_when_tree_empty() {
        let ctx = Context::new();
        let unknown = bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xff_u8; 32]);

        assert!(ctx.height_for_hash(unknown).is_none());
    }
}
