use alloc::sync::Arc;
use core::fmt;

use arc_swap::{ArcSwap, ArcSwapOption};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::{Block, Transaction, Txid};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_primitives::Hash256;
use compact_str::CompactString;
use crossbeam_channel::{Receiver, Sender, unbounded};
use hashbrown::HashMap;
use parking_lot::RwLock;

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

/// Shared state consumed by JSON-RPC handlers.
pub struct Context {
    /// Best-chain tip snapshot published by chain validation.
    pub chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// In-memory mempool handle.
    pub mempool: Arc<RwLock<Mempool>>,
    /// Block records already available without blocking storage readers.
    pub blocks: Arc<RwLock<Vec<BlockRecord>>>,
    /// Raw transactions indexed by txid for Core transaction RPCs.
    pub transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    /// Network counters and peers.
    pub network: Arc<RwLock<NetworkState>>,
    /// Current getblocktemplate long-poll id.
    pub mining_template_id: Arc<ArcSwap<CompactString>>,
    /// Receiver notified when mining template inputs change.
    pub mining_notifications: Receiver<()>,
    mining_sender: Sender<()>,
}

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
    pub fn new() -> Self {
        let (mining_sender, mining_notifications) = unbounded();
        Self {
            chain_tip: Arc::new(ArcSwapOption::empty()),
            mempool: Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            blocks: Arc::new(RwLock::new(Vec::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            network: Arc::new(RwLock::new(NetworkState::default())),
            mining_template_id: Arc::new(ArcSwap::from_pointee(CompactString::new("0"))),
            mining_notifications,
            mining_sender,
        }
    }

    /// Publishes a new best-chain tip and wakes getblocktemplate long polls.
    pub fn set_chain_tip(&self, tip: TipSnapshot) {
        self.mining_template_id
            .store(Arc::new(CompactString::from(tip.hash.to_string_be())));
        self.chain_tip.store(Some(Arc::new(tip)));
        let _ignored = self.mining_sender.send(());
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

    /// Returns the current best block hash, or all-zero before initial sync.
    #[must_use]
    pub fn best_hash(&self) -> Hash256 {
        self.chain_tip
            .load_full()
            .map_or_else(Hash256::default, |tip| tip.hash)
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
}
