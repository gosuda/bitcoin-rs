use alloc::sync::Arc;
use core::fmt;

use arc_swap::{ArcSwap, ArcSwapOption};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex, FromHex as _};
use bitcoin::{Block, OutPoint, Transaction, Txid};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_primitives::{Hash256, Network};
use compact_str::CompactString;
use crossbeam_channel::{Receiver, Sender, unbounded};
use hashbrown::HashMap;
use parking_lot::RwLock;

const SERIALIZED_BLOCK_HEADER_LEN: usize = 80;

/// Block data made available to RPC handlers without forcing storage I/O.
#[derive(Clone, Debug)]
pub struct BlockRecord {
    /// Block hash in conventional big-endian hex order.
    pub hash: Hash256,
    /// Height in the active chain.
    pub height: u32,
    /// Serialized block bytes as lowercase hex.
    pub block_hex: String,
    /// Serialized block byte length.
    pub body_size: usize,
    /// Serialized block header bytes as lowercase hex.
    pub header_hex: String,
    /// Transaction count in the block.
    pub tx_count: usize,
    /// Block header timestamp (UNIX seconds).
    pub time: u32,
}

/// The node's block-record log, with the two whole-log sums kept as it changes.
///
/// The log holds one record per applied block and grows for the life of the
/// process — ~963k entries on a mainnet node at the time of writing. Two
/// RPC-visible figures are sums over all of it: `size_on_disk` in
/// `getblockchaininfo`, and `txcount` in `getchaintxstats`. Folding the log to
/// answer them made a call that reports a handful of scalars cost time linear in
/// chain length, and it was paid **under the log's read lock**, which is the
/// lock block application takes to append. The sums are maintained here instead.
///
/// Deliberately not a `Vec<BlockRecord>` with the totals kept beside it: the log
/// is appended from `apply`, from `Context::add_block`, and from tests, and a
/// total that any of those could forget to update is a total that will drift.
/// Mutation goes through the methods below, so it cannot.
///
/// Reads are unchanged. The type derefs to `[BlockRecord]`, so every existing
/// slice, index, iterator and binary search over the log keeps working.
#[derive(Clone, Debug, Default)]
pub struct BlockLog {
    records: Vec<BlockRecord>,
    /// Sum of `body_size` over every record.
    total_body_size: u64,
    /// `cumulative_tx_count[i]` is the sum of `tx_count` over `records[..=i]`.
    ///
    /// A single running total would answer `txcount` only when the applied tip
    /// is the log's last record, and would fall back to walking everything above
    /// it otherwise — a cliff, not a bound. Prefix sums answer any prefix in
    /// constant time, so the cost no longer depends on where the applied tip
    /// sits relative to the log. Eight bytes per record, ~7.7 MB at a mainnet
    /// tip, against ~254 MB the records themselves occupy.
    cumulative_tx_count: Vec<u64>,
}

impl BlockLog {
    /// Creates an empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            total_body_size: 0,
            cumulative_tx_count: Vec::new(),
        }
    }

    /// Appends a record, extending the running body-size sum and the prefix sums.
    pub fn push(&mut self, record: BlockRecord) {
        self.total_body_size = self
            .total_body_size
            .saturating_add(u64::try_from(record.body_size).unwrap_or(u64::MAX));
        // Read the last prefix directly rather than through `total_tx_count`:
        // that one carries a `debug_assert` which folds the log, and paying it
        // per append would make block application quadratic in debug builds.
        let running = self
            .cumulative_tx_count
            .last()
            .copied()
            .unwrap_or(0)
            .saturating_add(u64::try_from(record.tx_count).unwrap_or(0));
        self.cumulative_tx_count.push(running);
        self.records.push(record);
    }

    /// Removes the last record, taking it back out of both.
    ///
    /// This is the disconnect path: a reorg pops the tip's record after checking
    /// it is the one being disconnected.
    pub fn pop(&mut self) -> Option<BlockRecord> {
        let record = self.records.pop()?;
        let _ = self.cumulative_tx_count.pop();
        self.total_body_size = self
            .total_body_size
            .saturating_sub(u64::try_from(record.body_size).unwrap_or(u64::MAX));
        Some(record)
    }

    /// Empties the log.
    pub fn clear(&mut self) {
        self.records.clear();
        self.cumulative_tx_count.clear();
        self.total_body_size = 0;
    }

    /// Reserves capacity for `additional` more records.
    pub fn reserve(&mut self, additional: usize) {
        self.records.reserve(additional);
        self.cumulative_tx_count.reserve(additional);
    }

    /// Mutable access to the records, for fields the running sums do not cover.
    ///
    /// Pruning uses this to release cached block bodies. `body_size` and
    /// `tx_count` describe the block and do not change when its body is dropped,
    /// so the sums stay correct — and `debug_assert`s in [`Self::size_on_disk`]
    /// and [`Self::tx_count_before`] fail loudly if a caller ever changes them.
    pub fn records_mut(&mut self) -> impl Iterator<Item = &mut BlockRecord> {
        self.records.iter_mut()
    }

    /// Sum of every record's serialized block length, in bytes.
    ///
    /// This is `getblockchaininfo`'s `size_on_disk`. It counts the block sizes
    /// the node has recorded, which is what the fold it replaced counted;
    /// pruning does not remove records, so a pruned node still reports the bytes
    /// its blocks would occupy.
    #[must_use]
    pub fn size_on_disk(&self) -> u64 {
        debug_assert_eq!(
            self.total_body_size,
            self.records.iter().fold(0_u64, |total, record| total
                .saturating_add(u64::try_from(record.body_size).unwrap_or(u64::MAX))),
            "running body-size total drifted from the records it summarizes"
        );
        self.total_body_size
    }

    /// Sum of `tx_count` over the first `count` records.
    ///
    /// `count` is clamped to the log's length, so a caller that computed a
    /// boundary against a longer log gets the whole sum rather than a panic.
    #[must_use]
    pub fn tx_count_before(&self, count: usize) -> u64 {
        // The prefix vector is parallel to the records. Stating it here rather
        // than relying on the clamp below is the difference between a mutation
        // that drops a `pop` dying on the invariant it broke and dying on an
        // out-of-range read further along.
        debug_assert_eq!(
            self.records.len(),
            self.cumulative_tx_count.len(),
            "the tx-count prefix vector is no longer parallel to the records"
        );
        let count = count.min(self.records.len());
        let prefix = count
            .checked_sub(1)
            .and_then(|last| self.cumulative_tx_count.get(last).copied())
            .unwrap_or(0);
        debug_assert_eq!(
            prefix,
            self.records[..count]
                .iter()
                .fold(0_u64, |total, record| total
                    .saturating_add(u64::try_from(record.tx_count).unwrap_or(0))),
            "tx-count prefix sums drifted from the records they summarize"
        );
        prefix
    }

    /// Sum of every record's transaction count.
    #[must_use]
    pub fn total_tx_count(&self) -> u64 {
        self.tx_count_before(self.cumulative_tx_count.len())
    }
}

impl core::ops::Deref for BlockLog {
    type Target = [BlockRecord];

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

impl FromIterator<BlockRecord> for BlockLog {
    fn from_iter<I: IntoIterator<Item = BlockRecord>>(iter: I) -> Self {
        let mut log = Self::new();
        for record in iter {
            log.push(record);
        }
        log
    }
}

/// `getchaintxstats`'s figures, read from the log without walking all of it.
///
/// The log is appended in height order and only ever popped from the tail
/// (`apply::disconnect_block` checks the tail's hash before popping), so it is
/// non-decreasing by height. `Context::block_at_height` already relies on that
/// and binary-searches it; this reads the same three boundaries out of it:
///
/// - `end`: one past the last record at or below the applied tip.
/// - `tip_start`: the *first* record at the applied height. Duplicate heights
///   are possible across a reorg, and the fold this replaces took the first one.
/// - `window_start`: the first record inside the requested window.
///
/// Both transaction counts are differences of prefix sums across those
/// boundaries, so neither depends on where the applied tip sits in the log.
///
/// Only the window is then walked, and only for `earliest_window_time`: it is a
/// minimum over block timestamps, which are not monotonic, so no prefix sum can
/// answer it. The window is the caller's `nblocks` (~4,320 by default), not the
/// chain.
///
/// [`fold_block_records`] is the implementation this replaced, kept as
/// the oracle `chain_stats_matches_the_fold_it_replaced` compares against.
#[must_use]
pub fn chain_stats(log: &BlockLog, applied_height: u32, lowest_window_height: u64) -> ChainStats {
    let blocks: &[BlockRecord] = log;
    debug_assert!(
        blocks
            .windows(2)
            .all(|pair| pair[0].height <= pair[1].height),
        "the block log must be non-decreasing by height for these searches"
    );

    let end = blocks.partition_point(|record| record.height <= applied_height);
    let applied = &blocks[..end];

    let tip_start = applied.partition_point(|record| record.height < applied_height);
    let tip_time = applied
        .get(tip_start)
        .filter(|record| record.height == applied_height)
        .map(|record| record.time);

    let window_start =
        applied.partition_point(|record| u64::from(record.height) < lowest_window_height);
    let mut earliest_window_time: Option<u32> = None;
    for record in &applied[window_start..] {
        earliest_window_time =
            Some(earliest_window_time.map_or(record.time, |earliest| earliest.min(record.time)));
    }
    let total_tx_count = log.tx_count_before(end);
    let window_tx_count = total_tx_count.saturating_sub(log.tx_count_before(window_start));

    ChainStats {
        total_tx_count,
        window_tx_count,
        tip_time,
        earliest_window_time,
    }
}

/// The figures `getchaintxstats` reports, read from a [`BlockLog`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainStats {
    /// Sum of `tx_count` over records at or below the applied tip.
    pub total_tx_count: u64,
    /// Sum of `tx_count` over records inside the requested window.
    pub window_tx_count: u64,
    /// Timestamp of the first record at the applied height.
    pub tip_time: Option<u32>,
    /// Lowest timestamp inside the requested window.
    pub earliest_window_time: Option<u32>,
}
/// What a whole-log fold produced for the chain-info RPCs.
///
/// See [`fold_block_records`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FoldedBlockRecords {
    /// Sum of `body_size` over every record.
    pub size_on_disk: u64,
    /// Sum of `tx_count` over records at or below the applied tip.
    pub total_tx_count: u64,
    /// Sum of `tx_count` over records inside the requested window.
    pub window_tx_count: u64,
    /// Timestamp of the first record at the applied height.
    pub tip_time: Option<u32>,
    /// Lowest timestamp inside the requested window.
    pub earliest_window_time: Option<u32>,
}

/// The whole-log fold `getblockchaininfo` and `getchaintxstats` used to run.
///
/// Retained deliberately, not left behind. It is the oracle the equivalence
/// tests compare [`BlockLog`]'s running sums and the windowed search against,
/// and the `before` arm of `benches/chaininfo.rs` — both arms have to run in one
/// process over one fixture for the ratio to mean anything, which they cannot do
/// if this is deleted.
///
/// Nothing in the node calls it. It walks every record the node holds, which is
/// the entire reason it was replaced.
///
/// It makes no assumption about the log's ordering, which is the point: the
/// replacement binary-searches, and an oracle that shared that assumption could
/// not catch it being wrong.
#[must_use]
pub fn fold_block_records(
    blocks: &[BlockRecord],
    applied_height: u32,
    lowest_window_height: Option<u64>,
) -> FoldedBlockRecords {
    let mut stats = FoldedBlockRecords::default();
    for record in blocks {
        stats.size_on_disk = stats
            .size_on_disk
            .saturating_add(u64::try_from(record.body_size).unwrap_or(u64::MAX));
        if record.height > applied_height {
            continue;
        }
        stats.total_tx_count = stats
            .total_tx_count
            .saturating_add(u64::try_from(record.tx_count).unwrap_or(0));
        if record.height == applied_height && stats.tip_time.is_none() {
            stats.tip_time = Some(record.time);
        }
        if lowest_window_height.is_some_and(|lowest| u64::from(record.height) >= lowest) {
            stats.window_tx_count = stats
                .window_tx_count
                .saturating_add(u64::try_from(record.tx_count).unwrap_or(0));
            stats.earliest_window_time = Some(
                stats
                    .earliest_window_time
                    .map_or(record.time, |earliest| earliest.min(record.time)),
            );
        }
    }
    stats
}

/// Block payload facts available without materializing a full block body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockBodyMetadata {
    /// Serialized block byte length.
    pub body_size: usize,
    /// Number of transactions encoded in the block.
    pub tx_count: usize,
}

/// Storage-backed block body reader used when block records keep only metadata.
pub trait BlockBodySource: Send + Sync {
    /// Returns serialized block bytes for `height` and `hash`, if available.
    fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>>;

    /// Returns indexed body facts. Implementations that cannot answer without
    /// I/O may leave this absent; header-only callers then remain header-only.
    fn block_body_metadata(&self, _height: u32, _hash: Hash256) -> Option<BlockBodyMetadata> {
        None
    }

    /// Bytes this source's block storage currently occupies on disk.
    ///
    /// This is `getblockchaininfo`'s `size_on_disk`, and it has to come from
    /// whatever owns the bytes. The block-record log can only offer the sum of
    /// the block sizes it has seen, which is a different number: records outlive
    /// the bodies they describe, so that sum keeps counting bytes pruning has
    /// already deleted — under a field name that is read to check whether
    /// pruning is working.
    ///
    /// `None` means "this source does not know", and the caller falls back to
    /// that sum. A source with no durable storage behind it — a test fixture, a
    /// cache-only context — has nothing better to say.
    fn disk_usage(&self) -> Option<u64> {
        None
    }

    /// Returns `len` body bytes starting `offset` bytes into the serialized
    /// block, letting a caller read one transaction without materializing the
    /// whole body.
    ///
    /// Defaults to `None` so a backend that cannot slice keeps working: callers
    /// must treat `None` as "read the whole body instead", never as "those bytes
    /// do not exist". An out-of-range request also yields `None` rather than a
    /// short read — a truncated transaction decodes into something other than
    /// the one that was asked for.
    fn block_body_range(
        &self,
        _height: u32,
        _hash: Hash256,
        _offset: u32,
        _len: u32,
    ) -> Option<Vec<u8>> {
        None
    }
}

impl BlockRecord {
    /// Builds a record from a decoded Bitcoin block.
    #[must_use]
    pub fn from_block(height: u32, block: &Block) -> Self {
        let block_bytes = serialize(block);
        Self::from_block_bytes(height, block, &block_bytes)
    }

    /// Builds a record from a decoded Bitcoin block and its serialized bytes.
    ///
    /// Callers on hot paths can pass bytes already produced for persistence or
    /// indexes instead of serializing the full block a second time.
    #[must_use]
    pub fn from_block_bytes(height: u32, block: &Block, block_bytes: &[u8]) -> Self {
        let block_hash = block.block_hash();
        let hash = Hash256::from_le_bytes(block_hash.as_byte_array());
        let header_hex = header_hex_from_block_bytes(block, block_bytes);
        let block_hex = block_bytes.to_lower_hex_string();
        Self {
            hash,
            height,
            block_hex,
            body_size: block_bytes.len(),
            header_hex,
            tx_count: block.txdata.len(),
            time: block.header.time,
        }
    }

    /// Builds a metadata-only record for nodes that serve block bodies from storage.
    #[must_use]
    pub fn from_block_metadata(height: u32, block: &Block) -> Self {
        let block_bytes = serialize(block);
        Self::from_block_metadata_bytes(height, block, &block_bytes)
    }

    /// Builds a metadata-only record from bytes already serialized by the caller.
    #[must_use]
    pub fn from_block_metadata_bytes(height: u32, block: &Block, block_bytes: &[u8]) -> Self {
        let block_hash = block.block_hash();
        let hash = Hash256::from_le_bytes(block_hash.as_byte_array());
        let header_hex = header_hex_from_block_bytes(block, block_bytes);
        Self {
            hash,
            height,
            block_hex: String::new(),
            body_size: block_bytes.len(),
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
            body_size: 0,
            header_hex: String::new(),
            tx_count: 0,
            time: 0,
        }
    }
}

fn header_hex_from_block_bytes(block: &Block, block_bytes: &[u8]) -> String {
    block_bytes.get(..SERIALIZED_BLOCK_HEADER_LEN).map_or_else(
        || serialize(&block.header).to_lower_hex_string(),
        DisplayHex::to_lower_hex_string,
    )
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

/// Node-owned control plane for consensus-affecting chain RPCs.
pub trait ChainControl: Send + Sync {
    /// Invalidates a block and descendants and selects the best remaining chain.
    fn invalidate_block(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), ChainControlError>;
}

/// Failure from a node-owned chain mutation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainControlError {
    /// The requested block is unknown.
    #[error("unknown block")]
    UnknownBlock,
    /// Genesis cannot be invalidated.
    #[error("cannot invalidate the genesis block")]
    Genesis,
    /// The mutation failed after its request was accepted.
    #[error("{0}")]
    Failed(String),
}
#[derive(Debug, Default)]
struct NoopFilterIndex;

impl bitcoin_rs_filters::FilterIndexLike for NoopFilterIndex {
    fn put_filter(
        &self,
        _block_hash: bitcoin_rs_primitives::Hash256,
        _prev_header: bitcoin_rs_primitives::Hash256,
        _filter_bytes: &[u8],
    ) -> Result<bitcoin_rs_primitives::Hash256, bitcoin_rs_filters::FilterIndexError> {
        Ok(bitcoin_rs_primitives::Hash256::default())
    }

    fn filter_header(
        &self,
        _block_hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<bitcoin_rs_primitives::Hash256>, bitcoin_rs_filters::FilterIndexError> {
        Ok(None)
    }

    fn filter(
        &self,
        _block_hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_filters::FilterIndexError> {
        Ok(None)
    }
}

fn noop_filter_index() -> Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>> {
    let filter_index: Box<dyn bitcoin_rs_filters::FilterIndexLike> = Box::new(NoopFilterIndex);
    Arc::new(filter_index)
}

/// Actual progress reported by the node-owned transaction index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxIndexInfo {
    /// Whether the index has completely caught up to the authoritative chain tip.
    pub synced: bool,
    /// Height of the best block completely covered by the index.
    pub best_block_height: u32,
}

/// Failure from a complete transaction-index query.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TxQueryError {
    /// The query raced index or chain progress and should be retried.
    #[error("transaction index changed during query; retry")]
    Retry,
    /// The index cannot currently prove a complete answer.
    #[error("transaction index unavailable: {0}")]
    Unavailable(CompactString),
    /// Durable index storage failed.
    #[error("transaction index storage error: {0}")]
    Storage(CompactString),
}

/// Lockless read-only adapter for complete transaction-index queries.
pub trait TxIndexQuery: Send + Sync {
    /// Resolves a confirmed transaction, returning `None` only after complete absence is proven.
    fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, TxQueryError>;
    /// Resolves a confirmed prevout value, returning `None` only after complete absence is proven.
    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError>;
    /// Returns the transaction index's actual durable progress.
    fn index_info(&self) -> Result<TxIndexInfo, TxQueryError>;
}

impl TxQueryError {
    /// Maps a transaction-index failure to an explicit JSON-RPC error.
    #[must_use]
    pub fn into_rpc_error(self) -> crate::error::RpcError {
        match self {
            Self::Retry => crate::error::RpcError::Internal(
                "transaction index is still catching up; retry later".to_owned(),
            ),
            Self::Unavailable(reason) => {
                crate::error::RpcError::Internal(format!("transaction index unavailable: {reason}"))
            }
            Self::Storage(reason) => crate::error::RpcError::Internal(format!(
                "transaction index storage error: {reason}"
            )),
        }
    }
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
    pub blocks: Arc<RwLock<BlockLog>>,
    /// Raw transactions indexed by txid for Core transaction RPCs.
    pub transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    /// UTXO set snapshot handle used by chain metadata RPCs.
    pub utxo: Arc<bitcoin_rs_utxo::UtxoSet>,
    /// Incremental UTXO-set statistics.
    pub coin_stats: Arc<bitcoin_rs_coinstats::CoinStatsListener>,
    /// BIP157/158 compact-filter index used by filter RPCs.
    pub filter_index: Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>,
    /// Optional storage pruning mutator.
    pub prune_service: Option<Arc<dyn PruneService>>,
    /// Optional node-owned chain mutation service.
    pub chain_control: Option<Arc<dyn ChainControl>>,
    /// Optional node-owned complete transaction-index query adapter.
    /// `None` when transaction indexing is disabled.
    pub tx_index: Option<Arc<dyn TxIndexQuery>>,
    /// Network counters and peers.
    pub network: Arc<RwLock<NetworkState>>,
    /// Network selector used by handlers needing consensus parameters (e.g.
    /// difficulty calculation).
    pub chain_network: Network,
    /// Shared registry of currently-handshook peers.
    pub peers: Arc<RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>>,
    /// Shared in-memory block tree.
    pub block_tree: Arc<parking_lot::RwLock<bitcoin_rs_chain::BlockTree>>,
    /// Optional durable block body reader for metadata-only block records.
    pub block_body_source: Option<Arc<dyn BlockBodySource>>,
    /// Current getblocktemplate long-poll id.
    pub mining_template_id: Arc<ArcSwap<CompactString>>,
    /// Receiver notified when mining template inputs change.
    pub mining_notifications: Receiver<()>,
    /// Optional outbound channel that submits decoded blocks back to the node's
    /// `BlockSync::tick` for the canonical apply path. `None` when no node is
    /// wired (tests, embedded callers).
    pub inbound_blocks_sender: Option<crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>>,
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
            blocks: Arc::new(RwLock::new(BlockLog::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            utxo: Arc::new(utxo),
            coin_stats,
            filter_index: noop_filter_index(),
            tx_index: None,
            prune_service: None,
            chain_control: None,
            network: Arc::new(RwLock::new(NetworkState::default())),
            chain_network: Network::Mainnet,
            peers: Arc::new(RwLock::new(Vec::new())),
            block_tree: Arc::new(parking_lot::RwLock::new(bitcoin_rs_chain::BlockTree::new())),
            block_body_source: None,
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
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
        utxo: Arc<bitcoin_rs_utxo::UtxoSet>,
        coin_stats: Arc<bitcoin_rs_coinstats::CoinStatsListener>,
        filter_index: Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>,
        network: Arc<RwLock<NetworkState>>,
        mining_template_id: Arc<ArcSwap<CompactString>>,
        peers: Arc<RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>>,
        block_tree: Arc<parking_lot::RwLock<bitcoin_rs_chain::BlockTree>>,
        chain_network: Network,
        inbound_blocks_sender: Option<crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>>,
        p2p_outbound_sender: Option<crossbeam_channel::Sender<std::net::SocketAddr>>,
        banned: Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
        added_nodes: Arc<parking_lot::RwLock<Vec<std::net::SocketAddr>>>,
        tx_index: Option<Arc<dyn TxIndexQuery>>,
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
            tx_index,
            network,
            chain_network,
            peers,
            block_tree,
            block_body_source: None,
            mining_template_id,
            mining_notifications,
            inbound_blocks_sender,
            p2p_outbound_sender,
            banned,
            added_nodes,
            prune_service: None,
            chain_control: None,
            zmq_notifications: Arc::from(Vec::<ZmqNotification>::new()),
            mining_sender,
        }
    }

    /// Returns `self` with a durable block body source.
    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
    }

    /// Attaches the node-owned pruning mutator used by `pruneblockchain`.
    #[must_use]
    pub fn with_prune_service(mut self, prune_service: Arc<dyn PruneService>) -> Self {
        self.prune_service = Some(prune_service);
        self
    }

    /// Attaches the node-owned chain mutation service.
    #[must_use]
    pub fn with_chain_control(mut self, chain_control: Arc<dyn ChainControl>) -> Self {
        self.chain_control = Some(chain_control);
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

    /// Returns the f64 difficulty for `bits` using Bitcoin Core's calculation.
    ///
    /// Keep the operation order here in sync with Core's `GetDifficulty`;
    /// changing the repeated 256 scaling into an equivalent exponentiation can
    /// change the final floating-point bit.
    #[must_use]
    pub fn difficulty_for_bits(&self, bits: bitcoin::CompactTarget) -> f64 {
        let consensus_bits = bits.to_consensus();
        let mantissa = consensus_bits & 0x00ff_ffff;
        if mantissa == 0 {
            return 0.0;
        }
        let mut shift = (consensus_bits >> 24) & 0xff;
        let mut difficulty = f64::from(0x0000_ffff_u32) / f64::from(mantissa);
        while shift < 29 {
            difficulty *= 256.0;
            shift += 1;
        }
        while shift > 29 {
            difficulty /= 256.0;
            shift -= 1;
        }
        difficulty
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

    fn hash_at_height_from_tip(&self, tip: &TipSnapshot, height: u32) -> Option<Hash256> {
        if height > tip.height {
            return None;
        }
        if height == tip.height {
            return Some(tip.hash);
        }
        let tree = self.block_tree.read();
        let node_id = tree.node_at_height_from(tip.tip_id, height)?;
        Some(tree.node(node_id).ok()?.hash)
    }

    /// Returns the applied-chain hash at `height`, from the restored header index.
    #[must_use]
    pub fn active_hash_at_height(&self, height: u32) -> Option<Hash256> {
        let tip = self.applied_tip.load_full()?;
        self.hash_at_height_from_tip(&tip, height)
    }

    fn header_record(&self, hash: Hash256) -> Option<BlockRecord> {
        let tree = self.block_tree.read();
        let node = tree.node_by_hash(hash)?;
        Some(BlockRecord {
            hash,
            height: node.height,
            block_hex: String::new(),
            body_size: 0,
            header_hex: serialize(&node.header).to_lower_hex_string(),
            tx_count: 0,
            time: node.header.time,
        })
    }

    /// Resolves a block record for `hash`.
    ///
    /// The restored header tree is the identity authority: when it knows the
    /// hash its `(hash, height)` pair wins, and the session vector contributes
    /// only a matching payload cache or durable body metadata. When the tree
    /// has no node for `hash` (cache-only fixtures, or a block seen before a
    /// checkpoint restore) the vector supplies a record by exact hash as a
    /// legacy fallback. A stale cached height can therefore never override an
    /// active-tree identity.
    #[must_use]
    pub fn record_for_hash(&self, hash: Hash256) -> Option<BlockRecord> {
        // 1. Tree authority. When the restored header index knows this hash its
        //    identity wins; enrich with a height-matched cached payload, else
        //    with durable body metadata.
        if let Some(mut record) = self.header_record(hash) {
            if let Some(cached) = self
                .blocks
                .read()
                .iter()
                .find(|candidate| candidate.hash == hash && candidate.height == record.height)
            {
                return Some(cached.clone());
            }
            if let Some(metadata) = self
                .block_body_source
                .as_ref()
                .and_then(|source| source.block_body_metadata(record.height, hash))
            {
                record.body_size = metadata.body_size;
                record.tx_count = metadata.tx_count;
            }
            return Some(record);
        }
        // 2. Legacy/cache-only fallback. The tree cannot resolve this identity,
        //    so accept a vector record by exact hash. Metadata-only records and
        //    pruned-body payloads pass through unchanged via their own fields.
        self.blocks
            .read()
            .iter()
            .find(|candidate| candidate.hash == hash)
            .cloned()
    }

    /// Returns the block hash for an applied height.
    ///
    /// Once an applied tip exists, its ancestry is authoritative and heights
    /// above it are absent even when header sync has found a better fork.
    /// Before the first applied-tip publication, genesis and cache-only test
    /// records remain available.
    #[must_use]
    pub fn block_hash_at_height(&self, height: u32) -> Option<Hash256> {
        if let Some(tip) = self.applied_tip.load_full() {
            return self.hash_at_height_from_tip(&tip, height);
        }
        if height == 0 {
            return Some(Hash256::from_le_bytes(
                bitcoin::blockdata::constants::genesis_block(bitcoin_network(self.chain_network))
                    .block_hash()
                    .as_byte_array(),
            ));
        }
        self.blocks
            .read()
            .iter()
            .find(|candidate| candidate.height == height)
            .map(|candidate| candidate.hash)
    }

    /// Returns a known block by hash.
    #[must_use]
    pub fn block_by_hash(&self, hash: Hash256) -> Option<BlockRecord> {
        self.record_for_hash(hash)
    }

    /// Returns the applied block at a height.
    ///
    /// Once an applied tip exists, its ancestry is authoritative. The session
    /// vector is a cache-only fallback before the first applied-tip publication.
    #[must_use]
    pub fn block_by_height(&self, height: u32) -> Option<BlockRecord> {
        if let Some(tip) = self.applied_tip.load_full() {
            let hash = self.hash_at_height_from_tip(&tip, height)?;
            return self.record_for_hash(hash);
        }
        self.blocks
            .read()
            .iter()
            .find(|candidate| candidate.height == height)
            .cloned()
    }

    /// Returns serialized block bytes from the record or durable storage.
    #[must_use]
    pub fn block_body_bytes(&self, record: &BlockRecord) -> Option<Vec<u8>> {
        if !record.block_hex.is_empty() {
            return Vec::<u8>::from_hex(&record.block_hex).ok();
        }
        self.block_body_source
            .as_ref()?
            .block_body(record.height, record.hash)
    }

    /// Bytes the node's block storage occupies on disk, when it can say.
    ///
    /// `None` when there is no durable body source, or it does not track usage.
    #[must_use]
    pub fn block_storage_disk_usage(&self) -> Option<u64> {
        self.block_body_source.as_ref()?.disk_usage()
    }

    /// Returns lowercase serialized block hex from the record or durable storage.
    #[must_use]
    pub fn block_body_hex(&self, record: &BlockRecord) -> Option<String> {
        if !record.block_hex.is_empty() {
            return Some(record.block_hex.clone());
        }
        Some(self.block_body_bytes(record)?.to_lower_hex_string())
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

fn bitcoin_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet3 => bitcoin::Network::Testnet,
        Network::Testnet4 => bitcoin::Network::Testnet4,
        Network::Signet => bitcoin::Network::Signet,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            Arc::new(RwLock::new(BlockLog::new())),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::clone(&utxo),
            Arc::clone(&coin_stats),
            Arc::clone(&filter_index),
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
            Arc::ptr_eq(&ctx.filter_index, &filter_index),
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
    fn block_record_from_block_bytes_matches_from_block() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_bytes = serialize(&block);

        let from_block = BlockRecord::from_block(0, &block);
        let from_bytes = BlockRecord::from_block_bytes(0, &block, &block_bytes);

        assert_eq!(from_bytes.hash, from_block.hash);
        assert_eq!(from_bytes.height, from_block.height);
        assert_eq!(from_bytes.block_hex, from_block.block_hex);
        assert_eq!(from_bytes.body_size, from_block.body_size);
        assert_eq!(from_bytes.header_hex, from_block.header_hex);
        assert_eq!(from_bytes.tx_count, from_block.tx_count);
        assert_eq!(from_bytes.time, from_block.time);
    }

    #[test]
    fn context_reads_metadata_only_block_record_from_body_source() {
        struct SingleBlockSource {
            height: u32,
            hash: Hash256,
            body: Vec<u8>,
        }

        impl BlockBodySource for SingleBlockSource {
            fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
                (height == self.height && hash == self.hash).then(|| self.body.clone())
            }
        }

        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let body = serialize(&block);
        let record = BlockRecord::from_block_metadata(0, &block);
        let source = Arc::new(SingleBlockSource {
            height: 0,
            hash: record.hash,
            body: body.clone(),
        });
        let ctx = Context::new().with_block_body_source(source);
        ctx.add_block(record.clone());

        assert!(record.block_hex.is_empty());
        assert_eq!(record.body_size, body.len());
        assert_eq!(
            ctx.block_body_bytes(&record).as_deref(),
            Some(body.as_slice())
        );
        let expected_hex = body.to_lower_hex_string();
        assert_eq!(
            ctx.block_body_hex(&record).as_deref(),
            Some(expected_hex.as_str())
        );
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
    #[test]
    fn block_by_height_prefers_tree_identity_over_stale_cache()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::block::Version;
        use bitcoin::hashes::Hash as _;
        use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
        use bitcoin_rs_chain::NodeStatus;

        let ctx = Context::new();
        let (child_hash, stale_hash) = {
            let mut tree = ctx.block_tree.write();
            let genesis = bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let mut child = bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: genesis.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_900,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            child.nonce = 1;
            let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::Active)?;
            let child_hash = tree.node(child_id)?.hash;
            let applied_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing child tip"))?;
            ctx.set_applied_tip((*applied_tip).clone());
            // Stale cache entry at the SAME height as the tree child but with a
            // different hash. The active-tree identity must win over this cache.
            let stale_hash = Hash256::from_le_bytes(&[0xa5_u8; 32]);
            ctx.add_block(BlockRecord::synthetic(1, stale_hash));
            (child_hash, stale_hash)
        };

        assert_ne!(child_hash, stale_hash, "test fixture hashes must differ");
        let found = ctx
            .block_by_height(1)
            .ok_or_else(|| std::io::Error::other("tree child missing at height 1"))?;
        assert_eq!(
            found.hash, child_hash,
            "active-tree identity must win over a stale cached hash"
        );
        assert_eq!(found.height, 1);
        Ok(())
    }

    #[test]
    fn height_lookups_follow_applied_tip_when_header_fork_leads()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::block::Version;
        use bitcoin::hashes::Hash as _;
        use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
        use bitcoin_rs_chain::NodeStatus;

        let ctx = Context::new();
        let (applied_tip, header_tip) = {
            let mut tree = ctx.block_tree.write();
            let genesis = bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let applied = bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: genesis.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_900,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
            };
            let applied_id = tree.insert_node(Some(genesis_id), applied, NodeStatus::Active)?;
            let applied_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
            assert_eq!(applied_tip.tip_id, applied_id);

            let fork = bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: genesis.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_901,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 2,
            };
            let fork_id = tree.insert_node(Some(genesis_id), fork, NodeStatus::HeaderValid)?;
            let fork_tip = bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: fork.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_001_800,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 3,
            };
            let header_tip_id =
                tree.insert_node(Some(fork_id), fork_tip, NodeStatus::HeaderValid)?;
            let header_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing header tip"))?;
            assert_eq!(header_tip.tip_id, header_tip_id);
            (applied_tip, header_tip)
        };

        ctx.set_applied_tip((*applied_tip).clone());
        ctx.set_chain_tip((*header_tip).clone());
        ctx.add_block(BlockRecord::synthetic(2, header_tip.hash));

        assert_eq!(
            ctx.active_hash_at_height(1),
            Some(applied_tip.hash),
            "height lookup must stay on the applied branch"
        );
        assert_eq!(ctx.block_hash_at_height(1), Some(applied_tip.hash));
        assert_eq!(
            ctx.block_by_height(1).map(|record| record.hash),
            Some(applied_tip.hash)
        );
        assert!(ctx.block_hash_at_height(2).is_none());
        assert!(ctx.block_by_height(2).is_none());
        Ok(())
    }
}
