use alloc::sync::Arc;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits, MempoolObserver, MutationResult};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Network, OutPoint, Tx, Txid, consensus_bytes,
};
use compact_str::CompactString;
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const SERIALIZED_BLOCK_HEADER_LEN: usize = 80;

/// How stale the applied tip may be while the node still counts as synced.
///
/// Bitcoin Core's `DEFAULT_MAX_TIP_AGE`, 24 hours. Core exposes it as
/// `-maxtipage`; this node has no such option yet, so the default stands.
const MAX_TIP_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Core `sendrawtransaction` default `maxfeerate`: 0.1 BTC/kvB in sat/kvB.
///
/// The node applies the identical cap to every admission surface, including
/// the embedded [`bitcoin_rs_node::Node::broadcast`], via
/// [`Context::admit_transaction`].
pub const DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB: u64 = 10_000_000;

/// Full-block REST responses materialize the block and a response buffer.
/// Bound concurrent materializations independently of socket connections.
const MAX_CONCURRENT_REST_BLOCK_RENDERS: usize = 2;

/// Encodes `bytes` as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[derive(Debug)]
struct RestRenderBudget {
    in_flight: AtomicUsize,
}

impl RestRenderBudget {
    const fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<RestRenderPermit> {
        let mut in_flight = self.in_flight.load(Ordering::Acquire);
        loop {
            if in_flight >= MAX_CONCURRENT_REST_BLOCK_RENDERS {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                in_flight,
                in_flight + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(RestRenderPermit {
                        budget: Arc::clone(self),
                    });
                }
                Err(actual) => in_flight = actual,
            }
        }
    }
}

pub(crate) struct RestRenderPermit {
    budget: Arc<RestRenderBudget>,
}

impl Drop for RestRenderPermit {
    fn drop(&mut self) {
        let previous = self.budget.in_flight.fetch_sub(1, Ordering::Release);
        debug_assert!(previous > 0, "REST render permit count underflowed");
    }
}

/// Block metadata made available to RPC handlers without forcing storage I/O.
///
/// The serialized block body lives in durable storage behind
/// [`BlockBodySource`]; records carry only identity and size facts.
#[derive(Clone, Debug)]
pub struct BlockRecord {
    /// Block hash in conventional big-endian hex order.
    pub hash: BlockHash,
    /// Height in the active chain.
    pub height: u32,
    /// Serialized block byte length.
    pub body_size: usize,
    /// Serialized block header bytes, when the record carries a header.
    ///
    /// **The log never carries one.** A record is held for every applied block
    /// for the life of the process, and the `BlockTree` already holds that
    /// block's header — so storing it here stored it twice. Every constructor
    /// leaves this `None`; [`Context::header_record`] is the only thing that
    /// fills it, from the tree node it resolved, on the way out to a caller.
    ///
    /// Boxed rather than inline for the same reason. An `Option<[u8; 80]>`
    /// costs its full 80 bytes in every record even when it is `None`, so
    /// leaving the log's records empty would have saved nothing. Boxing makes
    /// an absent header cost 8 bytes and allocates only where one is actually
    /// produced, which is once per RPC answer rather than once per block.
    pub header: Option<Box<[u8; SERIALIZED_BLOCK_HEADER_LEN]>>,
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
/// The equivalence oracle this was checked against has since been deleted;
/// direct expected-value tests in `handlers::chain::tests` pin every figure
/// against hand-computed values instead.
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

/// Finds the record at `height`, or `None` when the log holds no such height.
///
/// The log is append-only in height order — `Context::add_block` pushes, and the
/// only removal is the tail `pop` a disconnect performs on the applied tip — so
/// it is non-decreasing by height and binary-searchable. Where several records
/// share a height, this returns the first.
///
/// The direct index is tried first because the log is usually dense from height
/// zero, which makes the common case one bounds check instead of a search. The
/// guard on the preceding record is what keeps that fast path honest when it is
/// not dense.
#[must_use]
pub fn record_at_height(records: &[BlockRecord], height: u32) -> Option<&BlockRecord> {
    if let Ok(index) = usize::try_from(height)
        && let Some(record) = records.get(index)
        && record.height == height
        && index
            .checked_sub(1)
            .and_then(|previous| records.get(previous))
            .is_none_or(|previous| previous.height < height)
    {
        return Some(record);
    }

    let mut index = records
        .binary_search_by_key(&height, |record| record.height)
        .ok()?;
    while index > 0 && records[index.saturating_sub(1)].height == height {
        index = index.saturating_sub(1);
    }
    records.get(index)
}

/// Finds the record with both `height` and `hash`, or `None`.
///
/// Several records can share a height — a reorg leaves the losing block in the
/// log beside the winner — so the binary search lands anywhere in that run and
/// this walks it in both directions before comparing hashes. Returning the first
/// record at the height without checking the hash would hand back the wrong
/// block on exactly the chain shape this exists to handle.
#[must_use]
pub fn record_at_height_hash(
    records: &[BlockRecord],
    height: u32,
    hash: Hash256,
) -> Option<&BlockRecord> {
    let mut index = records
        .binary_search_by_key(&height, |record| record.height)
        .ok()?;
    while index > 0 && records[index.saturating_sub(1)].height == height {
        index = index.saturating_sub(1);
    }
    while index < records.len() && records[index].height == height {
        if Hash256::from(records[index].hash) == hash {
            return Some(&records[index]);
        }
        index += 1;
    }
    None
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
    fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>>;

    /// Returns indexed body facts. Implementations that cannot answer without
    /// I/O may leave this absent; header-only callers then remain header-only.
    fn block_body_metadata(&self, _height: u32, _hash: BlockHash) -> Option<BlockBodyMetadata> {
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
        _hash: BlockHash,
        _offset: u32,
        _len: u32,
    ) -> Option<Vec<u8>> {
        None
    }
}

/// Read-only source of rollback-evidence warnings for `getblockchaininfo`.
///
/// Implemented by the node crate's `WarningStore`. Each call loads one
/// immutable snapshot; the handler copies rendered strings into the
/// existing `warnings` field without reading disk or reparsing markers.
pub trait RollbackWarningSource: Send + Sync {
    /// Returns rendered warnings in deterministic order.
    fn rollback_warnings(&self) -> Vec<String>;
}

impl BlockRecord {
    /// Builds a record from a decoded Bitcoin block.
    ///
    /// The record is metadata only: `body_size` is the native consensus-encoded length.
    #[must_use]
    pub fn from_block(height: u32, block: &Block) -> Self {
        let hash = block.block_hash();
        Self {
            hash,
            height,
            body_size: consensus_bytes(block).len(),
            // Not stored: the block tree holds this block's header, and
            // `Context::header_record` supplies it on the way out.
            header: None,
            tx_count: block.txs.len(),
            time: block.header.time,
        }
    }

    /// Builds a synthetic record used by tests and empty-state scaffolds.
    #[must_use]
    pub fn synthetic(height: u32, hash: BlockHash) -> Self {
        Self {
            hash,
            height,
            body_size: 0,
            header: None,
            tx_count: 0,
            time: 0,
        }
    }

    /// The serialized block header, when the record carries one.
    ///
    /// A record read straight out of the log never does. One resolved through
    /// [`Context::record_for_hash`] does, because that fills it from the block
    /// tree.
    #[must_use]
    pub fn header_bytes(&self) -> Option<&[u8; SERIALIZED_BLOCK_HEADER_LEN]> {
        self.header.as_deref()
    }

    /// The serialized block header as lowercase hex, empty when absent.
    ///
    /// Encoded on demand. The record is stored for every block for the life of
    /// the process; this is read by one RPC call, and the other two readers want
    /// the bytes back anyway.
    #[must_use]
    pub fn header_hex(&self) -> String {
        self.header
            .as_ref()
            .map_or_else(String::new, |bytes| hex_encode(bytes.as_slice()))
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

/// One capability advertised by a `getblocktemplate` caller.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MiningCapability(CompactString);

impl MiningCapability {
    /// Preserves a BIP22/BIP23 capability name without coupling it to JSON.
    #[must_use]
    pub fn new(name: impl Into<CompactString>) -> Self {
        Self(name.into())
    }

    /// Returns the capability name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// One versionbits rule named by a template request or response.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MiningRule(CompactString);

impl MiningRule {
    /// Preserves a deployment rule name without coupling it to its wire encoding.
    #[must_use]
    pub fn new(name: impl Into<CompactString>) -> Self {
        Self(name.into())
    }

    /// Returns the deployment rule name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Operation selected by a BIP22/BIP23 block-template request.
#[derive(Clone, Debug)]
pub enum BlockTemplateMode {
    /// Assemble or wait for a mining candidate.
    Template,
    /// Dry-run validation of a caller-provided block.
    Proposal(Block),
}

/// Transport-neutral input to [`MiningControl::get_block_template`].
#[derive(Clone, Debug)]
pub struct BlockTemplateRequest {
    /// Template assembly or proposal validation.
    pub mode: BlockTemplateMode,
    /// Advisory BIP22/BIP23 capabilities advertised by the caller.
    pub capabilities: Vec<MiningCapability>,
    /// Versionbits rules the caller can enforce.
    pub rules: Vec<MiningRule>,
    /// Opaque BIP22/BIP23 generation to wait beyond in template mode.
    pub long_poll_id: Option<CompactString>,
}

/// One versionbits deployment available for caller negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableMiningRule {
    /// Deployment rule name.
    pub rule: MiningRule,
    /// Header-version bit assigned to the deployment.
    pub bit: u8,
}

/// Candidate fields a template consumer may change before solving.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemplateMutation {
    /// Header time may advance within the consensus bounds.
    Time,
    /// Transactions may be added, removed, or reordered consistently.
    Transactions,
    /// The previous-block field may be replaced after a tip change.
    PreviousBlock,
}

/// Semantic template assembled by the node-owned mining coordinator.
#[derive(Clone, Debug)]
pub struct BlockTemplate {
    /// Immutable candidate generation and transaction facts.
    pub candidate: Arc<bitcoin_rs_mining::Candidate>,
    /// Active rules a solver must enforce.
    pub rules: Vec<MiningRule>,
    /// Optional deployments available for versionbits negotiation.
    pub version_bits_available: Vec<AvailableMiningRule>,
    /// Header-version bits the solver must preserve.
    pub version_bits_required: u32,
    /// Capabilities implemented by this template producer.
    pub capabilities: Vec<MiningCapability>,
    /// Candidate fields the solver may mutate.
    pub mutable: Vec<TemplateMutation>,
    /// Whether work derived from the request's prior generation remains valid.
    pub submit_old: Option<bool>,
    /// Opaque server work identity when the producer requires one on submission.
    pub work_id: Option<CompactString>,
}

/// BIP22 validation vocabulary shared by proposal and solved-block submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockValidationResult {
    /// The block is valid and, for submission, was synchronously applied.
    Accepted,
    /// The block was already accepted.
    Duplicate,
    /// The block duplicates one already known to be invalid.
    DuplicateInvalid,
    /// The block duplicates one whose validity is not yet conclusive.
    DuplicateInconclusive,
    /// Validation could not reach a conclusive result.
    Inconclusive,
    /// Consensus or contextual validation rejected the block.
    Rejected(CompactString),
}

/// Semantic result of template assembly or proposal validation.
#[derive(Clone, Debug)]
pub enum BlockTemplateResult {
    /// A candidate ready for projection into a BIP22 template.
    Template(BlockTemplate),
    /// Dry-run proposal validation, with no chain or mempool mutation.
    Proposal(BlockValidationResult),
}

/// Facts from the most recently assembled candidate, when one exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LastCandidateInfo {
    /// Total candidate weight.
    pub weight: u64,
    /// Number of transactions including the coinbase.
    pub transactions: u64,
}

/// Signet-specific mining configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignetMiningInfo {
    /// Consensus signet challenge script.
    pub challenge: Vec<u8>,
}

/// Authoritative semantic state returned by [`MiningControl::mining_info`].
#[derive(Clone, Debug, PartialEq)]
pub struct MiningInfo {
    /// Current applied-chain height.
    pub blocks: u32,
    /// Most recently assembled candidate facts.
    pub last_candidate: Option<LastCandidateInfo>,
    /// Compact target bits of the applied tip.
    pub bits: u32,
    /// Difficulty represented by `bits`.
    pub difficulty: f64,
    /// Estimated network hashes per second.
    pub network_hashes_per_second: f64,
    /// Transactions currently available in the mempool.
    pub pooled_transactions: u64,
    /// Active consensus network.
    pub network: Network,
    /// Compact target bits for the next candidate.
    pub next_bits: u32,
    /// Difficulty represented by `next_bits`.
    pub next_difficulty: f64,
    /// Configured minimum mining feerate in satoshis per kvB.
    pub minimum_fee_rate: u64,
    /// Signet mining data, absent on other networks.
    pub signet: Option<SignetMiningInfo>,
    /// Active node warnings.
    pub warnings: Vec<CompactString>,
}

/// Failure to execute a node-owned mining operation.
#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum MiningControlError {
    /// The semantic request is internally inconsistent or unsupported.
    #[error("{0}")]
    InvalidRequest(CompactString),
    /// Authoritative mining state is not currently available.
    #[error("{0}")]
    Unavailable(CompactString),
    /// Candidate construction, validation, or application failed operationally.
    #[error("{0}")]
    Failed(CompactString),
}

/// Node-owned control plane for candidate lifecycle and solved-block submission.
pub trait MiningControl: Send + Sync {
    /// Assembles or long-polls a template, or dry-validates a proposal.
    fn get_block_template(
        &self,
        request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError>;

    /// Captures one coherent mining-state report.
    fn mining_info(&self) -> Result<MiningInfo, MiningControlError>;

    /// Synchronously validates and applies a solved block.
    fn submit_block(&self, block: Block) -> Result<BlockValidationResult, MiningControlError>;

    /// Publishes a completed authoritative mutation to template waiters.
    fn publish_generation(&self);
}

/// Returns the f64 difficulty for `bits` using Bitcoin Core's calculation.
#[must_use]
pub fn difficulty_for_bits(consensus_bits: u32) -> f64 {
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

/// Actual progress reported by the node-owned transaction index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxIndexInfo {
    /// Whether the index has completely caught up to the authoritative chain tip.
    pub synced: bool,
    /// Height of the best block completely covered by the index.
    pub best_block_height: u32,
}

/// Lifecycle state reported for a node-owned RPC capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CapabilityState {
    /// The capability is current with the applied chain tip.
    Ready,
    /// The capability is catching up to the applied chain tip.
    CatchingUp {
        /// Height covered by the capability.
        processed_height: u32,
        /// Applied-chain height the capability is approaching.
        target_height: u32,
    },
    /// The capability failed and cannot currently provide complete answers.
    Failed {
        /// Failure description.
        reason: String,
    },
    /// The capability is not enabled for this node.
    Disabled,
    /// The capability is opening and cannot answer yet.
    Opening,
    /// The capability worker was abandoned during shutdown.
    ShutdownAbandoned,
}

/// Status of one concrete node capability exposed through RPC.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityStatus {
    /// Stable capability identifier.
    pub id: String,
    /// Whether the capability is compiled into this binary.
    pub compiled: bool,
    /// Whether the capability is enabled for this node.
    pub enabled: bool,
    /// Current lifecycle state.
    pub state: CapabilityState,
}

/// Point-in-time status report for concrete node capabilities.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    /// Status rows in the node's stable capability order.
    pub capabilities: Vec<CapabilityStatus>,
}

/// Read-only provider implemented by the node for the RPC capability report.
pub trait CapabilityProvider: Send + Sync {
    /// Captures the current capability status.
    fn snapshot(&self) -> CapabilitySnapshot;
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
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError>;
    /// Resolves a confirmed prevout value, returning `None` only after complete absence is proven.
    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError>;
    /// Resolves the height of the block confirming `txid`, without materializing the transaction.
    ///
    /// Callers that only need to locate the block — `gettxoutproof` is the one —
    /// would otherwise deserialize a transaction and throw it away. The default
    /// answers `None`, which every caller must already handle as "the index
    /// cannot say", so an implementor that does not track heights keeps working.
    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        let _ = txid;
        Ok(None)
    }
    /// Returns the transaction index's actual durable progress.
    fn index_info(&self) -> Result<TxIndexInfo, TxQueryError>;
}

/// One current unspent output indexed for a script.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptIndexRecord {
    /// Transaction creating the output.
    pub txid: Txid,
    /// Confirmed block height.
    pub height: u32,
    /// Output value in satoshis.
    pub value: u64,
    /// Output index.
    pub vout: u32,
}

/// One confirmed transaction in script history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptHistoryRecord {
    /// Transaction identifier.
    pub txid: Txid,
    /// Confirming block height.
    pub height: u32,
}

/// One confirmed transaction spending an indexed outpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendingRecord {
    /// Spending transaction identifier.
    pub txid: Txid,
    /// Confirming block height.
    pub height: u32,
    /// Input index that spends the outpoint.
    pub vin: u32,
}

/// A point-in-time script-history answer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScriptIndexSnapshot {
    /// All confirmed funding and spending transactions for the script.
    pub history: Vec<ScriptHistoryRecord>,
    /// Every confirmed output paying the script, spent ones included.
    ///
    /// Carried out of the same budgeted storage snapshot that produced
    /// `history`. Address statistics are sums over these rows; a caller without
    /// them has to re-read one transaction per history entry, and each of those
    /// reads is a fresh index query with its own budget, so the total escapes
    /// the bound this snapshot is taken under.
    pub funding: Vec<ScriptIndexRecord>,
}

/// Lockless query adapter for the node-owned generic script index.
///
/// A result is returned only when the script-index watermark proves coverage
/// of the exact applied tip.  `Retry` and `Unavailable` therefore never mean
/// an empty address.
pub trait ScriptIndexQuery: Send + Sync {
    /// Returns current UTXOs for a script.
    fn unspent_outputs(
        &self,
        script_hash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError>;
    /// Returns confirmed history from one storage snapshot.
    fn history_snapshot(
        &self,
        script_hash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError>;
    /// Returns the confirmed transaction spending `outpoint`, if any.
    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError>;
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

/// Handles owned by the node and observed by the RPC context, grouped by
/// node capability: chain, mempool, indexes, network, and mining.
///
/// A struct-of-structs grouping, not a trait layer. `Context::from_handles`
/// consumes one `ContextHandles` value and the handler surface reads only
/// these capability groups — RPC consumes node capabilities and never names a
/// storage backend or backend engine type.
#[derive(Clone)]
pub struct ContextHandles {
    /// Chain capability: tips, block log, UTXO set, and block tree.
    pub chain: ChainHandles,
    /// Mempool capability: the in-memory transaction pool.
    pub mempool: MempoolHandles,
    /// Index capability: transaction and script index query adapters.
    pub indexes: IndexHandles,
    /// Network capability: peer registry, reachability, and connection control.
    pub network: NetworkHandles,
    /// Mining capability: the template coordinator, when one is attached.
    pub mining: MiningHandles,
    /// Live capability report for concrete node-owned services.
    pub capabilities: Option<Arc<dyn CapabilityProvider>>,
}

/// Chain capability handles.
#[derive(Clone)]
pub struct ChainHandles {
    /// Best header-chain tip.
    pub chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Best fully-applied block tip.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Applied block metadata log.
    pub blocks: Arc<RwLock<BlockLog>>,
    /// Transactions retained for direct RPC lookup.
    pub transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    /// Authoritative UTXO set.
    pub utxo: Arc<bitcoin_rs_utxo::UtxoSet>,
    /// Incremental UTXO statistics.
    pub coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    /// Shared block tree.
    pub block_tree: Arc<parking_lot::RwLock<bitcoin_rs_chain::BlockTree>>,
    /// Consensus network.
    pub chain_network: Network,
}

/// Mempool capability handles.
#[derive(Clone)]
pub struct MempoolHandles {
    /// The process-wide mutation gateway in front of the in-memory pool.
    pub mempool: Arc<MempoolGateway>,
}

/// Index capability handles.
#[derive(Clone)]
pub struct IndexHandles {
    /// Complete transaction-index query adapter.
    pub tx_index: Option<Arc<dyn TxIndexQuery>>,
    /// Generic script-index query adapter.
    pub script_index: Option<Arc<dyn ScriptIndexQuery>>,
}

/// Network capability handles.
#[derive(Clone)]
pub struct NetworkHandles {
    /// Network state.
    pub network: Arc<RwLock<NetworkState>>,
    /// Whether the node accepts or starts P2P connections.
    pub network_active: Arc<core::sync::atomic::AtomicBool>,
    /// Authoritative live peer sessions.
    pub peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    /// Channel that requests outbound P2P connections.
    pub p2p_outbound_sender: Option<crossbeam_channel::Sender<std::net::SocketAddr>>,
    /// Manual IP/CIDR bans.
    pub banned: Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
    /// Persisted `addnode add` entries.
    pub added_nodes: Arc<parking_lot::RwLock<Vec<std::net::SocketAddr>>>,
}

/// Mining capability handles.
#[derive(Clone)]
pub struct MiningHandles {
    /// Node-owned mining coordinator. `None` when mining is not wired.
    pub mining_control: Option<Arc<dyn MiningControl>>,
}

/// Shared state consumed by JSON-RPC handlers.
pub struct Context {
    /// Best-chain tip snapshot published by chain validation.
    pub chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Best-applied-block tip snapshot published after block application.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Serializes whole-chainstate RPC reads with node-owned connect/disconnect transitions.
    chain_transition: Arc<Mutex<()>>,
    /// Cumulative transaction count of the applied chain, `0` when unknown.
    ///
    /// Maintained by block application and restored from the chainstate
    /// checkpoint, so it survives a restart. Read through
    /// [`Self::chain_tx_count`], which turns Bitcoin Core's zero-means-unset
    /// encoding into an `Option`.
    chain_tx_count: Arc<core::sync::atomic::AtomicU64>,
    /// Whether this node has ever observed itself to be out of initial block
    /// download. Once set it is never cleared.
    ///
    /// Bitcoin Core latches the same way (`m_cached_is_ibd`, cleared once by
    /// `UpdateIBDStatus` and never set again) and logs "Leaving
    /// `InitialBlockDownload (latching to false)`" when it happens. Without the
    /// latch the answer oscillates: a synced node that has not seen a block for
    /// longer than the tip-age window would announce that it is back in initial
    /// sync, and callers treat that as "do not trust this node's data yet".
    left_initial_block_download: Arc<core::sync::atomic::AtomicBool>,
    /// Mempool mutation gateway: the only production route that takes the
    /// pool write lock, publishing ordered mutation events to observers.
    pub mempool: Arc<MempoolGateway>,
    /// Block records already available without blocking storage readers.
    pub blocks: Arc<RwLock<BlockLog>>,
    /// Raw transactions indexed by txid for Core transaction RPCs.
    pub transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    /// UTXO set snapshot handle used by chain metadata RPCs.
    pub utxo: Arc<bitcoin_rs_utxo::UtxoSet>,
    /// Incremental UTXO-set statistics.
    pub coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    /// Optional storage pruning mutator.
    pub prune_service: Option<Arc<dyn PruneService>>,
    /// Optional node-owned chain mutation service.
    pub chain_control: Option<Arc<dyn ChainControl>>,
    /// Optional node-owned mining coordinator.
    pub mining_control: Option<Arc<dyn MiningControl>>,
    /// Optional node-owned complete transaction-index query adapter.
    /// `None` when transaction indexing is disabled.
    pub tx_index: Option<Arc<dyn TxIndexQuery>>,
    /// Complete transaction lookup used internally by Esplora projections.
    ///
    /// This may be available with `--scriptindex` even when `tx_index` is
    /// absent, because it does not advertise the Core `--txindex` contract.
    pub esplora_tx_index: Option<Arc<dyn TxIndexQuery>>,
    /// Optional node-owned generic script-index query adapter.
    pub script_index: Option<Arc<dyn ScriptIndexQuery>>,
    /// Live capability report for concrete node-owned services.
    pub capabilities: Option<Arc<dyn CapabilityProvider>>,
    /// Network counters and peers.
    pub network: Arc<RwLock<NetworkState>>,
    /// Network selector used by handlers needing consensus parameters (e.g.
    /// difficulty calculation).
    pub chain_network: Network,
    /// Authoritative live peer sessions.
    pub peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    /// Whether outbound and inbound network activity is enabled through RPC.
    pub network_active: Arc<core::sync::atomic::AtomicBool>,
    /// Shared in-memory block tree.
    pub block_tree: Arc<parking_lot::RwLock<bitcoin_rs_chain::BlockTree>>,
    /// Optional durable block body reader for metadata-only block records.
    pub block_body_source: Option<Arc<dyn BlockBodySource>>,
    /// Optional outbound channel for `addnode` to request new P2P connections.
    /// `None` for embedded/test callers without a live P2P listener.
    pub p2p_outbound_sender: Option<crossbeam_channel::Sender<std::net::SocketAddr>>,
    /// Manual IP/CIDR bans shared with P2P enforcement.
    pub banned: Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
    /// Persisted `addnode add` entries.
    pub added_nodes: Arc<parking_lot::RwLock<Vec<std::net::SocketAddr>>>,
    /// Active ZMQ PUB notifications.
    pub zmq_notifications: Arc<[ZmqNotification]>,
    /// Configured node debug-log path for `getrpcinfo`.
    pub debug_log_path: Option<PathBuf>,
    /// Limits concurrent full-block REST response materializations.
    rest_render_budget: Arc<RestRenderBudget>,
    /// Rollback-evidence warning source for `getblockchaininfo`.
    ///
    /// `None` in test contexts; populated by `NodeState` with the process-wide
    /// `WarningStore`. Each request loads one immutable snapshot.
    pub rollback_warnings: Option<Arc<dyn RollbackWarningSource>>,
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
        let coin_stats_listener = bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        );
        let mut utxo = bitcoin_rs_utxo::UtxoSet::new();
        utxo.set_listener(Box::new(coin_stats_listener.clone()));
        let coin_stats = Arc::new(coin_stats_listener);
        let mempool = MempoolGateway::shared(Arc::new(RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))));
        Self {
            chain_tip: Arc::new(ArcSwapOption::empty()),
            applied_tip: Arc::new(ArcSwapOption::empty()),
            chain_transition: Arc::new(Mutex::new(())),
            chain_tx_count: Arc::new(core::sync::atomic::AtomicU64::new(0)),
            left_initial_block_download: Arc::new(core::sync::atomic::AtomicBool::new(false)),
            mempool,
            blocks: Arc::new(RwLock::new(BlockLog::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            utxo: Arc::new(utxo),
            coin_stats,
            tx_index: None,
            esplora_tx_index: None,
            script_index: None,
            capabilities: None,
            prune_service: None,
            chain_control: None,
            peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
            network_active: Arc::new(core::sync::atomic::AtomicBool::new(true)),
            mining_control: None,
            network: Arc::new(RwLock::new(NetworkState::default())),
            chain_network: Network::Mainnet,
            block_tree: Arc::new(parking_lot::RwLock::new(bitcoin_rs_chain::BlockTree::new())),
            block_body_source: None,
            p2p_outbound_sender: None,
            banned: Arc::new(RwLock::new(Vec::new())),
            added_nodes: Arc::new(RwLock::new(Vec::new())),
            zmq_notifications: Arc::from(Vec::<ZmqNotification>::new()),
            debug_log_path: None,
            rest_render_budget: Arc::new(RestRenderBudget::new()),
            rollback_warnings: None,
        }
    }

    /// Builds an empty context whose mempool gateway carries `observer`.
    ///
    /// Like [`Self::new`] but the gateway is constructed with the supplied
    /// observer instead of `None`. Test-only: production wiring constructs
    /// the gateway through `NodeState::open`.
    #[must_use]
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn new_with_mempool_observer(observer: Arc<dyn MempoolObserver>) -> Self {
        let coin_stats_listener = bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        );
        let mut utxo = bitcoin_rs_utxo::UtxoSet::new();
        utxo.set_listener(Box::new(coin_stats_listener.clone()));
        let coin_stats = Arc::new(coin_stats_listener);
        let mempool = MempoolGateway::shared_with(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            observer,
        );
        Self {
            chain_tip: Arc::new(ArcSwapOption::empty()),
            applied_tip: Arc::new(ArcSwapOption::empty()),
            chain_transition: Arc::new(Mutex::new(())),
            chain_tx_count: Arc::new(core::sync::atomic::AtomicU64::new(0)),
            left_initial_block_download: Arc::new(core::sync::atomic::AtomicBool::new(false)),
            mempool,
            blocks: Arc::new(RwLock::new(BlockLog::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            utxo: Arc::new(utxo),
            coin_stats,
            tx_index: None,
            esplora_tx_index: None,
            script_index: None,
            capabilities: None,
            prune_service: None,
            chain_control: None,
            peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
            network_active: Arc::new(core::sync::atomic::AtomicBool::new(true)),
            mining_control: None,
            network: Arc::new(RwLock::new(NetworkState::default())),
            chain_network: Network::Mainnet,
            block_tree: Arc::new(parking_lot::RwLock::new(bitcoin_rs_chain::BlockTree::new())),
            block_body_source: None,
            p2p_outbound_sender: None,
            banned: Arc::new(RwLock::new(Vec::new())),
            added_nodes: Arc::new(RwLock::new(Vec::new())),
            zmq_notifications: Arc::from(Vec::<ZmqNotification>::new()),
            debug_log_path: None,
            rest_render_budget: Arc::new(RestRenderBudget::new()),
            rollback_warnings: None,
        }
    }
    /// Builds a context that shares pre-existing handles owned elsewhere.
    #[must_use]
    pub fn from_handles(handles: ContextHandles) -> Self {
        let ContextHandles {
            chain:
                ChainHandles {
                    chain_tip,
                    applied_tip,
                    blocks,
                    transactions,
                    utxo,
                    coin_stats,
                    block_tree,
                    chain_network,
                },
            mempool: MempoolHandles { mempool },
            indexes:
                IndexHandles {
                    tx_index,
                    script_index,
                },
            network:
                NetworkHandles {
                    network,
                    network_active,
                    peer_table,
                    p2p_outbound_sender,
                    banned,
                    added_nodes,
                },
            mining: MiningHandles { mining_control },
            capabilities,
        } = handles;
        Self {
            chain_tip,
            applied_tip,
            chain_transition: Arc::new(Mutex::new(())),
            chain_tx_count: Arc::new(core::sync::atomic::AtomicU64::new(0)),
            left_initial_block_download: Arc::new(core::sync::atomic::AtomicBool::new(false)),
            mempool,
            blocks,
            transactions,
            utxo,
            coin_stats,
            tx_index,
            esplora_tx_index: None,
            script_index,
            capabilities,
            network,
            chain_network,
            peer_table,
            network_active,
            block_tree,
            block_body_source: None,
            p2p_outbound_sender,
            banned,
            added_nodes,
            prune_service: None,
            chain_control: None,
            mining_control,
            zmq_notifications: Arc::from(Vec::<ZmqNotification>::new()),
            debug_log_path: None,
            rest_render_budget: Arc::new(RestRenderBudget::new()),
            rollback_warnings: None,
        }
    }

    /// Attaches the internal transaction lookup required for Esplora output
    /// projections without exposing it to Core transaction-index RPCs.
    #[must_use]
    pub fn with_esplora_tx_index(mut self, tx_index: Option<Arc<dyn TxIndexQuery>>) -> Self {
        self.esplora_tx_index = tx_index;
        self
    }

    /// Returns `self` with a durable block body source.
    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
    }

    /// Attaches the rollback-evidence warning source for `getblockchaininfo`.
    #[must_use]
    pub fn with_rollback_warnings(mut self, source: Arc<dyn RollbackWarningSource>) -> Self {
        self.rollback_warnings = Some(source);
        self
    }

    /// Attaches the node-owned pruning mutator used by `pruneblockchain`.
    #[must_use]
    pub fn with_prune_service(mut self, prune_service: Arc<dyn PruneService>) -> Self {
        self.prune_service = Some(prune_service);
        self
    }

    /// Attaches the node-owned mining coordinator to a context built without
    /// handles (`Context::new`). Production wiring passes the coordinator
    /// through `ContextHandles::mining` instead.
    #[must_use]
    pub fn with_mining_control(mut self, mining_control: Arc<dyn MiningControl>) -> Self {
        self.mining_control = Some(mining_control);
        self
    }

    /// Attaches the node-owned chain mutation service.
    #[must_use]
    pub fn with_chain_control(mut self, chain_control: Arc<dyn ChainControl>) -> Self {
        self.chain_control = Some(chain_control);
        self
    }

    /// Shares the node's authoritative connect/disconnect lock with RPC readers.
    #[must_use]
    pub fn with_chain_transition(mut self, chain_transition: Arc<Mutex<()>>) -> Self {
        self.chain_transition = chain_transition;
        self
    }

    /// Runs a read while authoritative UTXO and applied-tip transitions are excluded.
    pub fn with_stable_chainstate<R>(&self, read: impl FnOnce() -> R) -> R {
        let _transition = self.chain_transition.lock();
        read()
    }

    /// Attaches active ZMQ notification metadata reported by `getzmqnotifications`.
    #[must_use]
    pub fn with_zmq_notifications(mut self, notifications: Vec<ZmqNotification>) -> Self {
        self.zmq_notifications = Arc::from(notifications);
        self
    }

    /// Attaches the configured node debug-log path.
    #[must_use]
    pub fn with_debug_log_path(mut self, path: PathBuf) -> Self {
        self.debug_log_path = Some(path);
        self
    }

    /// Acquires a bounded full-block REST render slot, if one is available.
    pub(crate) fn try_acquire_rest_render(&self) -> Option<RestRenderPermit> {
        self.rest_render_budget.try_acquire()
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
    pub fn difficulty_for_bits(&self, bits: u32) -> f64 {
        let mantissa = bits & 0x00ff_ffff;
        if mantissa == 0 {
            return 0.0;
        }
        let mut shift = (bits >> 24) & 0xff;
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

    /// Publishes a new best-chain tip.
    pub fn set_chain_tip(&self, tip: TipSnapshot) {
        self.chain_tip.store(Some(Arc::new(tip)));
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
    pub fn add_transaction(&self, tx: Tx) -> Txid {
        let txid = tx.txid();
        self.transactions.write().insert(txid, tx);
        txid
    }

    /// Admits one transaction through the full policy stack, then mutates
    /// the mempool only through the node's one [`MempoolGateway`].
    ///
    /// This is the shared typed admission operation: `sendrawtransaction`
    /// and the embedded `Node::broadcast` both run it. The gateway's
    /// [`MempoolGateway::admit_transaction`] holds the pool write lock
    /// across the entire mempool-dependent policy evaluation — the
    /// already-known check, prevout-resolved fee/vsize/sigop context,
    /// standardness policy, the live min-relay / mempool-min floor, the
    /// caller's max-feerate cap, BIP125 replacement analysis, and package
    /// limits — and commits the authorized
    /// [`MempoolGateway::replace_transaction`] inside that same lock
    /// interval, so no concurrent admission can invalidate the verdict
    /// before it lands.
    ///
    /// The pool and transaction-cache fast paths here remain best-effort
    /// pre-checks for the "already known" no-op; the authoritative
    /// already-known re-check runs inside the locked evaluation.
    ///
    /// `max_feerate_sat_per_kvb` of `None` disables the max-fee cap,
    /// matching `sendrawtransaction`'s `maxfeerate=0` behavior.
    ///
    /// # Errors
    ///
    /// Returns the policy rejection verbatim (Core rejection strings) or
    /// the failure verbatim; nothing is inserted when this fails.
    pub fn admit_transaction(
        &self,
        tx: Tx,
        max_feerate_sat_per_kvb: Option<u64>,
    ) -> Result<MutationResult, String> {
        crate::handlers::tx::admit_transaction(self, tx, max_feerate_sat_per_kvb)
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

    /// Returns `self` sharing `handle` as the cumulative chain transaction count.
    ///
    /// The node owns the counter; the RPC surface only reads it.
    #[must_use]
    pub fn with_chain_tx_count(mut self, handle: Arc<core::sync::atomic::AtomicU64>) -> Self {
        self.chain_tx_count = handle;
        self
    }

    /// Returns the cumulative transaction count of the applied chain, or `None`
    /// when this node cannot know it.
    ///
    /// This is Bitcoin Core's `CBlockIndex::m_chain_tx_count`, and `None` is its
    /// `HaveNumChainTxs() == false`: a chain whose history was applied before
    /// the node tracked the count cannot recover it without re-reading every
    /// block body. Callers must treat `None` as *unknown*, never as zero — the
    /// two differ by an entire chain.
    #[must_use]
    pub fn chain_tx_count(&self) -> Option<u64> {
        match self
            .chain_tx_count
            .load(core::sync::atomic::Ordering::Relaxed)
        {
            0 => None,
            count => Some(count),
        }
    }

    /// Answers Bitcoin Core's `IsInitialBlockDownload()` for the applied tip.
    ///
    /// A node has left initial block download once its applied tip has at least
    /// the network's `nMinimumChainWork` **and** carries a timestamp no older
    /// than `max_tip_age` (Core's 24-hour default). Both are required: work
    /// alone would trust a stale chain, and recency alone would trust a cheap
    /// one that simply claims a recent timestamp.
    ///
    /// The answer latches. Once this returns `false` it returns `false` for the
    /// life of the process, exactly as Core's `m_cached_is_ibd` does, so a
    /// synced node that goes an hour without a block does not announce that it
    /// is resyncing.
    ///
    /// `now` is UNIX seconds, taken by the caller so the decision itself stays a
    /// pure function of observable state.
    #[must_use]
    pub fn is_initial_block_download(&self, now: u64) -> bool {
        use core::sync::atomic::Ordering;

        if self.left_initial_block_download.load(Ordering::Relaxed) {
            return false;
        }
        let Some(tip) = self.applied_tip.load_full() else {
            return true;
        };
        // Big-endian, fixed width: byte order is numeric order.
        let work: [u8; 32] = tip.chainwork.to_be_bytes();
        if work < self.chain_network.minimum_chain_work() {
            return true;
        }
        // `TipSnapshot` carries no timestamp, so the tip's header supplies it —
        // the same route `getdifficulty` takes to the tip's `bits`.
        let Some(tip_time) = self
            .block_tree
            .read()
            .node(tip.tip_id)
            .ok()
            .map(|node| node.header.time)
        else {
            return true;
        };
        if u64::from(tip_time) < now.saturating_sub(MAX_TIP_AGE_SECONDS) {
            return true;
        }
        self.left_initial_block_download
            .store(true, Ordering::Relaxed);
        false
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
            hash: BlockHash::from(hash),
            height: node.height,
            body_size: 0,
            // The one place a header is produced. Every constructor leaves the
            // field empty, so the tree node reached here is the single source of
            // truth for what a block's header is.
            header: consensus_bytes(&node.header).try_into().ok().map(Box::new),
            tx_count: 0,
            time: node.header.time,
        })
    }

    /// Resolves a block record for `hash`.
    ///
    /// The restored header tree is the only identity authority. A hash it does
    /// not know resolves to `None`, even when the block log carries a record for
    /// it. For a tree-resolved `(height, hash)` pair, the log may contribute
    /// matching durable body metadata.
    #[must_use]
    pub fn record_for_hash(&self, hash: Hash256) -> Option<BlockRecord> {
        // Tree authority resolves identity first; the exact `(height, hash)`
        // record may then enrich its payload fields.
        if let Some(mut record) = self.header_record(hash) {
            // The tree already gave us the height, so this is a binary search
            // over a height-ordered log rather than a walk of every record on
            // the chain. `getblock` and `getblockheader` both land here.
            if let Some(cached) = record_at_height_hash(&self.blocks.read(), record.height, hash) {
                // The cached record supplies the payload facts — size and
                // transaction count — and the tree supplies the header, because
                // the log does not store one. Returning the cached record as it
                // stands would answer with no header at all.
                //
                // Costs no extra lock: `header_record` has already taken and
                // released the tree guard, and the header it produced outlives
                // it.
                let mut cached = cached.clone();
                cached.header = record.header.take();
                return Some(cached);
            }
            if let Some(metadata) = self
                .block_body_source
                .as_ref()
                .and_then(|source| source.block_body_metadata(record.height, BlockHash::from(hash)))
            {
                record.body_size = metadata.body_size;
                record.tx_count = metadata.tx_count;
            }
            return Some(record);
        }
        None
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
            return Some(self.chain_network.genesis_block_hash());
        }
        record_at_height(&self.blocks.read(), height).map(|candidate| Hash256::from(candidate.hash))
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
        record_at_height(&self.blocks.read(), height).cloned()
    }

    /// Returns serialized block bytes from durable body storage.
    #[must_use]
    pub fn block_body_bytes(&self, record: &BlockRecord) -> Option<Vec<u8>> {
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

    /// Returns lowercase serialized block hex from durable body storage.
    #[must_use]
    pub fn block_body_hex(&self, record: &BlockRecord) -> Option<String> {
        Some(hex_encode(&self.block_body_bytes(record)?))
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
        Some(hex_encode(&bytes))
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// A log whose heights are non-decreasing but not a clean `0..n`.
    ///
    /// Height 3 is recorded three times, as two reorgs leave it; the log starts
    /// at height 1, as a restored or pruned log may; and heights 6 and 7 are
    /// missing. All three break the "record for height `h` is at index `h`"
    /// assumption the direct-index fast path tries first.
    ///
    /// The starting height is load-bearing. With the log starting at zero, index
    /// 3 holds the *first* record at height 3, so a fast path that skipped the
    /// "is the predecessor lower?" guard would answer correctly anyway. Starting
    /// at one puts a duplicate at index 3 and the run head at index 2, which is
    /// where the two disagree.
    fn shaped_records() -> Vec<BlockRecord> {
        const HEIGHTS: [u32; 8] = [1, 2, 3, 3, 3, 4, 8, 9];
        HEIGHTS
            .into_iter()
            .enumerate()
            .map(|(index, height)| {
                let mut hash = [0_u8; 32];
                // Distinct per record, not per height: the duplicates have to be
                // distinguishable by hash or the walk has nothing to walk.
                hash[0] = u8::try_from(index).unwrap_or(0);
                let mut record =
                    BlockRecord::synthetic(height, BlockHash::from(Hash256::from_le_bytes(&hash)));
                record.time = 1_000 + u32::try_from(index).unwrap_or(0);
                record
            })
            .collect()
    }

    /// Every record at a duplicated height must be reachable by its own hash.
    ///
    /// A search that stopped at the run's first record would answer `None` for
    /// the others, turning `getblock` on a stale branch into "block not found".
    #[test]
    fn every_record_at_a_duplicated_height_is_reachable() {
        let records = shaped_records();
        let duplicates = records
            .iter()
            .filter(|record| record.height == 3)
            .map(|record| (record.hash, record.time))
            .collect::<Vec<_>>();
        assert_eq!(duplicates.len(), 3, "the fixture must duplicate height 3");

        for (hash, time) in duplicates {
            assert_eq!(
                record_at_height_hash(&records, 3, Hash256::from(hash)).map(|r| r.time),
                Some(time),
                "a record at a duplicated height was not reachable by its hash"
            );
        }
    }

    /// `block_by_height` with no applied tip reads the log directly.
    ///
    /// That fallback used to scan for the first record at the height and now
    /// searches for it. It is the path a Context takes before the first tip is
    /// published, and nothing covered it: a mutation replacing it with "the last
    /// record in the log" stayed green.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn block_by_height_without_an_applied_tip_reads_the_log() {
        let ctx = Context::new();
        for record in shaped_records() {
            ctx.add_block(record);
        }

        for height in 0_u32..12 {
            let expected = shaped_records()
                .into_iter()
                .find(|candidate| candidate.height == height)
                .map(|record| record.hash);
            assert_eq!(
                ctx.block_by_height(height).map(|record| record.hash),
                expected,
                "block_by_height disagrees with the log at height {height}"
            );
        }
    }

    /// A reorg leaves the losing block in the log beside the winner, so a height
    /// can address two records. The binary search lands anywhere in that run,
    /// which is why the lookup walks it and compares hashes; returning the first
    /// record at the height would hand back the wrong block on exactly the shape
    /// this exists for.
    #[test]
    fn record_at_height_hash_picks_the_matching_hash_within_a_duplicate_height() {
        let first = Hash256::from_le_bytes(&[0x11_u8; 32]);
        let second = Hash256::from_le_bytes(&[0x22_u8; 32]);
        let records = vec![
            BlockRecord::synthetic(0, BlockHash::from(Hash256::from_le_bytes(&[0x00_u8; 32]))),
            BlockRecord::synthetic(1, BlockHash::from(first)),
            BlockRecord::synthetic(1, BlockHash::from(second)),
            BlockRecord::synthetic(2, BlockHash::from(Hash256::from_le_bytes(&[0x33_u8; 32]))),
        ];

        assert_eq!(
            record_at_height_hash(&records, 1, second).map(|record| Hash256::from(record.hash)),
            Some(second),
            "the second record at the height must be reachable, not just the first"
        );
        assert_eq!(
            record_at_height_hash(&records, 1, first).map(|record| Hash256::from(record.hash)),
            Some(first)
        );
        assert!(
            record_at_height_hash(&records, 1, Hash256::from_le_bytes(&[0x99_u8; 32])).is_none(),
            "a hash absent from the height run must not resolve to a sibling"
        );
    }

    /// Heights `[1, 1, 2]` are chosen so the dense fast path indexes straight
    /// onto the *second* of the duplicates: `records[1]` has height 1, so the
    /// height check alone would accept it. Only the guard on the preceding
    /// record rejects it and sends the lookup to the search that finds the run
    /// start. A log starting at height 0 never exercises that, which is how an
    /// earlier version of this test passed while the guard was removed.
    #[test]
    fn record_at_height_returns_the_first_record_of_a_duplicate_height() {
        let first = Hash256::from_le_bytes(&[0x11_u8; 32]);
        let records = vec![
            BlockRecord::synthetic(1, BlockHash::from(first)),
            BlockRecord::synthetic(1, BlockHash::from(Hash256::from_le_bytes(&[0x22_u8; 32]))),
            BlockRecord::synthetic(2, BlockHash::from(Hash256::from_le_bytes(&[0x33_u8; 32]))),
        ];

        assert_eq!(
            record_at_height(&records, 1).map(|record| Hash256::from(record.hash)),
            Some(first),
            "the dense index lands on the second duplicate; the first must win"
        );
        assert!(record_at_height(&records, 7).is_none());
    }

    /// The dense fast path indexes straight into the log. It must not fire when
    /// the log does not start at height zero, or it would answer with whatever
    /// record happens to sit at that index.
    #[test]
    fn record_at_height_does_not_trust_the_index_on_a_sparse_log() {
        let wanted = Hash256::from_le_bytes(&[0x44_u8; 32]);
        let records = vec![
            BlockRecord::synthetic(10, BlockHash::from(Hash256::from_le_bytes(&[0x0a_u8; 32]))),
            BlockRecord::synthetic(11, BlockHash::from(wanted)),
            BlockRecord::synthetic(12, BlockHash::from(Hash256::from_le_bytes(&[0x0c_u8; 32]))),
        ];

        assert_eq!(
            record_at_height(&records, 11).map(|record| Hash256::from(record.hash)),
            Some(wanted),
            "a log that does not start at zero must still resolve by search"
        );
        assert!(record_at_height(&records, 1).is_none());
    }
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn from_handles_shares_tip_handles_with_caller() {
        use alloc::sync::Arc;

        let chain_tip = Arc::new(ArcSwapOption::empty());
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let utxo = Arc::new(bitcoin_rs_utxo::UtxoSet::new());
        let coin_stats = Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        ));
        let block_tree = Arc::new(RwLock::new(bitcoin_rs_chain::BlockTree::new()));
        let banned = Arc::new(RwLock::new(Vec::<bitcoin_rs_p2p::BannedSubnet>::new()));
        let added_nodes = Arc::new(RwLock::new(Vec::new()));
        let network_active = Arc::new(core::sync::atomic::AtomicBool::new(true));
        let ctx = Context::from_handles(ContextHandles {
            chain: ChainHandles {
                chain_tip: Arc::clone(&chain_tip),
                applied_tip: Arc::clone(&applied_tip),
                blocks: Arc::new(RwLock::new(BlockLog::new())),
                transactions: Arc::new(RwLock::new(HashMap::new())),
                utxo: Arc::clone(&utxo),
                coin_stats: Arc::clone(&coin_stats),
                block_tree: Arc::clone(&block_tree),
                chain_network: Network::Mainnet,
            },
            mempool: MempoolHandles {
                mempool: MempoolGateway::shared(Arc::new(RwLock::new(Mempool::new(
                    MempoolLimits::default(),
                )))),
            },
            indexes: IndexHandles {
                tx_index: None,
                script_index: None,
            },
            network: NetworkHandles {
                network: Arc::new(RwLock::new(NetworkState::default())),
                network_active: Arc::clone(&network_active),
                peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
                p2p_outbound_sender: None,
                banned: Arc::clone(&banned),
                added_nodes: Arc::clone(&added_nodes),
            },
            mining: MiningHandles {
                mining_control: None,
            },
            capabilities: None,
        });
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
            Arc::ptr_eq(&ctx.block_tree, &block_tree),
            "block_tree must be shared with caller"
        );
        assert!(
            Arc::ptr_eq(&ctx.network_active, &network_active),
            "network activity must be shared with caller"
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
    fn rest_render_budget_releases_dropped_permits() {
        let ctx = Context::new();
        let first = ctx.try_acquire_rest_render().expect("first permit");
        let second = ctx.try_acquire_rest_render().expect("second permit");
        assert!(ctx.try_acquire_rest_render().is_none());
        drop(first);
        assert!(ctx.try_acquire_rest_render().is_some());
        drop(second);
    }

    #[test]
    fn new_context_wires_utxo_commits_to_coin_stats() {
        use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
        use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};

        let ctx = Context::new();
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[1_u8; 32])), 0);
        let txout = TxOut {
            value: 125_000,
            script_pubkey: Vec::new(),
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
    fn block_record_from_block_is_metadata_only() {
        let block = Network::Regtest.genesis_block();
        let record = BlockRecord::from_block(0, &block);

        assert_eq!(record.hash, block.block_hash());
        assert_eq!(record.height, 0);
        assert_eq!(record.body_size, consensus_bytes(&block).len());
        assert_eq!(record.header, None);
        assert_eq!(record.tx_count, block.txs.len());
        assert_eq!(record.time, block.header.time);
    }

    #[test]
    fn context_reads_metadata_only_block_record_from_body_source() {
        struct SingleBlockSource {
            height: u32,
            hash: BlockHash,
            body: Vec<u8>,
        }

        impl BlockBodySource for SingleBlockSource {
            fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
                (height == self.height && hash == self.hash).then(|| self.body.clone())
            }
        }

        let block = Network::Regtest.genesis_block();
        let body = consensus_bytes(&block);
        let record = BlockRecord::from_block(0, &block);
        let source = Arc::new(SingleBlockSource {
            height: 0,
            hash: record.hash,
            body: body.clone(),
        });
        let ctx = Context::new().with_block_body_source(source);
        ctx.add_block(record.clone());

        assert_eq!(record.body_size, consensus_bytes(&block).len());
        assert_eq!(
            ctx.block_body_bytes(&record).as_deref(),
            Some(body.as_slice())
        );
        let expected_hex = hex_encode(&body);
        assert_eq!(
            ctx.block_body_hex(&record).as_deref(),
            Some(expected_hex.as_str())
        );
    }

    /// Pins the cost this change exists to remove.
    ///
    /// One `BlockRecord` is held per applied block for the life of the process
    /// and nothing removes one, so the record's own footprint *is* the cost.
    ///
    /// The field was 104 bytes inline plus a 160-byte heap `String` of hex —
    /// 264 bytes and an allocation per block. Storing the raw header inline took
    /// that to 168 with no allocation. Not storing it at all takes it to **64**:
    /// a further **24 bytes per block**, about **23.1 MiB** at a mainnet-sized
    /// chain, on top of the 73.5 MiB the boxed header saved.
    ///
    /// The boxing is what buys those 80 bytes and is easy to undo by accident.
    /// An `Option<[u8; 80]>` costs its full width in every record even when it
    /// is `None`, so emptying the log's records would have saved nothing at all.
    /// This test is here so that reverting the box fails loudly.
    #[test]
    fn a_record_costs_64_bytes_and_carries_no_header() {
        let block = Network::Regtest.genesis_block();

        assert_eq!(
            core::mem::size_of::<BlockRecord>(),
            64,
            "BlockRecord footprint changed; re-measure the per-block saving"
        );
        for record in [
            BlockRecord::from_block(0, &block),
            BlockRecord::synthetic(0, BlockHash::default()),
        ] {
            assert!(
                record.header_bytes().is_none(),
                "a constructed record must not carry a header; the tree holds it"
            );
        }
    }

    /// The hex a caller sees must be byte-identical to what the stored `String`
    /// used to hold; only where it is produced changed.
    ///
    /// Read through a resolved record now, because that is where a header comes
    /// from: the tree, via `record_for_hash`. A record built straight from a
    /// block has none.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn header_hex_is_unchanged_by_sourcing_the_header_from_the_tree() {
        let block = Network::Regtest.genesis_block();
        let ctx = Arc::new(Context::new());
        {
            let mut tree = ctx.block_tree.write();
            let _ = tree.insert_node(None, block.header, bitcoin_rs_chain::NodeStatus::Active);
        }
        let hash = Hash256::from(block.block_hash());
        let Some(record) = ctx.record_for_hash(hash) else {
            panic!("the tree knows this hash");
        };

        assert_eq!(
            record.header_hex(),
            hex_encode(&consensus_bytes(&block.header))
        );
        assert_eq!(record.header_hex().len(), SERIALIZED_BLOCK_HEADER_LEN * 2);
    }

    /// The tree's header must reach a caller even when the log has the block.
    ///
    /// `record_for_hash` returns the cached record for its payload facts — size,
    /// transaction count — and that record has no header. Returning
    /// it unchanged would answer with none, which is what an earlier revision of
    /// this change did until this test caught it.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn record_for_hash_answers_with_the_tree_header_for_a_cached_record() {
        let block = Network::Regtest.genesis_block();
        let ctx = Arc::new(Context::new());
        {
            let mut tree = ctx.block_tree.write();
            let _ = tree.insert_node(None, block.header, bitcoin_rs_chain::NodeStatus::Active);
        }
        let cached = BlockRecord::from_block(0, &block);
        let hash = Hash256::from(cached.hash);
        let expected_body_size = cached.body_size;
        let expected_tx_count = cached.tx_count;
        assert!(cached.header_bytes().is_none(), "the log stores no header");
        ctx.add_block(cached);

        let Some(record) = ctx.record_for_hash(hash) else {
            panic!("the tree knows this hash");
        };
        assert_eq!(
            record.header_bytes().map(<[u8; 80]>::as_slice),
            Some(consensus_bytes(&block.header).as_slice()),
            "the resolved record must carry the tree's header"
        );
        assert_eq!(
            record.body_size, expected_body_size,
            "the cached body size must survive the header splice"
        );
        assert_eq!(
            record.tx_count, expected_tx_count,
            "the cached transaction count must survive the header splice"
        );
    }
    /// A log-only hash must not make a block identity visible.
    ///
    /// The old tree-miss fallback scanned every log record and accepted the
    /// matching hash, making unknown-hash RPC cost linear in chain length and
    /// allowing fixture-only state to masquerade as a real node identity.
    #[test]
    fn block_by_hash_ignores_log_records_the_tree_does_not_know() {
        let ctx = Context::new();
        let hash = Hash256::from_le_bytes(&[3_u8; 32]);
        ctx.add_block(BlockRecord::synthetic(3, BlockHash::from(hash)));

        assert!(ctx.record_for_hash(hash).is_none());
        assert!(ctx.block_by_hash(hash).is_none());
    }

    /// A record with no header must render as the empty string, the way an empty
    /// `String` field did, so callers that inspected it for emptiness still see
    /// what they saw.
    #[test]
    fn synthetic_record_has_no_header_and_renders_empty_hex() {
        let record =
            BlockRecord::synthetic(7, BlockHash::from(Hash256::from_le_bytes(&[3_u8; 32])));

        assert!(record.header_bytes().is_none());
        assert!(record.header_hex().is_empty());
    }

    /// Covers the record the block tree derives, which had no test at all.
    ///
    /// `header_record` builds its header with `try_into().ok()`, so a length that
    /// does not fit yields `None` and the header vanishes silently — where the
    /// old `String` field would at least have carried something. A mutation that
    /// dropped the header from this path failed no test before this one existed.
    #[test]
    fn tree_derived_record_carries_the_header() {
        use bitcoin_rs_chain::NodeStatus;
        use bitcoin_rs_primitives::Header;

        let ctx = Context::new();
        let header = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_000_000,
            bits: 0x207f_ffff,
            nonce: 7,
        };
        let hash = {
            let mut tree = ctx.block_tree.write();
            let id = tree
                .insert_node(None, header, NodeStatus::Active)
                .expect("genesis inserts");
            tree.node(id).expect("inserted node").hash
        };

        // Nothing was pushed into `blocks`, so the record can only come from the
        // tree.
        let record = ctx.record_for_hash(hash).expect("tree resolves the hash");

        assert_eq!(
            record.header_bytes().map(|bytes| &bytes[..]),
            Some(consensus_bytes(&header).as_slice()),
            "the tree-derived record must carry the header the tree holds"
        );
        assert_eq!(record.header_hex(), hex_encode(&consensus_bytes(&header)));
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
        use bitcoin_rs_chain::NodeStatus;
        use bitcoin_rs_primitives::Header;

        let ctx = Context::new();
        let (child_hash, stale_hash) = {
            let mut tree = ctx.block_tree.write();
            let genesis = Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_000_000,
                bits: 0x207f_ffff,
                nonce: 0,
            };
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let mut child = Header {
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: 1_000_900,
                bits: 0x207f_ffff,
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
            ctx.add_block(BlockRecord::synthetic(1, BlockHash::from(stale_hash)));
            (child_hash, stale_hash)
        };

        assert_ne!(child_hash, stale_hash, "test fixture hashes must differ");
        let found = ctx
            .block_by_height(1)
            .ok_or_else(|| std::io::Error::other("tree child missing at height 1"))?;
        assert_eq!(
            found.hash,
            BlockHash::from(child_hash),
            "active-tree identity must win over a stale cached hash"
        );
        assert_eq!(found.height, 1);
        Ok(())
    }

    #[test]
    fn height_lookups_follow_applied_tip_when_header_fork_leads()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_chain::NodeStatus;
        use bitcoin_rs_primitives::Header;

        let ctx = Context::new();
        let (applied_tip, header_tip) = {
            let mut tree = ctx.block_tree.write();
            let genesis = Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_000_000,
                bits: 0x207f_ffff,
                nonce: 0,
            };
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let applied = Header {
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: 1_000_900,
                bits: 0x207f_ffff,
                nonce: 1,
            };
            let applied_id = tree.insert_node(Some(genesis_id), applied, NodeStatus::Active)?;
            let applied_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
            assert_eq!(applied_tip.tip_id, applied_id);

            let fork = Header {
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: 1_000_901,
                bits: 0x207f_ffff,
                nonce: 2,
            };
            let fork_id = tree.insert_node(Some(genesis_id), fork, NodeStatus::HeaderValid)?;
            let fork_tip = Header {
                version: 1,
                prev_blockhash: fork.compute_hash(),
                merkle_root: Hash256::default(),
                time: 1_001_800,
                bits: 0x207f_ffff,
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
        ctx.add_block(BlockRecord::synthetic(2, BlockHash::from(header_tip.hash)));

        assert_eq!(
            ctx.active_hash_at_height(1),
            Some(applied_tip.hash),
            "height lookup must stay on the applied branch"
        );
        assert_eq!(ctx.block_hash_at_height(1), Some(applied_tip.hash));
        assert_eq!(
            ctx.block_by_height(1)
                .map(|record| Hash256::from(record.hash)),
            Some(applied_tip.hash)
        );
        assert!(ctx.block_hash_at_height(2).is_none());
        assert!(ctx.block_by_height(2).is_none());
        Ok(())
    }
}
