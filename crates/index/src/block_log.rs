//! Applied-block record log shared between the chain owner and index consumers.
//!
//! The node records one [`BlockRecord`] per applied block; the derived-index
//! runtime resolves block identity against the same log. The type lives here
//! so both owners read it without an edge on the RPC surface crate.

#[cfg(any(test, feature = "test-seam"))]
use parking_lot::RwLockWriteGuard;
use parking_lot::{RwLock, RwLockReadGuard};
use std::sync::Arc;

use bitcoin_rs_primitives::{Block, BlockHash, Hash256};

/// Cloneable, read-only capability to observe the applied-block log.
///
/// Write access stays private to the owning chain followers.
#[derive(Clone, Debug)]
pub struct BlockLogReader {
    inner: Arc<RwLock<BlockLog>>,
}

impl BlockLogReader {
    /// Wraps a block log without exposing its write lock in production.
    #[must_use]
    pub const fn new(inner: Arc<RwLock<BlockLog>>) -> Self {
        Self { inner }
    }

    /// Acquires a shared block-log read guard.
    pub fn read(&self) -> RwLockReadGuard<'_, BlockLog> {
        self.inner.read()
    }

    /// Acquires a fixture-only write guard. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn write(&self) -> RwLockWriteGuard<'_, BlockLog> {
        self.inner.write()
    }

    /// Raw block-log handle for test fixtures.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn raw_handle(&self) -> &Arc<RwLock<BlockLog>> {
        &self.inner
    }

    /// Builds an empty block-log fixture for testing.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn fixture_empty() -> Self {
        Self::new(Arc::new(RwLock::new(BlockLog::new())))
    }
}

impl From<Arc<RwLock<BlockLog>>> for BlockLogReader {
    fn from(inner: Arc<RwLock<BlockLog>>) -> Self {
        Self::new(inner)
    }
}

const SERIALIZED_BLOCK_HEADER_LEN: usize = 80;

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
    /// The log never carries one: the `BlockTree` already holds the header of
    /// every applied block. Every constructor leaves this `None`, and
    /// [`Context::header_record`] is the only thing that fills it. Boxed so an
    /// absent header costs 8 bytes rather than the full 80 in every record.
    pub header: Option<Box<[u8; SERIALIZED_BLOCK_HEADER_LEN]>>,
    /// Transaction count in the block.
    pub tx_count: usize,
    /// Block header timestamp (UNIX seconds).
    pub time: u32,
}

/// Compile-time gate for the per-block record cost documented on
/// [`BlockRecord::header`]. Boxing the header is what keeps the record at 64
/// bytes instead of 144, and it is easy to undo by accident, so reverting it
/// fails here at compile time rather than in a runtime test. The figure is the
/// 64-bit layout; narrower targets are smaller still.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(
    core::mem::size_of::<BlockRecord>() == 64,
    "BlockRecord footprint changed; re-measure the per-block saving"
);
const _: () = assert!(
    core::mem::size_of::<BlockRecord>() <= 64,
    "BlockRecord grew past the 64-byte bound; re-measure the per-block saving"
);

/// Applied block records with cached body-size and transaction-prefix sums.
#[derive(Clone, Debug, Default)]
pub struct BlockLog {
    records: Vec<BlockRecord>,
    /// Sum of `body_size` over every record.
    total_body_size: u64,
    /// `cumulative_tx_count[i]` is the sum of `tx_count` over `records[..=i]`.
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
        // Avoid total_tx_count's debug fold on every append.
        let running = self
            .cumulative_tx_count
            .last()
            .copied()
            .unwrap_or(0)
            .saturating_add(u64::try_from(record.tx_count).unwrap_or(0));
        self.cumulative_tx_count.push(running);
        self.records.push(record);
    }

    /// Removes the last record and its contribution to both sums.
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
    /// Pruning retains records, so this includes bytes pruned blocks would occupy.
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

/// Cumulative transactions through `height`, when the log can still say.
///
/// The log is appended in height order from wherever this process began
/// applying, and is rebuilt empty on every open. A prefix that does not start
/// at genesis sums to a number that is not a chain total, so the answer is
/// `None` rather than an under-count.
#[must_use]
pub fn cumulative_tx_count_through(log: &BlockLog, height: u32) -> Option<u64> {
    let blocks: &[BlockRecord] = log;
    if blocks.first()?.height != 0 || blocks.last()?.height < height {
        return None;
    }
    Some(log.tx_count_before(blocks.partition_point(|record| record.height <= height)))
}

/// Finds the record at `height`, or `None` when the log holds no such height.
///
/// Records must be sorted by non-decreasing height. Returns the first duplicate.
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
/// Records must be sorted by non-decreasing height; hashes disambiguate duplicates.
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
            body_size: block.total_size(),
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
        self.header.as_ref().map_or_else(String::new, |bytes| {
            bitcoin_rs_storage::checkpoint::hex_encode(bytes.as_slice())
        })
    }
}
