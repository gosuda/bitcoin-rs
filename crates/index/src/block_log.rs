//! Applied-block record log shared between the chain owner and index consumers.

#[cfg(any(test, feature = "test-seam"))]
use parking_lot::RwLockWriteGuard;
use parking_lot::{RwLock, RwLockReadGuard};
use std::sync::Arc;

use bitcoin_rs_primitives::{Block, BlockHash, Hash256};

#[derive(Clone, Debug)]
pub struct BlockLogReader {
    inner: Arc<RwLock<BlockLog>>,
}

impl BlockLogReader {
    #[must_use]
    pub const fn new(inner: Arc<RwLock<BlockLog>>) -> Self {
        Self { inner }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, BlockLog> {
        self.inner.read()
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn write(&self) -> RwLockWriteGuard<'_, BlockLog> {
        self.inner.write()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn raw_handle(&self) -> &Arc<RwLock<BlockLog>> {
        &self.inner
    }

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

#[derive(Clone, Debug)]
pub struct BlockRecord {
    pub hash: BlockHash,
    pub height: u32,
    pub body_size: usize,
    /// Serialized block header bytes, when the record carries a header.
    pub header: Option<Box<[u8; bitcoin_rs_primitives::Header::LEN]>>,
    pub tx_count: usize,
    pub time: u32,
}

/// Boxing the header keeps the record at 64 bytes instead of 144;
/// reverting it fails this compile-time gate.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(
    core::mem::size_of::<BlockRecord>() == 64,
    "BlockRecord footprint changed; re-measure the per-block saving"
);
const _: () = assert!(
    core::mem::size_of::<BlockRecord>() <= 64,
    "BlockRecord grew past the 64-byte bound; re-measure the per-block saving"
);

#[derive(Clone, Debug, Default)]
pub struct BlockLog {
    records: Vec<BlockRecord>,
    total_body_size: u64,
    /// `cumulative_tx_count[i]` is the sum of `tx_count` over `records[..=i]`.
    cumulative_tx_count: Vec<u64>,
}

impl BlockLog {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            total_body_size: 0,
            cumulative_tx_count: Vec::new(),
        }
    }

    pub fn push(&mut self, record: BlockRecord) {
        self.total_body_size = self
            .total_body_size
            .saturating_add(u64::try_from(record.body_size).unwrap_or(u64::MAX));
        let running = self
            .cumulative_tx_count
            .last()
            .copied()
            .unwrap_or(0)
            .saturating_add(u64::try_from(record.tx_count).unwrap_or(0));
        self.cumulative_tx_count.push(running);
        self.records.push(record);
    }

    pub fn pop(&mut self) -> Option<BlockRecord> {
        let record = self.records.pop()?;
        let _ = self.cumulative_tx_count.pop();
        self.total_body_size = self
            .total_body_size
            .saturating_sub(u64::try_from(record.body_size).unwrap_or(u64::MAX));
        Some(record)
    }

    pub fn clear(&mut self) {
        self.records.clear();
        self.cumulative_tx_count.clear();
        self.total_body_size = 0;
    }

    pub fn reserve(&mut self, additional: usize) {
        self.records.reserve(additional);
        self.cumulative_tx_count.reserve(additional);
    }

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

    #[must_use]
    pub fn tx_count_before(&self, count: usize) -> u64 {
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

#[must_use]
pub fn cumulative_tx_count_through(log: &BlockLog, height: u32) -> Option<u64> {
    let blocks: &[BlockRecord] = log;
    if blocks.first()?.height != 0 || blocks.last()?.height < height {
        return None;
    }
    Some(log.tx_count_before(blocks.partition_point(|record| record.height <= height)))
}

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
    /// The record is metadata only: `body_size` is the native consensus-encoded length.
    #[must_use]
    pub fn from_block(height: u32, block: &Block) -> Self {
        let hash = block.block_hash();
        Self {
            hash,
            height,
            body_size: block.total_size(),
            header: None,
            tx_count: block.txs.len(),
            time: block.header.time,
        }
    }

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

    #[must_use]
    pub fn header_bytes(&self) -> Option<&[u8; bitcoin_rs_primitives::Header::LEN]> {
        self.header.as_deref()
    }

    #[must_use]
    pub fn header_hex(&self) -> String {
        self.header.as_ref().map_or_else(String::new, |bytes| {
            bitcoin_rs_primitives::encode::hex_encode(bytes.as_slice())
        })
    }
}
