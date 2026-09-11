//! Bounded prepared-block ownership and batch admission.

use super::{
    capability::IndexCapabilities, capability::IndexWatermark, rows::IndexRowCounts,
    rows::PendingRows,
};

/// Hard limits for one prepared forward write.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PreparedBatchLimits {
    /// Maximum retained index rows in a normal batch.
    pub max_rows: usize,
    /// Maximum encoded index key/value bytes in a normal batch.
    pub max_bytes: usize,
}

/// Compact mutations for one identity-checked serialized block.
pub struct PreparedBlock {
    /// Active-chain height represented by this block.
    pub height: u32,
    /// Full block identity at `height`.
    pub hash: [u8; 32],
    /// Full parent identity read from the exact serialized header.
    pub parent_hash: [u8; 32],
    /// Number of retained, deduplicated row mutations.
    pub row_count: usize,
    /// Actual encoded key/value bytes retained by the row mutations.
    pub encoded_bytes: usize,
    pub(super) capabilities: IndexCapabilities,
    /// Row mutations retained from the serialized body.
    pub(super) rows: PendingRows,
}

impl PreparedBlock {
    /// Returns the watermark this block represents.
    pub const fn watermark(&self) -> IndexWatermark {
        IndexWatermark {
            height: self.height,
            hash: self.hash,
        }
    }

    /// Row-family counts retained by this prepared block.
    pub fn row_counts(&self) -> IndexRowCounts {
        self.rows.counts()
    }
}

/// Prepared blocks admitted to one bounded atomic forward write.
pub struct PreparedBatch {
    limits: PreparedBatchLimits,
    blocks: Vec<PreparedBlock>,
    row_count: usize,
    encoded_bytes: usize,
    capabilities: Option<IndexCapabilities>,
}

impl PreparedBatch {
    /// Creates an empty batch with caller-selected hard limits.
    pub const fn new(limits: PreparedBatchLimits) -> Self {
        Self {
            limits,
            blocks: Vec::new(),
            row_count: 0,
            encoded_bytes: 0,
            capabilities: None,
        }
    }

    /// Admits `block`, or returns it unchanged when a non-empty batch would exceed a limit.
    ///
    /// An oversized first block is admitted so callers always make progress.
    #[expect(
        clippy::result_large_err,
        reason = "returning the prepared block avoids a hot-path allocation"
    )]
    pub fn try_push(&mut self, block: PreparedBlock) -> Result<(), PreparedBlock> {
        let capabilities = block.capabilities;
        if self
            .capabilities
            .is_some_and(|current| current != capabilities)
        {
            return Err(block);
        }
        let new_rows = self.row_count.checked_add(block.row_count);
        let new_bytes = self.encoded_bytes.checked_add(block.encoded_bytes);
        let fits = new_rows.is_some_and(|rows| rows <= self.limits.max_rows)
            && new_bytes.is_some_and(|bytes| bytes <= self.limits.max_bytes);
        if !self.blocks.is_empty() && !fits {
            return Err(block);
        }
        self.row_count = new_rows.unwrap_or(usize::MAX);
        self.encoded_bytes = new_bytes.unwrap_or(usize::MAX);
        self.blocks.push(block);
        self.capabilities.get_or_insert(capabilities);
        Ok(())
    }

    /// Returns whether no blocks have been admitted.
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Number of admitted blocks.
    pub const fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Number of retained row mutations.
    pub const fn row_count(&self) -> usize {
        self.row_count
    }

    /// Actual encoded key/value bytes retained by row mutations.
    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
    /// Returns whether either normal admission limit has been reached.
    ///
    /// An oversized first block also makes the batch full.
    pub const fn is_full(&self) -> bool {
        self.row_count >= self.limits.max_rows || self.encoded_bytes >= self.limits.max_bytes
    }

    /// Returns the endpoint represented by the last admitted block.
    pub fn watermark(&self) -> Option<IndexWatermark> {
        self.blocks.last().map(PreparedBlock::watermark)
    }

    /// Consumes the batch and returns the admitted blocks.
    pub(crate) fn into_blocks(self) -> Vec<PreparedBlock> {
        self.blocks
    }

    /// Returns the row families represented by the admitted blocks.
    pub const fn capabilities(&self) -> Option<IndexCapabilities> {
        self.capabilities
    }
}
