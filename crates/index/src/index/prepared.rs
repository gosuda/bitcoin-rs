//! Bounded prepared-block ownership and batch admission.

use super::{capability::IndexCapabilities, capability::IndexWatermark, rows::PendingRows};

pub(crate) use super::rows::IndexRowBytes;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PreparedBatchLimits {
    pub max_rows: usize,
    pub max_bytes: usize,
}

pub struct PreparedBlock {
    pub height: u32,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub row_count: usize,
    pub encoded_bytes: usize,
    pub(crate) family_bytes: IndexRowBytes,
    pub(super) capabilities: IndexCapabilities,
    pub(super) rows: PendingRows,
}

impl PreparedBlock {
    pub const fn watermark(&self) -> IndexWatermark {
        IndexWatermark {
            height: self.height,
            hash: self.hash,
        }
    }
}

pub struct PreparedBatch {
    limits: PreparedBatchLimits,
    blocks: Vec<PreparedBlock>,
    row_count: usize,
    encoded_bytes: usize,
    family_bytes: IndexRowBytes,
    capabilities: Option<IndexCapabilities>,
}

impl PreparedBatch {
    pub const fn new(limits: PreparedBatchLimits) -> Self {
        Self {
            limits,
            blocks: Vec::new(),
            row_count: 0,
            encoded_bytes: 0,
            family_bytes: IndexRowBytes::ZERO,
            capabilities: None,
        }
    }

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
        let Some(new_family) = self.family_bytes.checked_add(&block.family_bytes).ok() else {
            return Err(block);
        };
        let new_rows = self.row_count.checked_add(block.row_count);
        let new_bytes = self.encoded_bytes.checked_add(block.encoded_bytes);

        let fits = new_rows.is_some_and(|rows| rows <= self.limits.max_rows)
            && new_bytes.is_some_and(|bytes| bytes <= self.limits.max_bytes);
        if !self.blocks.is_empty() && !fits {
            return Err(block);
        }
        self.family_bytes = new_family;
        self.row_count = new_rows.unwrap_or(usize::MAX);
        self.encoded_bytes = new_bytes.unwrap_or(usize::MAX);
        self.blocks.push(block);
        self.capabilities.get_or_insert(capabilities);
        Ok(())
    }

    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub const fn len(&self) -> usize {
        self.blocks.len()
    }

    pub const fn row_count(&self) -> usize {
        self.row_count
    }

    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }

    pub(crate) const fn family_bytes(&self) -> IndexRowBytes {
        self.family_bytes
    }
    pub const fn is_full(&self) -> bool {
        self.row_count >= self.limits.max_rows || self.encoded_bytes >= self.limits.max_bytes
    }

    pub fn watermark(&self) -> Option<IndexWatermark> {
        self.blocks.last().map(PreparedBlock::watermark)
    }

    pub(crate) fn into_blocks(self) -> Vec<PreparedBlock> {
        self.blocks
    }

    pub(crate) const fn capabilities(&self) -> Option<IndexCapabilities> {
        self.capabilities
    }
}
