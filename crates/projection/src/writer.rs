use parking_lot::RwLock;

use std::path::Path;

use crate::{
    ConsumerCursorUpdate, IndexCapabilities, IndexError, IndexWatermark, IndexWatermarks,
    IndexWriteFence, IndexWriter, PreparedBatch, PreparedBlock, SpentCoins,
};
use bitcoin_rs_storage::ColumnFamily;

pub struct TxLookupAttachment<'a> {
    pub headers: &'a [&'a [u8; crate::types::HEADER_ROW_SIZE]],
    pub base: IndexWatermark,
    pub floor: u32,
    pub scratch: &'a Path,
}

pub struct ScriptHistoryAttachment<'a> {
    pub base: IndexWatermark,
    pub floor: u32,
    pub scratch: &'a Path,
}

pub struct CompactFilterRow {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub filter_hash: [u8; 32],
    pub header: [u8; 32],
    pub filter: Vec<u8>,
}

pub struct CompactFilterAttachment<'a> {
    pub base: IndexWatermark,
    pub records: u64,
    pub scratch: &'a Path,
}

pub trait TxIndexWriter: Send + Sync {
    fn fenced_watermarks(&self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError>;
    fn prepare_block_with_spent_scripts(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
        spent_scripts: &dyn SpentCoins,
    ) -> Result<PreparedBlock, IndexError>;
    fn prepare_block_from_facts(
        &self,
        capabilities: IndexCapabilities,
        block: bitcoin_rs_storage::CommittedBlock,
    ) -> Result<PreparedBlock, IndexError>;
    fn stage_script_live_rows(
        &self,
        rows: &mut dyn Iterator<Item = Vec<u8>>,
    ) -> Result<usize, IndexError>;
    fn publish_script_live_seed(&self, seed_tip: IndexWatermark) -> Result<(), IndexError>;
    fn attach_tx_lookup_segment(
        &self,
        segment: &crate::segment::import::ImportedSegment,
        attachment: &TxLookupAttachment<'_>,
    ) -> Result<u64, IndexError>;
    fn attach_script_history_segment(
        &self,
        segment: &crate::segment::import::ImportedSegment,
        attachment: &ScriptHistoryAttachment<'_>,
    ) -> Result<u64, IndexError>;
    fn attach_streamed_tx_lookup(
        &self,
        tx_dir: &crate::segment::import::StreamedFamily,
        seal: &crate::segment::import::StreamedSeal,
        attachment: &TxLookupAttachment<'_>,
    ) -> Result<u64, IndexError>;
    fn attach_streamed_script_history(
        &self,
        families: &[(ColumnFamily, crate::segment::import::StreamedFamily)],
        seal: &crate::segment::import::StreamedSeal,
        attachment: &ScriptHistoryAttachment<'_>,
    ) -> Result<u64, IndexError>;
    fn clear_unpublished_segments(&self) -> Result<(), IndexError>;
    fn attach_compact_filter_segment(
        &self,
        by_height: &mut dyn Iterator<Item = CompactFilterRow>,
        attachment: &CompactFilterAttachment<'_>,
    ) -> Result<u64, IndexError>;
    fn commit_forward_with_cursor(
        &self,
        fence: IndexWriteFence,
        batch: PreparedBatch,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError>;
    fn commit_rollback_one_for_with_cursor_with_spent_scripts(
        &self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
        spent_scripts: &dyn SpentCoins,
    ) -> Result<(), IndexError>;

    fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError>;
    fn reset_interrupted_script_live_seed(&self) -> Result<bool, IndexError>;
    fn anchor_watermark(
        &self,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
        floor: u32,
    ) -> Result<(), IndexError>;
    fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError>;
    fn commit_consumer_cursor(
        &self,
        fence: IndexWriteFence,
        cursor: &[u8],
    ) -> Result<(), IndexError>;
}

impl<S> TxIndexWriter for RwLock<IndexWriter<S>>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    fn fenced_watermarks(&self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError> {
        self.write().fenced_watermarks()
    }

    fn prepare_block_with_spent_scripts(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
        spent_scripts: &dyn SpentCoins,
    ) -> Result<PreparedBlock, IndexError> {
        self.read().prepare_block_with_spent_scripts(
            capabilities,
            height,
            hash,
            body,
            spent_scripts,
        )
    }

    fn prepare_block_from_facts(
        &self,
        capabilities: IndexCapabilities,
        block: bitcoin_rs_storage::CommittedBlock,
    ) -> Result<PreparedBlock, IndexError> {
        self.read().prepare_block_from_facts(capabilities, block)
    }

    fn commit_forward_with_cursor(
        &self,
        fence: IndexWriteFence,
        batch: PreparedBatch,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError> {
        self.write()
            .commit_forward_with_cursor(fence, batch, cursor)
    }

    fn stage_script_live_rows(
        &self,
        rows: &mut dyn Iterator<Item = Vec<u8>>,
    ) -> Result<usize, IndexError> {
        self.write().stage_script_live_rows(rows)
    }

    fn publish_script_live_seed(&self, seed_tip: IndexWatermark) -> Result<(), IndexError> {
        self.write().publish_script_live_seed(seed_tip)
    }

    fn attach_tx_lookup_segment(
        &self,
        segment: &crate::segment::import::ImportedSegment,
        attachment: &TxLookupAttachment<'_>,
    ) -> Result<u64, IndexError> {
        self.write().attach_tx_lookup_segment(segment, attachment)
    }

    fn attach_script_history_segment(
        &self,
        segment: &crate::segment::import::ImportedSegment,
        attachment: &ScriptHistoryAttachment<'_>,
    ) -> Result<u64, IndexError> {
        self.write()
            .attach_script_history_segment(segment, attachment)
    }

    fn attach_streamed_tx_lookup(
        &self,
        tx_dir: &crate::segment::import::StreamedFamily,
        seal: &crate::segment::import::StreamedSeal,
        attachment: &TxLookupAttachment<'_>,
    ) -> Result<u64, IndexError> {
        self.write()
            .attach_streamed_tx_lookup(tx_dir, seal, attachment)
    }

    fn attach_streamed_script_history(
        &self,
        families: &[(ColumnFamily, crate::segment::import::StreamedFamily)],
        seal: &crate::segment::import::StreamedSeal,
        attachment: &ScriptHistoryAttachment<'_>,
    ) -> Result<u64, IndexError> {
        self.write()
            .attach_streamed_script_history(families, seal, attachment)
    }

    fn attach_compact_filter_segment(
        &self,
        by_height: &mut dyn Iterator<Item = CompactFilterRow>,
        attachment: &CompactFilterAttachment<'_>,
    ) -> Result<u64, IndexError> {
        self.write()
            .attach_compact_filter_segment(by_height, attachment)
    }

    fn clear_unpublished_segments(&self) -> Result<(), IndexError> {
        self.write().clear_unpublished_segments()
    }

    fn commit_rollback_one_for_with_cursor_with_spent_scripts(
        &self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
        spent_scripts: &dyn SpentCoins,
    ) -> Result<(), IndexError> {
        self.write()
            .commit_rollback_one_for_with_cursor_with_spent_scripts(
                fence,
                capabilities,
                prev,
                body,
                cursor,
                spent_scripts,
            )
    }

    fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError> {
        self.write().reset_capabilities(capabilities)
    }

    fn reset_interrupted_script_live_seed(&self) -> Result<bool, IndexError> {
        self.write().reset_interrupted_script_live_seed()
    }

    fn anchor_watermark(
        &self,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
        floor: u32,
    ) -> Result<(), IndexError> {
        self.write()
            .anchor_watermark(capabilities, watermark, floor)
    }

    fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError> {
        self.read().consumer_cursor()
    }

    fn commit_consumer_cursor(
        &self,
        fence: IndexWriteFence,
        cursor: &[u8],
    ) -> Result<(), IndexError> {
        self.write().commit_consumer_cursor(fence, cursor)
    }
}
