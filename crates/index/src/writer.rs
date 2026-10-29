//! Object-safe access to the existing durable index writer.

use bitcoin_rs_primitives::OutPoint;
use parking_lot::RwLock;

use crate::{
    ConsumerCursorUpdate, IndexCapabilities, IndexError, IndexWatermark, IndexWatermarks,
    IndexWriteFence, IndexWriter, PreparedBatch, PreparedBlock, ScriptHash, SpentCoinScripts,
    index::PortableImportRow,
};

pub(crate) type ScriptLiveSeedProduce<'a> = dyn FnMut(&mut dyn FnMut(OutPoint, ScriptHash) -> Result<(), IndexError>) -> Result<(), IndexError>
    + 'a;

pub(crate) type PortableImportProduce<'a> = dyn FnMut(&mut dyn FnMut(PortableImportRow<'_>) -> Result<(), IndexError>) -> Result<(), IndexError>
    + 'a;

pub(crate) trait TxIndexWriter: Send + Sync {
    fn fenced_watermarks(&self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError>;
    fn prepare_block_with_spent_scripts(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<PreparedBlock, IndexError>;
    fn seed_script_live_stream(
        &self,
        produce: &mut ScriptLiveSeedProduce<'_>,
        tip: IndexWatermark,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<usize, IndexError>;
    fn import_tx_lookup_stream(
        &self,
        produce: &mut PortableImportProduce<'_>,
        base: IndexWatermark,
        floor: u32,
    ) -> Result<usize, IndexError>;
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
        spent_scripts: &dyn SpentCoinScripts,
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
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<PreparedBlock, IndexError> {
        self.read().prepare_block_with_spent_scripts(
            capabilities,
            height,
            hash,
            body,
            spent_scripts,
        )
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

    fn seed_script_live_stream(
        &self,
        produce: &mut ScriptLiveSeedProduce<'_>,
        tip: IndexWatermark,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<usize, IndexError> {
        self.write()
            .seed_script_live_stream(produce, tip, cancelled)
    }

    fn import_tx_lookup_stream(
        &self,
        produce: &mut PortableImportProduce<'_>,
        base: IndexWatermark,
        floor: u32,
    ) -> Result<usize, IndexError> {
        self.write().import_tx_lookup_stream(produce, base, floor)
    }

    fn commit_rollback_one_for_with_cursor_with_spent_scripts(
        &self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
        spent_scripts: &dyn SpentCoinScripts,
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
