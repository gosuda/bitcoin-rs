//! Object-safe access to the existing durable index writer.
//!
//! Preparation takes a shared lock; fence capture, resets, and commits take
//! an exclusive lock. This is the same writer and the same persistence
//! protocol, not a second representation or a parallel mutation path.

use bitcoin_rs_primitives::OutPoint;
use parking_lot::RwLock;

use crate::{
    ConsumerCursorUpdate, IndexCapabilities, IndexError, IndexWatermark, IndexWatermarks,
    IndexWriteFence, IndexWriter, PreparedBatch, PreparedBlock, ScriptHash, SpentCoinScripts,
};

/// Object-safe `ScriptLive` seed producer used by [`TxIndexWriter`].
pub type ScriptLiveSeedProduce<'a> = dyn FnMut(&mut dyn FnMut(OutPoint, ScriptHash) -> Result<(), IndexError>) -> Result<(), IndexError>
    + 'a;

/// Erased prepared-index writer used by derived-index reconciliation.
///
/// Prepare and rollback have one owner each: spent-script-aware
/// [`Self::prepare_block_with_spent_scripts`] and
/// [`Self::commit_rollback_one_for_with_cursor_with_spent_scripts`].
/// Callers that are not rebuilding `ScriptLive` pass [`crate::NoSpentScripts`].
/// Durability, crash visibility, and failure classification for rollback are
/// owned by [`IndexWriter::commit_rollback_one_for_with_cursor_with_spent_scripts`]
/// (`IDX-06` / `IDX-07`).
pub trait TxIndexWriter: Send + Sync {
    /// Captures the exact write fence and all capability watermarks together.
    fn fenced_watermarks(&self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError>;
    /// Prepares rows using the supplied spent-coin script authority.
    fn prepare_block_with_spent_scripts(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<PreparedBlock, IndexError>;
    /// Seeds the live view from a caller-fenced authoritative coin stream.
    fn seed_script_live_stream(
        &self,
        produce: &mut ScriptLiveSeedProduce<'_>,
        tip: IndexWatermark,
    ) -> Result<usize, IndexError> {
        let _ = (produce, tip);
        Err(IndexError::UnsupportedRollback)
    }
    /// Commits prepared rows and the consumer cursor under one exact fence.
    fn commit_forward_with_cursor(
        &self,
        fence: IndexWriteFence,
        batch: PreparedBatch,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError>;
    /// Rolls back selected row families and the cursor atomically.
    fn commit_rollback_one_for_with_cursor_with_spent_scripts(
        &self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<(), IndexError>;

    /// Resets only the selected derived row families through the durable reset protocol.
    fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError> {
        let _ = capabilities;
        Err(IndexError::UnsupportedRollback)
    }
    /// Reads the opaque durable reconciliation cursor.
    fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError>;
    /// Commits an opaque cursor without changing rows, subject to the write fence.
    fn commit_consumer_cursor(
        &self,
        fence: IndexWriteFence,
        cursor: &[u8],
    ) -> Result<(), IndexError>;
}

/// `RwLock`-backed writer: `prepare_block_with_spent_scripts` and
/// `consumer_cursor` take a shared read lock so the CPU-bound decode/row-build
/// can run concurrently across the rayon pool, while `commit_*`,
/// `fenced_watermarks`, and `reset_capabilities` take an exclusive write lock
/// to preserve the single-writer atomic commit and watermark semantics.
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
    ) -> Result<usize, IndexError> {
        self.write().seed_script_live_stream(produce, tip)
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
