//! Durable rollback, live anchors, and cursor commit points.

use super::{CursorCommit, PendingForward, TxIndexWorkerError, Worker};
use crate::txindex::forward::UndoScripts;
use bitcoin_rs_index::{
    ConsumerCursorUpdate, IndexCapabilities, IndexError, IndexWatermark, IndexWatermarks,
    IndexWriteFence, NoSpentScripts,
};
use bitcoin_rs_primitives::Hash256;

impl Worker {
    /// Persists the consumer cursor once the rows provably mirror the live
    /// snapshot.
    ///
    /// The cursor is advisory: it lets a restarted or hint-starved consumer
    /// trust its position and lets a new epoch invalidate it. It is written
    /// only when the publisher snapshot names exactly the tip the rows
    /// reached, so it can never describe rows the store does not hold. The
    /// publisher briefly lags `applied_tip` inside one commit, so a disagreeing
    /// snapshot simply skips the write; the next caught-up pass retries.
    pub(super) fn persist_chain_cursor(&self) -> Result<CursorCommit, TxIndexWorkerError> {
        let (fence, watermarks) = match self.writer.fenced_watermarks() {
            Ok(snapshot) => snapshot,
            Err(IndexError::ResetInProgress) => return Ok(CursorCommit::ResetRejected),
            Err(error) => return Err(TxIndexWorkerError::Index(error)),
        };
        let loaded_tip = self.applied_tip.load_full();
        let Some(target) = loaded_tip.as_deref() else {
            return Ok(CursorCommit::Settled);
        };
        let snapshot = self.chain_events.snapshot();
        if snapshot.tip_hash != target.hash || snapshot.tip_height != target.height {
            return Ok(CursorCommit::Settled);
        }
        let expected = IndexWatermark {
            height: snapshot.tip_height,
            hash: snapshot.tip_hash.to_le_bytes(),
        };
        if (self.enabled.tx_lookup && watermarks.tx_lookup != Some(expected))
            || (self.enabled.script_history && watermarks.script_history != Some(expected))
            || (self.enabled.script_live && watermarks.script_live != Some(expected))
        {
            return Ok(CursorCommit::NotAligned);
        }
        let bytes = crate::reconcile::cursor_from_snapshot(&snapshot).to_bytes();
        if self
            .writer
            .consumer_cursor()
            .map_err(TxIndexWorkerError::Index)?
            .is_some_and(|stored| stored == bytes)
        {
            return Ok(CursorCommit::Settled);
        }
        match self.writer.commit_consumer_cursor(fence, &bytes) {
            Ok(()) => Ok(CursorCommit::Settled),
            Err(IndexError::ResetInProgress) => Ok(CursorCommit::ResetRejected),
            Err(IndexError::StaleIndexState) => Ok(CursorCommit::NotAligned),
            Err(error) => Err(TxIndexWorkerError::Index(error)),
        }
    }
    /// Rolls back one complete block for every selected capability.
    pub(in crate::txindex) fn rollback_one(
        &self,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
    ) -> Result<Option<IndexWatermark>, TxIndexWorkerError> {
        let watermark_hash = Hash256::from_le_bytes(&watermark.hash);
        let body = self.load_body(watermark.height, watermark_hash)?;
        let anchor = capabilities
            .script_live
            .then(|| self.live_anchor(watermark.height, watermark.hash))
            .transpose()?;

        let spent: &dyn bitcoin_rs_index::SpentCoinScripts =
            anchor.as_ref().map_or(&NoSpentScripts, |anchor| anchor);

        let prev = if watermark.height == 0 {
            None
        } else {
            let prepared = self
                .writer
                .prepare_block_with_spent_scripts(
                    capabilities,
                    watermark.height,
                    watermark.hash,
                    &body,
                    spent,
                )
                .map_err(TxIndexWorkerError::Index)?;
            Some(IndexWatermark {
                height: watermark.height.saturating_sub(1),
                hash: prepared.parent_hash,
            })
        };

        if self.runtime.should_stop() {
            return Err(TxIndexWorkerError::Stopped);
        }
        let cursor = self.cursor_for_result(capabilities, prev, watermarks);
        let cursor = cursor
            .as_ref()
            .map_or(ConsumerCursorUpdate::Clear, |bytes| {
                ConsumerCursorUpdate::Set(bytes.as_slice())
            });
        self.writer
            .commit_rollback_one_for_with_cursor_with_spent_scripts(
                fence,
                capabilities,
                prev,
                &body,
                cursor,
                spent,
            )
            .map_err(TxIndexWorkerError::Index)?;
        Ok(prev)
    }

    pub(in crate::txindex) fn load_body(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<Vec<u8>, TxIndexWorkerError> {
        let Some(store) = self.body_store.as_ref() else {
            return Err(TxIndexWorkerError::NoBodyStore);
        };
        store
            .load_block_body(height, hash)
            .map_err(TxIndexWorkerError::Storage)?
            .ok_or(TxIndexWorkerError::MissingBody { height, hash })
    }

    pub(in crate::txindex) fn live_anchor(
        &self,
        height: u32,
        hash_bytes: [u8; 32],
    ) -> Result<UndoScripts, TxIndexWorkerError> {
        let hash = Hash256::from_le_bytes(&hash_bytes);
        let Some(store) = self.body_store.as_ref() else {
            return Err(TxIndexWorkerError::NoBodyStore);
        };
        let bytes = store
            .undo_record(height, hash)
            .map_err(TxIndexWorkerError::Storage)?
            .ok_or(TxIndexWorkerError::UndoUnavailable { height, hash })?;
        UndoScripts::from_undo_bytes(&bytes, hash)
            .map_err(|_| TxIndexWorkerError::UndoUnavailable { height, hash })
    }

    pub(in crate::txindex) fn sync_and_commit(
        &self,
        state: PendingForward,
    ) -> Result<Option<IndexWatermark>, TxIndexWorkerError> {
        let PendingForward {
            fence,
            watermarks,
            batch,
            ..
        } = state;
        if batch.is_empty() {
            return Ok(None);
        }
        if let Some(store) = self.body_store.as_ref() {
            store.sync().map_err(TxIndexWorkerError::Storage)?;
        }
        if self.runtime.should_stop() {
            return Ok(None);
        }

        let endpoint = batch
            .watermark()
            .ok_or(TxIndexWorkerError::PendingDurableChanged)?;
        let capabilities = batch
            .capabilities()
            .ok_or(TxIndexWorkerError::PendingDurableChanged)?;
        let cursor = self.cursor_for_result(capabilities, Some(endpoint), watermarks);
        let watermark = match self.writer.commit_forward_with_cursor(
            fence,
            batch,
            cursor.as_ref().map_or(ConsumerCursorUpdate::Keep, |bytes| {
                ConsumerCursorUpdate::Set(bytes.as_slice())
            }),
        ) {
            Ok(watermark) => watermark,
            Err(IndexError::ResetInProgress) => {
                tracing::debug!("index reset rejected a stale forward batch");
                return Ok(None);
            }
            Err(IndexError::StaleIndexState) => {
                tracing::debug!("index CAS lost with unchanged reset; re-deriving");
                return Ok(None);
            }
            Err(error) => return Err(TxIndexWorkerError::Index(error)),
        };
        Ok(Some(watermark))
    }

    pub(in crate::txindex) fn cursor_for_result(
        &self,
        capabilities: IndexCapabilities,
        result: Option<IndexWatermark>,
        mut watermarks: IndexWatermarks,
    ) -> Option<[u8; crate::reconcile::CURSOR_BYTE_LEN]> {
        let snapshot = self.chain_events.snapshot();
        let result = result?;
        if result.height != snapshot.tip_height || result.hash != snapshot.tip_hash.to_le_bytes() {
            return None;
        }
        if capabilities.tx_lookup {
            watermarks.tx_lookup = Some(result);
        }
        if capabilities.script_history {
            watermarks.script_history = Some(result);
        }
        if capabilities.script_live {
            watermarks.script_live = Some(result);
        }
        let aligned = (!self.enabled.tx_lookup || watermarks.tx_lookup == Some(result))
            && (!self.enabled.script_history || watermarks.script_history == Some(result))
            && (!self.enabled.script_live || watermarks.script_live == Some(result));
        aligned.then(|| crate::reconcile::cursor_from_snapshot(&snapshot).to_bytes())
    }

    pub(in crate::txindex) fn commit_pending(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<bool, TxIndexWorkerError> {
        let Some(state) = pending.take() else {
            unreachable!("commit_pending has a pending batch");
        };
        Ok(self.sync_and_commit(state)?.is_some())
    }
}
