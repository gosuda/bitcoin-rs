//! Fenced row/cursor commits and retained forward-batch settlement.

use super::CursorCommit;
use super::DerivedIndexWorkerError;
use super::PendingForward;
use super::Worker;
use bitcoin_rs_index::ConsumerCursorUpdate;
use bitcoin_rs_index::IndexCapabilities;
use bitcoin_rs_index::IndexError;
use bitcoin_rs_index::IndexWatermark;
use bitcoin_rs_index::IndexWatermarks;

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
    pub(super) fn persist_chain_cursor(&self) -> Result<CursorCommit, DerivedIndexWorkerError> {
        let (fence, watermarks) = match self.writer.fenced_watermarks() {
            Ok(snapshot) => snapshot,
            Err(IndexError::ResetInProgress) => return Ok(CursorCommit::ResetRejected),
            Err(error) => return Err(DerivedIndexWorkerError::Index(error)),
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
            .map_err(DerivedIndexWorkerError::Index)?
            .is_some_and(|stored| stored == bytes)
        {
            return Ok(CursorCommit::Settled);
        }
        match self.writer.commit_consumer_cursor(fence, &bytes) {
            Ok(()) => Ok(CursorCommit::Settled),
            Err(IndexError::ResetInProgress) => Ok(CursorCommit::ResetRejected),
            Err(IndexError::StaleIndexState) => Ok(CursorCommit::NotAligned),
            Err(error) => Err(DerivedIndexWorkerError::Index(error)),
        }
    }

    pub(super) fn sync_and_commit(
        &self,
        state: PendingForward,
    ) -> Result<Option<IndexWatermark>, DerivedIndexWorkerError> {
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
            store.sync().map_err(DerivedIndexWorkerError::Storage)?;
        }
        if self.runtime.should_stop() {
            return Ok(None);
        }

        let endpoint = batch
            .watermark()
            .ok_or(DerivedIndexWorkerError::PendingDurableChanged)?;
        let capabilities = batch
            .capabilities()
            .ok_or(DerivedIndexWorkerError::PendingDurableChanged)?;
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
            Err(error) => return Err(DerivedIndexWorkerError::Index(error)),
        };
        Ok(Some(watermark))
    }

    pub(super) fn cursor_for_result(
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

    pub(super) fn commit_pending(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<bool, DerivedIndexWorkerError> {
        let Some(state) = pending.take() else {
            unreachable!("commit_pending has a pending batch");
        };
        Ok(self.sync_and_commit(state)?.is_some())
    }
}
