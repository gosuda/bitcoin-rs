//! Fenced row/cursor commits and retained forward-batch settlement.

use super::CursorCommit;
use super::DerivedIndexWorkerError;
use super::PendingForward;
use super::Worker;
use crate::ConsumerCursorUpdate;
use crate::IndexCapabilities;
use crate::IndexCapability;
use crate::IndexError;
use crate::IndexWatermark;
use crate::IndexWatermarks;

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
        let snapshot = self.chain_events.cursor();
        if snapshot.hash != target.hash || snapshot.height != target.height {
            return Ok(CursorCommit::Settled);
        }
        let expected = IndexWatermark {
            height: snapshot.height,
            hash: snapshot.hash.to_le_bytes(),
        };
        if (self.enabled.contains(IndexCapability::TxLookup)
            && watermarks.tx_lookup != Some(expected))
            || (self.enabled.contains(IndexCapability::ScriptHistory)
                && watermarks.script_history != Some(expected))
            || (self.enabled.contains(IndexCapability::ScriptLive)
                && watermarks.script_live != Some(expected))
        {
            return Ok(CursorCommit::NotAligned);
        }
        let bytes = snapshot.to_bytes();
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
        let snapshot = self.chain_events.cursor();
        let result = result?;
        if result.height != snapshot.height || result.hash != snapshot.hash.to_le_bytes() {
            return None;
        }
        if capabilities.contains(IndexCapability::TxLookup) {
            watermarks.tx_lookup = Some(result);
        }
        if capabilities.contains(IndexCapability::ScriptHistory) {
            watermarks.script_history = Some(result);
        }
        if capabilities.contains(IndexCapability::ScriptLive) {
            watermarks.script_live = Some(result);
        }
        let aligned = (!self.enabled.contains(IndexCapability::TxLookup)
            || watermarks.tx_lookup == Some(result))
            && (!self.enabled.contains(IndexCapability::ScriptHistory)
                || watermarks.script_history == Some(result))
            && (!self.enabled.contains(IndexCapability::ScriptLive)
                || watermarks.script_live == Some(result));
        aligned.then(|| snapshot.to_bytes())
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
