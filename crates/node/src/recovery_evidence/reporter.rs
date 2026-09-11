//! Recovery event construction, warning publication, and durable marker persistence.
//!
//! Each report emits the warning and updates the in-memory warning snapshot
//! before attempting the durable marker write. That order is intentional: if
//! durable marker publication fails, the reporting process still exposes the
//! recovery warning while returning the persistence error to its caller.

use super::ChainRollbackEvent;
use super::EvidenceError;
use super::RecoveryReporter;
use super::RollbackEventKind;
use super::write_marker;

// ---------------------------------------------------------------------------
// Warning message rendering
// ---------------------------------------------------------------------------

/// Renders a checkpoint-fallback warning message.
///
/// Says the durable applied-tip witness is ahead of the restored
/// checkpoint/cold/headers-only tip. Does not say recoverable live
/// chainstate was rejected.
pub(super) fn checkpoint_fallback_warning(witness_height: u32, restored_height: u32) -> String {
    format!(
        "Durable applied-tip witness at height {witness_height} is ahead of \
         the restored tip at height {restored_height}. \
         Chainstate was restored from a clean checkpoint, not rejected."
    )
}

/// Renders an index-watermark-ahead warning message.
pub(super) fn index_ahead_warning(
    capability: &str,
    watermark_height: u32,
    restored_height: u32,
    gap: u32,
) -> String {
    format!(
        "Index capability '{capability}' watermark at height \
         {watermark_height} is {gap} block(s) ahead of the restored tip \
         at height {restored_height}."
    )
}

impl RecoveryReporter {
    /// Reports a checkpoint-fallback event. Marker failure aborts
    /// `NodeState::open`.
    pub(crate) fn report_checkpoint_fallback(
        &self,
        witness_height: u32,
        restored_height: u32,
        restored_hash: &str,
        source: &str,
        old_hash: &str,
        time: u64,
    ) -> Result<(), EvidenceError> {
        let msg = checkpoint_fallback_warning(witness_height, restored_height);
        tracing::warn!(%msg, witness_height, restored_height, "checkpoint fallback detected");

        // Update in-memory snapshot.
        self.warning_store.set_checkpoint(&msg);

        // Durably publish the event marker.
        let event = ChainRollbackEvent::new(
            &self.genesis_hash,
            self.detecting_epoch,
            time,
            RollbackEventKind::CheckpointFallback {
                restored_height,
                restored_hash: restored_hash.to_owned(),
                source: source.to_owned(),
                old_height: witness_height,
                old_hash: old_hash.to_owned(),
            },
        );
        write_marker(&self.data_dir, &event)
    }

    /// Reports an index-watermark-ahead event. The warning snapshot is
    /// updated before the marker write, so a marker failure (returned to the
    /// caller) still leaves the fact RPC-visible for this process.
    pub(crate) fn report_index_ahead(
        &self,
        capability: &str,
        watermark_height: u32,
        restored_height: u32,
        restored_hash: &str,
        old_hash: &str,
        gap: u32,
        time: u64,
    ) -> Result<(), EvidenceError> {
        let msg = index_ahead_warning(capability, watermark_height, restored_height, gap);
        tracing::warn!(
            %msg, capability, watermark_height, restored_height, gap,
            "index watermark ahead of restored tip"
        );

        // Update in-memory snapshot (preserves checkpoint warning).
        self.warning_store.add_index(&msg);

        // Durably publish the event marker.
        let event = ChainRollbackEvent::new(
            &self.genesis_hash,
            self.detecting_epoch,
            time,
            RollbackEventKind::IndexWatermarkAhead {
                capability: capability.to_owned(),
                restored_height,
                restored_hash: restored_hash.to_owned(),
                old_height: watermark_height,
                old_hash: old_hash.to_owned(),
                gap,
            },
        );
        write_marker(&self.data_dir, &event)
    }
}
