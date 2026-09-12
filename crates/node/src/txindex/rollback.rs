//! Capability rollback, selective rebuilding, live seeding, and recovery evidence.

use super::DerivedIndexWorkerError;
use super::UndoScripts;
use super::Worker;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::ConsumerCursorUpdate;
use bitcoin_rs_index::IndexCapabilities;
use bitcoin_rs_index::IndexWatermark;
use bitcoin_rs_index::IndexWatermarks;
use bitcoin_rs_index::IndexWriteFence;
use bitcoin_rs_index::NoSpentScripts;
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_index::reconcile::ReconcileLeg;
use bitcoin_rs_primitives::Hash256;

pub(super) fn index_ahead_capability_label(capabilities: IndexCapabilities) -> Option<String> {
    let mut names = Vec::new();
    if capabilities.tx_lookup {
        names.push("tx_lookup");
    }
    if capabilities.script_history {
        names.push("script_history");
    }
    if capabilities.script_live {
        names.push("script_live");
    }
    (!names.is_empty()).then(|| names.join(","))
}

impl Worker {
    pub(super) fn seed_live_from_utxo(&self) -> Result<(), DerivedIndexWorkerError> {
        let Some(utxo) = self.utxo.as_ref() else {
            return Err(DerivedIndexWorkerError::MissingUtxo);
        };
        let Some(chain_transition) = self.chain_transition.as_ref() else {
            return Err(DerivedIndexWorkerError::MissingChainTransition);
        };
        // Hold chain-transition until the stable UTXO view is acquired so
        // `target` names the exact state we traverse. Release the transition
        // before persistence; the view guard keeps the scan consistent while
        // rows stream in bounded batches. Lock order matches apply:
        // chain_transition, then stable-view read.
        let (target, view) = {
            let _transition = chain_transition.lock();
            let current = self.applied_tip.load_full();
            let Some(current) = current.as_deref() else {
                return Ok(());
            };
            let target = IndexWatermark {
                height: current.height,
                hash: current.hash.to_le_bytes(),
            };
            (target, utxo.lock_stable_view())
        };

        // `seed_script_live_stream` owns leftover-row reset: an interrupted
        // seed is rows without a watermark, and the stream clears that
        // family before any new locator is committed.
        let written = self
            .writer
            .seed_script_live_stream(
                &mut |emit| {
                    let mut result = Ok(());
                    view.for_each_all(|outpoint, script| {
                        if result.is_err() {
                            return;
                        }
                        if let Err(error) = emit(*outpoint, ScriptHash::from_script_bytes(script)) {
                            result = Err(error);
                        }
                    });
                    result
                },
                target,
            )
            .map_err(DerivedIndexWorkerError::Index)?;
        tracing::info!(
            height = target.height,
            rows = written,
            "seeded ScriptLive after chainstate restoration"
        );
        Ok(())
    }

    /// Resets `capabilities` for a rebuild from genesis and publishes the
    /// rebuild phase, returning the post-reset fence and watermarks.
    pub(super) fn reset_for_rebuild(
        &self,
        capabilities: IndexCapabilities,
    ) -> Result<(IndexWriteFence, IndexWatermarks), DerivedIndexWorkerError> {
        self.writer
            .reset_capabilities(capabilities)
            .map_err(DerivedIndexWorkerError::Index)?;
        self.runtime
            .publish_leg(capabilities, ReconcileLeg::Rebuilding);
        self.writer
            .fenced_watermarks()
            .map_err(DerivedIndexWorkerError::Index)
    }

    /// Publishes the index-ahead rollback evidence for a watermark above the
    /// applied tip. The marker is part of the rollback transition: a data dir
    /// that cannot hold it fails this optional index, never the chain.
    pub(super) fn report_index_ahead(
        &self,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
        target: &TipSnapshot,
    ) -> Result<(), DerivedIndexWorkerError> {
        let Some(capability) = index_ahead_capability_label(capabilities) else {
            return Ok(());
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.reporter
            .report_index_ahead(
                &capability,
                watermark.height,
                target.height,
                &target.hash.to_string_be(),
                &Hash256::from_le_bytes(&watermark.hash).to_string_be(),
                watermark.height.saturating_sub(target.height),
                now,
            )
            .map_err(DerivedIndexWorkerError::RollbackEvidence)
    }

    /// Rolls back one complete block for every selected capability.
    pub(super) fn rollback_one(
        &self,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
    ) -> Result<Option<IndexWatermark>, DerivedIndexWorkerError> {
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
                .map_err(DerivedIndexWorkerError::Index)?;
            Some(IndexWatermark {
                height: watermark.height.saturating_sub(1),
                hash: prepared.parent_hash,
            })
        };

        if self.runtime.should_stop() {
            return Err(DerivedIndexWorkerError::Stopped);
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
            .map_err(DerivedIndexWorkerError::Index)?;
        Ok(prev)
    }

    pub(super) fn load_body(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<Vec<u8>, DerivedIndexWorkerError> {
        let Some(store) = self.body_store.as_ref() else {
            return Err(DerivedIndexWorkerError::NoBodyStore);
        };
        store
            .load_block_body(height, hash)
            .map_err(DerivedIndexWorkerError::Storage)?
            .ok_or(DerivedIndexWorkerError::MissingBody { height, hash })
    }

    pub(super) fn live_anchor(
        &self,
        height: u32,
        hash_bytes: [u8; 32],
    ) -> Result<UndoScripts, DerivedIndexWorkerError> {
        let hash = Hash256::from_le_bytes(&hash_bytes);
        let Some(store) = self.body_store.as_ref() else {
            return Err(DerivedIndexWorkerError::NoBodyStore);
        };
        let bytes = store
            .undo_record(height, hash)
            .map_err(DerivedIndexWorkerError::Storage)?
            .ok_or(DerivedIndexWorkerError::UndoUnavailable { height, hash })?;
        UndoScripts::from_undo_bytes(&bytes, hash)
            .map_err(|_| DerivedIndexWorkerError::UndoUnavailable { height, hash })
    }
}
