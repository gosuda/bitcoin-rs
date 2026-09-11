//! Reconciliation selection, recovery, and pending-window settlement.

use super::{
    PendingForward, ReconcileAction, TxIndexWorkerError, Worker, index_ahead_capability_label,
};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::{
    IndexCapabilities, IndexError, IndexWatermark, IndexWatermarks, IndexWriteFence, ScriptHash,
    reconcile::{ReconcileLeg, ReconcilePhase, SelectedWatermark, selected_watermark},
};
use bitcoin_rs_primitives::Hash256;
use std::{sync::Arc, time::Instant};

impl Worker {
    /// Reconciles the durable watermark to the current applied tip in one pass.
    ///
    /// All `BlockTree` data needed for the pass is copied under a short read
    /// lock before any body I/O or index commit.  Body loads, prepares, and
    /// commits happen with the lock released.
    pub(in crate::txindex) fn reconcile_once(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        let action = self.reconcile_pass(pending)?;
        if !matches!(action, ReconcileAction::CaughtUp) {
            return Ok(action);
        }
        // A forward leg commits one capability set at a time, so its
        // completion is only `CaughtUp` when no enabled capability needs
        // another transition against the current tip; otherwise the pass
        // merely progressed and the remaining legs (and their published
        // phase) carry over.
        let (target, _, watermarks) = self.capture_target_watermarks()?;
        if self
            .rollback_selection(watermarks, target.as_deref())
            .is_some()
            || target
                .as_deref()
                .is_some_and(|target| self.forward_selection(watermarks, target).is_some())
        {
            return Ok(ReconcileAction::Progressed);
        }
        self.runtime.publish_phase(ReconcilePhase::FORWARD);
        Ok(ReconcileAction::CaughtUp)
    }

    pub(in crate::txindex) fn reconcile_pass(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        let (target, fence, watermarks) = self.capture_target_watermarks()?;
        let leftover = self.enabled.leftover(watermarks);
        if !leftover.is_empty() {
            // `full` → `utxo` (and dropping internal TxLookup when explicit
            // `txindex` is off) must reset only the families that are no
            // longer configured. Live stays queryable through that demotion.
            self.writer
                .reset_capabilities(leftover)
                .map_err(TxIndexWorkerError::Index)?;
            return Ok(ReconcileAction::Progressed);
        }

        if pending.is_some() {
            return self.reconcile_pending(pending, fence, watermarks, target.as_deref());
        }

        let mut fence = fence;
        let mut watermarks = watermarks;
        let mut reported_ahead = false;
        while let Some((capabilities, watermark)) =
            self.rollback_selection(watermarks, target.as_deref())
        {
            // Report once per pass: an 834k-block stale branch would otherwise
            // report once per rolled-back block.
            if let Some(target) = target.as_deref()
                && !reported_ahead
                && watermark.height > target.height
            {
                reported_ahead = true;
                self.report_index_ahead(capabilities, watermark, target)?;
            }
            let depth = self.rollback_depth_for(watermark, target.as_deref());
            if depth.is_some_and(|depth| depth > self.rollback_rebuild_cutover) {
                tracing::warn!(
                    depth,
                    cutover = self.rollback_rebuild_cutover,
                    tx_lookup = capabilities.tx_lookup,
                    script_history = capabilities.script_history,
                    script_live = capabilities.script_live,
                    "stale index watermark exceeds the rollback cutover; rebuilding selected capabilities"
                );
                (fence, watermarks) = self.reset_for_rebuild(capabilities)?;
                continue;
            }
            self.runtime.publish_leg(
                capabilities,
                ReconcileLeg::RollingBack {
                    from_height: watermark.height,
                    to_height: depth.map_or(0, |depth| watermark.height.saturating_sub(depth)),
                },
            );
            match self.rollback_one(fence, watermarks, capabilities, watermark) {
                Ok(_) => {
                    let (next_fence, next_watermarks) = self
                        .writer
                        .fenced_watermarks()
                        .map_err(TxIndexWorkerError::Index)?;
                    fence = next_fence;
                    watermarks = next_watermarks;
                }
                Err(error @ TxIndexWorkerError::UndoUnavailable { .. }) => {
                    // Undo is the ScriptLive spend-script authority. TxLookup
                    // and ScriptHistory roll back from the block body alone,
                    // so a pruned undo must not force those families through
                    // a full rebuild.
                    tracing::warn!(
                        error = %error,
                        "index cursor cannot restore ScriptLive without undo; rebuilding ScriptLive"
                    );
                    (fence, watermarks) = self.reset_for_rebuild(IndexCapabilities::SCRIPT_LIVE)?;
                    continue;
                }
                Err(error) if error.requires_capability_rebuild() => {
                    tracing::warn!(
                        error = %error,
                        tx_lookup = capabilities.tx_lookup,
                        script_history = capabilities.script_history,
                        script_live = capabilities.script_live,
                        "index cursor cannot be rolled back; rebuilding selected capabilities"
                    );
                    (fence, watermarks) = self.reset_for_rebuild(capabilities)?;
                    continue;
                }
                Err(TxIndexWorkerError::Index(
                    IndexError::ResetInProgress | IndexError::StaleIndexState,
                )) => {
                    return Ok(ReconcileAction::Stalled);
                }
                Err(error) => return Err(error),
            }
        }
        // A rewind ends with the rollback loop; a rebuild ends only when the
        // reset capabilities reach the tip again.
        self.runtime
            .publish_phase(self.runtime.phase().rollbacks_finished());

        let Some(target) = target else {
            return Ok(ReconcileAction::CaughtUp);
        };
        // Live has no watermark after restoration, an interrupted seed, or a
        // same-pass `reset_for_rebuild`. Seed from one stable UTXO view
        // before `forward_selection` would replay it from genesis (`IDX-07`).
        if self.enabled.script_live && watermarks.script_live.is_none() {
            self.seed_live_from_utxo()?;
            return Ok(ReconcileAction::Progressed);
        }
        let Some((capabilities, watermark)) = self.forward_selection(watermarks, &target) else {
            return Ok(ReconcileAction::CaughtUp);
        };
        self.catch_up_to(&target, fence, watermarks, watermark, capabilities, pending)
    }

    pub(in crate::txindex) fn seed_live_from_utxo(&self) -> Result<(), TxIndexWorkerError> {
        let Some(utxo) = self.utxo.as_ref() else {
            return Err(TxIndexWorkerError::MissingUtxo);
        };
        let Some(chain_transition) = self.chain_transition.as_ref() else {
            return Err(TxIndexWorkerError::MissingChainTransition);
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
            .map_err(TxIndexWorkerError::Index)?;
        tracing::info!(
            height = target.height,
            rows = written,
            "seeded ScriptLive after chainstate restoration"
        );
        Ok(())
    }

    /// Resets `capabilities` for a rebuild from genesis and publishes the
    /// rebuild phase, returning the post-reset fence and watermarks.
    pub(in crate::txindex) fn reset_for_rebuild(
        &self,
        capabilities: IndexCapabilities,
    ) -> Result<(IndexWriteFence, IndexWatermarks), TxIndexWorkerError> {
        self.writer
            .reset_capabilities(capabilities)
            .map_err(TxIndexWorkerError::Index)?;
        self.runtime
            .publish_leg(capabilities, ReconcileLeg::Rebuilding);
        self.writer
            .fenced_watermarks()
            .map_err(TxIndexWorkerError::Index)
    }

    /// Publishes the index-ahead rollback evidence for a watermark above the
    /// applied tip. The marker is part of the rollback transition: a data dir
    /// that cannot hold it fails this optional index, never the chain.
    pub(in crate::txindex) fn report_index_ahead(
        &self,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
        target: &TipSnapshot,
    ) -> Result<(), TxIndexWorkerError> {
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
            .map_err(TxIndexWorkerError::RollbackEvidence)
    }

    pub(in crate::txindex) fn reconcile_pending(
        &self,
        pending: &mut Option<PendingForward>,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        target: Option<&TipSnapshot>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        let Some(state) = pending.as_ref() else {
            return Err(TxIndexWorkerError::PendingDurableChanged);
        };
        // Any fence change invalidates the retained rows. Discard them and
        // re-derive from the new reset, revision, and watermark state.
        if fence != state.fence {
            *pending = None;
            return Ok(ReconcileAction::Stalled);
        }
        // A different watermark under the same fence is an incoherent writer
        // response, not a concurrent commit. Treat it as corruption.
        if selected_watermark(watermarks, state.capabilities)
            != SelectedWatermark::Valid(state.durable)
        {
            return Err(TxIndexWorkerError::PendingDurableChanged);
        }
        let endpoint = state.endpoint();
        let Some(target) = target else {
            return if self.commit_pending(pending)? {
                Ok(ReconcileAction::Progressed)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        };

        if endpoint.height == target.height && endpoint.hash == target.hash.to_le_bytes() {
            if Instant::now() < state.deadline {
                return Ok(ReconcileAction::Buffered);
            }
            return if self.commit_pending(pending)? {
                Ok(ReconcileAction::CaughtUp)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        }
        if endpoint.height < target.height && self.watermark_is_on_target_chain(endpoint, target) {
            if Instant::now() >= state.deadline {
                return if self.commit_pending(pending)? {
                    Ok(ReconcileAction::Progressed)
                } else {
                    Ok(ReconcileAction::Stalled)
                };
            }
            return self.catch_up_to(
                target,
                state.fence,
                state.watermarks,
                state.durable,
                state.capabilities,
                pending,
            );
        }

        if self.commit_pending(pending)? {
            Ok(ReconcileAction::Progressed)
        } else {
            Ok(ReconcileAction::Stalled)
        }
    }

    pub(in crate::txindex) fn capture_target_watermarks(
        &self,
    ) -> Result<(Option<Arc<TipSnapshot>>, IndexWriteFence, IndexWatermarks), TxIndexWorkerError>
    {
        let (fence, watermarks) = self
            .writer
            .fenced_watermarks()
            .map_err(TxIndexWorkerError::Index)?;
        let target = self.applied_tip.load_full();
        Ok((target, fence, watermarks))
    }

    pub(in crate::txindex) fn rollback_selection(
        &self,
        watermarks: IndexWatermarks,
        target: Option<&TipSnapshot>,
    ) -> Option<(IndexCapabilities, IndexWatermark)> {
        let tx = self
            .enabled
            .tx_lookup
            .then_some(watermarks.tx_lookup)
            .flatten();
        let script_index = self
            .enabled
            .script_history
            .then_some(watermarks.script_history)
            .flatten();
        let script_live = self
            .enabled
            .script_live
            .then_some(watermarks.script_live)
            .flatten();
        let needs_rollback = |watermark: IndexWatermark| {
            target.is_none_or(|target| !self.watermark_is_on_target_chain(watermark, target))
        };
        let selected = [tx, script_index, script_live]
            .into_iter()
            .flatten()
            .filter(|watermark| needs_rollback(*watermark))
            .max_by_key(|watermark| watermark.height)?;
        Some((
            IndexCapabilities {
                tx_lookup: tx == Some(selected) && needs_rollback(selected),
                script_history: script_index == Some(selected) && needs_rollback(selected),
                script_live: script_live == Some(selected) && needs_rollback(selected),
            },
            selected,
        ))
    }

    pub(in crate::txindex) fn watermark_is_on_target_chain(
        &self,
        watermark: IndexWatermark,
        target: &TipSnapshot,
    ) -> bool {
        let tree = self.block_tree.read();
        crate::reconcile::position_on_active_chain(
            &tree,
            Hash256::from_le_bytes(&watermark.hash),
            watermark.height,
            target.tip_id,
        )
    }
    /// Canonical rollback-versus-rebuild depth for one watermark, captured
    /// under a short tree lock. `None` leaves the per-block rollback route:
    /// an unresolvable watermark hash or an absent target fails inside
    /// `rollback_one` into the error-driven reset arm.
    pub(in crate::txindex) fn rollback_depth_for(
        &self,
        watermark: IndexWatermark,
        target: Option<&TipSnapshot>,
    ) -> Option<u32> {
        let target = target?;
        let tree = self.block_tree.read();
        crate::reconcile::rollback_depth(
            &tree,
            Hash256::from_le_bytes(&watermark.hash),
            watermark.height,
            target.tip_id,
        )
    }
}
