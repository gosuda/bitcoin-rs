//! Index reconciliation state machine and supplied chain-position decisions.

use super::CursorCommit;
use super::DerivedIndexWorkerError;
use super::PendingForward;
use super::ReconcileAction;
use super::Worker;
use super::scheduling::BatchWait;
use super::scheduling::wait_for_batch_deadline;
use super::scheduling::wait_for_revision_quiet;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::IndexCapabilities;
use bitcoin_rs_index::IndexError;
use bitcoin_rs_index::IndexWatermark;
use bitcoin_rs_index::IndexWatermarks;
use bitcoin_rs_index::IndexWriteFence;
use bitcoin_rs_index::reconcile::ReconcileLeg;
use bitcoin_rs_index::reconcile::ReconcilePhase;
use bitcoin_rs_index::reconcile::SelectedWatermark;
use bitcoin_rs_index::reconcile::selected_watermark;
use bitcoin_rs_primitives::Hash256;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

impl Worker {
    pub(super) fn run(self) -> Result<(), DerivedIndexWorkerError> {
        let mut quiet_armed = false;
        let mut pending = None;
        loop {
            if self.runtime.should_stop() {
                break;
            }
            if quiet_armed {
                quiet_armed = false;
                if wait_for_revision_quiet(
                    &self.runtime,
                    &self.wake_rx,
                    self.quiet_period,
                    self.runtime.revision(),
                )
                .is_none()
                {
                    break;
                }
            }

            let revision_before = self.runtime.revision();
            let action = match self.reconcile_once(&mut pending) {
                Ok(action) => action,
                Err(DerivedIndexWorkerError::Stopped) => break,
                Err(DerivedIndexWorkerError::Index(
                    IndexError::ResetInProgress | IndexError::StaleIndexState,
                )) => {
                    pending = None;
                    ReconcileAction::Stalled
                }
                Err(error) => return Err(error),
            };
            if self.runtime.should_stop() {
                break;
            }

            match action {
                ReconcileAction::Progressed => continue,
                ReconcileAction::CaughtUp => {
                    // A wake can be coalesced or consumed while this pass runs.
                    // The revision is authoritative: never sleep after it moved.
                    if self.runtime.revision() != revision_before {
                        continue;
                    }
                    match self.persist_chain_cursor()? {
                        CursorCommit::Settled => {}
                        CursorCommit::ResetRejected | CursorCommit::NotAligned => {
                            quiet_armed = true;
                            continue;
                        }
                    }
                    match self.wake_rx.recv_timeout(Duration::from_secs(1)) {
                        Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }
                }
                ReconcileAction::Buffered => {
                    let Some(deadline) = pending.as_ref().map(|state| state.deadline) else {
                        unreachable!("buffered action has a pending batch");
                    };
                    match wait_for_batch_deadline(&self.runtime, &self.wake_rx, deadline) {
                        BatchWait::Woken => continue,
                        BatchWait::Deadline => {
                            if !self.commit_pending(&mut pending)? {
                                // `commit_pending` already took the pending
                                // forward; `Ok(false)` means a retryable
                                // reset rejection, not a permanent failure.
                                // Exit only on shutdown; otherwise let the
                                // quiet wait throttle the retry.
                                if self.runtime.should_stop() {
                                    break;
                                }
                                quiet_armed = true;
                                continue;
                            }
                        }
                        BatchWait::Stopped => break,
                    }
                }
                ReconcileAction::Stalled => {
                    // Missing bodies and stopped writes retry only after one
                    // revision lull; forward progress never waits.
                    quiet_armed = true;
                }
            }
        }
        Ok(())
    }

    /// Reconciles the durable watermark to the current applied tip in one pass.
    ///
    /// All `BlockTree` data needed for the pass is copied under a short read
    /// lock before any body I/O or index commit.  Body loads, prepares, and
    /// commits happen with the lock released.
    pub(super) fn reconcile_once(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, DerivedIndexWorkerError> {
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

    pub(super) fn reconcile_pass(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, DerivedIndexWorkerError> {
        let (target, fence, watermarks) = self.capture_target_watermarks()?;
        let leftover = self.enabled.leftover(watermarks);
        if !leftover.is_empty() {
            // `full` → `utxo` (and dropping internal TxLookup when explicit
            // `txindex` is off) must reset only the families that are no
            // longer configured. Live stays queryable through that demotion.
            self.writer
                .reset_capabilities(leftover)
                .map_err(DerivedIndexWorkerError::Index)?;
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
                        .map_err(DerivedIndexWorkerError::Index)?;
                    fence = next_fence;
                    watermarks = next_watermarks;
                }
                Err(error @ DerivedIndexWorkerError::UndoUnavailable { .. }) => {
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
                Err(DerivedIndexWorkerError::Index(
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

    pub(super) fn reconcile_pending(
        &self,
        pending: &mut Option<PendingForward>,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        target: Option<&TipSnapshot>,
    ) -> Result<ReconcileAction, DerivedIndexWorkerError> {
        let Some(state) = pending.as_ref() else {
            return Err(DerivedIndexWorkerError::PendingDurableChanged);
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
            return Err(DerivedIndexWorkerError::PendingDurableChanged);
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

    pub(super) fn capture_target_watermarks(
        &self,
    ) -> Result<(Option<Arc<TipSnapshot>>, IndexWriteFence, IndexWatermarks), DerivedIndexWorkerError>
    {
        let (fence, watermarks) = self
            .writer
            .fenced_watermarks()
            .map_err(DerivedIndexWorkerError::Index)?;
        let target = self.applied_tip.load_full();
        Ok((target, fence, watermarks))
    }

    pub(super) fn rollback_selection(
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

    pub(super) fn forward_selection(
        &self,
        watermarks: IndexWatermarks,
        target: &TipSnapshot,
    ) -> Option<(IndexCapabilities, Option<IndexWatermark>)> {
        let tx = self.enabled.tx_lookup.then_some(watermarks.tx_lookup);
        let script_index = self
            .enabled
            .script_history
            .then_some(watermarks.script_history);
        let script_live = self.enabled.script_live.then_some(watermarks.script_live);
        let needs_forward = |watermark: Option<IndexWatermark>| {
            watermark.is_none_or(|watermark| watermark.height < target.height)
        };
        let start_height = |watermark: Option<IndexWatermark>| {
            watermark.map_or(0, |watermark| watermark.height.saturating_add(1))
        };
        let selected_start = [tx, script_index, script_live]
            .into_iter()
            .flatten()
            .filter(|watermark| needs_forward(*watermark))
            .map(start_height)
            .min()?;
        let selected_watermark = if selected_start == 0 {
            None
        } else {
            let height = selected_start - 1;
            [tx, script_index, script_live]
                .into_iter()
                .flatten()
                .flatten()
                .find(|watermark| watermark.height == height)
        };
        Some((
            IndexCapabilities {
                tx_lookup: tx.is_some_and(|watermark| {
                    needs_forward(watermark) && start_height(watermark) == selected_start
                }),
                script_history: script_index.is_some_and(|watermark| {
                    needs_forward(watermark) && start_height(watermark) == selected_start
                }),
                script_live: script_live.is_some_and(|watermark| {
                    needs_forward(watermark) && start_height(watermark) == selected_start
                }),
            },
            selected_watermark,
        ))
    }

    pub(super) fn watermark_is_on_target_chain(
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
    pub(super) fn rollback_depth_for(
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
