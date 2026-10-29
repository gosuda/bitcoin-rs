//! Index reconciliation state machine and supplied chain-position decisions.

use super::CursorCommit;
use super::DerivedIndexWorkerError;
use super::ForwardLeg;
use super::PendingForward;
use super::ReconcileAction;
use super::Worker;
use super::catch_up::BatchWait;
use super::rollback::SeedFlow;
use crate::IndexCapabilities;
use crate::IndexCapability;
use crate::IndexError;
use crate::IndexWatermark;
use crate::IndexWatermarks;
use crate::IndexWriteFence;
use crate::reconcile::ReconcileLeg;
use crate::reconcile::ReconcilePhase;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

/// First height a capability whose durable watermark is `watermark` still
fn forward_start(watermark: Option<IndexWatermark>) -> u32 {
    watermark.map_or(0, |watermark| watermark.height.saturating_add(1))
}

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
                if self
                    .wait_for_revision_quiet(self.runtime.revision())
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
                    match self.wait_for_batch_deadline(deadline) {
                        BatchWait::Woken => continue,
                        BatchWait::Deadline => {
                            if !self.commit_pending(&mut pending)? {
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
                    quiet_armed = true;
                }
            }
        }
        Ok(())
    }

    pub(super) fn reconcile_once(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, DerivedIndexWorkerError> {
        let action = self.reconcile_pass(pending)?;
        if !matches!(action, ReconcileAction::CaughtUp) {
            return Ok(action);
        }
        let (target, _, watermarks) = self.capture_target_watermarks()?;
        if self
            .rollback_selection(watermarks, target.as_deref())
            .is_some()
            || target
                .as_deref()
                .is_some_and(|target| self.forward_selection(watermarks, target, None).is_some())
        {
            return Ok(ReconcileAction::Progressed);
        }
        self.runtime.publish_phase(ReconcilePhase::FORWARD);
        Ok(ReconcileAction::CaughtUp)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep rollback recovery decisions and their fence updates together"
    )]
    pub(super) fn reconcile_pass(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, DerivedIndexWorkerError> {
        let (target, fence, watermarks) = self.capture_target_watermarks()?;
        let leftover = self.enabled.leftover(watermarks);
        if !leftover.is_empty() {
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
            if let Some(target) = target.as_deref()
                && !reported_ahead
                && watermark.height > target.height
            {
                reported_ahead = true;
                self.report_index_ahead(capabilities, watermark, target)?;
            }
            let depth = target.as_ref().and_then(|target| {
                crate::reconcile::block_tree::rollback_depth(
                    &self.block_tree.read(),
                    Hash256::from_le_bytes(&watermark.hash),
                    watermark.height,
                    target.tip_id,
                )
            });
            if depth.is_some_and(|depth| depth > self.rollback_rebuild_cutover) {
                tracing::warn!(
                    depth,
                    cutover = self.rollback_rebuild_cutover,
                    tx_lookup = capabilities.contains(IndexCapability::TxLookup),
                    script_history = capabilities.contains(IndexCapability::ScriptHistory),
                    script_live = capabilities.contains(IndexCapability::ScriptLive),
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
                    if capabilities.contains(IndexCapability::CompactFilters) {
                        self.runtime.fail_compact_filters(&error);
                        continue;
                    }
                    tracing::warn!(
                        error = %error,
                        "index cursor cannot restore ScriptLive without undo; rebuilding ScriptLive"
                    );
                    (fence, watermarks) = self.reset_for_rebuild(IndexCapabilities::SCRIPT_LIVE)?;
                    continue;
                }
                Err(error @ DerivedIndexWorkerError::HistoryUnavailable(_)) => {
                    if matches!(
                        error,
                        DerivedIndexWorkerError::HistoryUnavailable(
                            bitcoin_rs_storage::pruning::HistoryUnavailable::Pruned { .. }
                        )
                    ) && capabilities.contains(IndexCapability::CompactFilters)
                    {
                        self.runtime.fail_compact_filters(&error);
                        continue;
                    }
                    tracing::debug!(
                        error = %error,
                        "index rollback waits on a provisional history answer"
                    );
                    return Ok(ReconcileAction::Stalled);
                }
                Err(error) if error.requires_capability_rebuild() => {
                    if matches!(error, DerivedIndexWorkerError::MissingBody { .. })
                        && capabilities.contains(IndexCapability::ScriptLive)
                    {
                        tracing::warn!(
                            error = %error,
                            "ScriptLive rollback history pruned; marking unavailable"
                        );
                        self.runtime
                            .fail_script_live(&DerivedIndexWorkerError::ScriptLiveHistoryPruned);
                        if let Some(slot) = self.seed_slot.as_ref() {
                            slot.want();
                        }
                        continue;
                    }
                    tracing::warn!(
                        error = %error,
                        tx_lookup = capabilities.contains(IndexCapability::TxLookup),
                        script_history = capabilities.contains(IndexCapability::ScriptHistory),
                        script_live = capabilities.contains(IndexCapability::ScriptLive),
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
        self.finish_reconcile_pass(target, fence, watermarks, pending)
    }

    fn finish_reconcile_pass(
        &self,
        target: Option<Arc<TipSnapshot>>,
        mut fence: IndexWriteFence,
        mut watermarks: IndexWatermarks,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, DerivedIndexWorkerError> {
        self.runtime
            .publish_phase(self.runtime.phase().rollbacks_finished());
        let Some(target) = target else {
            return Ok(ReconcileAction::CaughtUp);
        };
        let mut want_on_stall = false;
        if self.enabled.contains(IndexCapability::ScriptLive) {
            if watermarks.script_live.is_some() {
                if self.runtime.script_live_failure.read().is_none() {
                    self.rest_seed_cell();
                } else {
                    self.writer
                        .reset_capabilities(IndexCapabilities::SCRIPT_LIVE)
                        .map_err(DerivedIndexWorkerError::Index)?;
                    (fence, watermarks) = self
                        .writer
                        .fenced_watermarks()
                        .map_err(DerivedIndexWorkerError::Index)?;
                    self.runtime.clear_script_live();
                    match self.seed_dispatch(pending.as_ref())? {
                        SeedFlow::Return(action) => return Ok(action),
                        SeedFlow::Seeded => return Ok(ReconcileAction::Progressed),
                        SeedFlow::FallThrough { want_on_stall: w } => want_on_stall = w,
                    }
                }
                self.release_seed_lease_if_superseded(watermarks.script_live);
            } else {
                match self.seed_dispatch(pending.as_ref())? {
                    SeedFlow::Return(action) => return Ok(action),
                    SeedFlow::Seeded => return Ok(ReconcileAction::Progressed),
                    SeedFlow::FallThrough { want_on_stall: w } => want_on_stall = w,
                }
            }
        }
        let mut seed_lease = self.take_seed_lease();
        let mut after_start = None;
        loop {
            let Some((capabilities, watermark)) =
                self.forward_selection(watermarks, &target, after_start)
            else {
                let action = if after_start.is_some() {
                    ReconcileAction::Stalled
                } else {
                    ReconcileAction::CaughtUp
                };
                self.park_seed_lease(seed_lease.take());
                if want_on_stall
                    && matches!(action, ReconcileAction::Stalled)
                    && watermarks.script_live.is_none()
                    && self.seed_bundle.lock().is_none()
                    && !self.runtime.should_stop()
                {
                    if let Some(slot) = self.seed_slot.as_ref() {
                        slot.want();
                    }
                }
                return Ok(action);
            };
            let leg = self.catch_up_to(
                &target,
                fence,
                watermarks,
                watermark,
                capabilities,
                pending,
                &mut seed_lease,
            )?;
            match leg {
                ForwardLeg::Settled(action) => {
                    if !matches!(action, ReconcileAction::CaughtUp) {
                        self.park_seed_lease(seed_lease.take());
                    }
                    return Ok(action);
                }
                ForwardLeg::BodyAbsent => after_start = Some(forward_start(watermark)),
            }
        }
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
        if fence != state.fence {
            *pending = None;
            return Ok(ReconcileAction::Stalled);
        }
        if watermarks.selected(state.capabilities).ok() != Some(state.durable) {
            return Err(DerivedIndexWorkerError::PendingDurableChanged);
        }
        let endpoint = state.endpoint();
        let Some(target) = target else {
            return if self.commit_pending_and_clear(pending)? {
                Ok(ReconcileAction::Progressed)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        };

        if endpoint.height == target.height && endpoint.hash == target.hash.to_le_bytes() {
            if Instant::now() < state.deadline {
                return Ok(ReconcileAction::Buffered);
            }
            return if self.commit_pending_and_clear(pending)? {
                Ok(ReconcileAction::CaughtUp)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        }
        if endpoint.height < target.height && self.watermark_is_on_target_chain(endpoint, target) {
            if Instant::now() >= state.deadline {
                return if self.commit_pending_and_clear(pending)? {
                    Ok(ReconcileAction::Progressed)
                } else {
                    Ok(ReconcileAction::Stalled)
                };
            }
            let mut no_seed_lease = None;
            let leg = self.catch_up_to(
                target,
                state.fence,
                state.watermarks,
                state.durable,
                state.capabilities,
                pending,
                &mut no_seed_lease,
            )?;
            return Ok(match leg {
                ForwardLeg::Settled(action) => action,
                ForwardLeg::BodyAbsent => ReconcileAction::Stalled,
            });
        }

        if self.commit_pending_and_clear(pending)? {
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

    pub(super) fn effective_enabled(&self) -> IndexCapabilities {
        let mut enabled = self.enabled;
        if self.runtime.compact_filter_failure.read().is_some() {
            enabled = enabled.without(IndexCapability::CompactFilters);
        }
        if self.runtime.script_live_failure.read().is_some() {
            enabled = enabled.without(IndexCapability::ScriptLive);
        }
        enabled
    }

    fn commit_pending_and_clear(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<bool, DerivedIndexWorkerError> {
        let capabilities = pending
            .as_ref()
            .map(|state| state.capabilities)
            .ok_or(DerivedIndexWorkerError::PendingDurableChanged)?;
        let endpoint = pending
            .as_ref()
            .map(PendingForward::endpoint)
            .ok_or(DerivedIndexWorkerError::PendingDurableChanged)?;
        let committed = self.commit_pending(pending)?;
        if committed && capabilities.contains(IndexCapability::ScriptLive) {
            self.runtime.clear_script_live();
            self.release_seed_lease_if_superseded(Some(endpoint));
        }
        Ok(committed)
    }

    pub(super) fn rollback_selection(
        &self,
        watermarks: IndexWatermarks,
        target: Option<&TipSnapshot>,
    ) -> Option<(IndexCapabilities, IndexWatermark)> {
        let enabled = self.effective_enabled();
        let enabled_watermark = |capability: IndexCapability| {
            enabled
                .contains(capability)
                .then_some(watermarks.get(capability))
                .flatten()
        };
        let needs_rollback = |watermark: IndexWatermark| {
            target.is_none_or(|target| !self.watermark_is_on_target_chain(watermark, target))
        };
        let selected = IndexCapability::ALL
            .into_iter()
            .filter_map(&enabled_watermark)
            .filter(|watermark| needs_rollback(*watermark))
            .max_by_key(|watermark| watermark.height)?;
        let selection = IndexCapability::ALL
            .into_iter()
            .filter(|&capability| {
                enabled_watermark(capability) == Some(selected)
                    && !(capability == IndexCapability::ScriptLive
                        && self.runtime.script_live_failure.read().is_some())
            })
            .collect();
        Some((selection, selected))
    }

    pub(super) fn forward_selection(
        &self,
        watermarks: IndexWatermarks,
        target: &TipSnapshot,
        after_start: Option<u32>,
    ) -> Option<(IndexCapabilities, Option<IndexWatermark>)> {
        let enabled = self.effective_enabled();
        let enabled_watermark = |capability: IndexCapability| {
            enabled
                .contains(capability)
                .then_some(watermarks.get(capability))
        };
        let needs_forward = |watermark: Option<IndexWatermark>| {
            watermark.is_none_or(|watermark| watermark.height < target.height)
        };
        let selected_start = IndexCapability::ALL
            .into_iter()
            .filter_map(&enabled_watermark)
            .filter(|watermark| needs_forward(*watermark))
            .map(forward_start)
            .filter(|start| after_start.is_none_or(|after| *start > after))
            .min()?;
        let selected_watermark = if selected_start == 0 {
            None
        } else {
            let height = selected_start - 1;
            IndexCapability::ALL
                .into_iter()
                .filter_map(&enabled_watermark)
                .flatten()
                .find(|watermark| watermark.height == height)
        };
        let selection = IndexCapability::ALL
            .into_iter()
            .filter(|&capability| {
                enabled_watermark(capability).is_some_and(|watermark| {
                    needs_forward(watermark) && forward_start(watermark) == selected_start
                })
            })
            .collect();
        Some((selection, selected_watermark))
    }

    pub(super) fn watermark_is_on_target_chain(
        &self,
        watermark: IndexWatermark,
        target: &TipSnapshot,
    ) -> bool {
        let tree = self.block_tree.read();
        crate::reconcile::block_tree::position_on_active_chain(
            &tree,
            Hash256::from_le_bytes(&watermark.hash),
            watermark.height,
            target.tip_id,
        )
    }
}
