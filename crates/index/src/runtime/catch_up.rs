//! Bounded body-reader sessions, parallel preparation, and ordered batch admission.

use super::BlockIdentity;
use super::ChunkAction;
use super::DerivedIndexWorkerError;
use super::ForwardLeg;
use super::IDENTITY_CHUNK_BLOCKS;
use super::POSITION_PREFETCH_BLOCKS;
use super::PREPARE_CHUNK_BLOCKS;
use super::PREPARE_CHUNK_BYTES;
use super::PendingForward;
use super::ReconcileAction;
use super::Worker;
use crate::IndexCapabilities;
use crate::IndexCapability;
use crate::IndexError;
use crate::IndexWatermark;
use crate::IndexWatermarks;
use crate::IndexWriteFence;
use crate::NoSpentScripts;
use crate::PreparedBatch;
use crate::PreparedBlock;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyReader;
use bitcoin_rs_storage::pruning::{HistoryLease, HistoryUnavailable};
use rayon::prelude::*;
use std::ops::ControlFlow;
use std::time::Instant;

/// One block's preparation. The outer `Err` is a spent-script anchor failure,
/// which is read before any block is admitted; the inner result is the
/// writer's preparation outcome, which surfaces in height order at admission.
type AnchoredPreparation = Result<Result<PreparedBlock, IndexError>, DerivedIndexWorkerError>;

impl Worker {
    /// Copies one bounded chunk of active-chain identities under one short
    /// read lock.
    pub(super) fn collect_target_chain(
        &self,
        target: &TipSnapshot,
        start_height: u32,
        end_height: u32,
    ) -> Result<Vec<BlockIdentity>, DerivedIndexWorkerError> {
        let tree = self.block_tree.read();
        let capacity = usize::try_from(end_height.saturating_sub(start_height).saturating_add(1))
            .unwrap_or(usize::MAX);
        let mut identities = Vec::with_capacity(capacity);
        for height in start_height..=end_height {
            let node_id = tree
                .node_at_height_from(target.tip_id, height)
                .ok_or(DerivedIndexWorkerError::MissingTargetChain { height })?;
            let node = tree
                .node(node_id)
                .map_err(|_| DerivedIndexWorkerError::MissingTargetChain { height })?;
            let parent_hash = if height == 0 {
                [0_u8; 32]
            } else {
                let parent_id = tree
                    .parent_id(node_id)
                    .map_err(|_| DerivedIndexWorkerError::MissingTargetChain { height })?
                    .ok_or(DerivedIndexWorkerError::MissingTargetChain { height })?;
                let parent = tree
                    .node(parent_id)
                    .map_err(|_| DerivedIndexWorkerError::MissingTargetChain { height })?;
                *parent.hash.as_byte_array()
            };
            identities.push(BlockIdentity {
                height,
                hash: *node.hash.as_byte_array(),
                parent_hash,
            });
        }
        Ok(identities)
    }

    /// Runs one forward leg for `capabilities` from their shared `watermark`.
    ///
    /// Only an absent body with nothing retained answers
    /// [`ForwardLeg::BodyAbsent`], which is the one answer that lets the
    /// caller look at a different capability group. Retained rows keep their
    /// fence and flush deadline, so an absent body behind them answers
    /// `Buffered`: the rows commit at the deadline, and only the next pass,
    /// with `pending` empty and a fresh fence and watermark capture, may reach
    /// another group.
    #[expect(clippy::too_many_lines, reason = "Leg scheduling stays in one owner")]
    pub(super) fn catch_up_to(
        &self,
        target: &TipSnapshot,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        watermark: Option<IndexWatermark>,
        capabilities: IndexCapabilities,
        pending: &mut Option<PendingForward>,
        seed_lease: &mut Option<HistoryLease>,
    ) -> Result<ForwardLeg, DerivedIndexWorkerError> {
        if self.runtime.should_stop() {
            return Ok(ForwardLeg::Settled(ReconcileAction::Stalled));
        }

        let mut state = pending.take().unwrap_or_else(|| PendingForward {
            fence,
            watermarks,
            capabilities,
            durable: watermark,
            batch: PreparedBatch::new(self.batch_limits),
            deadline: Instant::now() + self.batch_delay,
        });
        if state.durable != watermark || state.capabilities != capabilities {
            return Err(DerivedIndexWorkerError::PendingDurableChanged);
        }
        let start_height = state.batch.watermark().map_or_else(
            || watermark.map_or(0, |w| w.height.saturating_add(1)),
            |endpoint| endpoint.height.saturating_add(1),
        );
        // The leg consumed the seed pin iff the seed covered this start and
        // the grant took it (leaving the slot empty).
        let seed_covering = seed_lease
            .as_ref()
            .is_some_and(|lease| lease.floor().is_some_and(|floor| floor <= start_height));
        let pass_history = match self.grant_leg_history(
            start_height,
            capabilities,
            target,
            &mut state,
            pending,
            seed_lease,
        )? {
            ControlFlow::Continue(lease) => lease,
            ControlFlow::Break(leg) => return Ok(leg),
        };
        let from_seed = seed_covering && seed_lease.is_none();
        if start_height > target.height {
            return Ok(ForwardLeg::Settled(
                if self.commit_forward(state, &pass_history)?.is_some() {
                    ReconcileAction::CaughtUp
                } else {
                    Self::park_unused_seed_lease(seed_lease, from_seed, pass_history);
                    ReconcileAction::Stalled
                },
            ));
        }

        let chunk_end = start_height
            .saturating_add(IDENTITY_CHUNK_BLOCKS - 1)
            .min(target.height);
        let identities = self.collect_target_chain(target, start_height, chunk_end)?;
        if self.runtime.should_stop() {
            Self::park_unused_seed_lease(seed_lease, from_seed, pass_history);
            return Ok(ForwardLeg::Settled(ReconcileAction::Stalled));
        }
        let Some(body_store) = self.body_store.as_ref() else {
            return Err(DerivedIndexWorkerError::NoBodyStore);
        };
        let mut body_reader = body_store
            .reader()
            .map_err(DerivedIndexWorkerError::Storage)?;
        let mut requests = Vec::with_capacity(POSITION_PREFETCH_BLOCKS);
        for identities in identities.chunks(POSITION_PREFETCH_BLOCKS) {
            if self.runtime.should_stop() {
                Self::park_unused_seed_lease(seed_lease, from_seed, pass_history);
                return Ok(ForwardLeg::Settled(ReconcileAction::Stalled));
            }
            requests.clear();
            requests.extend(
                identities
                    .iter()
                    .map(|identity| (identity.height, Hash256::from_le_bytes(&identity.hash))),
            );
            body_reader
                .prefetch_positions(&requests)
                .map_err(DerivedIndexWorkerError::Storage)?;

            // Sub-chunk: load bodies serially until the count or byte cap
            // (preserving the reader's prefetch state), prepare blocks in
            // parallel across the rayon pool, then push prepared blocks into
            // the batch in height order. The single-writer commit and
            // watermark publish remain the only ordering points.
            let mut remaining = identities;
            while !remaining.is_empty() {
                match self.prepare_and_admit_chunk(
                    &mut remaining,
                    &mut body_reader,
                    capabilities,
                    &mut state,
                    &pass_history,
                    pending,
                )? {
                    ChunkAction::Continue => {}
                    ChunkAction::Stalled => {
                        Self::park_unused_seed_lease(seed_lease, from_seed, pass_history);
                        return Ok(ForwardLeg::Settled(ReconcileAction::Stalled));
                    }
                    ChunkAction::Progressed => {
                        return Ok(ForwardLeg::Settled(ReconcileAction::Progressed));
                    }
                    ChunkAction::MissingBody if state.batch.is_empty() => {
                        Self::park_unused_seed_lease(seed_lease, from_seed, pass_history);
                        return Ok(ForwardLeg::BodyAbsent);
                    }
                    ChunkAction::MissingBody => {
                        // The prepared prefix keeps its fence and deadline and
                        // commits when the scheduler's deadline wait expires.
                        *pending = Some(state);
                        Self::park_unused_seed_lease(seed_lease, from_seed, pass_history);
                        return Ok(ForwardLeg::Settled(ReconcileAction::Buffered));
                    }
                }
            }
        }

        let action = self.finish_catch_up(state, chunk_end, target, &pass_history, pending)?;
        // Only a commit-backed advance releases the pin: any retained
        // `pending` rows keep their history cover, whether the pass stalled,
        // buffered, or progressed after the target tip moved past the batch
        // endpoint. A short `chunk_end` is one such retained case; a moved
        // tip at equal height is another.
        if !matches!(
            action,
            ReconcileAction::Progressed | ReconcileAction::CaughtUp
        ) || chunk_end < target.height
            || pending.is_some()
        {
            Self::park_unused_seed_lease(seed_lease, from_seed, pass_history);
        }
        Ok(ForwardLeg::Settled(action))
    }

    /// Parks a consumed seed pin back when the leg made no durable progress.
    /// Progress paths drop it (release is exact: advance-then-drop on durable
    /// progress); a lapsed pin drops too instead of parking dead weight.
    fn park_unused_seed_lease(
        seed_lease: &mut Option<HistoryLease>,
        from_seed: bool,
        pass_history: HistoryLease,
    ) {
        if from_seed && pass_history.floor().is_some() {
            *seed_lease = Some(pass_history);
        }
    }

    /// Asks the authority to hold this leg's history from `start_height`.
    ///
    /// While the grant lives no row at or above `start_height` is deleted, so
    /// a body that reads back absent is transient absence rather than lost
    /// history, and the pass never has to re-derive a prune line. A refusal is
    /// the owner's typed answer: `Pruned` disables filters (their header chain
    /// needs the full prefix); other indexes rebuild from what remains.
    /// `Reserved` and the transient answers only wait: a reservation can
    /// abort and release its range, and a missing row can still arrive.
    ///
    /// `Continue` carries the granted lease. `Break` is the leg's settled
    /// answer to a refusal. A refusal never answers `BodyAbsent`, so it never
    /// lets the caller look at another capability group.
    fn grant_leg_history(
        &self,
        start_height: u32,
        capabilities: IndexCapabilities,
        target: &TipSnapshot,
        state: &mut PendingForward,
        pending: &mut Option<PendingForward>,
        seed_lease: &mut Option<HistoryLease>,
    ) -> Result<ControlFlow<ForwardLeg, HistoryLease>, DerivedIndexWorkerError> {
        // Single-holder rule: a live seed pin covering this start is consumed
        // directly with no second `request_history`. Any other seed pin is
        // dropped before the fresh request — a dead pin is superseded, and a
        // live higher pin is subsumed by the lower grant (which pins a
        // superset while the committed seed watermark already covers that
        // height) — so no observer ever sees two live leases. A refusal
        // restores the live pin, so a transient `Reserved`, `Missing`,
        // `Shutdown`, or `Pruned` never loses the seed.
        let mut parked = None;
        if let Some(lease) = seed_lease.take() {
            if lease.floor().is_some_and(|floor| floor <= start_height) {
                return Ok(ControlFlow::Continue(lease));
            }
            if lease.floor().is_some() {
                parked = Some(lease);
            }
        }
        let action = match self.history.request_history(start_height) {
            Ok(lease) => return Ok(ControlFlow::Continue(lease)),
            Err(HistoryUnavailable::Pruned { below }) => {
                *seed_lease = parked;
                tracing::warn!(
                    below,
                    start_height,
                    "derived index needs history the pruning authority deleted"
                );
                // Prepared rows belong to the pre-reset position: the rebuild
                // re-derives from the frontier, so they cannot be carried.
                *pending = None;
                if capabilities.contains(IndexCapability::CompactFilters) {
                    self.runtime.fail_compact_filters(
                        &DerivedIndexWorkerError::HistoryUnavailable(HistoryUnavailable::Pruned {
                            below,
                        }),
                    );
                    ReconcileAction::Progressed
                } else if capabilities.contains(IndexCapability::ScriptLive) {
                    // D1: scoped terminal for `ScriptLive`. No
                    // `rebuild_from_pruned` (it would loop back into seeding)
                    // and no global worker failure. Demand stays wanted so a
                    // future token retries the seed without a history spin;
                    // other families keep their rows and settle next passes
                    // with selection skipping the failed capability. A fresh
                    // `Pruned` sets the flag again after any clear.
                    self.runtime
                        .fail_script_live(&DerivedIndexWorkerError::ScriptLiveHistoryPruned);
                    if let Some(slot) = self.seed_slot.as_ref() {
                        slot.want();
                    }
                    ReconcileAction::Stalled
                } else {
                    self.rebuild_from_pruned(capabilities, below, target)?
                }
            }
            Err(error) => {
                *seed_lease = parked;
                // The grant is deferred, not denied: keep the prepared rows
                // so the retry continues where this pass left off instead of
                // re-deriving them.
                if !state.batch.is_empty() {
                    *pending = Some(state.take(self.batch_limits));
                }
                tracing::debug!(%error, "derived index history grant deferred");
                ReconcileAction::Stalled
            }
        };
        Ok(ControlFlow::Break(ForwardLeg::Settled(action)))
    }

    /// Loads bodies serially until the count or byte cap, prepares that prefix
    /// in parallel across the rayon pool, then admits them into the batch in
    /// height order on the single writer thread. Advances `identities` past
    /// the loaded prefix.
    ///
    /// Returns `MissingBody` if a body is absent (the caller owns whether rows
    /// are retained), `Stalled` if shutdown was requested, the history pin was
    /// revoked, a commit was rejected, or an anchor failure reset a
    /// capability, `Progressed` if the batch filled and was committed or
    /// filters were disabled, or `Continue` to keep processing.
    ///
    /// Each block's spent-script anchor lives only inside its own preparation
    /// task. Before any block is admitted, the lowest-height anchor failure of
    /// the window is handled, so it outranks every preparation failure.
    #[allow(
        clippy::too_many_lines,
        reason = "Keep bounded preparation, capability failure and batch admission in one owner"
    )]
    pub(super) fn prepare_and_admit_chunk(
        &self,
        identities: &mut &[BlockIdentity],
        body_reader: &mut Box<dyn BlockBodyReader + '_>,
        capabilities: IndexCapabilities,
        state: &mut PendingForward,
        history: &HistoryLease,
        pending: &mut Option<PendingForward>,
    ) -> Result<ChunkAction, DerivedIndexWorkerError> {
        if self.runtime.should_stop() {
            return Ok(ChunkAction::Stalled);
        }
        // A held optional pin can still expire under a concurrent prune pass
        // (`floor()` answers `None` once revoked). Reading past it mislabels
        // deleted rows as transient absence and stalls this pass anyway, so
        // stop now and let the next `request_history` route the `Pruned`
        // refusal into the rebuild.
        if history.floor().is_none() {
            if !state.batch.is_empty() {
                *pending = Some(state.take(self.batch_limits));
            }
            return Ok(ChunkAction::Stalled);
        }

        let (bodies, missing_body) = self
            .load_body_prefix(body_reader.as_mut(), identities)
            .map_err(DerivedIndexWorkerError::Storage)?;
        if self.runtime.should_stop() {
            return Ok(ChunkAction::Stalled);
        }
        if bodies.is_empty() && missing_body {
            return Ok(ChunkAction::MissingBody);
        }
        let loaded = bodies.len();
        let sub_chunk = &identities[..loaded];

        let needs_anchor = capabilities.contains(IndexCapability::ScriptLive)
            || capabilities.contains(IndexCapability::CompactFilters);

        // Prepare blocks in parallel. A task decodes its block's anchor before
        // the writer's shared read lock is taken, so only the CPU-bound row
        // build runs under it, and drops the anchor when that block is
        // prepared. Anchors alive at once are therefore bounded by the tasks
        // in flight, not by the window. Without `ScriptLive` or
        // `CompactFilters` no undo record is read.
        //
        // `collect` into a plain `Vec` keeps index (height) order; rayon's own
        // `Result` collection would surface an arbitrary failure.
        let outcomes: Vec<AnchoredPreparation> = sub_chunk
            .par_iter()
            .zip(bodies.par_iter())
            .map(|(identity, body)| -> AnchoredPreparation {
                let prepare = |spent: &dyn crate::SpentCoinScripts| {
                    self.writer.prepare_block_with_spent_scripts(
                        capabilities,
                        identity.height,
                        identity.hash,
                        body.as_slice(),
                        spent,
                    )
                };
                if !needs_anchor {
                    return Ok(prepare(&NoSpentScripts));
                }
                let anchor = self.live_anchor(identity.height, identity.hash)?;
                Ok(prepare(&anchor))
            })
            .collect();
        drop(bodies);

        // Read the outcomes in height order for an anchor failure before any
        // block is admitted. The sequential `Result` collection stops at the
        // first failure, which is the lowest height. Preparation failures are
        // not examined here: they surface in order at admission below, after
        // the blocks before them have been admitted.
        let prepared = match outcomes.into_iter().collect::<Result<Vec<_>, _>>() {
            Ok(prepared) => prepared,
            Err(error @ DerivedIndexWorkerError::UndoUnavailable { .. }) => {
                // Prepared rows belong to the pre-reset position.
                *pending = None;
                if capabilities.contains(IndexCapability::CompactFilters) {
                    self.runtime.fail_compact_filters(&error);
                    return Ok(ChunkAction::Progressed);
                }
                self.writer
                    .reset_capabilities(IndexCapabilities::SCRIPT_LIVE)
                    .map_err(DerivedIndexWorkerError::Index)?;
                state.batch = PreparedBatch::new(self.batch_limits);
                self.runtime.fail_script_live(&error);
                if let Some(slot) = self.seed_slot.as_ref() {
                    slot.want();
                }
                tracing::warn!(error = %error, "ScriptLive unavailable after missing undo; awaiting verified seed");
                return Ok(ChunkAction::MissingBody);
            }
            Err(error) => return Err(error),
        };

        if self.runtime.should_stop() {
            return Ok(ChunkAction::Stalled);
        }

        // Push prepared blocks into the batch in height order on the single
        // writer thread.
        for (result, identity) in prepared.into_iter().zip(sub_chunk.iter()) {
            let prepared = result.map_err(DerivedIndexWorkerError::Index)?;
            if identity.height > 0 && prepared.parent_hash != identity.parent_hash {
                return Err(DerivedIndexWorkerError::MissingTargetChain {
                    height: identity.height,
                });
            }
            if state.batch.try_push(prepared).is_err() {
                return if self
                    .commit_forward(state.take(self.batch_limits), history)?
                    .is_some()
                {
                    Ok(ChunkAction::Progressed)
                } else {
                    Ok(ChunkAction::Stalled)
                };
            }
            if state.batch.is_full() {
                return if self
                    .commit_forward(state.take(self.batch_limits), history)?
                    .is_some()
                {
                    Ok(ChunkAction::Progressed)
                } else {
                    Ok(ChunkAction::Stalled)
                };
            }
        }
        *identities = &identities[loaded..];
        if missing_body {
            return Ok(ChunkAction::MissingBody);
        }
        Ok(ChunkAction::Continue)
    }

    pub(super) fn finish_catch_up(
        &self,
        state: PendingForward,
        chunk_end: u32,
        target: &TipSnapshot,
        history: &HistoryLease,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, DerivedIndexWorkerError> {
        if chunk_end < target.height {
            *pending = Some(state);
            return Ok(ReconcileAction::Progressed);
        }

        let endpoint = state.endpoint();
        let latest = self.applied_tip.load_full();
        if latest.as_deref().is_some_and(|tip| {
            endpoint.height < tip.height && self.watermark_is_on_target_chain(endpoint, tip)
        }) {
            *pending = Some(state);
            return Ok(ReconcileAction::Progressed);
        }

        if latest.as_deref().is_some_and(|tip| {
            endpoint.height == tip.height && endpoint.hash == tip.hash.to_le_bytes()
        }) {
            *pending = Some(state);
            return Ok(ReconcileAction::Buffered);
        }

        if self.commit_forward(state, history)?.is_some() {
            Ok(ReconcileAction::Progressed)
        } else {
            Ok(ReconcileAction::Stalled)
        }
    }

    /// Commits one forward batch and moves the history pin to the position
    /// that batch made durable.
    ///
    /// POST: the authority may then prune the history this consumer has
    /// already indexed, so a long catch-up costs a bounded window instead of
    /// every row above its starting watermark.
    fn commit_forward(
        &self,
        state: PendingForward,
        history: &HistoryLease,
    ) -> Result<Option<IndexWatermark>, DerivedIndexWorkerError> {
        let capabilities = state.capabilities;
        let durable = self.sync_and_commit(state)?;
        if let Some(endpoint) = durable.as_ref() {
            history.advance(endpoint.height.saturating_add(1));
            if capabilities.contains(IndexCapability::ScriptLive) {
                self.runtime.clear_script_live();
                self.release_seed_lease_if_superseded(Some(*endpoint));
            }
        }
        Ok(durable)
    }

    /// The permanent `Pruned` answer: reset `capabilities` and anchor their
    /// durable watermarks at the frontier so the rebuild starts at the first
    /// surviving height instead of asking for deleted history forever.
    ///
    /// `ScriptLive` needs no anchor: it reseeds from an immutable artifact or
    /// retained history, so the reset alone sends it through that path.
    fn rebuild_from_pruned(
        &self,
        capabilities: IndexCapabilities,
        below: u32,
        target: &TipSnapshot,
    ) -> Result<ReconcileAction, DerivedIndexWorkerError> {
        // `below` is at least 1: a refusal requires `floor < below` and no
        // floor is negative.
        let anchor_height = below - 1;
        if anchor_height > target.height {
            // The frontier has already passed the applied tip, so no
            // surviving row is indexable: the consumer keeps its derived
            // rows and waits rather than churning a reset every pass.
            return Ok(ReconcileAction::Stalled);
        }
        let anchored = capabilities.without(IndexCapability::ScriptLive);
        // Resolve the anchor identity before the durable reset: it is a pure
        // read — the block tree keeps headers for pruned heights — so a
        // missing node fails before any derived row is erased, not after.
        let identity = if anchored.is_empty() {
            None
        } else {
            Some(
                self.collect_target_chain(target, anchor_height, anchor_height)?
                    .into_iter()
                    .next()
                    .ok_or(DerivedIndexWorkerError::MissingTargetChain {
                        height: anchor_height,
                    })?,
            )
        };
        self.reset_for_rebuild(capabilities)?;
        let Some(identity) = identity else {
            return Ok(ReconcileAction::Progressed);
        };
        self.writer
            .anchor_watermark(
                anchored,
                IndexWatermark {
                    height: anchor_height,
                    hash: identity.hash,
                },
                below,
            )
            .map_err(DerivedIndexWorkerError::Index)?;
        Ok(ReconcileAction::Progressed)
    }

    /// Loads bodies for a prefix of `identities` in order, stopping once
    /// `PREPARE_CHUNK_BLOCKS` bodies are held or the serialized total reaches
    /// `PREPARE_CHUNK_BYTES`. Every body the reader hands out is retained, so the
    /// returned prefix is exactly the set of prefetched positions the reader
    /// consumed; the body that reaches the byte cap may carry the total past it.
    /// Stops early, keeping what was loaded, on shutdown. `Ok(None)` when a
    /// body is unavailable. Returns the loaded prefix and whether a successor
    /// was absent, so callers can retain the prefix instead of discarding it.
    fn load_body_prefix(
        &self,
        reader: &mut dyn BlockBodyReader,
        identities: &[BlockIdentity],
    ) -> Result<(Vec<Vec<u8>>, bool), StorageError> {
        let mut bodies = Vec::new();
        let mut loaded_bytes = 0_usize;
        for identity in identities.iter().take(PREPARE_CHUNK_BLOCKS) {
            if self.runtime.should_stop() {
                break;
            }
            let hash = Hash256::from_le_bytes(&identity.hash);
            let Some(body) = reader.load_block_body(identity.height, hash)? else {
                return Ok((bodies, true));
            };
            loaded_bytes = loaded_bytes.saturating_add(body.len());
            bodies.push(body);
            if loaded_bytes >= PREPARE_CHUNK_BYTES {
                break;
            }
        }
        Ok((bodies, false))
    }

    pub(super) fn wait_for_revision_quiet(&self, mut seen_revision: u64) -> Option<u64> {
        loop {
            if self.runtime.should_stop() {
                return None;
            }
            match self.wake_rx.recv_timeout(self.quiet_period) {
                Ok(()) => seen_revision = self.runtime.revision(),
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    let current = self.runtime.revision();
                    if current == seen_revision {
                        return Some(current);
                    }
                    seen_revision = current;
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// Waits for a wake hint or the pending batch's original deadline.
    pub(super) fn wait_for_batch_deadline(&self, deadline: Instant) -> BatchWait {
        if self.runtime.should_stop() {
            return BatchWait::Stopped;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return BatchWait::Deadline;
        };
        if remaining.is_zero() {
            return BatchWait::Deadline;
        }
        match self.wake_rx.recv_timeout(remaining) {
            Ok(()) if self.runtime.should_stop() => BatchWait::Stopped,
            Ok(()) => BatchWait::Woken,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) if self.runtime.should_stop() => {
                BatchWait::Stopped
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => BatchWait::Deadline,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => BatchWait::Stopped,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BatchWait {
    Woken,
    Deadline,
    Stopped,
}
