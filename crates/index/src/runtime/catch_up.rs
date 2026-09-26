//! Bounded body-reader sessions, parallel preparation, and ordered batch admission.

use super::BlockIdentity;
use super::ChunkAction;
use super::DerivedIndexRuntime;
use super::DerivedIndexWorkerError;
use super::IDENTITY_CHUNK_BLOCKS;
use super::POSITION_PREFETCH_BLOCKS;
use super::PREPARE_CHUNK_BLOCKS;
use super::PREPARE_CHUNK_BYTES;
use super::PendingForward;
use super::ReconcileAction;
use super::Worker;
use crate::IndexCapabilities;
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
use crossbeam_channel::Receiver;
use rayon::prelude::*;
use std::time::{Duration, Instant};

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

    pub(super) fn catch_up_to(
        &self,
        target: &TipSnapshot,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        watermark: Option<IndexWatermark>,
        capabilities: IndexCapabilities,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, DerivedIndexWorkerError> {
        if self.runtime.should_stop() {
            return Ok(ReconcileAction::Stalled);
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
        // Ask the authority to hold this leg's history. While the grant
        // lives no row at or above `start_height` is deleted, so a body that
        // reads back absent is transient absence rather than lost history,
        // and the pass never has to re-derive a prune line. A refusal is the
        // owner's typed answer: `Pruned` is permanent and routes to a rebuild
        // from what remains, while `Reserved` and the transient answers only
        // wait — a reservation can abort and release its range, and a missing
        // row can still arrive.
        let pass_history = match self.history.request_history(start_height) {
            Ok(lease) => lease,
            Err(HistoryUnavailable::Pruned { below }) => {
                tracing::warn!(
                    below,
                    start_height,
                    "derived index needs history the pruning authority deleted"
                );
                // Prepared rows belong to the pre-reset position: the rebuild
                // re-derives from the frontier, so they cannot be carried.
                *pending = None;
                return self.rebuild_from_pruned(capabilities, below, target);
            }
            Err(error) => {
                // The grant is deferred, not denied: keep the prepared rows
                // so the retry continues where this pass left off instead of
                // re-deriving them.
                if !state.batch.is_empty() {
                    *pending = Some(state);
                }
                tracing::debug!(%error, "derived index history grant deferred");
                return Ok(ReconcileAction::Stalled);
            }
        };
        if start_height > target.height {
            return if self.commit_forward(state, &pass_history)?.is_some() {
                Ok(ReconcileAction::CaughtUp)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        }

        let chunk_end = start_height
            .saturating_add(IDENTITY_CHUNK_BLOCKS - 1)
            .min(target.height);
        let identities = self.collect_target_chain(target, start_height, chunk_end)?;
        if self.runtime.should_stop() {
            return Ok(ReconcileAction::Stalled);
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
                return Ok(ReconcileAction::Stalled);
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
            // watermark publish remain the only ordering points (#209
            // invariants).
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
                    ChunkAction::Stalled => return Ok(ReconcileAction::Stalled),
                    ChunkAction::Progressed => return Ok(ReconcileAction::Progressed),
                }
            }
        }

        self.finish_catch_up(state, chunk_end, target, &pass_history, pending)
    }

    /// Loads bodies serially until the count or byte cap, prepares that prefix
    /// in parallel across the rayon pool, then admits them into the batch in
    /// height order on the single writer thread. Advances `identities` past
    /// the loaded prefix. Returns `Stalled` if a body is missing or shutdown
    /// was requested, `Progressed` if the batch filled and was committed, or
    /// `Continue` to keep processing.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::too_many_arguments)]
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

        let Some(bodies) = load_body_prefix(body_reader.as_mut(), identities, &|| {
            self.runtime.should_stop()
        })
        .map_err(DerivedIndexWorkerError::Storage)?
        else {
            if !state.batch.is_empty() {
                *pending = Some(state.take(self.batch_limits));
            }
            return Ok(ChunkAction::Stalled);
        };
        if self.runtime.should_stop() {
            return Ok(ChunkAction::Stalled);
        }
        let loaded = bodies.len();
        let sub_chunk = &identities[..loaded];

        let anchors = if capabilities.script_live {
            let mut anchors = Vec::with_capacity(sub_chunk.len());
            for identity in sub_chunk {
                match self.live_anchor(identity.height, identity.hash) {
                    Ok(anchor) => anchors.push(anchor),
                    Err(error @ DerivedIndexWorkerError::UndoUnavailable { .. }) => {
                        *pending = None;
                        self.writer
                            .reset_capabilities(IndexCapabilities::SCRIPT_LIVE)
                            .map_err(DerivedIndexWorkerError::Index)?;
                        tracing::warn!(error = %error, "rebuilding ScriptLive after pruned undo");
                        return Ok(ChunkAction::Stalled);
                    }
                    Err(error) => return Err(error),
                }
            }
            Some(anchors)
        } else {
            None
        };

        // Prepare blocks in parallel. Each call takes a shared read lock on the
        // RwLock-backed writer, so the CPU-bound decode/row-build runs
        // concurrently across pool threads.
        let prepared: Vec<Result<PreparedBlock, IndexError>> = sub_chunk
            .par_iter()
            .zip(bodies.par_iter())
            .enumerate()
            .map(|(index, (identity, body))| {
                let spent: &dyn crate::SpentCoinScripts = match anchors.as_ref() {
                    Some(anchors) => &anchors[index],
                    None => &NoSpentScripts,
                };
                self.writer.prepare_block_with_spent_scripts(
                    capabilities,
                    identity.height,
                    identity.hash,
                    body.as_slice(),
                    spent,
                )
            })
            .collect();
        drop(bodies);

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
        let durable = self.sync_and_commit(state)?;
        if let Some(endpoint) = durable.as_ref() {
            history.advance(endpoint.height.saturating_add(1));
        }
        Ok(durable)
    }

    /// The permanent `Pruned` answer: reset `capabilities` and anchor their
    /// durable watermarks at the frontier so the rebuild starts at the first
    /// surviving height instead of asking for deleted history forever.
    ///
    /// `ScriptLive` needs no anchor: it reseeds from the authoritative UTXO
    /// view at the tip, so the reset alone sends it through that path.
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
        let anchored = IndexCapabilities {
            script_live: false,
            ..capabilities
        };
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
}

/// Loads bodies for a prefix of `identities` in order, stopping once
/// `PREPARE_CHUNK_BLOCKS` bodies are held or the serialized total reaches
/// `PREPARE_CHUNK_BYTES`. Every body the reader hands out is retained, so the
/// returned prefix is exactly the set of prefetched positions the reader
/// consumed; the body that reaches the byte cap may carry the total past it.
/// Stops early, keeping what was loaded, when `should_stop` reports shutdown.
/// `Ok(None)` when a body is unavailable.
fn load_body_prefix(
    reader: &mut dyn BlockBodyReader,
    identities: &[BlockIdentity],
    should_stop: &dyn Fn() -> bool,
) -> Result<Option<Vec<Vec<u8>>>, StorageError> {
    let mut bodies = Vec::new();
    let mut loaded_bytes = 0_usize;
    for identity in identities.iter().take(PREPARE_CHUNK_BLOCKS) {
        if should_stop() {
            break;
        }
        let hash = Hash256::from_le_bytes(&identity.hash);
        let Some(body) = reader.load_block_body(identity.height, hash)? else {
            return Ok(None);
        };
        loaded_bytes = loaded_bytes.saturating_add(body.len());
        bodies.push(body);
        if loaded_bytes >= PREPARE_CHUNK_BYTES {
            break;
        }
    }
    Ok(Some(bodies))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BatchWait {
    Woken,
    Deadline,
    Stopped,
}

pub(super) fn wait_for_revision_quiet(
    runtime: &DerivedIndexRuntime,
    wake_rx: &Receiver<()>,
    quiet_period: Duration,
    mut seen_revision: u64,
) -> Option<u64> {
    loop {
        if runtime.should_stop() {
            return None;
        }
        match wake_rx.recv_timeout(quiet_period) {
            Ok(()) => seen_revision = runtime.revision(),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                let current = runtime.revision();
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
pub(super) fn wait_for_batch_deadline(
    runtime: &DerivedIndexRuntime,
    wake_rx: &Receiver<()>,
    deadline: Instant,
) -> BatchWait {
    if runtime.should_stop() {
        return BatchWait::Stopped;
    }
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return BatchWait::Deadline;
    };
    if remaining.is_zero() {
        return BatchWait::Deadline;
    }
    match wake_rx.recv_timeout(remaining) {
        Ok(()) if runtime.should_stop() => BatchWait::Stopped,
        Ok(()) => BatchWait::Woken,
        Err(crossbeam_channel::RecvTimeoutError::Timeout) if runtime.should_stop() => {
            BatchWait::Stopped
        }
        Err(crossbeam_channel::RecvTimeoutError::Timeout) => BatchWait::Deadline,
        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => BatchWait::Stopped,
    }
}
