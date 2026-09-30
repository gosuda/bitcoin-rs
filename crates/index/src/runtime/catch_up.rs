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
use crate::IndexCapability;
use crate::IndexError;
use crate::IndexHistoryFailure;
use crate::IndexWatermark;
use crate::IndexWatermarks;
use crate::IndexWriteFence;
use crate::NoSpentScripts;
use crate::PreparedBatch;
use crate::PreparedBlock;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::{BlockBodyReader, BlockBodyStore};
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

        let state = pending.take().unwrap_or_else(|| PendingForward {
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
        if start_height > target.height {
            return if self.sync_and_commit(state)?.is_some() {
                Ok(ReconcileAction::CaughtUp)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        }
        let Some((pass_history, mut state)) =
            self.acquire_history(target, start_height, capabilities, state, pending)?
        else {
            return Ok(ReconcileAction::Stalled);
        };

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
            if let Err(error) = body_reader.prefetch_positions(&requests) {
                if matches!(error, StorageError::IncompatibleData(_)) {
                    let required =
                        first_incompatible_identity(body_store.as_ref(), identities)?.watermark();
                    return Err(DerivedIndexWorkerError::PermanentHistory {
                        capabilities,
                        failure: IndexHistoryFailure::Corrupt { required },
                    });
                }
                return Err(DerivedIndexWorkerError::Storage(error));
            }

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

    /// Asks the storage authority to hold this leg's history and preserves a
    /// prepared batch when that grant is only deferred.
    fn acquire_history(
        &self,
        target: &TipSnapshot,
        start_height: u32,
        capabilities: IndexCapabilities,
        state: PendingForward,
        pending: &mut Option<PendingForward>,
    ) -> Result<Option<(HistoryLease, PendingForward)>, DerivedIndexWorkerError> {
        match self.history.request_history(start_height) {
            Ok(lease) => Ok(Some((lease, state))),
            Err(HistoryUnavailable::Pruned { .. }) => {
                *pending = None;
                let required = self
                    .collect_target_chain(target, start_height, start_height)?
                    .into_iter()
                    .next()
                    .ok_or(DerivedIndexWorkerError::MissingTargetChain {
                        height: start_height,
                    })?;
                Err(DerivedIndexWorkerError::PermanentHistory {
                    capabilities,
                    failure: IndexHistoryFailure::Pruned {
                        required: required.watermark(),
                    },
                })
            }
            Err(HistoryUnavailable::Shutdown) => Err(DerivedIndexWorkerError::Stopped),
            Err(error @ (HistoryUnavailable::Reserved { .. } | HistoryUnavailable::Missing)) => {
                // The grant is deferred, not denied: keep the prepared rows
                // so the retry continues where this pass left off instead of
                // re-deriving them.
                if !state.batch.is_empty() {
                    *pending = Some(state);
                }
                tracing::debug!(%error, "derived index history grant deferred");
                Ok(None)
            }
            Err(HistoryUnavailable::Corrupt) => {
                *pending = None;
                let required = self
                    .collect_target_chain(target, start_height, start_height)?
                    .into_iter()
                    .next()
                    .ok_or(DerivedIndexWorkerError::MissingTargetChain {
                        height: start_height,
                    })?;
                Err(DerivedIndexWorkerError::PermanentHistory {
                    capabilities,
                    failure: IndexHistoryFailure::Corrupt {
                        required: required.watermark(),
                    },
                })
            }
        }
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
        // A held optional pin can still expire under a concurrent prune pass
        // (`floor()` answers `None` once revoked). Stop before another read
        // and let the next `request_history` route the owner's `Pruned`
        // refusal into the historical capability's terminal state.
        if history.floor().is_none() {
            if !state.batch.is_empty() {
                *pending = Some(state.take(self.batch_limits));
            }
            return Ok(ChunkAction::Stalled);
        }

        let bodies = load_body_prefix(body_reader.as_mut(), identities, &|| {
            self.runtime.should_stop()
        })
        .map_err(DerivedIndexWorkerError::Storage)?;
        let bodies = match bodies {
            BodyPrefix::Loaded(bodies) => bodies,
            BodyPrefix::Unavailable {
                identity: _,
                reason: HistoryUnavailable::Missing | HistoryUnavailable::Reserved { .. },
            } => {
                if !state.batch.is_empty() {
                    *pending = Some(state.take(self.batch_limits));
                }
                return Ok(ChunkAction::Stalled);
            }
            BodyPrefix::Unavailable {
                reason: HistoryUnavailable::Shutdown,
                ..
            } => return Err(DerivedIndexWorkerError::Stopped),
            BodyPrefix::Unavailable {
                identity,
                reason: HistoryUnavailable::Pruned { .. },
            } => {
                return Err(DerivedIndexWorkerError::PermanentHistory {
                    capabilities,
                    failure: IndexHistoryFailure::Pruned {
                        required: identity.watermark(),
                    },
                });
            }
            BodyPrefix::Unavailable {
                identity,
                reason: HistoryUnavailable::Corrupt,
            } => {
                return Err(DerivedIndexWorkerError::PermanentHistory {
                    capabilities,
                    failure: IndexHistoryFailure::Corrupt {
                        required: identity.watermark(),
                    },
                });
            }
        };
        if self.runtime.should_stop() {
            return Ok(ChunkAction::Stalled);
        }
        let loaded = bodies.len();
        let sub_chunk = &identities[..loaded];

        let anchors = if capabilities.contains(IndexCapability::ScriptLive) {
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
            let prepared = match result {
                Ok(prepared) => prepared,
                Err(IndexError::BlockParse(_) | IndexError::BlockIdentityMismatch { .. }) => {
                    return Err(DerivedIndexWorkerError::PermanentHistory {
                        capabilities,
                        failure: IndexHistoryFailure::Corrupt {
                            required: identity.watermark(),
                        },
                    });
                }
                Err(error) => return Err(DerivedIndexWorkerError::Index(error)),
            };
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
}

enum BodyPrefix {
    Loaded(Vec<Vec<u8>>),
    Unavailable {
        identity: BlockIdentity,
        reason: HistoryUnavailable,
    },
}

/// Loads bodies for a prefix of `identities` in order, stopping once
/// `PREPARE_CHUNK_BLOCKS` bodies are held or the serialized total reaches
/// `PREPARE_CHUNK_BYTES`. Every body the reader hands out is retained, so the
/// returned prefix is exactly the set of prefetched positions the reader
/// consumed; the body that reaches the byte cap may carry the total past it.
/// Stops early, keeping what was loaded, when `should_stop` reports shutdown.
/// Returns the storage owner's typed availability result with the exact first
/// identity that could not be loaded.
fn load_body_prefix(
    reader: &mut dyn BlockBodyReader,
    identities: &[BlockIdentity],
    should_stop: &dyn Fn() -> bool,
) -> Result<BodyPrefix, StorageError> {
    let mut bodies = Vec::new();
    let mut loaded_bytes = 0_usize;
    for identity in identities.iter().take(PREPARE_CHUNK_BLOCKS) {
        if should_stop() {
            break;
        }
        let hash = Hash256::from_le_bytes(&identity.hash);
        let body = match reader.load_retained_block_body(identity.height, hash) {
            Ok(Ok(body)) => body,
            Ok(Err(reason)) => {
                return Ok(BodyPrefix::Unavailable {
                    identity: *identity,
                    reason,
                });
            }
            Err(StorageError::IncompatibleData(_)) => {
                return Ok(BodyPrefix::Unavailable {
                    identity: *identity,
                    reason: HistoryUnavailable::Corrupt,
                });
            }
            Err(error) => return Err(error),
        };
        loaded_bytes = loaded_bytes.saturating_add(body.len());
        bodies.push(body);
        if loaded_bytes >= PREPARE_CHUNK_BYTES {
            break;
        }
    }
    Ok(BodyPrefix::Loaded(bodies))
}

/// Locates the first malformed retained locator after a batched prefetch
/// reports only an aggregate storage error. This runs only on corruption and
/// uses ordinary storage-owned reader sessions; it does not infer pruning
/// policy from rows or a copied frontier.
fn first_incompatible_identity(
    store: &dyn BlockBodyStore,
    identities: &[BlockIdentity],
) -> Result<BlockIdentity, StorageError> {
    for identity in identities {
        let hash = Hash256::from_le_bytes(&identity.hash);
        let mut reader = store.reader()?;
        match reader.load_retained_block_body(identity.height, hash) {
            Ok(Err(HistoryUnavailable::Corrupt)) | Err(StorageError::IncompatibleData(_)) => {
                return Ok(*identity);
            }
            Err(error) => return Err(error),
            Ok(_) => {}
        }
    }
    identities
        .first()
        .copied()
        .ok_or(StorageError::InvalidOperation(
            "incompatible body prefetch covered no identities",
        ))
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
