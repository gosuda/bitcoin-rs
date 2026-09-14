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
        if start_height > target.height {
            return if self.sync_and_commit(state)?.is_some() {
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
                    pending,
                )? {
                    ChunkAction::Continue => {}
                    ChunkAction::Stalled => return Ok(ReconcileAction::Stalled),
                    ChunkAction::Progressed => return Ok(ReconcileAction::Progressed),
                }
            }
        }

        self.finish_catch_up(state, chunk_end, target, pending)
    }

    /// Loads bodies serially until the count or byte cap, prepares that prefix
    /// in parallel across the rayon pool, then admits them into the batch in
    /// height order on the single writer thread. Advances `identities` past
    /// the loaded prefix. Returns `Stalled` if a body is missing or shutdown
    /// was requested, `Progressed` if the batch filled and was committed, or
    /// `Continue` to keep processing.
    #[allow(clippy::too_many_lines)]
    pub(super) fn prepare_and_admit_chunk(
        &self,
        identities: &mut &[BlockIdentity],
        body_reader: &mut Box<dyn BlockBodyReader + '_>,
        capabilities: IndexCapabilities,
        state: &mut PendingForward,
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
                    .sync_and_commit(state.take(self.batch_limits))?
                    .is_some()
                {
                    Ok(ChunkAction::Progressed)
                } else {
                    Ok(ChunkAction::Stalled)
                };
            }
            if state.batch.is_full() {
                return if self
                    .sync_and_commit(state.take(self.batch_limits))?
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

        if self.sync_and_commit(state)?.is_some() {
            Ok(ReconcileAction::Progressed)
        } else {
            Ok(ReconcileAction::Stalled)
        }
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

#[cfg(all(test, feature = "fjall"))]
mod tests {
    use super::*;
    use bitcoin_rs_storage::FjallStore;
    use bitcoin_rs_storage::FlatFileBlockStore;
    use bitcoin_rs_storage::block_body::{BlockBodyStore, IndexedBlockBodyStore};
    use std::cell::Cell;
    use std::sync::Arc;
    fn identity(height: u32) -> BlockIdentity {
        let mut hash = [0_u8; 32];
        hash[0..4].copy_from_slice(&height.to_le_bytes());
        BlockIdentity {
            height,
            hash,
            parent_hash: [0_u8; 32],
        }
    }

    fn body_store(
        dir: &std::path::Path,
    ) -> Result<IndexedBlockBodyStore<FjallStore>, Box<dyn std::error::Error>> {
        let index = Arc::new(FjallStore::open(dir.join("index"))?);
        let files = Arc::new(FlatFileBlockStore::open(dir)?);
        Ok(IndexedBlockBodyStore::new(index, files))
    }

    /// The store's prefetched-position cursor is consumed strictly in request
    /// order: every `load_block_body` advances it. `load_body_prefix` must retain
    /// every body it loads, so `identities` advances by exactly the positions the
    /// cursor consumed (#1032).
    #[test]
    fn byte_cap_retains_every_body_the_cursor_consumed() -> Result<(), Box<dyn std::error::Error>> {
        // Three bodies of just over half the cap: the second reaches the cap.
        let size = PREPARE_CHUNK_BYTES / 2 + 1;
        let identities: Vec<BlockIdentity> = (0..3).map(identity).collect();

        let temp = tempfile::tempdir()?;
        let store = body_store(temp.path())?;
        for identity in &identities {
            store.persist_block_body(
                identity.height,
                Hash256::from_le_bytes(&identity.hash),
                &vec![0_u8; size],
            )?;
        }
        let requests: Vec<(u32, Hash256)> = identities
            .iter()
            .map(|identity| (identity.height, Hash256::from_le_bytes(&identity.hash)))
            .collect();
        let mut reader = store.reader()?;
        reader.prefetch_positions(&requests)?;

        let first = load_body_prefix(reader.as_mut(), &identities, &|| false)?
            .ok_or(StorageError::InvalidOperation("body missing"))?;
        assert_eq!(first.len(), 2);

        let rest = load_body_prefix(reader.as_mut(), &identities[first.len()..], &|| false)?
            .ok_or(StorageError::InvalidOperation("body missing"))?;
        assert_eq!(rest.len(), 1);

        // The cursor consumed all three prefetched positions; identities and the
        // reader are aligned.
        assert!(matches!(
            reader.load_block_body(
                identities[2].height,
                Hash256::from_le_bytes(&identities[2].hash)
            ),
            Err(StorageError::InvalidOperation(
                "prefetched body positions are exhausted"
            ))
        ));
        Ok(())
    }

    #[test]
    fn count_cap_bounds_the_prefix() -> Result<(), Box<dyn std::error::Error>> {
        let count = u32::try_from(PREPARE_CHUNK_BLOCKS)
            .map_err(|_| StorageError::InvalidOperation("cap exceeds u32"))?;
        let identities: Vec<BlockIdentity> = (0..=count).map(identity).collect();

        let temp = tempfile::tempdir()?;
        let store = body_store(temp.path())?;
        for identity in &identities {
            store.persist_block_body(
                identity.height,
                Hash256::from_le_bytes(&identity.hash),
                &[0_u8],
            )?;
        }
        let requests: Vec<(u32, Hash256)> = identities
            .iter()
            .map(|identity| (identity.height, Hash256::from_le_bytes(&identity.hash)))
            .collect();
        let mut reader = store.reader()?;
        reader.prefetch_positions(&requests)?;

        let first = load_body_prefix(reader.as_mut(), &identities, &|| false)?
            .ok_or(StorageError::InvalidOperation("body missing"))?;
        assert_eq!(first.len(), PREPARE_CHUNK_BLOCKS);

        // Exactly `PREPARE_CHUNK_BLOCKS` positions were consumed; the next cursor
        // entry is identities[256].
        let next = reader.load_block_body(
            identities[PREPARE_CHUNK_BLOCKS].height,
            Hash256::from_le_bytes(&identities[PREPARE_CHUNK_BLOCKS].hash),
        )?;
        assert!(next.is_some());
        Ok(())
    }

    /// A mid-load shutdown keeps the bodies already read: the returned prefix is
    /// still exactly the positions the cursor consumed.
    #[test]
    fn shutdown_keeps_the_prefix_aligned_with_the_cursor() -> Result<(), Box<dyn std::error::Error>>
    {
        let identities: Vec<BlockIdentity> = (0..3).map(identity).collect();

        let temp = tempfile::tempdir()?;
        let store = body_store(temp.path())?;
        for identity in &identities {
            store.persist_block_body(
                identity.height,
                Hash256::from_le_bytes(&identity.hash),
                &[0_u8],
            )?;
        }
        let requests: Vec<(u32, Hash256)> = identities
            .iter()
            .map(|identity| (identity.height, Hash256::from_le_bytes(&identity.hash)))
            .collect();
        let mut reader = store.reader()?;
        reader.prefetch_positions(&requests)?;

        // Shutdown is polled before each load; it fires on the second poll, so
        // only the first body is retained.
        let polls = Cell::new(0_u32);
        let should_stop = || {
            polls.set(polls.get() + 1);
            polls.get() >= 2
        };
        let prefix = load_body_prefix(reader.as_mut(), &identities, &should_stop)?
            .ok_or(StorageError::InvalidOperation("body missing"))?;
        assert_eq!(prefix.len(), 1);

        // The cursor sits at exactly position 1: loading identities[1] succeeds.
        let next = reader.load_block_body(
            identities[1].height,
            Hash256::from_le_bytes(&identities[1].hash),
        )?;
        assert!(next.is_some());
        Ok(())
    }
    use super::{BatchWait, wait_for_batch_deadline, wait_for_revision_quiet};
    use crate::runtime::DerivedIndexRuntime;

    // Contract: docs/contracts/indexing.md, version 1.1, IDX-08 (wake coalescing).
    #[test]
    fn coalesced_wakes_still_observe_the_latest_revision() {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let runtime = DerivedIndexRuntime::new(sender);
        runtime.wake();
        runtime.wake();
        assert_eq!(receiver.len(), 1);
        assert_eq!(runtime.revision(), 2);
        assert_eq!(
            wait_for_revision_quiet(&runtime, &receiver, Duration::ZERO, 0),
            Some(2)
        );
    }

    // Contract: docs/contracts/indexing.md, version 1.1, IDX-08 (shutdown precedence).
    #[test]
    fn shutdown_short_circuits_quiet_wait() {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let runtime = DerivedIndexRuntime::new(sender);
        runtime.request_shutdown();
        assert_eq!(
            wait_for_revision_quiet(&runtime, &receiver, Duration::ZERO, 0),
            None
        );
    }

    // Contract: docs/contracts/indexing.md, version 1.1, IDX-08 (shutdown precedence).
    #[test]
    fn shutdown_takes_precedence_over_an_expired_deadline() {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let runtime = DerivedIndexRuntime::new(sender);
        let deadline = Instant::now();
        runtime.request_shutdown();
        assert_eq!(
            wait_for_batch_deadline(&runtime, &receiver, deadline),
            BatchWait::Stopped
        );
    }

    // Contract: docs/contracts/indexing.md, version 1.1, IDX-08 (deadline expiry).
    #[test]
    fn an_expired_batch_deadline_does_not_wait_for_a_wake() {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let runtime = DerivedIndexRuntime::new(sender);
        assert_eq!(
            wait_for_batch_deadline(&runtime, &receiver, Instant::now()),
            BatchWait::Deadline
        );
    }

    // Contract: docs/contracts/indexing.md, version 1.1, IDX-08 (wake/deadline behavior).
    #[test]
    fn a_queued_wake_interrupts_the_wait_without_replacing_the_deadline() {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let runtime = DerivedIndexRuntime::new(sender);
        let deadline = Instant::now() + Duration::from_mins(1);
        runtime.wake();
        assert_eq!(
            wait_for_batch_deadline(&runtime, &receiver, deadline),
            BatchWait::Woken
        );
        assert_eq!(runtime.revision(), 1);
    }
}
