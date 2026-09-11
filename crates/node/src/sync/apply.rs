//! Applied-chain handoff, prefix settlement, and reorg recovery.

use alloc::vec::Vec;

use bitcoin_rs_chain::plan_reorg;

use bitcoin_rs_primitives::{Block, Hash256};

use crate::apply::error::ApplyError;

use std::time::Instant;

use super::{BlockSync, expected::ExpectedBlockHashes};

pub(super) fn settle_window_failure(
    transition: crate::apply::ChainTransition<'_>,
    mut error: crate::apply::WindowApplyError,
) -> crate::apply::WindowApplyError {
    if matches!(error.source, ApplyError::UtxoCommit(_)) {
        error.disposition = crate::apply::WindowApplyDisposition::Fatal;
    } else if let Err(finish_source) = transition.finish() {
        tracing::error!(
            original = %error.source,
            finish = %finish_source,
            "chain transition could not be settled after a window failure; \
             mempool admission stays closed until recovery or restart"
        );
        error.disposition = crate::apply::WindowApplyDisposition::Fatal;
    }
    error
}

/// Settles a successful window: finishes the transition, or classifies a
/// finish failure as [`WindowApplyDisposition::Fatal`] when the reserved
/// even generation could not be published.
///
/// Symmetric with [`settle_window_failure`]: both paths attempt `finish`
/// and surface a `Fatal` disposition when the CAS fails, so the caller
/// stops retrying instead of wedging on an odd generation.
#[allow(clippy::result_large_err)]
pub(super) fn settle_window_success(
    transition: crate::apply::ChainTransition<'_>,
    applied: usize,
    committed: Vec<crate::apply::ConnectOutcome>,
) -> core::result::Result<usize, crate::apply::WindowApplyError> {
    match transition.finish() {
        Ok(()) => Ok(applied),
        Err(finish_source) => {
            tracing::error!(
                finish = %finish_source,
                "chain transition could not be settled after a committed window; \
                 mempool admission stays closed until recovery or restart"
            );
            Err(crate::apply::WindowApplyError {
                applied,
                committed,
                source: finish_source,
                disposition: crate::apply::WindowApplyDisposition::Fatal,
                invalidated: Box::default(),
            })
        }
    }
}

/// Where restoration of un-applied drained blocks must start.
///
/// When the whole chunk committed and only the chain-transition finish failed
/// (`stopped == chunk_len`), there is no refused block to skip: restoration
/// starts at the head of the next chunk, `chunk_start + stopped`. When a block
/// was refused inside the chunk (`stopped < chunk_len`), that block is dropped
/// for retry and restoration starts one past it, `chunk_start + stopped + 1`.
pub(super) fn restore_split(chunk_start: usize, stopped: usize, chunk_len: usize) -> usize {
    let base = chunk_start.saturating_add(stopped);
    if stopped < chunk_len {
        base.saturating_add(1)
    } else {
        base
    }
}
impl BlockSync {
    /// Applies a window, then dispatches derived consumers while the
    /// transition is still held.
    #[allow(clippy::result_large_err)]
    pub(super) fn apply_window_followed(
        &self,
        blocks: &[&Block],
        bodies: &[bytes::Bytes],
    ) -> core::result::Result<usize, crate::apply::WindowApplyError> {
        let transition =
            self.handles
                .begin_transition()
                .map_err(|source| crate::apply::WindowApplyError {
                    applied: 0,
                    committed: Vec::new(),
                    source,
                    // Admission can also stay closed after a prior torn
                    // `UtxoCommit` or a `Fatal` settlement; recovery must
                    // reset the gateway generation before a retry can begin
                    // (`ChainTransition` owns that recovery rule).
                    disposition: crate::apply::WindowApplyDisposition::Operational,
                    invalidated: Box::default(),
                })?;
        match transition.connect_window(blocks, bodies) {
            Ok(outcomes) => {
                for (block, outcome) in blocks.iter().zip(&outcomes) {
                    self.followers.connected(block, outcome);
                }
                let applied = outcomes.len();
                settle_window_success(transition, applied, outcomes)
            }
            Err(error) => {
                for (block, outcome) in blocks.iter().zip(&error.committed) {
                    self.followers.connected(block, outcome);
                }
                // `ChainTransition` documents which failures may safely
                // publish the reserved even generation.
                Err(settle_window_failure(transition, error))
            }
        }
    }

    /// Moves the applied chain onto the header tip's branch when it has been
    /// outweighed.
    ///
    /// `chain_tip` tracks the heaviest headers and `applied_tip` the validated
    /// chain; the two diverge exactly when a competing branch wins. Forward
    /// application cannot close that gap, because the blocks it wants to apply
    /// do not build on the applied tip.
    ///
    /// Availability is left to [`crate::reorg::switch_to_branch`]. It may
    /// commit the contiguous winning prefix already present in bounded staging,
    /// then report `MissingBody` for the first absent suffix block. Only a
    /// zero-length available connect prefix guarantees no mutation. Keeping
    /// this as one authority avoids a pre-check that can disagree with the
    /// transition witness.
    pub(super) fn switch_branch_if_outweighed(&self) {
        let Some(target) = self.outweighed_branch_target() else {
            return;
        };
        let outcome = crate::reorg::switch_to_branch(
            &self.handles,
            &self.followers,
            target,
            |hash| self.block_stager.lock().staged_body(hash),
            |hash| self.retire_applied_reorg_body(hash),
        );
        match outcome {
            Ok(()) => {
                let height = self
                    .handles
                    .applied_tip
                    .load_full()
                    .map_or(0, |tip| tip.height);
                tracing::info!(height, "block sync: switched to the heavier branch");
            }
            Err(crate::reorg::ReorgError::MissingBody { height, .. }) => {
                tracing::trace!(height, "block sync: heavier branch still downloading");
            }
            Err(error @ crate::reorg::ReorgError::Fatal(_)) => {
                self.handles.admission.close_permanently();
                self.handles
                    .shutdown
                    .store(true, std::sync::atomic::Ordering::Release);
                tracing::error!(
                    %error,
                    "block sync: chainstate torn by a failed disconnect, shutting down"
                );
            }
            Err(error @ crate::reorg::ReorgError::TransitionSettlement { .. }) => {
                // The reorg owner has closed admission and requested shutdown.
                tracing::error!(%error, "block sync: reorg generation settlement failed");
            }
            Err(error @ crate::reorg::ReorgError::CheckpointSettlement(_)) => {
                tracing::error!(
                    %error,
                    "block sync: reorg left checkpoint debt unsettled; a clean shutdown will retry"
                );
            }
            Err(crate::reorg::ReorgError::ConnectFailed {
                hash, invalidated, ..
            }) => {
                // Invalid descendants cannot occupy bounded download state or
                // they can prevent the newly selected valid branch from refilling.
                if !invalidated.is_empty() {
                    {
                        let mut stager = self.block_stager.lock();
                        for invalid_hash in &invalidated {
                            stager.retire_applied(invalid_hash);
                        }
                    }
                    {
                        let mut window = self.download_window.lock();
                        for invalid_hash in &invalidated {
                            window.drop_for_retry(invalid_hash);
                        }
                    }
                    // Invalidation can move the active branch away from the
                    // pinned assume-valid anchor.
                    self.handles
                        .assume_valid_gate
                        .evaluate(&self.handles.block_tree.read());
                }
                tracing::warn!(
                    failed_hash = %hash,
                    invalidated = invalidated.len(),
                    "block sync: connect failed"
                );
            }
            Err(crate::reorg::ReorgError::DisconnectBodyLost {
                disconnected,
                stopped_at,
                ..
            }) => {
                tracing::debug!(
                    disconnected,
                    stopped_at,
                    "block sync: disconnect body unreadable mid-rollback, coherent at reached tip"
                );
            }
            Err(error) => {
                tracing::warn!(%error, "block sync: branch switch failed");
            }
        }
    }

    pub(super) fn retire_applied_reorg_body(&self, hash: Hash256) {
        self.download_window.lock().mark_received_applied(&hash);
        self.block_stager.lock().retire_applied(&hash);
    }

    /// Returns the header tip when the applied chain is not on its branch.
    ///
    /// The applied tip is on the branch exactly when the header tip's ancestor
    /// at the applied height is the applied block itself.
    pub(super) fn outweighed_branch_target(&self) -> Option<bitcoin_rs_chain::NodeId> {
        let chain_tip = self.handles.chain_tip.load_full()?;
        let applied = self.handles.applied_tip.load_full()?;
        if chain_tip.hash == applied.hash {
            return None;
        }
        let tree = self.handles.block_tree.read();
        let applied_id = tree.lookup(applied.hash)?;
        let plan = plan_reorg(&tree, applied_id, chain_tip.tip_id).ok()?;
        (!plan.disconnect.is_empty()).then_some(chain_tip.tip_id)
    }

    /// Records a Fatal window settlement: logs the terminal state and latches
    /// the halt flag so later ticks keep staging inbound blocks but start no
    /// further chain transition. Staged blocks stay queued until recreation.
    pub(super) fn note_fatal_settlement(&self, stopped: usize, source: &ApplyError) {
        tracing::error!(
            applied = stopped,
            error = %source,
            "block sync: chain transition could not be settled; \
             mempool admission is closed and the node will not \
             retry until recovery or restart"
        );
        self.apply_halted
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn apply_buffered_blocks(
        &self,
        next_expected_hash: Option<Hash256>,
    ) -> (usize, usize) {
        // A latched Fatal settlement left the gateway generation odd: starting
        // another transition would bounce off `AlreadyActive` and churn staged
        // state every tick. Staged blocks stay queued until recreation. The
        // counter keeps the stall observable: the one `error!` in
        // `note_fatal_settlement` fires once, these ticks stay quiet.
        if self.apply_halted.load(std::sync::atomic::Ordering::SeqCst) {
            metrics::counter!("node.sync.apply_halted_ticks").increment(1);
            return (0, 0);
        }
        let mut applied = 0_usize;
        let mut failed = 0_usize;
        let Some(staged_count) = self
            .block_stager
            .lock()
            .ready_received_len(next_expected_hash)
        else {
            return (0, 0);
        };
        let started = Instant::now();
        let (drained, expected_len) = self
            .drain_cached_expected_blocks(staged_count)
            .unwrap_or_else(|| {
                // Cache miss: walk the block tree once for the expected run, drain
                // the staged prefix, and repopulate the cache from the freshly
                // computed hashes so subsequent rounds (as more blocks stage under
                // the same chain/applied tip) hit instead of re-walking.
                let horizon = self.expected_apply_horizon(staged_count);
                let run = self.expected_block_hashes(horizon);
                let expected_len = run.as_ref().map_or(0, |run| run.hashes.len());
                let drained = match run.as_ref() {
                    Some(run) => self.block_stager.lock().drain_expected_prefix(&run.hashes),
                    None => Vec::new(),
                };
                if let Some(run) = run {
                    self.populate_expected_apply_cache(run);
                }
                (drained, expected_len)
            });
        let mut applied_hashes = ExpectedBlockHashes::with_capacity(expected_len);
        let mut failed_hash = None;
        // Applied in windows, not one at a time: the window verifies every
        // block's input scripts in a single dispatch, which is where the
        // measured apply win comes from. Blocks still commit one by one and in
        // order inside the window, so nothing about the applied chain changes.
        let drained: Vec<_> = drained.into_iter().collect();
        let mut chunk_start = 0_usize;
        while chunk_start < drained.len() {
            // Bounded by block count AND by bytes, so a window of tip-sized
            // blocks does not hold gigabytes just because the count allows it.
            let chunk_end = chunk_start.saturating_add(crate::apply::window_len(
                drained[chunk_start..]
                    .iter()
                    .map(|drained| drained.serialized.len()),
            ));
            let chunk = &drained[chunk_start..chunk_end];
            // Borrowed, not cloned. `DrainedBlock` owns a whole block, so
            // cloning one deep-copies every transaction and witness; doing that
            // per block per window would spend the dispatch win on memcpy.
            let blocks: Vec<&Block> = chunk.iter().map(|drained| &drained.block).collect();
            let bodies: Vec<bytes::Bytes> = chunk
                .iter()
                .map(|drained| drained.serialized.clone())
                .collect();
            // The window reports how far it got rather than just failing,
            // because only the committed prefix may be marked applied; the rest
            // has to go back on the stager untouched.
            let committed = match self.apply_window_followed(&blocks, &bodies) {
                Ok(applied) => applied,
                Err(error) => {
                    let stopped = error.applied.min(chunk.len());
                    failed = failed.saturating_add(1);
                    let blocker = chunk.get(stopped);
                    if let Some(blocker) = blocker {
                        failed_hash = Some(blocker.hash);
                    }
                    if error.disposition == crate::apply::WindowApplyDisposition::Fatal {
                        self.note_fatal_settlement(stopped, &error.source);
                    } else if let Some(blocker) = blocker {
                        tracing::warn!(
                            hash = %blocker.hash,
                            error = %error.source,
                            "block sync: failed to apply buffered block"
                        );
                    }
                    for drained in chunk.iter().take(stopped) {
                        applied_hashes.push(drained.hash);
                    }
                    applied = applied.saturating_add(stopped);
                    // Everything after the block that failed, in the order it
                    // was drained: the rest of this chunk past the failure, then
                    // every chunk not yet attempted. When the whole chunk
                    // committed and only finish failed (`stopped == chunk.len()`),
                    // there is no refused block to skip, so restoration starts
                    // at the next chunk head.
                    let restore_from =
                        restore_split(chunk_start, stopped, chunk.len()).min(drained.len());
                    self.block_stager
                        .lock()
                        .restore_many(drained[restore_from..].iter().cloned());
                    if error.disposition == crate::apply::WindowApplyDisposition::Permanent {
                        // The failed block's descendants can never become
                        // valid, so they must not occupy bounded download
                        // state or the frontier would cycle on them forever.
                        // Purge every invalidated hash from the stager and
                        // from the window's pending/received maps; the
                        // expected-apply cache is dropped below because the
                        // round failed.
                        {
                            let mut stager = self.block_stager.lock();
                            for invalid_hash in &error.invalidated {
                                stager.retire_applied(invalid_hash);
                            }
                        }
                        {
                            let mut window = self.download_window.lock();
                            for invalid_hash in &error.invalidated {
                                window.drop_for_retry(invalid_hash);
                            }
                        }
                        metrics::counter!("node.sync.invalidated_blocks")
                            .increment(u64::try_from(error.invalidated.len()).unwrap_or(u64::MAX));
                    }
                    break;
                }
            };
            for drained in chunk.iter().take(committed) {
                applied_hashes.push(drained.hash);
            }
            applied = applied.saturating_add(committed);
            chunk_start = chunk_end;
        }
        if !applied_hashes.is_empty() || failed_hash.is_some() {
            {
                let mut window = self.download_window.lock();
                for hash in &applied_hashes {
                    window.mark_received_applied(hash);
                }
                if let Some(hash) = failed_hash {
                    window.drop_received_for_retry(&hash);
                }
            }
            self.advance_expected_apply_cache(&applied_hashes, failed_hash.is_some());
            metrics::histogram!("node.sync.apply_buffered_blocks_seconds")
                .record(started.elapsed().as_secs_f64());
        }
        (applied, failed)
    }
}
