//! Ordered staged-block application, generation settlement, and expected-prefix caching.

use super::BlockSync;
use super::ExpectedApplyCache;
use super::ExpectedBlockHashes;
use super::ExpectedRun;
use crate::apply::error::ApplyError;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitcoin_rs_p2p::DrainedBlock;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use std::time::Instant;

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

    /// Horizon for an apply-cache repopulation: the larger of `staged_count`
    /// (the run must cover this round's drain) and the download window's
    /// pending-block budget (so later rounds hit the cache).
    ///
    /// `staged_count` covers the blocks already ready to apply this round.
    /// Extending up to `max_pending_blocks` lets later rounds — which apply the
    /// blocks that were merely in flight when this run was computed — hit the
    /// cache instead of re-walking. The result is bounded by the larger of the
    /// two budgets: `staged_count` never exceeds the stager's
    /// `RECEIVED_BLOCK_BUDGET`, and the const assertion next to
    /// `ExpectedBlockHashes` pins that equal to `PENDING_BUDGET`, so the run
    /// always fits the inline `SmallVec` capacity.
    pub(super) fn expected_apply_horizon(&self, staged_count: usize) -> usize {
        // Snapshot the cap and release the window lock before any tree read so we
        // never invert the tree -> window lock order used elsewhere.
        let max_pending_blocks = self.download_window.lock().max_pending_blocks();
        staged_count.max(max_pending_blocks)
    }

    /// Walks the active header chain from `applied_tip + 1` up to `max_count`
    /// blocks, snapshotting the chain/applied tip it walked against.
    ///
    /// Returns `None` unless the run reaches `start_height` contiguously (the
    /// reorg / pruning guard); a partial run is never returned so the caller
    /// cannot apply or cache a non-contiguous prefix.
    pub(super) fn expected_block_hashes(&self, max_count: usize) -> Option<ExpectedRun> {
        if max_count == 0 {
            return None;
        }
        let chain_tip = self.handles.chain_tip.load_full()?;
        let applied_tip = self.handles.applied_tip.load_full()?;
        let start_height = applied_tip.height.checked_add(1)?;
        if start_height > chain_tip.height {
            return None;
        }

        let max_offset = u32::try_from(max_count.saturating_sub(1)).unwrap_or(u32::MAX);
        let end_height = start_height
            .saturating_add(max_offset)
            .min(chain_tip.height);
        let capacity = usize::try_from(end_height.saturating_sub(start_height).saturating_add(1))
            .unwrap_or(max_count);
        let tree = self.handles.block_tree.read();
        let mut cursor = tree.node_at_height_from(chain_tip.tip_id, end_height)?;
        let mut hashes = ExpectedBlockHashes::with_capacity(capacity);
        let mut reached_start = false;
        while let Ok(node) = tree.node(cursor) {
            if node.height < start_height {
                break;
            }
            hashes.push(node.hash);
            if node.height == start_height {
                reached_start = true;
                break;
            }
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
        }
        if !reached_start {
            return None;
        }
        hashes.reverse();
        Some(ExpectedRun {
            chain_tip_hash: chain_tip.hash,
            applied_tip_hash: applied_tip.hash,
            applied_tip_height: applied_tip.height,
            hashes,
        })
    }

    /// Repopulates the apply cache from a freshly computed expected run.
    ///
    /// Stores the full horizon at `offset: 0` keyed by the snapshot the run was
    /// computed against. `advance_expected_apply_cache` then advances `offset`
    /// past the blocks applied this round, so the next round drains the
    /// remaining suffix on a cache hit. The run is empty only when there is
    /// nothing to apply, in which case caching would be a no-op.
    pub(super) fn populate_expected_apply_cache(&self, run: ExpectedRun) {
        if run.hashes.is_empty() {
            return;
        }
        *self.expected_apply_cache.lock() = Some(ExpectedApplyCache {
            chain_tip_hash: run.chain_tip_hash,
            applied_tip_hash: run.applied_tip_hash,
            applied_tip_height: run.applied_tip_height,
            offset: 0,
            hashes: run.hashes,
        });
    }

    pub(super) fn drain_cached_expected_blocks(
        &self,
        max_count: usize,
    ) -> Option<(Vec<DrainedBlock>, usize)> {
        let chain_tip = self.handles.chain_tip.load_full()?;
        let applied_tip = self.handles.applied_tip.load_full()?;
        let cache = self.expected_apply_cache.lock();
        let cache = cache.as_ref()?;
        if cache.chain_tip_hash != chain_tip.hash
            || cache.applied_tip_hash != applied_tip.hash
            || cache.applied_tip_height != applied_tip.height
        {
            return None;
        }
        let remaining = cache.hashes.len().saturating_sub(cache.offset);
        let expected_len = remaining.min(max_count);
        if expected_len == 0 {
            return None;
        }
        let expected_end = cache.offset.saturating_add(expected_len);
        let drained = self
            .block_stager
            .lock()
            .drain_expected_prefix(&cache.hashes[cache.offset..expected_end]);
        Some((drained, expected_len))
    }

    pub(super) fn advance_expected_apply_cache(&self, applied_hashes: &[Hash256], failed: bool) {
        if failed {
            *self.expected_apply_cache.lock() = None;
            return;
        }
        if applied_hashes.is_empty() {
            return;
        }
        let mut cache_guard = self.expected_apply_cache.lock();
        if cache_guard.is_none() {
            return;
        }
        let Some(chain_tip) = self.handles.chain_tip.load_full() else {
            *cache_guard = None;
            return;
        };
        let Some(applied_tip) = self.handles.applied_tip.load_full() else {
            *cache_guard = None;
            return;
        };
        let Some(cache) = cache_guard.as_mut() else {
            return;
        };
        let applied_count = applied_hashes.len();
        let Some(expected_applied_height) = u32::try_from(applied_count)
            .ok()
            .and_then(|count| cache.applied_tip_height.checked_add(count))
        else {
            *cache_guard = None;
            return;
        };
        if cache.chain_tip_hash != chain_tip.hash
            || cache.hashes.len().saturating_sub(cache.offset) < applied_count
            || cache.hashes[cache.offset..cache.offset.saturating_add(applied_count)]
                != *applied_hashes
            || applied_tip.height != expected_applied_height
            || applied_tip.hash != applied_hashes[applied_count - 1]
        {
            *cache_guard = None;
            return;
        }
        cache.applied_tip_hash = applied_tip.hash;
        cache.applied_tip_height = applied_tip.height;
        cache.offset = cache.offset.saturating_add(applied_count);
        if cache.offset >= cache.hashes.len() {
            *cache_guard = None;
        }
    }

    pub(super) fn next_expected_block_hash(&self) -> Option<Hash256> {
        let chain_tip = self.handles.chain_tip.load_full()?;
        let applied_tip = self.handles.applied_tip.load_full()?;
        let height = applied_tip.height.checked_add(1)?;
        if height > chain_tip.height {
            return None;
        }
        let tree = self.handles.block_tree.read();
        let node_id = tree.node_at_height_from(chain_tip.tip_id, height)?;
        Some(tree.node(node_id).ok()?.hash)
    }

    pub(super) fn ensure_genesis_tip(&self) {
        if self.handles.applied_tip.load_full().is_some() {
            return;
        }

        let had_chain_tip = self.handles.chain_tip.load_full().is_some();
        let genesis = self.handles.network.genesis_block();
        match self.followers.apply_connect(&self.handles, &genesis) {
            Ok(outcome) => {
                if !had_chain_tip {
                    self.handles.chain_tip.store(Some(Arc::new(outcome.tip)));
                }
            }
            Err(error) => {
                tracing::warn!(%error, "block sync: failed to bootstrap genesis");
            }
        }
    }
}
