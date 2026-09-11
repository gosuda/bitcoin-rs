//! Tip-pinned expected-block runs and cache advancement.

use alloc::vec::Vec;

use bitcoin_rs_p2p::download_window::RECEIVED_BLOCK_BUDGET;

use bitcoin_rs_primitives::Hash256;

use smallvec::SmallVec;

use super::{BlockSync, stage::DrainedBlock};

pub(super) type ExpectedBlockHashes = SmallVec<[Hash256; RECEIVED_BLOCK_BUDGET]>;

#[derive(Clone, Debug)]
pub(super) struct ExpectedApplyCache {
    pub(super) chain_tip_hash: Hash256,
    pub(super) applied_tip_hash: Hash256,
    pub(super) applied_tip_height: u32,
    pub(super) offset: usize,
    pub(super) hashes: ExpectedBlockHashes,
}

/// A contiguous run of expected apply hashes together with the chain/applied
/// tip snapshot it was computed against.
///
/// The validity keys are captured at the moment the parent-walk reads the
/// block tree, so a cache built from this run is coherent with the hashes it
/// holds — no second `load_full` is taken (which would reopen a TOCTOU gap
/// between the hashes and the keys that guard them).
#[derive(Clone, Debug)]
pub(super) struct ExpectedRun {
    pub(super) chain_tip_hash: Hash256,
    pub(super) applied_tip_hash: Hash256,
    pub(super) applied_tip_height: u32,
    pub(super) hashes: ExpectedBlockHashes,
}
impl BlockSync {
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
}
