//! Ordered staged-block commit draining and expected-prefix caching.

use super::BlockSync;
use super::ExpectedApplyCache;
use super::ExpectedBlockHashes;
use super::SchedulerState;
use super::chain::WindowApplyDisposition;
use bitcoin_rs_primitives::{BlockPayload, Hash256};
use std::time::Instant;
use std::vec::Vec;

use crate::block_stager::DrainedBlock;

/// Where restoration of un-applied drained blocks must start.
pub(super) fn restore_split(chunk_start: usize, stopped: usize, chunk_len: usize) -> usize {
    let base = chunk_start.saturating_add(stopped);
    if stopped < chunk_len {
        base.saturating_add(1)
    } else {
        base
    }
}

impl BlockSync {
    fn punish_permanent_block_delivery(&self, blocker: &DrainedBlock) {
        self.punish_permanent_delivery_source(blocker.source(), blocker.hash);
    }

    pub(super) fn punish_permanent_delivery_source(
        &self,
        source: Option<crate::PeerSource>,
        hash: bitcoin_rs_primitives::Hash256,
    ) {
        let Some(source) = source else {
            return;
        };
        if !self.peer_table.disconnect_source(source) {
            return;
        }
        self.clear_header_request_for(source);
        self.scheduler
            .lock()
            .window
            .mark_peer_unresponsive(source, Instant::now());
        metrics::counter!("node.sync.invalid_block_disconnects").increment(1);
        tracing::warn!(
            peer_addr = ?source.endpoint,
            %hash,
            "block sync: disconnected the connection that delivered a consensus-invalid block"
        );
    }

    pub(super) fn note_fatal_settlement(
        &self,
        stopped: usize,
        source: &(dyn core::error::Error + Send + Sync),
    ) {
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

    #[expect(clippy::too_many_lines)]
    pub(super) fn apply_buffered_blocks(
        &self,
        next_expected_hash: Option<Hash256>,
    ) -> (usize, usize) {
        if self.apply_halted.load(std::sync::atomic::Ordering::SeqCst) {
            metrics::counter!("node.sync.apply_halted_ticks").increment(1);
            return (0, 0);
        }
        if !self.applied_is_chain_ancestor() {
            return (0, 0);
        }
        let mut applied = 0_usize;
        let mut failed = 0_usize;
        let Some(staged_count) = self
            .scheduler
            .lock()
            .stager
            .ready_received_len(next_expected_hash)
        else {
            return (0, 0);
        };
        let started = Instant::now();
        let (drained, expected_len) = self
            .drain_cached_expected_blocks(staged_count)
            .unwrap_or_else(|| {
                let horizon = self.expected_apply_horizon(staged_count);
                let cache = self.expected_block_hashes(horizon);
                let expected_len = cache.as_ref().map_or(0, |c| c.hashes.len());
                let mut scheduler = self.scheduler.lock();
                let drained = match cache.as_ref() {
                    Some(c) => scheduler.stager.drain_expected_prefix(&c.hashes),
                    None => Vec::new(),
                };
                if let Some(c) = cache {
                    scheduler.populate_expected_apply_cache(c);
                }
                (drained, expected_len)
            });
        let mut applied_hashes = ExpectedBlockHashes::with_capacity(expected_len);
        let mut failed_hash = None;
        let mut failed_permanent = false;
        let drained: Vec<_> = drained.into_iter().collect();
        let mut chunk_start = 0_usize;
        while chunk_start < drained.len() {
            let chunk_end = chunk_start.saturating_add(
                self.chain.window_len(
                    &mut drained[chunk_start..]
                        .iter()
                        .map(|d| d.payload().bytes().len()),
                ),
            );
            let chunk = &drained[chunk_start..chunk_end];
            let payloads: Vec<&BlockPayload> = chunk
                .iter()
                .map(super::super::block_stager::DrainedBlock::payload)
                .collect();
            let committed = match self.chain.commit_window(&payloads) {
                Ok(applied) => applied,
                Err(error) => {
                    let stopped = error.applied.min(chunk.len());
                    failed = failed.saturating_add(1);
                    let blocker = chunk.get(stopped);
                    if let Some(blocker) = blocker {
                        failed_hash = Some(blocker.hash);
                    }
                    failed_permanent = error.disposition == WindowApplyDisposition::Permanent;
                    if error.disposition == WindowApplyDisposition::Fatal {
                        self.note_fatal_settlement(stopped, error.source.as_ref());
                    } else if let Some(blocker) = blocker {
                        tracing::warn!(
                            hash = %blocker.hash,
                            error = %error.source,
                            "block sync: failed to apply buffered block"
                        );
                    }
                    for drained in chunk.iter().take(stopped) {
                        applied_hashes.push(drained.hash);
                        if let Some(source) = drained.source() {
                            self.peer_table.note_useful_block(source);
                        }
                    }
                    applied = applied.saturating_add(stopped);
                    let restore_from =
                        restore_split(chunk_start, stopped, chunk.len()).min(drained.len());
                    self.scheduler
                        .lock()
                        .stager
                        .restore_many(drained[restore_from..].iter().cloned());
                    if error.disposition == WindowApplyDisposition::Permanent {
                        self.purge_invalidated(&error.invalidated);
                        metrics::counter!("node.sync.invalidated_blocks")
                            .increment(u64::try_from(error.invalidated.len()).unwrap_or(u64::MAX));
                        if let Some(blocker) = blocker {
                            self.punish_permanent_block_delivery(blocker);
                        }
                    }
                    break;
                }
            };
            for drained in chunk.iter().take(committed) {
                applied_hashes.push(drained.hash);
                if let Some(source) = drained.source() {
                    self.peer_table.note_useful_block(source);
                }
            }
            applied = applied.saturating_add(committed);
            chunk_start = chunk_end;
        }
        if !applied_hashes.is_empty() || failed_hash.is_some() {
            if let Some(hash) = failed_hash.filter(|_| !failed_permanent) {
                let failed_height = {
                    let tree = self.chain.block_tree();
                    tree.height_of_hash(hash)
                };
                self.scheduler.lock().window.requeue_for_retry(
                    &hash,
                    failed_height,
                    Instant::now(),
                );
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
    pub(super) fn expected_apply_horizon(&self, staged_count: usize) -> usize {
        let max_pending_blocks = self.scheduler.lock().window.max_pending_blocks();
        staged_count.max(max_pending_blocks)
    }

    /// Walks the active header chain from `applied_tip + 1` up to `max_count`
    /// blocks, snapshotting the chain/applied tip it walked against.
    fn expected_block_hashes(&self, max_count: usize) -> Option<ExpectedApplyCache> {
        if max_count == 0 {
            return None;
        }
        let chain_tip = self.chain.chain_tip()?;
        let applied_tip = self.chain.applied_tip()?;
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
        let tree = self.chain.block_tree();
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
        Some(ExpectedApplyCache {
            chain_tip_hash: chain_tip.hash,
            applied_tip_hash: applied_tip.hash,
            applied_tip_height: applied_tip.height,
            offset: 0,
            hashes,
        })
    }

    pub(super) fn drain_cached_expected_blocks(
        &self,
        max_count: usize,
    ) -> Option<(Vec<DrainedBlock>, usize)> {
        let chain_tip = self.chain.chain_tip()?;
        let applied_tip = self.chain.applied_tip()?;
        let mut scheduler = self.scheduler.lock();
        let SchedulerState {
            stager,
            expected_apply_cache,
            ..
        } = &mut *scheduler;
        let cache = expected_apply_cache.as_ref()?;
        if cache.chain_tip_hash != chain_tip.hash
            || cache.applied_tip_hash != applied_tip.hash
            || cache.applied_tip_height != applied_tip.height
        {
            *expected_apply_cache = None;
            return None;
        }
        let remaining = cache.hashes.len().saturating_sub(cache.offset);
        let expected_len = remaining.min(max_count);
        if expected_len == 0 {
            return None;
        }
        let expected_end = cache.offset.saturating_add(expected_len);
        let drained = stager.drain_expected_prefix(&cache.hashes[cache.offset..expected_end]);
        Some((drained, expected_len))
    }

    fn advance_expected_apply_cache(&self, applied_hashes: &[Hash256], failed: bool) {
        let mut scheduler = self.scheduler.lock();
        if failed || applied_hashes.is_empty() {
            if failed {
                scheduler.expected_apply_cache = None;
            }
            return;
        }
        if scheduler.expected_apply_cache.is_none() {
            return;
        }
        let Some(chain_tip) = self.chain.chain_tip() else {
            scheduler.expected_apply_cache = None;
            return;
        };
        let Some(applied_tip) = self.chain.applied_tip() else {
            scheduler.expected_apply_cache = None;
            return;
        };
        let Some(cache) = scheduler.expected_apply_cache.as_mut() else {
            return;
        };
        let applied_count = applied_hashes.len();
        let Some(expected_applied_height) = u32::try_from(applied_count)
            .ok()
            .and_then(|count| cache.applied_tip_height.checked_add(count))
        else {
            scheduler.expected_apply_cache = None;
            return;
        };
        if cache.chain_tip_hash != chain_tip.hash
            || cache.hashes.len().saturating_sub(cache.offset) < applied_count
            || cache.hashes[cache.offset..cache.offset.saturating_add(applied_count)]
                != *applied_hashes
            || applied_tip.height != expected_applied_height
            || applied_tip.hash != applied_hashes[applied_count - 1]
        {
            scheduler.expected_apply_cache = None;
            return;
        }
        cache.applied_tip_hash = applied_tip.hash;
        cache.applied_tip_height = applied_tip.height;
        cache.offset = cache.offset.saturating_add(applied_count);
        if cache.offset >= cache.hashes.len() {
            scheduler.expected_apply_cache = None;
        }
    }

    fn applied_is_chain_ancestor(&self) -> bool {
        let (Some(chain_tip), Some(applied_tip)) =
            (self.chain.chain_tip(), self.chain.applied_tip())
        else {
            return false;
        };
        let tree = self.chain.block_tree();
        Self::is_ancestor_at_height(
            &tree,
            applied_tip.tip_id,
            applied_tip.height,
            chain_tip.tip_id,
        )
    }

    pub(super) fn next_expected_block(&self) -> Option<(u32, Hash256)> {
        self.next_required_body()
            .map(|body| (body.height, body.hash))
    }

    pub(super) fn next_expected_block_hash(&self) -> Option<Hash256> {
        self.next_expected_block().map(|(_, hash)| hash)
    }
}
