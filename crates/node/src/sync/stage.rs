use bitcoin_rs_p2p::SyncBudget;

use bitcoin_rs_primitives::{Block, Hash256};

use hashbrown::{HashMap, hash_map::Entry};

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(super) struct BlockStager {
    budget: SyncBudget,
    received: HashMap<Hash256, ReceivedBlock>,
    received_order: VecDeque<Hash256>,
    received_bytes: usize,
    next_received_deadline: Option<Instant>,
    /// Highest staged-block population observed; feeds the high-water gauge.
    received_blocks_high_water: usize,
    /// Highest staged-byte total observed; feeds the high-water gauge.
    received_bytes_high_water: usize,
}

#[derive(Debug)]
struct ReceivedBlock {
    block: Block,
    // Preserved P2P wire payload, reused by `apply_block_with_serialized` to
    // skip reserialization. This is a second buffer (~block size) held next to
    // the decoded `block` while it waits for its predecessor, so a fully
    // out-of-order staging window holds roughly twice `bytes` per entry; both
    // are still bounded by the received-block budget (max_received_blocks /
    // max_received_bytes).
    serialized: bytes::Bytes,
    received_at: Instant,
    bytes: usize,
}

#[derive(Clone, Debug)]
pub(super) struct DrainedBlock {
    pub(super) hash: Hash256,
    pub(super) block: Block,
    pub(super) serialized: bytes::Bytes,
    received_at: Instant,
    bytes: usize,
}

#[derive(Clone, Debug)]
pub(super) struct DroppedBlock {
    pub(super) hash: Hash256,
}

#[derive(Clone, Debug)]
pub(super) enum StagedBlock {
    AlreadyStaged,
    Memory {
        bytes: usize,
        dropped: Vec<DroppedBlock>,
    },
    DroppedForRetry {
        dropped: DroppedBlock,
    },
}

impl BlockStager {
    pub(super) fn new(budget: SyncBudget) -> Self {
        Self {
            budget,
            received: HashMap::with_capacity(budget.max_received_blocks),
            received_order: VecDeque::with_capacity(budget.max_received_blocks),
            received_bytes: 0,
            next_received_deadline: None,
            received_blocks_high_water: 0,
            received_bytes_high_water: 0,
        }
    }

    pub(super) fn received_len(&self) -> usize {
        self.received.len()
    }

    pub(super) fn received_bytes(&self) -> usize {
        self.received_bytes
    }

    /// Highest staged-block population ever observed this run.
    pub(super) const fn received_high_water(&self) -> usize {
        self.received_blocks_high_water
    }

    /// Highest staged-byte total observed; feeds the high-water gauge.
    pub(super) const fn received_bytes_high_water(&self) -> usize {
        self.received_bytes_high_water
    }

    pub(super) fn ready_received_len(&self, next_expected_hash: Option<Hash256>) -> Option<usize> {
        let received_len = self.received.len();
        if received_len == 0 {
            return None;
        }
        if let Some(next_expected_hash) = next_expected_hash
            && !self.received.contains_key(&next_expected_hash)
        {
            return None;
        }
        Some(received_len)
    }

    pub(super) fn insert(
        &mut self,
        hash: Hash256,
        next_expected_hash: Option<Hash256>,
        block: Block,
        serialized: bytes::Bytes,
        now: Instant,
    ) -> StagedBlock {
        let entry = match self.received.entry(hash) {
            Entry::Occupied(_) => return StagedBlock::AlreadyStaged,
            Entry::Vacant(entry) => entry,
        };
        let bytes = serialized.len();
        debug_assert_eq!(bytes, block_size(&block));
        if bytes > self.budget.max_received_bytes {
            return StagedBlock::DroppedForRetry {
                dropped: DroppedBlock { hash },
            };
        }
        // Byte-budget exhaustion is backpressure, not eviction: refuse the
        // incoming block (it stays re-requestable through the window's
        // drop-for-retry path) instead of evicting already-downloaded staged
        // progress into re-download churn. The next expected block is exempt —
        // it unblocks the apply frontier immediately, and refusing it while
        // staged successors hold the budget would deadlock the window.
        if Some(hash) != next_expected_hash
            && self.received_bytes.saturating_add(bytes) > self.budget.max_received_bytes
        {
            return StagedBlock::DroppedForRetry {
                dropped: DroppedBlock { hash },
            };
        }

        entry.insert(ReceivedBlock {
            block,
            serialized,
            received_at: now,
            bytes,
        });
        self.received_order.push_back(hash);
        self.received_bytes = self.received_bytes.saturating_add(bytes);
        self.received_blocks_high_water = self.received_blocks_high_water.max(self.received.len());
        self.received_bytes_high_water = self.received_bytes_high_water.max(self.received_bytes);
        self.track_received_deadline(now);

        let dropped = if self.is_over_count_budget() {
            self.evict_over_budget(next_expected_hash)
        } else {
            Vec::new()
        };
        if !dropped.is_empty() {
            self.refresh_next_received_deadline();
        }
        self.maybe_compact_received_order();

        StagedBlock::Memory { bytes, dropped }
    }

    /// Whether `hash` is currently staged. Feeds the stall detector's
    /// no-blame guard: a staged next-expected block means the apply side owns
    /// the frontier.
    pub(super) fn contains(&self, hash: &Hash256) -> bool {
        self.received.contains_key(hash)
    }

    /// Clones one staged decoded body and its original wire bytes without
    /// removing it from the bounded staging set.
    pub(super) fn staged_body(&self, hash: Hash256) -> Option<(Block, bytes::Bytes)> {
        self.received
            .get(&hash)
            .map(|entry| (entry.block.clone(), entry.serialized.clone()))
    }

    /// Releases one body after that exact block commits during a branch switch.
    pub(super) fn retire_applied(&mut self, hash: &Hash256) -> bool {
        let removed = self.take_entry(hash).is_some();
        if self.received.is_empty() {
            self.received_order.clear();
            self.next_received_deadline = None;
        }
        removed
    }

    pub(super) fn drain_expected_prefix(
        &mut self,
        expected_hashes: &[Hash256],
    ) -> Vec<DrainedBlock> {
        let mut drained = Vec::with_capacity(expected_hashes.len());
        for hash in expected_hashes {
            let Some(block) = self.take_entry(hash) else {
                break;
            };
            drained.push(block);
        }
        if self.received.is_empty() {
            self.received_order.clear();
            self.next_received_deadline = None;
        }
        drained
    }

    pub(super) fn restore_many(&mut self, drained: impl IntoIterator<Item = DrainedBlock>) {
        for drained in drained {
            let previous = self.received.insert(
                drained.hash,
                ReceivedBlock {
                    block: drained.block,
                    serialized: drained.serialized,
                    received_at: drained.received_at,
                    bytes: drained.bytes,
                },
            );
            if let Some(previous) = previous {
                self.received_bytes = self.received_bytes.saturating_sub(previous.bytes);
            } else if !self.received_order_contains(&drained.hash) {
                self.received_order.push_back(drained.hash);
            }
            self.received_bytes = self.received_bytes.saturating_add(drained.bytes);
            self.track_received_deadline(drained.received_at);
        }
        self.maybe_compact_received_order();
    }

    fn take_entry(&mut self, hash: &Hash256) -> Option<DrainedBlock> {
        let entry = self.received.remove(hash)?;
        self.received_bytes = self.received_bytes.saturating_sub(entry.bytes);
        Some(DrainedBlock {
            hash: *hash,
            block: entry.block,
            serialized: entry.serialized,
            received_at: entry.received_at,
            bytes: entry.bytes,
        })
    }

    pub(super) fn prune_expired(&mut self, now: Instant) -> Vec<DroppedBlock> {
        if self.received.is_empty() {
            self.next_received_deadline = None;
            return Vec::new();
        }
        if self
            .next_received_deadline
            .is_none_or(|deadline| now < deadline)
        {
            return Vec::new();
        }

        let mut dropped = Vec::new();
        let mut received_bytes = self.received_bytes;
        let mut next_received_deadline = None;
        let timeout = self.budget.received_timeout;
        self.received.retain(|hash, entry| {
            let deadline = received_deadline(entry.received_at, timeout);
            if now < deadline {
                next_received_deadline = Some(
                    next_received_deadline
                        .map_or(deadline, |current: Instant| current.min(deadline)),
                );
                return true;
            }
            received_bytes = received_bytes.saturating_sub(entry.bytes);
            dropped.push(DroppedBlock { hash: *hash });
            false
        });
        self.received_bytes = received_bytes;
        self.next_received_deadline = next_received_deadline;
        self.maybe_compact_received_order();
        dropped
    }

    fn evict_over_budget(&mut self, next_expected_hash: Option<Hash256>) -> Vec<DroppedBlock> {
        let mut dropped = Vec::new();
        while self.is_over_count_budget() {
            let Some(hash) = self.oldest_unprotected_candidate(next_expected_hash) else {
                break;
            };
            if let Some(evicted) = self.remove(&hash) {
                dropped.push(evicted);
            }
        }
        dropped
    }

    fn oldest_unprotected_candidate(
        &mut self,
        next_expected_hash: Option<Hash256>,
    ) -> Option<Hash256> {
        while let Some(hash) = self.received_order.pop_front() {
            if !self.received.contains_key(&hash) {
                continue;
            }
            if Some(hash) == next_expected_hash {
                self.received_order.push_front(hash);
                break;
            }
            return Some(hash);
        }
        let candidate_index = self.received_order.iter().position(|hash| {
            Some(*hash) != next_expected_hash && self.received.contains_key(hash)
        })?;
        self.received_order.remove(candidate_index)
    }

    /// Only the slot-count budget evicts staged blocks. The byte budget is
    /// enforced as admission backpressure in [`Self::insert`] (with a bounded
    /// overshoot for the next expected block), so byte exhaustion can never
    /// trigger evict/re-download churn.
    fn is_over_count_budget(&self) -> bool {
        self.received.len() > self.budget.max_received_blocks
    }

    fn remove(&mut self, hash: &Hash256) -> Option<DroppedBlock> {
        let entry = self.received.remove(hash)?;
        self.received_bytes = self.received_bytes.saturating_sub(entry.bytes);
        Some(DroppedBlock { hash: *hash })
    }

    fn track_received_deadline(&mut self, received_at: Instant) {
        let deadline = received_deadline(received_at, self.budget.received_timeout);
        self.next_received_deadline = Some(
            self.next_received_deadline
                .map_or(deadline, |current| current.min(deadline)),
        );
    }

    fn refresh_next_received_deadline(&mut self) {
        self.next_received_deadline = self
            .received
            .values()
            .map(|entry| received_deadline(entry.received_at, self.budget.received_timeout))
            .min();
    }

    fn maybe_compact_received_order(&mut self) {
        let live = self.received.len();
        let compact_after = self
            .budget
            .max_received_blocks
            .max(live)
            .max(16)
            .saturating_mul(2);
        if self.received_order.len() <= compact_after {
            return;
        }
        let received = &self.received;
        self.received_order
            .retain(|hash| received.contains_key(hash));
    }

    fn received_order_contains(&self, hash: &Hash256) -> bool {
        self.received_order.iter().any(|queued| queued == hash)
    }

    #[cfg(test)]
    fn received_order_len(&self) -> usize {
        self.received_order.len()
    }
}

fn received_deadline(received_at: Instant, timeout: Duration) -> Instant {
    received_at + timeout
}

fn block_size(block: &Block) -> usize {
    block.total_size()
}

#[cfg(test)]
mod tests;
