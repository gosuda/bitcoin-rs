//! Out-of-order block staging bounded by the download window budget.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use bitcoin_rs_primitives::{BlockPayload, Hash256, Header};
use hashbrown::{HashMap, hash_map::Entry};

use crate::PeerSource;
use crate::download_window::SyncBudget;

#[derive(Debug)]
pub(crate) struct BlockStager {
    budget: SyncBudget,
    received: HashMap<Hash256, ReceivedBlock>,
    received_order: VecDeque<Hash256>,
    received_bytes: usize,
    decoded_bytes: usize,
    next_received_deadline: Option<Instant>,
    received_blocks_high_water: usize,
    received_bytes_high_water: usize,
    retained_bytes_high_water: usize,
    gate_pending_count: usize,
}

#[derive(Debug)]
struct ReceivedBlock {
    payload: BlockPayload,
    received_at: Instant,
    bytes: usize,
    decoded_bytes: usize,
    source: Option<PeerSource>,
    gate_pending: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct DrainedBlock {
    pub hash: Hash256,
    payload: BlockPayload,
    received_at: Instant,
    bytes: usize,
    source: Option<PeerSource>,
    gate_pending: bool,
}

impl DrainedBlock {
    #[must_use]
    pub(crate) const fn source(&self) -> Option<PeerSource> {
        self.source
    }

    #[must_use]
    pub(crate) const fn payload(&self) -> &BlockPayload {
        &self.payload
    }
}

#[derive(Clone, Debug)]
pub(crate) enum StagedBlock {
    AlreadyStaged,
    Memory { bytes: usize, dropped: Vec<Hash256> },
    DroppedForRetry { hash: Hash256 },
}

impl BlockStager {
    #[must_use]
    pub(crate) fn new(budget: SyncBudget) -> Self {
        Self {
            budget,
            received: HashMap::with_capacity(budget.max_received_blocks),
            received_order: VecDeque::with_capacity(budget.max_received_blocks),
            received_bytes: 0,
            decoded_bytes: 0,
            next_received_deadline: None,
            received_blocks_high_water: 0,
            received_bytes_high_water: 0,
            retained_bytes_high_water: 0,
            gate_pending_count: 0,
        }
    }

    #[must_use]
    pub(crate) fn received_len(&self) -> usize {
        self.received.len()
    }

    #[must_use]
    pub(crate) fn received_bytes(&self) -> usize {
        self.received_bytes
    }

    #[must_use]
    pub(crate) const fn decoded_bytes(&self) -> usize {
        self.decoded_bytes
    }

    #[must_use]
    pub(crate) const fn retained_attributed_bytes(&self) -> usize {
        self.decoded_bytes.saturating_add(self.received_bytes)
    }

    #[must_use]
    pub(crate) const fn retained_attributed_bytes_high_water(&self) -> usize {
        self.retained_bytes_high_water
    }

    #[must_use]
    pub(crate) const fn received_high_water(&self) -> usize {
        self.received_blocks_high_water
    }

    #[must_use]
    pub(crate) const fn received_bytes_high_water(&self) -> usize {
        self.received_bytes_high_water
    }

    #[must_use]
    pub(crate) fn ready_received_len(&self, next_expected_hash: Option<Hash256>) -> Option<usize> {
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

    pub(crate) fn staged_hashes(&self) -> impl Iterator<Item = Hash256> + '_ {
        self.received.keys().copied()
    }

    pub(crate) fn insert(
        &mut self,
        hash: Hash256,
        next_expected_hash: Option<Hash256>,
        payload: BlockPayload,
        source: Option<PeerSource>,
        now: Instant,
    ) -> StagedBlock {
        let entry = match self.received.entry(hash) {
            Entry::Occupied(_) => return StagedBlock::AlreadyStaged,
            Entry::Vacant(entry) => entry,
        };
        let bytes = payload.bytes().len();
        if bytes > self.budget.max_received_bytes {
            return StagedBlock::DroppedForRetry { hash };
        }
        if Some(hash) != next_expected_hash
            && self.received_bytes.saturating_add(bytes) > self.budget.max_received_bytes
        {
            return StagedBlock::DroppedForRetry { hash };
        }

        let decoded_bytes = payload.block().retained_heap_bytes();
        entry.insert(ReceivedBlock {
            payload,
            received_at: now,
            bytes,
            decoded_bytes,
            source,
            gate_pending: false,
        });
        self.received_order.push_back(hash);
        self.count_staged(bytes, decoded_bytes);
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

    #[must_use]
    pub(crate) fn contains(&self, hash: &Hash256) -> bool {
        self.received.contains_key(hash)
    }

    pub(crate) fn staged_source(&self, hash: &Hash256) -> Option<PeerSource> {
        self.received.get(hash).and_then(|entry| entry.source)
    }

    pub(crate) fn gate_pending_count(&self) -> usize {
        self.gate_pending_count
    }

    pub(crate) fn staged_headers(
        &self,
    ) -> impl Iterator<Item = (Hash256, Header, Option<PeerSource>)> + '_ {
        self.received
            .iter()
            .map(|(hash, entry)| (*hash, entry.payload.block().header, entry.source))
    }

    #[must_use]
    pub(crate) fn staged_body(&self, hash: Hash256) -> Option<BlockPayload> {
        self.received.get(&hash).map(|entry| entry.payload.clone())
    }

    pub(crate) fn retire_applied(&mut self, hash: &Hash256) -> bool {
        let removed = self.take_entry(hash).is_some();
        if self.received.is_empty() {
            self.received_order.clear();
            self.next_received_deadline = None;
        }
        removed
    }

    pub(crate) fn drain_expected_prefix(
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

    pub(crate) fn restore_many(&mut self, drained: impl IntoIterator<Item = DrainedBlock>) {
        for drained in drained {
            let gate_pending = drained.gate_pending;
            let decoded_bytes = drained.payload.block().retained_heap_bytes();
            let previous = self.received.insert(
                drained.hash,
                ReceivedBlock {
                    payload: drained.payload,
                    received_at: drained.received_at,
                    bytes: drained.bytes,
                    decoded_bytes,
                    source: drained.source,
                    gate_pending,
                },
            );
            if let Some(previous) = previous {
                self.release(&previous);
            } else if !self.received_order_contains(&drained.hash) {
                self.received_order.push_back(drained.hash);
            }
            if gate_pending {
                self.gate_pending_count += 1;
            }
            self.count_staged(drained.bytes, decoded_bytes);
            self.track_received_deadline(drained.received_at);
        }
        self.maybe_compact_received_order();
    }

    fn take_entry(&mut self, hash: &Hash256) -> Option<DrainedBlock> {
        let entry = self.received.remove(hash)?;
        self.release(&entry);
        Some(DrainedBlock {
            hash: *hash,
            payload: entry.payload,
            received_at: entry.received_at,
            bytes: entry.bytes,
            source: entry.source,
            gate_pending: entry.gate_pending,
        })
    }

    pub(crate) fn prune_expired(&mut self, now: Instant) -> Vec<Hash256> {
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
        let mut decoded_bytes = self.decoded_bytes;
        let mut gate_pending_dropped = 0_usize;
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
            decoded_bytes = decoded_bytes.saturating_sub(entry.decoded_bytes);
            gate_pending_dropped += usize::from(entry.gate_pending);
            dropped.push(*hash);
            false
        });
        self.gate_pending_count = self.gate_pending_count.saturating_sub(gate_pending_dropped);
        self.received_bytes = received_bytes;
        self.decoded_bytes = decoded_bytes;
        self.next_received_deadline = next_received_deadline;
        self.maybe_compact_received_order();
        dropped
    }

    fn evict_over_budget(&mut self, next_expected_hash: Option<Hash256>) -> Vec<Hash256> {
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

    fn is_over_count_budget(&self) -> bool {
        self.received.len() > self.budget.max_received_blocks
    }

    fn remove(&mut self, hash: &Hash256) -> Option<Hash256> {
        let entry = self.received.remove(hash)?;
        self.release(&entry);
        Some(*hash)
    }

    pub(crate) fn discard(&mut self, hash: &Hash256) -> bool {
        self.remove(hash).is_some()
    }

    pub(crate) fn set_gate_pending(&mut self, hash: &Hash256) {
        if let Some(entry) = self.received.get_mut(hash)
            && !entry.gate_pending
        {
            entry.gate_pending = true;
            self.gate_pending_count += 1;
        }
    }

    pub(crate) fn gate_pending_hashes(&self) -> impl Iterator<Item = Hash256> + '_ {
        self.received
            .iter()
            .filter(|(_, entry)| entry.gate_pending)
            .map(|(hash, _)| *hash)
    }

    pub(crate) fn clear_gate_pending(&mut self, hash: &Hash256) {
        if let Some(entry) = self.received.get_mut(hash)
            && entry.gate_pending
        {
            entry.gate_pending = false;
            self.gate_pending_count = self.gate_pending_count.saturating_sub(1);
        }
    }

    #[must_use]
    pub(crate) fn count_headroom(&self) -> usize {
        self.budget
            .max_received_blocks
            .saturating_sub(self.received.len())
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

    fn count_staged(&mut self, bytes: usize, decoded_bytes: usize) {
        self.received_bytes = self.received_bytes.saturating_add(bytes);
        self.decoded_bytes = self.decoded_bytes.saturating_add(decoded_bytes);
        self.retained_bytes_high_water = self
            .retained_bytes_high_water
            .max(self.retained_attributed_bytes());
    }

    fn release(&mut self, entry: &ReceivedBlock) {
        if entry.gate_pending {
            self.gate_pending_count = self.gate_pending_count.saturating_sub(1);
        }
        self.received_bytes = self.received_bytes.saturating_sub(entry.bytes);
        self.decoded_bytes = self.decoded_bytes.saturating_sub(entry.decoded_bytes);
    }

    fn received_order_contains(&self, hash: &Hash256) -> bool {
        self.received_order.contains(hash)
    }

    #[cfg(test)]
    fn received_order_len(&self) -> usize {
        self.received_order.len()
    }
}

fn received_deadline(received_at: Instant, timeout: Duration) -> Instant {
    received_at + timeout
}

#[cfg(test)]
mod tests;
