use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use bitcoin_rs_primitives::Hash256;
use hashbrown::{HashMap, hash_map::Entry};

use super::window::SyncBudget;

#[derive(Debug)]
pub(super) struct BlockStager {
    budget: SyncBudget,
    received: HashMap<Hash256, ReceivedBlock>,
    received_order: VecDeque<Hash256>,
    received_bytes: usize,
    next_received_deadline: Option<Instant>,
}

#[derive(Debug)]
struct ReceivedBlock {
    block: bitcoin::Block,
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

#[derive(Debug)]
pub(super) struct DrainedBlock {
    pub(super) hash: Hash256,
    pub(super) block: bitcoin::Block,
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
        }
    }

    pub(super) fn received_len(&self) -> usize {
        self.received.len()
    }

    pub(super) fn received_bytes(&self) -> usize {
        self.received_bytes
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
        block: bitcoin::Block,
        serialized: bytes::Bytes,
        now: Instant,
    ) -> StagedBlock {
        let entry = match self.received.entry(hash) {
            Entry::Occupied(_) => return StagedBlock::AlreadyStaged,
            Entry::Vacant(entry) => entry,
        };
        let bytes = block_size(&block);
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

fn block_size(block: &bitcoin::Block) -> usize {
    block.total_size()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bitcoin::consensus::encode::serialize;
    use bitcoin_rs_primitives::Hash256;

    use super::{BlockStager, block_size};
    use crate::sync::default_sync_budget;

    #[test]
    fn block_size_matches_consensus_serialized_len() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);

        assert_eq!(block_size(&block), serialize(&block).len());
    }

    #[test]
    fn drain_expected_prefix_stops_at_first_missing_hash() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let block_bytes = block_size(&block);
        let mut stager = BlockStager::new(default_sync_budget());
        let now = std::time::Instant::now();
        let first = Hash256::from_le_bytes(&[0x01; 32]);
        let missing = Hash256::from_le_bytes(&[0x02; 32]);
        let third = Hash256::from_le_bytes(&[0x03; 32]);
        let fourth = Hash256::from_le_bytes(&[0x04; 32]);

        stager.insert(first, None, block.clone(), serialized.clone(), now);
        stager.insert(third, None, block.clone(), serialized.clone(), now);
        stager.insert(fourth, None, block, serialized.clone(), now);

        let drained = stager.drain_expected_prefix(&[first, missing, third, fourth]);

        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].hash, first);
        assert_eq!(stager.received_len(), 2);
        assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
        assert!(stager.contains(&third));
        assert!(stager.contains(&fourth));
    }

    #[test]
    fn restore_many_restores_tail_byte_accounting() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let block_bytes = block_size(&block);
        let mut stager = BlockStager::new(default_sync_budget());
        let now = std::time::Instant::now();
        let first = Hash256::from_le_bytes(&[0x11; 32]);
        let second = Hash256::from_le_bytes(&[0x22; 32]);
        let third = Hash256::from_le_bytes(&[0x33; 32]);

        stager.insert(first, None, block.clone(), serialized.clone(), now);
        stager.insert(second, None, block.clone(), serialized.clone(), now);
        stager.insert(third, None, block, serialized.clone(), now);
        let mut drained = stager.drain_expected_prefix(&[first, second, third]);
        assert_eq!(stager.received_order_len(), 0);
        assert_eq!(stager.next_received_deadline, None);
        let restored_tail = drained.split_off(1);

        stager.restore_many(restored_tail);

        assert_eq!(stager.received_len(), 2);
        assert_eq!(stager.received_order_len(), 2);
        assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
        assert!(!stager.contains(&first));
        assert!(stager.contains(&second));
        assert!(stager.contains(&third));
    }

    #[test]
    fn ready_received_len_requires_next_expected_hash_when_provided() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let mut stager = BlockStager::new(default_sync_budget());
        let now = std::time::Instant::now();
        let staged = Hash256::from_le_bytes(&[0x31; 32]);
        let missing = Hash256::from_le_bytes(&[0x32; 32]);

        assert_eq!(stager.ready_received_len(None), None);

        stager.insert(staged, None, block, serialized.clone(), now);

        assert_eq!(stager.ready_received_len(None), Some(1));
        assert_eq!(stager.ready_received_len(Some(staged)), Some(1));
        assert_eq!(stager.ready_received_len(Some(missing)), None);
    }

    #[test]
    fn prune_expired_recomputes_deadline_after_dropping_oldest() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let mut budget = default_sync_budget();
        budget.received_timeout = Duration::from_secs(10);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let old_received_at = now
            .checked_sub(Duration::from_secs(11))
            .unwrap_or_else(|| panic!("test instant underflow"));
        let fresh_received_at = now
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(|| panic!("test instant underflow"));
        let old = Hash256::from_le_bytes(&[0x41; 32]);
        let fresh = Hash256::from_le_bytes(&[0x42; 32]);

        stager.insert(
            old,
            None,
            block.clone(),
            serialized.clone(),
            old_received_at,
        );
        stager.insert(fresh, None, block, serialized.clone(), fresh_received_at);

        let first_drop = stager.prune_expired(now);

        assert_eq!(first_drop.len(), 1);
        assert_eq!(first_drop[0].hash, old);
        assert_eq!(stager.received_len(), 1);
        assert!(stager.contains(&fresh));

        let second_drop = stager.prune_expired(now + Duration::from_secs(1));

        assert!(second_drop.is_empty());
        assert!(stager.contains(&fresh));

        let final_drop = stager.prune_expired(now + Duration::from_secs(10));

        assert_eq!(final_drop.len(), 1);
        assert_eq!(final_drop[0].hash, fresh);
        assert_eq!(stager.received_len(), 0);
    }

    #[test]
    fn duplicate_insert_keeps_original_staged_deadline() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let block_bytes = block_size(&block);
        let mut budget = default_sync_budget();
        budget.received_timeout = Duration::from_secs(10);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let hash = Hash256::from_le_bytes(&[0x43; 32]);

        stager.insert(hash, None, block.clone(), serialized.clone(), now);
        stager.insert(
            hash,
            None,
            block,
            serialized.clone(),
            now + Duration::from_secs(5),
        );

        assert_eq!(stager.received_len(), 1);
        assert_eq!(stager.received_bytes(), block_bytes);

        let dropped = stager.prune_expired(now + Duration::from_secs(10));

        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].hash, hash);
        assert_eq!(stager.received_len(), 0);
        assert_eq!(stager.received_bytes(), 0);
    }

    #[test]
    fn insert_eviction_drops_oldest_unprotected_until_budget_fits() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let block_bytes = block_size(&block);
        let mut stager = BlockStager::new(default_sync_budget());
        let now = Instant::now();
        let protected = Hash256::from_le_bytes(&[0x51; 32]);
        let first = Hash256::from_le_bytes(&[0x52; 32]);
        let second = Hash256::from_le_bytes(&[0x53; 32]);
        let third = Hash256::from_le_bytes(&[0x54; 32]);
        let incoming = Hash256::from_le_bytes(&[0x55; 32]);

        stager.insert(protected, None, block.clone(), serialized.clone(), now);
        stager.insert(
            first,
            None,
            block.clone(),
            serialized.clone(),
            now + Duration::from_secs(1),
        );
        stager.insert(
            second,
            None,
            block.clone(),
            serialized.clone(),
            now + Duration::from_secs(2),
        );
        stager.insert(
            third,
            None,
            block.clone(),
            serialized.clone(),
            now + Duration::from_secs(3),
        );
        stager.budget.max_received_blocks = 2;

        let dropped = match stager.insert(
            incoming,
            Some(protected),
            block,
            serialized.clone(),
            now + Duration::from_secs(4),
        ) {
            super::StagedBlock::AlreadyStaged => {
                panic!("incoming block should not already be staged")
            }
            super::StagedBlock::Memory { dropped, .. } => dropped,
            super::StagedBlock::DroppedForRetry { .. } => {
                panic!("incoming block should fit after evicting staged blocks")
            }
        };

        assert_eq!(dropped.len(), 3);
        assert_eq!(dropped[0].hash, first);
        assert_eq!(dropped[1].hash, second);
        assert_eq!(dropped[2].hash, third);
        assert!(stager.contains(&protected));
        assert!(stager.contains(&incoming));
        assert_eq!(stager.received_len(), 2);
        assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
    }

    #[test]
    fn insert_eviction_uses_fifo_order_for_same_instant_blocks() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let mut stager = BlockStager::new(default_sync_budget());
        let now = Instant::now();
        let first = Hash256::from_le_bytes(&[0x61; 32]);
        let second = Hash256::from_le_bytes(&[0x62; 32]);
        let third = Hash256::from_le_bytes(&[0x63; 32]);
        let incoming = Hash256::from_le_bytes(&[0x64; 32]);

        stager.insert(first, None, block.clone(), serialized.clone(), now);
        stager.insert(second, None, block.clone(), serialized.clone(), now);
        stager.insert(third, None, block.clone(), serialized.clone(), now);
        stager.budget.max_received_blocks = 2;

        let dropped = match stager.insert(incoming, None, block, serialized.clone(), now) {
            super::StagedBlock::AlreadyStaged => {
                panic!("incoming block should not already be staged")
            }
            super::StagedBlock::Memory { dropped, .. } => dropped,
            super::StagedBlock::DroppedForRetry { .. } => {
                panic!("incoming block should fit after evicting staged blocks")
            }
        };

        assert_eq!(dropped.len(), 2);
        assert_eq!(dropped[0].hash, first);
        assert_eq!(dropped[1].hash, second);
        assert!(!stager.contains(&first));
        assert!(!stager.contains(&second));
        assert!(stager.contains(&third));
        assert!(stager.contains(&incoming));
    }

    #[test]
    fn insert_eviction_refreshes_received_deadline() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let mut budget = default_sync_budget();
        budget.max_received_blocks = 1;
        budget.received_timeout = Duration::from_secs(10);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let old = Hash256::from_le_bytes(&[0x65; 32]);
        let fresh = Hash256::from_le_bytes(&[0x66; 32]);

        stager.insert(old, None, block.clone(), serialized.clone(), now);
        stager.insert(
            fresh,
            None,
            block,
            serialized.clone(),
            now + Duration::from_secs(5),
        );

        assert_eq!(
            stager.next_received_deadline,
            Some(now + Duration::from_secs(15))
        );
        let dropped = stager.prune_expired(now + Duration::from_secs(10));

        assert!(dropped.is_empty());
        assert!(stager.contains(&fresh));
    }

    #[test]
    fn insert_eviction_skips_stale_order_entries_after_drain() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let mut stager = BlockStager::new(default_sync_budget());
        let now = Instant::now();
        let first = Hash256::from_le_bytes(&[0x71; 32]);
        let second = Hash256::from_le_bytes(&[0x72; 32]);
        let third = Hash256::from_le_bytes(&[0x73; 32]);
        let incoming = Hash256::from_le_bytes(&[0x74; 32]);

        stager.insert(first, None, block.clone(), serialized.clone(), now);
        stager.insert(second, None, block.clone(), serialized.clone(), now);
        stager.insert(third, None, block.clone(), serialized.clone(), now);
        let drained = stager.drain_expected_prefix(&[first]);
        assert_eq!(drained.len(), 1);
        stager.budget.max_received_blocks = 2;

        let dropped = match stager.insert(incoming, None, block, serialized.clone(), now) {
            super::StagedBlock::AlreadyStaged => {
                panic!("incoming block should not already be staged")
            }
            super::StagedBlock::Memory { dropped, .. } => dropped,
            super::StagedBlock::DroppedForRetry { .. } => {
                panic!("incoming block should fit after evicting staged blocks")
            }
        };

        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].hash, second);
        assert!(!stager.contains(&first));
        assert!(!stager.contains(&second));
        assert!(stager.contains(&third));
        assert!(stager.contains(&incoming));
    }

    /// Builds a block whose `total_size` is exactly `target` bytes by padding
    /// a single transaction's `script_sig`. Two-pass: the probe build keeps the
    /// script-length varint in the same width regime as the final build, so one
    /// adjustment is exact (asserted).
    fn block_with_total_size(target: usize) -> bitcoin::Block {
        let probe = padded_block(target);
        let probe_size = block_size(&probe);
        let padding = target.saturating_mul(2).saturating_sub(probe_size);
        let block = padded_block(padding);
        assert_eq!(block_size(&block), target);
        block
    }

    fn padded_block(script_len: usize) -> bitcoin::Block {
        bitcoin::Block {
            header: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header,
            txdata: vec![bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::null(),
                    script_sig: bitcoin::ScriptBuf::from(vec![0_u8; script_len]),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::ZERO,
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }],
            }],
        }
    }

    #[test]
    fn full_window_of_estimate_sized_blocks_stages_without_eviction() {
        let budget = default_sync_budget();
        // Budget-pair consistency (R9): the staging byte budget admits a full
        // download window of blocks at the high-height per-slot estimate.
        assert_eq!(
            budget.max_received_bytes,
            budget
                .max_received_blocks
                .saturating_mul(crate::sync::PENDING_BLOCK_BYTE_ESTIMATE)
        );
        let block = block_with_total_size(crate::sync::PENDING_BLOCK_BYTE_ESTIMATE);
        let serialized = bytes::Bytes::from(serialize(&block));
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let window_slots = budget.max_received_blocks;
        assert!(window_slots <= usize::from(u8::MAX));

        for index in 0..window_slots {
            let mut raw = [0xee_u8; 32];
            raw[0] = u8::try_from(index).unwrap_or_else(|_| panic!("window exceeds u8 range"));
            let hash = Hash256::from_le_bytes(&raw);
            match stager.insert(hash, None, block.clone(), serialized.clone(), now) {
                super::StagedBlock::Memory { dropped, .. } => {
                    assert!(
                        dropped.is_empty(),
                        "full window must stage without eviction"
                    );
                }
                other => panic!("estimate-sized block should stage in memory: {other:?}"),
            }
        }

        assert_eq!(stager.received_len(), window_slots);
        assert_eq!(stager.received_bytes(), budget.max_received_bytes);
    }

    #[test]
    fn byte_budget_exhaustion_rejects_incoming_without_evicting_staged() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let block_bytes = block_size(&block);
        let mut budget = default_sync_budget();
        budget.max_received_bytes = block_bytes.saturating_mul(2);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let expected = Hash256::from_le_bytes(&[0x01; 32]);
        let successor = Hash256::from_le_bytes(&[0x02; 32]);

        stager.insert(
            expected,
            Some(expected),
            block.clone(),
            serialized.clone(),
            now,
        );
        stager.insert(
            successor,
            Some(expected),
            block.clone(),
            serialized.clone(),
            now,
        );
        assert_eq!(stager.received_bytes(), budget.max_received_bytes);

        // Exhausted: every further non-expected block is refused outright —
        // backpressure, never evict/re-download churn of staged progress.
        for byte in [0x03_u8, 0x04] {
            let incoming = Hash256::from_le_bytes(&[byte; 32]);
            match stager.insert(
                incoming,
                Some(expected),
                block.clone(),
                serialized.clone(),
                now,
            ) {
                super::StagedBlock::DroppedForRetry { dropped } => {
                    assert_eq!(dropped.hash, incoming);
                }
                other => panic!("exhausted stager should refuse incoming block: {other:?}"),
            }
            // Non-churn pin: zero staged blocks evicted while exhausted.
            assert_eq!(stager.received_len(), 2);
            assert!(stager.contains(&expected));
            assert!(stager.contains(&successor));
            assert_eq!(stager.received_bytes(), budget.max_received_bytes);
        }
    }

    #[test]
    fn byte_budget_exhaustion_still_accepts_next_expected_block() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let block_bytes = block_size(&block);
        let mut budget = default_sync_budget();
        budget.max_received_bytes = block_bytes.saturating_mul(2);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let expected = Hash256::from_le_bytes(&[0x0a; 32]);
        let successor_one = Hash256::from_le_bytes(&[0x0b; 32]);
        let successor_two = Hash256::from_le_bytes(&[0x0c; 32]);

        stager.insert(
            successor_one,
            Some(expected),
            block.clone(),
            serialized.clone(),
            now,
        );
        stager.insert(
            successor_two,
            Some(expected),
            block.clone(),
            serialized.clone(),
            now,
        );
        assert_eq!(stager.received_bytes(), budget.max_received_bytes);

        // The next expected block must stage even at byte exhaustion (bounded
        // overshoot) — refusing it would deadlock the apply frontier behind
        // the staged successors that hold the budget.
        match stager.insert(
            expected,
            Some(expected),
            block.clone(),
            serialized.clone(),
            now,
        ) {
            super::StagedBlock::Memory { dropped, .. } => {
                assert!(
                    dropped.is_empty(),
                    "expected block must not evict staged successors"
                );
            }
            other => panic!("next expected block should stage at exhaustion: {other:?}"),
        }
        assert_eq!(stager.received_len(), 3);
        assert!(stager.contains(&expected));
        assert!(stager.contains(&successor_one));
        assert!(stager.contains(&successor_two));
    }

    #[test]
    fn received_order_compaction_bounds_stale_applied_entries() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(serialize(&block));
        let mut budget = default_sync_budget();
        budget.max_received_blocks = 1;
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();

        for byte in 0x01_u8..0x60 {
            let hash = Hash256::from_le_bytes(&[byte; 32]);
            stager.insert(hash, None, block.clone(), serialized.clone(), now);
            let drained = stager.drain_expected_prefix(&[hash]);
            assert_eq!(drained.len(), 1);
        }

        assert_eq!(stager.received_len(), 0);
        assert!(stager.received_order_len() <= 32);

        let first = Hash256::from_le_bytes(&[0xa1; 32]);
        let second = Hash256::from_le_bytes(&[0xa2; 32]);
        stager.insert(first, None, block.clone(), serialized.clone(), now);
        let dropped = match stager.insert(second, None, block, serialized.clone(), now) {
            super::StagedBlock::AlreadyStaged => {
                panic!("incoming block should not already be staged")
            }
            super::StagedBlock::Memory { dropped, .. } => dropped,
            super::StagedBlock::DroppedForRetry { .. } => {
                panic!("incoming block should fit after evicting staged blocks")
            }
        };

        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].hash, first);
        assert!(stager.contains(&second));
    }
}
