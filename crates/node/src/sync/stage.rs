use std::time::{Duration, Instant};

use bitcoin_rs_primitives::Hash256;
use hashbrown::HashMap;

use super::window::SyncBudget;

#[derive(Debug)]
pub(super) struct BlockStager {
    budget: SyncBudget,
    received: HashMap<Hash256, ReceivedBlock>,
    received_bytes: usize,
    next_received_deadline: Option<Instant>,
}

#[derive(Debug)]
struct ReceivedBlock {
    block: bitcoin::Block,
    received_at: Instant,
    bytes: usize,
}

#[derive(Debug)]
pub(super) struct DrainedBlock {
    pub(super) hash: Hash256,
    pub(super) block: bitcoin::Block,
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
            received: HashMap::new(),
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

    pub(super) fn insert(
        &mut self,
        hash: Hash256,
        next_expected_hash: Option<Hash256>,
        block: bitcoin::Block,
        now: Instant,
    ) -> StagedBlock {
        if self.received.contains_key(&hash) {
            return StagedBlock::AlreadyStaged;
        }

        let bytes = block_size(&block);
        if bytes > self.budget.max_received_bytes {
            return StagedBlock::DroppedForRetry {
                dropped: DroppedBlock { hash },
            };
        }

        let previous = self.received.insert(
            hash,
            ReceivedBlock {
                block,
                received_at: now,
                bytes,
            },
        );
        if let Some(previous) = previous {
            self.received_bytes = self.received_bytes.saturating_sub(previous.bytes);
        }
        self.received_bytes = self.received_bytes.saturating_add(bytes);
        self.track_received_deadline(now);

        let dropped = self.evict_over_budget(next_expected_hash);

        StagedBlock::Memory { bytes, dropped }
    }

    #[cfg(test)]
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
        drained
    }

    pub(super) fn restore_many(&mut self, drained: impl IntoIterator<Item = DrainedBlock>) {
        for drained in drained {
            let previous = self.received.insert(
                drained.hash,
                ReceivedBlock {
                    block: drained.block,
                    received_at: drained.received_at,
                    bytes: drained.bytes,
                },
            );
            if let Some(previous) = previous {
                self.received_bytes = self.received_bytes.saturating_sub(previous.bytes);
            }
            self.received_bytes = self.received_bytes.saturating_add(drained.bytes);
            self.track_received_deadline(drained.received_at);
        }
    }

    fn take_entry(&mut self, hash: &Hash256) -> Option<DrainedBlock> {
        let entry = self.received.remove(hash)?;
        self.received_bytes = self.received_bytes.saturating_sub(entry.bytes);
        Some(DrainedBlock {
            hash: *hash,
            block: entry.block,
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
        dropped
    }

    fn evict_over_budget(&mut self, next_expected_hash: Option<Hash256>) -> Vec<DroppedBlock> {
        let mut dropped = Vec::new();
        if !self.is_over_budget() {
            return dropped;
        }

        let Some((oldest_hash, oldest_bytes)) =
            self.oldest_unprotected_candidate(next_expected_hash)
        else {
            return dropped;
        };
        let fits_after_oldest = self.fits_after_removing(oldest_bytes);
        if let Some(evicted) = self.remove(&oldest_hash) {
            dropped.push(evicted);
        }
        if fits_after_oldest || !self.is_over_budget() {
            return dropped;
        }

        let mut candidates: Vec<(Instant, usize, Hash256)> = self
            .received
            .iter()
            .enumerate()
            .filter(|(_order, (hash, _entry))| Some(**hash) != next_expected_hash)
            .map(|(order, (hash, entry))| (entry.received_at, order, *hash))
            .collect();
        candidates.sort_unstable();
        for (_received_at, _order, hash) in candidates {
            if !self.is_over_budget() {
                break;
            }
            if let Some(evicted) = self.remove(&hash) {
                dropped.push(evicted);
            }
        }
        dropped
    }

    fn oldest_unprotected_candidate(
        &self,
        next_expected_hash: Option<Hash256>,
    ) -> Option<(Hash256, usize)> {
        self.received
            .iter()
            .enumerate()
            .filter(|(_order, (hash, _entry))| Some(**hash) != next_expected_hash)
            .min_by_key(|(order, (_hash, entry))| (entry.received_at, *order))
            .map(|(_order, (hash, entry))| (*hash, entry.bytes))
    }

    fn is_over_budget(&self) -> bool {
        self.received.len() > self.budget.max_received_blocks
            || self.received_bytes > self.budget.max_received_bytes
    }

    fn fits_after_removing(&self, bytes: usize) -> bool {
        self.received.len().saturating_sub(1) <= self.budget.max_received_blocks
            && self.received_bytes.saturating_sub(bytes) <= self.budget.max_received_bytes
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
        let block_bytes = block_size(&block);
        let mut stager = BlockStager::new(default_sync_budget());
        let now = std::time::Instant::now();
        let first = Hash256::from_le_bytes(&[0x01; 32]);
        let missing = Hash256::from_le_bytes(&[0x02; 32]);
        let third = Hash256::from_le_bytes(&[0x03; 32]);
        let fourth = Hash256::from_le_bytes(&[0x04; 32]);

        stager.insert(first, None, block.clone(), now);
        stager.insert(third, None, block.clone(), now);
        stager.insert(fourth, None, block, now);

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
        let block_bytes = block_size(&block);
        let mut stager = BlockStager::new(default_sync_budget());
        let now = std::time::Instant::now();
        let first = Hash256::from_le_bytes(&[0x11; 32]);
        let second = Hash256::from_le_bytes(&[0x22; 32]);
        let third = Hash256::from_le_bytes(&[0x33; 32]);

        stager.insert(first, None, block.clone(), now);
        stager.insert(second, None, block.clone(), now);
        stager.insert(third, None, block, now);
        let mut drained = stager.drain_expected_prefix(&[first, second, third]);
        let restored_tail = drained.split_off(1);

        stager.restore_many(restored_tail);

        assert_eq!(stager.received_len(), 2);
        assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
        assert!(!stager.contains(&first));
        assert!(stager.contains(&second));
        assert!(stager.contains(&third));
    }

    #[test]
    fn prune_expired_recomputes_deadline_after_dropping_oldest() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
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

        stager.insert(old, None, block.clone(), old_received_at);
        stager.insert(fresh, None, block, fresh_received_at);

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
        let block_bytes = block_size(&block);
        let mut budget = default_sync_budget();
        budget.received_timeout = Duration::from_secs(10);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let hash = Hash256::from_le_bytes(&[0x43; 32]);

        stager.insert(hash, None, block.clone(), now);
        stager.insert(hash, None, block, now + Duration::from_secs(5));

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
        let block_bytes = block_size(&block);
        let mut stager = BlockStager::new(default_sync_budget());
        let now = Instant::now();
        let protected = Hash256::from_le_bytes(&[0x51; 32]);
        let first = Hash256::from_le_bytes(&[0x52; 32]);
        let second = Hash256::from_le_bytes(&[0x53; 32]);
        let third = Hash256::from_le_bytes(&[0x54; 32]);
        let incoming = Hash256::from_le_bytes(&[0x55; 32]);

        stager.insert(protected, None, block.clone(), now);
        stager.insert(first, None, block.clone(), now + Duration::from_secs(1));
        stager.insert(second, None, block.clone(), now + Duration::from_secs(2));
        stager.insert(third, None, block.clone(), now + Duration::from_secs(3));
        stager.budget.max_received_blocks = 2;

        let dropped = match stager.insert(
            incoming,
            Some(protected),
            block,
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
        assert!(dropped.iter().any(|dropped| dropped.hash == first));
        assert!(dropped.iter().any(|dropped| dropped.hash == second));
        assert!(dropped.iter().any(|dropped| dropped.hash == third));
        assert!(stager.contains(&protected));
        assert!(stager.contains(&incoming));
        assert_eq!(stager.received_len(), 2);
        assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
    }
}
