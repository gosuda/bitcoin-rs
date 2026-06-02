use std::time::Instant;

use bitcoin::consensus::Encodable as _;
use bitcoin::io::sink;
use bitcoin_rs_primitives::Hash256;
use hashbrown::HashMap;

use super::window::SyncBudget;

#[derive(Debug)]
pub(super) struct BlockStager {
    budget: SyncBudget,
    received: HashMap<Hash256, ReceivedBlock>,
    received_bytes: usize,
}

#[derive(Debug)]
struct ReceivedBlock {
    block: bitcoin::Block,
    received_at: Instant,
    bytes: usize,
}

#[derive(Clone, Debug)]
pub(super) struct DroppedBlock {
    pub(super) hash: Hash256,
}

#[derive(Clone, Debug)]
pub(super) enum StagedBlock {
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

        let mut dropped = Vec::new();
        while self.received.len() > self.budget.max_received_blocks
            || self.received_bytes > self.budget.max_received_bytes
        {
            let Some(evicted) = self.evict_oldest_unprotected(next_expected_hash) else {
                break;
            };
            dropped.push(evicted);
        }

        StagedBlock::Memory { bytes, dropped }
    }

    pub(super) fn take(&mut self, hash: &Hash256) -> Option<bitcoin::Block> {
        let entry = self.received.remove(hash)?;
        self.received_bytes = self.received_bytes.saturating_sub(entry.bytes);
        Some(entry.block)
    }

    pub(super) fn prune_expired(&mut self, now: Instant) -> Vec<DroppedBlock> {
        let mut dropped = Vec::new();
        let mut received_bytes = self.received_bytes;
        self.received.retain(|hash, entry| {
            if now.duration_since(entry.received_at) < self.budget.received_timeout {
                return true;
            }
            received_bytes = received_bytes.saturating_sub(entry.bytes);
            dropped.push(DroppedBlock { hash: *hash });
            false
        });
        self.received_bytes = received_bytes;
        dropped
    }

    fn evict_oldest_unprotected(
        &mut self,
        next_expected_hash: Option<Hash256>,
    ) -> Option<DroppedBlock> {
        let evict_hash = self
            .received
            .iter()
            .filter(|(hash, _entry)| Some(**hash) != next_expected_hash)
            .min_by_key(|(_hash, entry)| entry.received_at)
            .map(|(hash, _entry)| *hash)?;
        self.remove(&evict_hash)
    }

    fn remove(&mut self, hash: &Hash256) -> Option<DroppedBlock> {
        let entry = self.received.remove(hash)?;
        self.received_bytes = self.received_bytes.saturating_sub(entry.bytes);
        Some(DroppedBlock { hash: *hash })
    }
}

fn block_size(block: &bitcoin::Block) -> usize {
    block
        .consensus_encode(&mut sink())
        .unwrap_or_else(|error| panic!("sink writer failed while sizing block: {error}"))
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::encode::serialize;

    use super::block_size;

    #[test]
    fn block_size_matches_consensus_serialized_len() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);

        assert_eq!(block_size(&block), serialize(&block).len());
    }
}
