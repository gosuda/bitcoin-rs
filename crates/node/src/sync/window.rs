use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use hashbrown::{HashMap, HashSet};

#[derive(Clone, Copy, Debug)]
pub(super) struct SyncBudget {
    pub(super) max_pending_blocks: usize,
    pub(super) max_pending_bytes: usize,
    pub(super) max_received_blocks: usize,
    pub(super) max_received_bytes: usize,
    pub(super) max_peer_inflight: usize,
    pub(super) getdata_batch_limit: usize,
    pub(super) pending_timeout: Duration,
    pub(super) received_timeout: Duration,
}

#[derive(Clone, Debug)]
pub(super) struct PeerRequest {
    peer_addr: SocketAddr,
    entries: Vec<PeerRequestEntry>,
    next_request_height: u32,
}

impl PeerRequest {
    pub(super) fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub(super) fn hashes(&self) -> impl Iterator<Item = Hash256> + '_ {
        self.entries.iter().map(|entry| entry.hash)
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Clone, Copy, Debug)]
struct PeerRequestEntry {
    hash: Hash256,
    height: u32,
}

#[derive(Clone, Copy, Debug)]
struct PendingBlock {
    peer_addr: SocketAddr,
    requested_at: Instant,
    height: u32,
    estimated_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct PeerInflight {
    blocks: usize,
}

#[derive(Debug)]
pub(super) struct DownloadWindow {
    budget: SyncBudget,
    pending: HashMap<Hash256, PendingBlock>,
    received: HashMap<Hash256, ReceivedBlock>,
    peer_inflight: HashMap<SocketAddr, PeerInflight>,
    pending_bytes: usize,
    received_bytes: usize,
    ewma_block_bytes: usize,
    next_request_height: u32,
}

#[derive(Clone, Copy, Debug)]
struct ReceivedBlock {
    height: u32,
    bytes: usize,
}

impl DownloadWindow {
    pub(super) fn new(budget: SyncBudget) -> Self {
        Self {
            budget,
            pending: HashMap::new(),
            received: HashMap::new(),
            peer_inflight: HashMap::new(),
            pending_bytes: 0,
            received_bytes: 0,
            ewma_block_bytes: 256 * 1024,
            next_request_height: 1,
        }
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(super) const fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    #[cfg(test)]
    pub(super) fn received_len(&self) -> usize {
        self.received.len()
    }

    #[cfg(test)]
    pub(super) fn contains_pending(&self, hash: &Hash256) -> bool {
        self.pending.contains_key(hash)
    }

    pub(super) fn release_disconnected_peers(&mut self, live_peers: &HashSet<SocketAddr>) {
        let mut retry_height = self.next_request_height;
        self.pending.retain(|_hash, pending| {
            if live_peers.contains(&pending.peer_addr) {
                return true;
            }
            retry_height = retry_height.min(pending.height);
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            false
        });
        self.peer_inflight
            .retain(|peer, _inflight| live_peers.contains(peer));
        self.next_request_height = retry_height;
    }

    pub(super) fn next_peer_request(
        &mut self,
        peer_addr: SocketAddr,
        chain_tip: &TipSnapshot,
        applied_tip: &TipSnapshot,
        peer_best_height: u32,
        tree: &BlockTree,
        now: Instant,
    ) -> Option<PeerRequest> {
        let mut expired = self.expire_pending(now);
        expired.sort_by_key(|entry| entry.height);

        let peer_inflight = self
            .peer_inflight
            .get(&peer_addr)
            .map_or(0, |inflight| inflight.blocks);
        let peer_capacity = self.budget.max_peer_inflight.saturating_sub(peer_inflight);
        let block_capacity = self
            .budget
            .max_pending_blocks
            .saturating_sub(self.pending.len());
        let mut byte_capacity = self
            .budget
            .max_pending_bytes
            .saturating_sub(self.pending_bytes);
        let batch_limit = self
            .budget
            .getdata_batch_limit
            .min(peer_capacity)
            .min(block_capacity);
        if batch_limit == 0 || byte_capacity < self.ewma_block_bytes {
            return None;
        }

        let mut entries = Vec::with_capacity(batch_limit);
        for entry in expired {
            if entries.len() >= batch_limit || byte_capacity < self.ewma_block_bytes {
                break;
            }
            if self.received.contains_key(&entry.hash) || self.pending.contains_key(&entry.hash) {
                continue;
            }
            byte_capacity = byte_capacity.saturating_sub(self.ewma_block_bytes);
            entries.push(entry);
        }

        let Some(mut height) = applied_tip.height.checked_add(1) else {
            return non_empty_request(peer_addr, entries, self.next_request_height);
        };
        height = height.max(self.next_request_height);
        let mut next_request_height = self.next_request_height;
        let request_tip_height = chain_tip.height.min(peer_best_height);
        while entries.len() < batch_limit
            && height <= request_tip_height
            && byte_capacity >= self.ewma_block_bytes
        {
            let Some(node_id) = tree.node_at_height_from(chain_tip.tip_id, height) else {
                break;
            };
            let Ok(node) = tree.node(node_id) else {
                break;
            };
            if !self.pending.contains_key(&node.hash) && !self.received.contains_key(&node.hash) {
                entries.push(PeerRequestEntry {
                    hash: node.hash,
                    height,
                });
                byte_capacity = byte_capacity.saturating_sub(self.ewma_block_bytes);
            }
            height = height.saturating_add(1);
            next_request_height = height;
        }
        non_empty_request(peer_addr, entries, next_request_height)
    }

    pub(super) fn mark_requested(&mut self, request: &PeerRequest, now: Instant) {
        let estimated_bytes = self.ewma_block_bytes;
        let inflight = self.peer_inflight.entry(request.peer_addr).or_default();
        for entry in &request.entries {
            if self.pending.contains_key(&entry.hash) || self.received.contains_key(&entry.hash) {
                continue;
            }
            self.pending.insert(
                entry.hash,
                PendingBlock {
                    peer_addr: request.peer_addr,
                    requested_at: now,
                    height: entry.height,
                    estimated_bytes,
                },
            );
            self.pending_bytes = self.pending_bytes.saturating_add(estimated_bytes);
            inflight.blocks = inflight.blocks.saturating_add(1);
        }
        self.next_request_height = self.next_request_height.max(request.next_request_height);
    }

    pub(super) fn mark_received(&mut self, hash: Hash256, height: u32, bytes: usize) {
        if let Some(pending) = self.pending.remove(&hash) {
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            self.release_peer_block(pending.peer_addr);
        }
        let previous = self.received.insert(hash, ReceivedBlock { height, bytes });
        if let Some(previous) = previous {
            self.received_bytes = self.received_bytes.saturating_sub(previous.bytes);
        }
        self.received_bytes = self.received_bytes.saturating_add(bytes);
        self.ewma_block_bytes = self
            .ewma_block_bytes
            .saturating_mul(7)
            .saturating_add(bytes)
            / 8;
        self.ewma_block_bytes = self.ewma_block_bytes.max(80);
    }

    pub(super) fn mark_applied(&mut self, hash: &Hash256) {
        self.remove_received(hash);
        if let Some(pending) = self.pending.remove(hash) {
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            self.release_peer_block(pending.peer_addr);
        }
    }

    pub(super) fn drop_received_for_retry(&mut self, hash: &Hash256) {
        if let Some(received) = self.remove_received(hash) {
            self.next_request_height = self.next_request_height.min(received.height);
        }
    }

    pub(super) fn drop_for_retry(&mut self, hash: &Hash256) {
        self.drop_received_for_retry(hash);
        if let Some(pending) = self.pending.remove(hash) {
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            self.release_peer_block(pending.peer_addr);
            self.next_request_height = self.next_request_height.min(pending.height);
        }
    }

    fn expire_pending(&mut self, now: Instant) -> Vec<PeerRequestEntry> {
        let expired: Vec<(Hash256, PendingBlock)> = self
            .pending
            .iter()
            .filter(|(_hash, pending)| {
                now.duration_since(pending.requested_at) >= self.budget.pending_timeout
            })
            .map(|(hash, pending)| (*hash, *pending))
            .collect();
        let mut entries = Vec::with_capacity(expired.len());
        for (hash, pending) in expired {
            self.pending.remove(&hash);
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            self.release_peer_block(pending.peer_addr);
            self.next_request_height = self.next_request_height.min(pending.height);
            entries.push(PeerRequestEntry {
                hash,
                height: pending.height,
            });
        }
        entries
    }

    fn remove_received(&mut self, hash: &Hash256) -> Option<ReceivedBlock> {
        let received = self.received.remove(hash)?;
        self.received_bytes = self.received_bytes.saturating_sub(received.bytes);
        Some(received)
    }

    fn release_peer_block(&mut self, peer_addr: SocketAddr) {
        let Some(inflight) = self.peer_inflight.get_mut(&peer_addr) else {
            return;
        };
        inflight.blocks = inflight.blocks.saturating_sub(1);
        if inflight.blocks == 0 {
            self.peer_inflight.remove(&peer_addr);
        }
    }
}

fn non_empty_request(
    peer_addr: SocketAddr,
    entries: Vec<PeerRequestEntry>,
    next_request_height: u32,
) -> Option<PeerRequest> {
    (!entries.is_empty()).then_some(PeerRequest {
        peer_addr,
        entries,
        next_request_height,
    })
}
