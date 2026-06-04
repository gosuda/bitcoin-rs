use std::collections::VecDeque;
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
struct RequestScan {
    height: u32,
    request_tip_height: u32,
    remaining_limit: usize,
    next_request_height: u32,
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
    next_pending_deadline: Option<Instant>,
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
            next_pending_deadline: None,
        }
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(super) const fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    pub(super) fn has_request_capacity(&self) -> bool {
        self.pending.len() < self.budget.max_pending_blocks
            && self.pending_bytes.saturating_add(self.ewma_block_bytes)
                <= self.budget.max_pending_bytes
    }

    #[cfg(test)]
    pub(super) fn received_len(&self) -> usize {
        self.received.len()
    }

    #[cfg(test)]
    pub(super) fn contains_pending(&self, hash: &Hash256) -> bool {
        self.pending.contains_key(hash)
    }

    fn pending_deadline(&self, requested_at: Instant) -> Instant {
        requested_at
            .checked_add(self.budget.pending_timeout)
            .unwrap_or(requested_at)
    }

    fn record_pending_deadline(&mut self, requested_at: Instant) {
        let deadline = self.pending_deadline(requested_at);
        if self
            .next_pending_deadline
            .is_none_or(|current| deadline < current)
        {
            self.next_pending_deadline = Some(deadline);
        }
    }

    fn refresh_next_pending_deadline(&mut self) {
        self.next_pending_deadline = self
            .pending
            .values()
            .map(|pending| self.pending_deadline(pending.requested_at))
            .min();
    }

    pub(super) fn release_disconnected_peers(
        &mut self,
        mut is_live_peer: impl FnMut(&SocketAddr) -> bool,
    ) {
        let mut retry_height = self.next_request_height;
        self.pending.retain(|_hash, pending| {
            if is_live_peer(&pending.peer_addr) {
                return true;
            }
            retry_height = retry_height.min(pending.height);
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            false
        });
        self.peer_inflight
            .retain(|peer, _inflight| is_live_peer(peer));
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

        let mut entries = self.expired_request_entries(expired, batch_limit, &mut byte_capacity);
        let mut selected_hashes = (!entries.is_empty()).then(|| {
            let mut selected_hashes = HashSet::with_capacity(entries.len());
            selected_hashes.extend(entries.iter().map(|entry| entry.hash));
            selected_hashes
        });

        let Some(mut height) = applied_tip.height.checked_add(1) else {
            return non_empty_request(peer_addr, entries, self.next_request_height);
        };
        height = height.max(self.next_request_height);
        let mut next_request_height = self.next_request_height;
        let request_tip_height = chain_tip.height.min(peer_best_height);
        let remaining_limit = batch_limit
            .saturating_sub(entries.len())
            .min(byte_capacity / self.ewma_block_bytes);
        if height <= request_tip_height && remaining_limit > 0 {
            if entries.is_empty() {
                let scan = RequestScan {
                    height,
                    request_tip_height,
                    remaining_limit,
                    next_request_height,
                };
                if let Some(request) = self.clean_contiguous_peer_request(
                    peer_addr,
                    chain_tip,
                    tree,
                    height,
                    request_tip_height,
                    remaining_limit,
                    next_request_height,
                ) {
                    return Some(request);
                }
                if let Some(request) =
                    self.received_filtered_peer_request(peer_addr, chain_tip, tree, scan)
                {
                    return Some(request);
                }
            }

            next_request_height = self.extend_request_by_reverse_scan(
                chain_tip,
                tree,
                RequestScan {
                    height,
                    request_tip_height,
                    remaining_limit,
                    next_request_height,
                },
                &mut selected_hashes,
                &mut entries,
            );
        }
        non_empty_request(peer_addr, entries, next_request_height)
    }

    fn extend_request_by_reverse_scan(
        &self,
        chain_tip: &TipSnapshot,
        tree: &BlockTree,
        scan: RequestScan,
        selected_hashes: &mut Option<HashSet<Hash256>>,
        entries: &mut Vec<PeerRequestEntry>,
    ) -> u32 {
        if scan.remaining_limit == 0 {
            return scan.next_request_height;
        }
        let mut next_request_height = scan.next_request_height;
        let skipped_hashes = self
            .pending
            .len()
            .saturating_add(self.received.len())
            .saturating_add(selected_hashes.as_ref().map_or(0, HashSet::len));
        // Each skipped hash can displace at most one eligible height from the prefix.
        let scan_limit = scan.remaining_limit.saturating_add(skipped_hashes);
        let scan_span = u32::try_from(scan_limit.saturating_sub(1)).unwrap_or(u32::MAX);
        let request_end_height = scan
            .height
            .saturating_add(scan_span)
            .min(scan.request_tip_height);
        let Some(mut cursor) = tree.node_at_height_from(chain_tip.tip_id, request_end_height)
        else {
            return scan.next_request_height;
        };
        let mut candidates: VecDeque<PeerRequestEntry> =
            VecDeque::with_capacity(scan.remaining_limit);
        while let Ok(node) = tree.node(cursor) {
            if node.height < scan.height {
                break;
            }
            if !self.pending.contains_key(&node.hash)
                && !self.received.contains_key(&node.hash)
                && selected_hashes
                    .as_ref()
                    .is_none_or(|hashes| !hashes.contains(&node.hash))
            {
                if candidates.len() == scan.remaining_limit
                    && let Some(removed) = candidates.pop_front()
                    && let Some(selected_hashes) = selected_hashes.as_mut()
                {
                    selected_hashes.remove(&removed.hash);
                }
                if let Some(selected_hashes) = selected_hashes.as_mut() {
                    selected_hashes.insert(node.hash);
                }
                candidates.push_back(PeerRequestEntry {
                    hash: node.hash,
                    height: node.height,
                });
            }
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
        }
        let scanned_all_eligible = candidates.len() < scan.remaining_limit;
        for entry in candidates.into_iter().rev() {
            next_request_height = next_request_height.max(entry.height.saturating_add(1));
            entries.push(entry);
        }
        if scanned_all_eligible {
            next_request_height =
                next_request_height.max(scan.request_tip_height.saturating_add(1));
        }
        next_request_height
    }

    fn received_filtered_peer_request(
        &self,
        peer_addr: SocketAddr,
        chain_tip: &TipSnapshot,
        tree: &BlockTree,
        scan: RequestScan,
    ) -> Option<PeerRequest> {
        if !self.pending.is_empty() || self.received.is_empty() || scan.remaining_limit == 0 {
            return None;
        }
        let scan_limit = scan.remaining_limit.saturating_add(self.received.len());
        let scan_span = u32::try_from(scan_limit.saturating_sub(1)).unwrap_or(u32::MAX);
        let request_end_height = scan
            .height
            .saturating_add(scan_span)
            .min(scan.request_tip_height);
        let mut cursor = tree.node_at_height_from(chain_tip.tip_id, request_end_height)?;
        let capacity = usize::try_from(
            request_end_height
                .saturating_sub(scan.height)
                .saturating_add(1),
        )
        .ok()?;
        let mut entries = Vec::with_capacity(capacity.min(scan_limit));
        while let Ok(node) = tree.node(cursor) {
            if node.height < scan.height {
                break;
            }
            if !self.received.contains_key(&node.hash) {
                entries.push(PeerRequestEntry {
                    hash: node.hash,
                    height: node.height,
                });
            }
            if node.height == scan.height {
                break;
            }
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
        }
        entries.reverse();
        if entries.len() > scan.remaining_limit {
            entries.truncate(scan.remaining_limit);
            let next_request_height = entries
                .iter()
                .fold(scan.next_request_height, |height, entry| {
                    height.max(entry.height.saturating_add(1))
                });
            return non_empty_request(peer_addr, entries, next_request_height);
        }
        let next_request_height = scan
            .next_request_height
            .max(request_end_height.saturating_add(1));
        non_empty_request(peer_addr, entries, next_request_height)
    }

    fn expired_request_entries(
        &self,
        expired: Vec<PeerRequestEntry>,
        batch_limit: usize,
        byte_capacity: &mut usize,
    ) -> Vec<PeerRequestEntry> {
        let mut entries = Vec::with_capacity(batch_limit);
        for entry in expired {
            if entries.len() >= batch_limit || *byte_capacity < self.ewma_block_bytes {
                break;
            }
            if self.received.contains_key(&entry.hash) || self.pending.contains_key(&entry.hash) {
                continue;
            }
            *byte_capacity = byte_capacity.saturating_sub(self.ewma_block_bytes);
            entries.push(entry);
        }
        entries
    }

    fn clean_contiguous_peer_request(
        &self,
        peer_addr: SocketAddr,
        chain_tip: &TipSnapshot,
        tree: &BlockTree,
        height: u32,
        request_tip_height: u32,
        remaining_limit: usize,
        next_request_height: u32,
    ) -> Option<PeerRequest> {
        if !self.pending.is_empty() || !self.received.is_empty() {
            return None;
        }
        let request_end_height = height
            .saturating_add(u32::try_from(remaining_limit.saturating_sub(1)).unwrap_or(u32::MAX))
            .min(request_tip_height);
        let entries =
            contiguous_request_entries(tree, chain_tip.tip_id, height, request_end_height)?;
        let next_request_height = entries.iter().fold(next_request_height, |height, entry| {
            height.max(entry.height.saturating_add(1))
        });
        non_empty_request(peer_addr, entries, next_request_height)
    }

    pub(super) fn mark_requested(&mut self, request: &PeerRequest, now: Instant) {
        let estimated_bytes = self.ewma_block_bytes;
        let inflight = self.peer_inflight.entry(request.peer_addr).or_default();
        let mut recorded_pending = false;
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
            recorded_pending = true;
        }
        if recorded_pending {
            self.record_pending_deadline(now);
        }
        self.next_request_height = self.next_request_height.max(request.next_request_height);
    }

    pub(super) fn mark_received(&mut self, hash: Hash256, bytes: usize) -> bool {
        let (height, needs_height_lookup) = if let Some(pending) = self.pending.remove(&hash) {
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            self.release_peer_block(pending.peer_addr);
            (pending.height, false)
        } else {
            (0, true)
        };
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
        needs_height_lookup
    }

    pub(super) fn update_received_height(&mut self, hash: &Hash256, height: u32) {
        if let Some(received) = self.received.get_mut(hash) {
            received.height = height;
        }
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
        if self
            .next_pending_deadline
            .is_none_or(|deadline| now < deadline)
        {
            return Vec::new();
        }
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
        self.refresh_next_pending_deadline();
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

fn contiguous_request_entries(
    tree: &BlockTree,
    tip_id: bitcoin_rs_chain::NodeId,
    start_height: u32,
    end_height: u32,
) -> Option<Vec<PeerRequestEntry>> {
    let mut cursor = tree.node_at_height_from(tip_id, end_height)?;
    let capacity =
        usize::try_from(end_height.saturating_sub(start_height).saturating_add(1)).ok()?;
    let mut entries = Vec::with_capacity(capacity);
    while let Ok(node) = tree.node(cursor) {
        if node.height < start_height {
            break;
        }
        entries.push(PeerRequestEntry {
            hash: node.hash,
            height: node.height,
        });
        if node.height == start_height {
            entries.reverse();
            return Some(entries);
        }
        cursor = node.parent?;
    }
    None
}
