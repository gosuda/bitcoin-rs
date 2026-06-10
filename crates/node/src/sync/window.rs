use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use hashbrown::{HashMap, HashSet};
use smallvec::SmallVec;

#[derive(Clone, Copy, Debug)]
pub(super) struct SyncBudget {
    pub(super) max_pending_blocks: usize,
    pub(super) max_pending_bytes: usize,
    pub(super) max_received_blocks: usize,
    pub(super) max_received_bytes: usize,
    pub(super) max_peer_inflight: usize,
    pub(super) fanout_peer_inflight: usize,
    pub(super) min_peers_for_fanout: usize,
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

    pub(super) fn entries(&self) -> impl Iterator<Item = (u32, Hash256)> + '_ {
        self.entries.iter().map(|entry| (entry.height, entry.hash))
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

enum SelectedHashes {
    Inline(SmallVec<[Hash256; 4]>),
    Set(HashSet<Hash256>),
}

impl SelectedHashes {
    fn from_entries(entries: &[PeerRequestEntry]) -> Option<Self> {
        if entries.is_empty() {
            return None;
        }
        if entries.len() <= 4 {
            return Some(Self::Inline(
                entries.iter().map(|entry| entry.hash).collect(),
            ));
        }
        let mut selected_hashes = HashSet::with_capacity(entries.len());
        selected_hashes.extend(entries.iter().map(|entry| entry.hash));
        Some(Self::Set(selected_hashes))
    }

    fn len(&self) -> usize {
        match self {
            Self::Inline(hashes) => hashes.len(),
            Self::Set(hashes) => hashes.len(),
        }
    }

    fn contains(&self, hash: &Hash256) -> bool {
        match self {
            Self::Inline(hashes) => hashes.contains(hash),
            Self::Set(hashes) => hashes.contains(hash),
        }
    }
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
    /// Whether block requests currently fan out across peers. Driven by the
    /// sync layer's per-tick count of fan-out-eligible peers (KTD6 predicate:
    /// outbound, witness-serving, header chain above ours, not soft-demoted)
    /// through [`Self::set_fanout_eligible_peers`]'s one-peer hysteresis.
    /// Starts disengaged so a fresh window always begins in single-peer
    /// fallback.
    fanout_engaged: bool,
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
            pending: HashMap::with_capacity(budget.max_pending_blocks),
            received: HashMap::with_capacity(budget.max_received_blocks),
            peer_inflight: HashMap::with_capacity(
                budget.max_pending_blocks.min(budget.max_peer_inflight),
            ),
            pending_bytes: 0,
            received_bytes: 0,
            ewma_block_bytes: 256 * 1024,
            next_request_height: 1,
            next_pending_deadline: None,
            fanout_engaged: false,
        }
    }

    /// Records how many peers currently satisfy the fan-out eligibility
    /// predicate and updates the fan-out engagement with one-peer hysteresis:
    /// engage at `min_peers_for_fanout`, hold at one below, disengage only
    /// further down.
    ///
    /// The count keeps KTD6's demotion clause (a stalled peer must not count
    /// toward fan-out), so without hysteresis a single transient soft-demotion
    /// at the threshold would flap the mode tick-to-tick and re-concentrate
    /// the whole window on one deep peer mid-stripe. Holding the mode one
    /// peer below the threshold instead costs at most one undistributed
    /// stripe (`fanout_peer_inflight` blocks) until the demotion clears or a
    /// second peer drops out — at which point the drop is structural and the
    /// single-peer fallback is the right mode.
    pub(super) fn set_fanout_eligible_peers(&mut self, count: usize) {
        if count >= self.budget.min_peers_for_fanout {
            self.fanout_engaged = true;
        } else if count.saturating_add(1) < self.budget.min_peers_for_fanout {
            self.fanout_engaged = false;
        }
    }

    /// Whether block requests fan out across peers (true) or collapse to the
    /// single-peer deep window (false). Fan-out engages only when enough
    /// eligible peers exist to fill the window at the shallow per-peer cap
    /// (with [`Self::set_fanout_eligible_peers`]'s hysteresis); below that
    /// the per-peer cap reverts to the deep fallback so one healthy peer can
    /// fill the whole window (no under-fill regression).
    pub(super) const fn fanout_active(&self) -> bool {
        self.fanout_engaged
    }

    /// Per-peer in-flight cap for the current mode: the shallow fan-out cap
    /// (Core's `MAX_BLOCKS_IN_TRANSIT_PER_PEER` shape) when fan-out is active,
    /// the deep fallback cap otherwise. The fan-out cap never exceeds the
    /// fallback cap, so injected shallow budgets stay binding in either mode.
    const fn effective_peer_inflight(&self) -> usize {
        if self.fanout_active() && self.budget.fanout_peer_inflight < self.budget.max_peer_inflight
        {
            self.budget.fanout_peer_inflight
        } else {
            self.budget.max_peer_inflight
        }
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Maximum number of blocks the download window will keep pending at once.
    ///
    /// Used as the horizon cap when the apply-side cache is repopulated on a
    /// miss: at most this many blocks can be in flight (and therefore stage)
    /// before the cache's validity keys change and force a refresh.
    pub(super) const fn max_pending_blocks(&self) -> usize {
        self.budget.max_pending_blocks
    }

    pub(super) const fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    pub(super) fn has_request_capacity(&self) -> bool {
        self.pending.len() < self.budget.max_pending_blocks
            && self.pending_bytes.saturating_add(self.ewma_block_bytes)
                <= self.budget.max_pending_bytes
            && self.staged_byte_headroom() >= self.ewma_block_bytes
            && self.staged_count_headroom(0) > 0
    }

    /// Staged-byte backpressure: once the blocks already received and waiting
    /// to apply have consumed the staging byte budget, stop issuing new block
    /// requests — arrivals would only be refused by the stager and
    /// re-requested, churning bandwidth. Capacity returns as staged blocks are
    /// applied (or expire) and their bytes are released.
    const fn staged_bytes_exhausted(&self) -> bool {
        self.received_bytes >= self.budget.max_received_bytes
    }

    /// Staging bytes still free if every in-flight pending block arrives at
    /// the current per-block estimate. Request sizing is clamped to this so a
    /// gate-open burst cannot top a partially full stager over its budget and
    /// trigger refuse/re-download churn in the high-height regime (the
    /// staged-byte gate alone is headroom-blind: it only closes once staging
    /// is already exhausted).
    ///
    /// The clamp engages only while blocks are actually staged. With an empty
    /// stager liveness wins: the window-front request must stay issuable even
    /// when one estimated block exceeds the staging budget (the stager's
    /// expected-block exemption and drop-for-retry are the degrade path
    /// there), and the default budget pair (`max_pending_bytes ==
    /// max_received_bytes`) already bounds a from-empty burst to exactly the
    /// staging budget.
    const fn staged_byte_headroom(&self) -> usize {
        if self.received_bytes == 0 {
            return usize::MAX;
        }
        self.budget
            .max_received_bytes
            .saturating_sub(self.received_bytes)
            .saturating_sub(self.pending_bytes)
    }

    /// Staging slots still free if every in-flight pending block arrives: the
    /// count-denominated twin of [`Self::staged_byte_headroom`]. The twin is
    /// load-bearing, not symmetry for its own sake: the stager enforces its
    /// byte budget as admission backpressure but its count budget by
    /// **evicting the oldest staged blocks** (`stage.rs`,
    /// `evict_over_budget`) — the blocks nearest the apply frontier. A window
    /// clamped on bytes alone keeps requesting while a stalled front-stripe
    /// peer freezes the frontier, and the healthy peers' next wave pushes the
    /// staged count over budget into evict → drop-for-retry → re-request →
    /// evict churn (the recorded live-collapse signature). Clamping requests
    /// so staged + pending never exceeds `max_received_blocks` turns count
    /// overflow into request backpressure, exactly like the byte bound.
    ///
    /// Same from-empty engagement rule as the byte twin: with nothing staged
    /// the clamp stands down for liveness, and the default budget pair
    /// (`max_pending_blocks == max_received_blocks`) bounds a from-empty
    /// burst at exactly the count budget — and the stager evicts only
    /// strictly *above* `max_received_blocks`, so even a fully delivered
    /// burst lands at the budget without eviction.
    ///
    /// `expired_pending_blocks` credits pendings past the re-request timeout
    /// back to headroom. Unlike the byte clamp (which leaves expired bytes
    /// uncredited and recovers through the staged-block prune, the tested U5
    /// chain), the count clamp must credit them in the scan limit: a stalled
    /// front whose pendings hold staged + pending at the budget would
    /// otherwise pin the scan limit at zero — and expiry runs only inside
    /// [`Self::next_peer_request`], so the wedge could not process its own
    /// deadlines until the prune discarded every staged block into
    /// re-download. With the credit, the scan limit reopens at the pending
    /// timeout and the normal request path expires and re-requests the front
    /// while the staged set survives intact. Late arrival of an expired
    /// original deduplicates against its re-request by hash, so the credit
    /// cannot double-fill staging.
    fn staged_count_headroom(&self, expired_pending_blocks: usize) -> usize {
        if self.received.is_empty() {
            return usize::MAX;
        }
        self.budget
            .max_received_blocks
            .saturating_sub(self.received.len())
            .saturating_sub(self.pending.len().saturating_sub(expired_pending_blocks))
    }

    pub(super) fn request_peer_scan_limit(&self, now: Instant) -> usize {
        if self.staged_bytes_exhausted() {
            return 0;
        }
        let per_peer = self
            .budget
            .getdata_batch_limit
            .min(self.effective_peer_inflight());
        if per_peer == 0 || self.ewma_block_bytes == 0 {
            return 0;
        }
        let (expired_blocks, expired_bytes) = self.expired_pending_capacity(now);
        let block_capacity = self
            .budget
            .max_pending_blocks
            .saturating_sub(self.pending.len().saturating_sub(expired_blocks))
            .min(self.staged_count_headroom(expired_blocks));
        // Expired bytes are credited back to pending capacity (they will be
        // re-requested) but not to staging byte headroom: a late arrival of
        // the original request still stages. The count headroom does credit
        // them — see `staged_count_headroom` for why the wedge needs it.
        let byte_capacity = self
            .budget
            .max_pending_bytes
            .saturating_sub(self.pending_bytes.saturating_sub(expired_bytes))
            .min(self.staged_byte_headroom())
            / self.ewma_block_bytes;
        let request_blocks = block_capacity.min(byte_capacity);
        if request_blocks == 0 {
            return 0;
        }
        request_blocks
            .div_ceil(per_peer)
            .saturating_add(self.peer_inflight.len())
    }

    fn expired_pending_capacity(&self, now: Instant) -> (usize, usize) {
        if self
            .next_pending_deadline
            .is_none_or(|deadline| now < deadline)
        {
            return (0, 0);
        }
        self.pending
            .values()
            .fold((0_usize, 0_usize), |(blocks, bytes), pending| {
                if now.duration_since(pending.requested_at) < self.budget.pending_timeout {
                    return (blocks, bytes);
                }
                (
                    blocks.saturating_add(1),
                    bytes.saturating_add(pending.estimated_bytes),
                )
            })
    }

    /// Whether `peer_addr` owns a pending block past the re-request timeout —
    /// the soft-demotion signal: such a peer gets no new front-of-window
    /// requests unless it is the last-resort peer, and it does not count as
    /// fan-out-eligible (KTD6's "not currently soft-demoted" clause).
    pub(super) fn peer_has_expired_pending(&self, peer_addr: SocketAddr, now: Instant) -> bool {
        if self
            .next_pending_deadline
            .is_none_or(|deadline| now < deadline)
        {
            return false;
        }
        self.pending.values().any(|pending| {
            pending.peer_addr == peer_addr
                && now.duration_since(pending.requested_at) >= self.budget.pending_timeout
        })
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
        let mut removed_earliest_deadline = false;
        let pending_timeout = self.budget.pending_timeout;
        let next_pending_deadline = self.next_pending_deadline;
        self.pending.retain(|_hash, pending| {
            if is_live_peer(&pending.peer_addr) {
                return true;
            }
            retry_height = retry_height.min(pending.height);
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            let deadline = pending
                .requested_at
                .checked_add(pending_timeout)
                .unwrap_or(pending.requested_at);
            if Some(deadline) == next_pending_deadline {
                removed_earliest_deadline = true;
            }
            false
        });
        self.peer_inflight
            .retain(|peer, _inflight| is_live_peer(peer));
        if removed_earliest_deadline {
            self.refresh_next_pending_deadline();
        }
        self.next_request_height = retry_height;
    }

    pub(super) fn next_peer_request(
        &mut self,
        peer_addr: SocketAddr,
        allow_expired_retry_from_peer: bool,
        chain_tip: &TipSnapshot,
        applied_tip: &TipSnapshot,
        peer_best_height: u32,
        tree: &BlockTree,
        now: Instant,
    ) -> Option<PeerRequest> {
        if self.staged_bytes_exhausted() {
            return None;
        }
        if !allow_expired_retry_from_peer && self.peer_has_expired_pending(peer_addr, now) {
            return None;
        }
        let mut expired = self.expire_pending(now);
        expired.sort_by_key(|entry| entry.height);

        let peer_inflight = self
            .peer_inflight
            .get(&peer_addr)
            .map_or(0, |inflight| inflight.blocks);
        let peer_capacity = self.effective_peer_inflight().saturating_sub(peer_inflight);
        // Expiry already ran above, so the count headroom needs no expired
        // credit here: `pending` reflects only live in-flight requests.
        let block_capacity = self
            .budget
            .max_pending_blocks
            .saturating_sub(self.pending.len())
            .min(self.staged_count_headroom(0));
        let mut byte_capacity = self
            .budget
            .max_pending_bytes
            .saturating_sub(self.pending_bytes)
            .min(self.staged_byte_headroom());
        let batch_limit = self
            .budget
            .getdata_batch_limit
            .min(peer_capacity)
            .min(block_capacity);
        if batch_limit == 0 || byte_capacity < self.ewma_block_bytes {
            return None;
        }

        let mut entries = self.expired_request_entries(expired, batch_limit, &mut byte_capacity);
        let selected_hashes = SelectedHashes::from_entries(&entries);

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
                selected_hashes.as_ref(),
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
        selected_hashes: Option<&SelectedHashes>,
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
            .saturating_add(selected_hashes.map_or(0, SelectedHashes::len));
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
        let mut candidates = Vec::with_capacity(scan_limit);
        while let Ok(node) = tree.node(cursor) {
            if node.height < scan.height {
                break;
            }
            if !self.pending.contains_key(&node.hash)
                && !self.received.contains_key(&node.hash)
                && selected_hashes.is_none_or(|hashes| !hashes.contains(&node.hash))
            {
                candidates.push(PeerRequestEntry {
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
        let first_selected = candidates.len().saturating_sub(scan.remaining_limit);
        for entry in candidates[first_selected..].iter().rev().copied() {
            next_request_height = next_request_height.max(entry.height.saturating_add(1));
            entries.push(entry);
        }
        if scanned_all_eligible {
            next_request_height =
                next_request_height.max(scan.request_tip_height.saturating_add(1));
        }
        next_request_height
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
        let next_request_height = next_request_height.max(request_end_height.saturating_add(1));
        non_empty_request(peer_addr, entries, next_request_height)
    }

    pub(super) fn mark_requested(&mut self, request: &PeerRequest, now: Instant) -> bool {
        let estimated_bytes = self.ewma_block_bytes;
        let inflight = self.peer_inflight.entry(request.peer_addr).or_default();
        for entry in &request.entries {
            debug_assert!(!self.pending.contains_key(&entry.hash));
            debug_assert!(!self.received.contains_key(&entry.hash));
            let previous = self.pending.insert(
                entry.hash,
                PendingBlock {
                    peer_addr: request.peer_addr,
                    requested_at: now,
                    height: entry.height,
                    estimated_bytes,
                },
            );
            debug_assert!(previous.is_none());
            self.pending_bytes = self.pending_bytes.saturating_add(estimated_bytes);
            inflight.blocks = inflight.blocks.saturating_add(1);
        }
        if !request.entries.is_empty() {
            self.record_pending_deadline(now);
        }
        self.next_request_height = self.next_request_height.max(request.next_request_height);
        self.has_request_capacity()
    }

    pub(super) fn mark_received(&mut self, hash: Hash256, bytes: usize) -> bool {
        let (height, needs_height_lookup) = if let Some(pending) = self.remove_pending(&hash) {
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

    #[cfg(test)]
    pub(super) fn mark_applied(&mut self, hash: &Hash256) {
        self.mark_received_applied(hash);
        self.remove_pending(hash);
    }

    pub(super) fn mark_received_applied(&mut self, hash: &Hash256) {
        self.remove_received(hash);
    }

    pub(super) fn drop_received_for_retry(&mut self, hash: &Hash256) {
        if let Some(received) = self.remove_received(hash) {
            self.next_request_height = self.next_request_height.min(received.height);
        }
    }

    pub(super) fn drop_for_retry(&mut self, hash: &Hash256) {
        self.drop_received_for_retry(hash);
        if let Some(pending) = self.remove_pending(hash) {
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
        let pending_timeout = self.budget.pending_timeout;
        let mut entries = Vec::new();
        {
            let peer_inflight = &mut self.peer_inflight;
            let pending_bytes = &mut self.pending_bytes;
            let next_request_height = &mut self.next_request_height;
            for (hash, pending) in self.pending.extract_if(|_hash, pending| {
                now.duration_since(pending.requested_at) >= pending_timeout
            }) {
                *pending_bytes = pending_bytes.saturating_sub(pending.estimated_bytes);
                release_peer_block(peer_inflight, pending.peer_addr);
                *next_request_height = (*next_request_height).min(pending.height);
                entries.push(PeerRequestEntry {
                    hash,
                    height: pending.height,
                });
            }
        }
        self.refresh_next_pending_deadline();
        entries
    }

    fn remove_received(&mut self, hash: &Hash256) -> Option<ReceivedBlock> {
        let received = self.received.remove(hash)?;
        self.received_bytes = self.received_bytes.saturating_sub(received.bytes);
        Some(received)
    }

    fn remove_pending(&mut self, hash: &Hash256) -> Option<PendingBlock> {
        let pending = self.pending.remove(hash)?;
        self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
        self.release_peer_block(pending.peer_addr);
        if Some(self.pending_deadline(pending.requested_at)) == self.next_pending_deadline {
            self.refresh_next_pending_deadline();
        }
        Some(pending)
    }

    fn release_peer_block(&mut self, peer_addr: SocketAddr) {
        release_peer_block(&mut self.peer_inflight, peer_addr);
    }
}

fn release_peer_block(
    peer_inflight: &mut HashMap<SocketAddr, PeerInflight>,
    peer_addr: SocketAddr,
) {
    let Some(inflight) = peer_inflight.get_mut(&peer_addr) else {
        return;
    };
    inflight.blocks = inflight.blocks.saturating_sub(1);
    if inflight.blocks == 0 {
        peer_inflight.remove(&peer_addr);
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bitcoin_rs_primitives::Hash256;

    use super::{DownloadWindow, SyncBudget};

    #[test]
    fn request_peer_scan_limit_accounts_for_pending_bytes_and_inflight_peers() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 8,
            max_pending_bytes: 4 * 256 * 1024,
            max_peer_inflight: 2,
            getdata_batch_limit: 4,
            ..test_budget()
        });
        window.pending_bytes = 256 * 1024;
        window.peer_inflight.insert(
            std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            super::PeerInflight { blocks: 2 },
        );

        assert_eq!(window.request_peer_scan_limit(Instant::now()), 3);
    }

    #[test]
    fn request_peer_scan_limit_counts_expired_pending_capacity() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 2,
            max_pending_bytes: 2 * 256 * 1024,
            max_peer_inflight: 2,
            getdata_batch_limit: 2,
            pending_timeout: Duration::ZERO,
            ..test_budget()
        });
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        for (byte, height) in [(1, 1_u32), (2, 2)] {
            window.pending.insert(
                hash(byte),
                super::PendingBlock {
                    peer_addr,
                    requested_at: now,
                    height,
                    estimated_bytes: 256 * 1024,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(256 * 1024);
        }
        window.next_pending_deadline = Some(now);
        window
            .peer_inflight
            .insert(peer_addr, super::PeerInflight { blocks: 2 });

        assert_eq!(window.request_peer_scan_limit(now), 2);
    }

    #[test]
    fn default_budget_keeps_full_request_window_for_large_blocks() {
        let mut window = DownloadWindow::new(crate::sync::default_sync_budget());
        window.ewma_block_bytes = 2 * 1024 * 1024;
        window.pending_bytes = window
            .budget
            .max_pending_blocks
            .saturating_sub(1)
            .saturating_mul(window.ewma_block_bytes);

        assert!(window.has_request_capacity());
    }

    #[test]
    fn release_disconnected_peers_refreshes_pending_deadline() {
        let mut window = DownloadWindow::new(SyncBudget {
            pending_timeout: Duration::from_secs(10),
            ..test_budget()
        });
        let now = Instant::now();
        let stale_peer = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let live_peer = std::net::SocketAddr::from(([127, 0, 0, 2], 8333));
        let stale_requested_at = now
            .checked_sub(Duration::from_secs(9))
            .unwrap_or_else(|| panic!("test instant underflow"));
        let estimated_bytes = 256 * 1024;
        for (peer_addr, requested_at, height, byte) in [
            (stale_peer, stale_requested_at, 1_u32, 0x81),
            (live_peer, now, 2_u32, 0x82),
        ] {
            window.pending.insert(
                hash(byte),
                super::PendingBlock {
                    peer_addr,
                    requested_at,
                    height,
                    estimated_bytes,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(estimated_bytes);
            window.record_pending_deadline(requested_at);
        }

        window.release_disconnected_peers(|peer| *peer == live_peer);

        assert_eq!(window.pending_len(), 1);
        assert_eq!(window.pending_bytes(), estimated_bytes);
        assert_eq!(window.next_request_height, 1);
        assert_eq!(
            window.next_pending_deadline,
            Some(now + Duration::from_secs(10))
        );
    }

    #[test]
    fn mark_received_refreshes_pending_deadline_after_earliest_pending() {
        let mut window = DownloadWindow::new(SyncBudget {
            pending_timeout: Duration::from_secs(10),
            ..test_budget()
        });
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let earliest = hash(0x91);
        let later = hash(0x92);
        let earliest_requested_at = now
            .checked_sub(Duration::from_secs(5))
            .unwrap_or_else(|| panic!("test instant underflow"));
        let estimated_bytes = 256 * 1024;
        for (hash, requested_at, height) in [
            (earliest, earliest_requested_at, 1_u32),
            (later, now, 2_u32),
        ] {
            window.pending.insert(
                hash,
                super::PendingBlock {
                    peer_addr,
                    requested_at,
                    height,
                    estimated_bytes,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(estimated_bytes);
            window.record_pending_deadline(requested_at);
        }
        window
            .peer_inflight
            .insert(peer_addr, super::PeerInflight { blocks: 2 });

        let needs_height_lookup = window.mark_received(earliest, 80);

        assert!(!needs_height_lookup);
        assert_eq!(window.pending_len(), 1);
        assert!(window.contains_pending(&later));
        assert_eq!(
            window.next_pending_deadline,
            Some(now + Duration::from_secs(10))
        );
    }

    #[test]
    fn mark_received_applied_removes_only_received_accounting() {
        let mut window = DownloadWindow::new(test_budget());
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let applied = hash(0xa1);
        let pending = hash(0xa2);
        let pending_bytes = 256 * 1024;
        let received_bytes = 80;
        window.pending.insert(
            pending,
            super::PendingBlock {
                peer_addr,
                requested_at: now,
                height: 2,
                estimated_bytes: pending_bytes,
            },
        );
        window.pending_bytes = pending_bytes;
        window.received.insert(
            applied,
            super::ReceivedBlock {
                height: 1,
                bytes: received_bytes,
            },
        );
        window.received_bytes = received_bytes;

        window.mark_received_applied(&applied);

        assert_eq!(window.received_len(), 0);
        assert_eq!(window.received_bytes, 0);
        assert_eq!(window.pending_len(), 1);
        assert!(window.contains_pending(&pending));
        assert_eq!(window.pending_bytes(), pending_bytes);
    }

    #[test]
    fn staged_byte_exhaustion_stops_new_requests_until_applied() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_received_bytes: 100,
            ..test_budget()
        });
        let staged = hash(0xb1);
        assert!(window.has_request_capacity());
        assert_ne!(window.request_peer_scan_limit(Instant::now()), 0);

        window.mark_received(staged, 100);

        // Staged bytes at the budget: stop issuing new block requests instead
        // of letting arrivals bounce off the exhausted stager.
        assert!(!window.has_request_capacity());
        assert_eq!(window.request_peer_scan_limit(Instant::now()), 0);

        window.mark_received_applied(&staged);

        // Applying the staged block releases its bytes and reopens the window.
        assert!(window.has_request_capacity());
        assert_ne!(window.request_peer_scan_limit(Instant::now()), 0);
    }

    #[test]
    fn fanout_threshold_switches_effective_peer_cap() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 128,
            max_peer_inflight: 128,
            fanout_peer_inflight: 16,
            min_peers_for_fanout: 8,
            getdata_batch_limit: 128,
            ..test_budget()
        });
        let now = Instant::now();

        // Below the threshold: single-peer deep window — one peer can take
        // the full 128, so only one peer needs scanning.
        window.set_fanout_eligible_peers(7);
        assert!(!window.fanout_active());
        assert_eq!(window.request_peer_scan_limit(now), 1);

        // At the threshold: shallow per-peer cap engages and the scan fans
        // out to enough peers to fill the window (128 / 16 = 8).
        window.set_fanout_eligible_peers(8);
        assert!(window.fanout_active());
        assert_eq!(window.request_peer_scan_limit(now), 8);
    }

    #[test]
    fn request_sizing_clamped_to_staged_byte_headroom() {
        // Staging budget of four estimated blocks with three already staged:
        // the gate is still open, but only one more block fits — a gate-open
        // burst must not over-request past that headroom.
        let slot = 256 * 1024;
        let mut window = DownloadWindow::new(SyncBudget {
            max_received_bytes: 4 * slot,
            ..test_budget()
        });
        for byte in [0xc1, 0xc2, 0xc3] {
            window.mark_received(hash(byte), slot);
        }

        assert!(window.has_request_capacity());
        assert_eq!(window.request_peer_scan_limit(Instant::now()), 1);

        // The fourth staged block consumes the last slot: headroom hits zero
        // and request capacity closes before any eviction can happen.
        window.mark_received(hash(0xc4), slot);
        assert!(!window.has_request_capacity());
        assert_eq!(window.request_peer_scan_limit(Instant::now()), 0);
    }

    #[test]
    fn request_sizing_clamped_to_staged_count_headroom() {
        // Count budget of four with three blocks already staged: the byte
        // budgets are unbounded, so only the count clamp can stop a burst
        // from over-requesting into the stager's eviction threshold.
        let mut window = DownloadWindow::new(SyncBudget {
            max_received_blocks: 4,
            ..test_budget()
        });
        for byte in [0xd1, 0xd2, 0xd3] {
            window.mark_received(hash(byte), 80);
        }

        assert!(window.has_request_capacity());
        assert_eq!(window.request_peer_scan_limit(Instant::now()), 1);

        // The fourth staged block consumes the last slot: count headroom hits
        // zero and requests stop — overflow becomes request backpressure
        // before the stager's count budget could ever evict.
        window.mark_received(hash(0xd4), 80);
        assert!(!window.has_request_capacity());
        assert_eq!(window.request_peer_scan_limit(Instant::now()), 0);
    }

    #[test]
    fn expired_pendings_reopen_scan_limit_through_count_headroom() {
        // Count wedge: staged (2) + pending (2) at the count budget (4), with
        // the pendings held by a stalled peer. While the pendings are live
        // the scan limit must be zero; once they pass the re-request timeout
        // the credit must reopen the scan limit so the request path can
        // expire and re-request the front (otherwise the wedge can only be
        // broken by pruning every staged block into re-download).
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 4,
            max_received_blocks: 4,
            max_peer_inflight: 4,
            getdata_batch_limit: 4,
            pending_timeout: Duration::from_secs(10),
            ..test_budget()
        });
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        for (byte, height) in [(0xe1, 1_u32), (0xe2, 2)] {
            window.pending.insert(
                hash(byte),
                super::PendingBlock {
                    peer_addr,
                    requested_at: now,
                    height,
                    estimated_bytes: 256 * 1024,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(256 * 1024);
            window.record_pending_deadline(now);
        }
        window
            .peer_inflight
            .insert(peer_addr, super::PeerInflight { blocks: 2 });
        for byte in [0xe3, 0xe4] {
            window.mark_received(hash(byte), 80);
        }

        assert_eq!(window.request_peer_scan_limit(now), 0);

        let after_timeout = now + Duration::from_secs(10);
        assert_ne!(window.request_peer_scan_limit(after_timeout), 0);
    }

    #[test]
    fn fanout_engagement_has_one_peer_hysteresis() {
        let mut window = DownloadWindow::new(SyncBudget {
            min_peers_for_fanout: 8,
            ..test_budget()
        });

        // Fresh window: disengaged until the threshold is reached.
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(7);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(8);
        assert!(window.fanout_active());

        // One transient demotion at the threshold must not flap the mode.
        window.set_fanout_eligible_peers(7);
        assert!(window.fanout_active());
        window.set_fanout_eligible_peers(8);
        assert!(window.fanout_active());

        // A second peer dropping out is structural: disengage, and stay
        // disengaged at one-below until the full threshold returns.
        window.set_fanout_eligible_peers(6);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(7);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(8);
        assert!(window.fanout_active());
    }

    fn test_budget() -> SyncBudget {
        SyncBudget {
            max_pending_blocks: 128,
            max_pending_bytes: usize::MAX,
            max_received_blocks: 128,
            max_received_bytes: usize::MAX,
            max_peer_inflight: 128,
            // Fan-out disengaged: these unit tests pin the legacy single-mode
            // mechanics where `max_peer_inflight` is always the binding cap.
            fanout_peer_inflight: 128,
            min_peers_for_fanout: usize::MAX,
            getdata_batch_limit: 16,
            pending_timeout: Duration::from_secs(30),
            received_timeout: Duration::from_secs(30),
        }
    }

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_le_bytes(&[byte; 32])
    }
}
