//! Out-of-order block staging bounded by the download window budget.
//!
//! [`BlockStager`] holds decoded inbound bodies until their predecessor is
//! applied. Slot-count eviction and byte-budget backpressure live here;
//! [`crate::DownloadWindow`] owns in-flight assignment. The node sync
//! coordinator stages arrivals and drains a contiguous apply prefix; it does
//! not own this policy. The ownership boundary is defined by the
//! [architecture contract](../../../docs/contracts/architecture.md).

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use bitcoin_rs_primitives::{BlockPayload, Hash256, Header};
use hashbrown::{HashMap, hash_map::Entry};

use crate::PeerSource;
use crate::download_window::SyncBudget;

/// Bounded in-memory staging set for inbound block bodies.
#[derive(Debug)]
pub(crate) struct BlockStager {
    budget: SyncBudget,
    received: HashMap<Hash256, ReceivedBlock>,
    received_order: VecDeque<Hash256>,
    /// Serialized bytes of staged bodies. This is the admission fact: the byte
    /// budget and `staged_byte_headroom` read it and never the attribution
    /// totals below.
    received_bytes: usize,
    /// Sum of `ReceivedBlock::decoded_bytes` over staged bodies. Attribution
    /// only: nothing admits or evicts on it.
    decoded_bytes: usize,
    next_received_deadline: Option<Instant>,
    /// Highest staged-block population observed; feeds the high-water gauge.
    received_blocks_high_water: usize,
    /// Highest staged-byte total observed; feeds the high-water gauge.
    received_bytes_high_water: usize,
    /// Highest `decoded_bytes + received_bytes` observed; feeds the
    /// retained-bytes high-water gauge.
    retained_bytes_high_water: usize,
    /// Live count of staged bodies still awaiting the admission clauses
    /// because the tree could not resolve their hash at arrival. The shared
    /// quota on this count bounds orphan floods (`MAX_UNRESOLVED_STAGED_BODIES`).
    gate_pending_count: usize,
}

#[derive(Debug)]
struct ReceivedBlock {
    // One exact payload: decoded block plus the exact bytes it carries,
    // reused by the unified `apply_block` to skip reserialization. The
    // received-block budget (max_received_blocks / max_received_bytes) counts
    // only `bytes`; `decoded_bytes` attributes the decoded side and admits
    // nothing.
    payload: BlockPayload,
    received_at: Instant,
    bytes: usize,
    /// `block.retained_heap_bytes()` measured once when the stager took
    /// ownership of this `Block` allocation (`insert`, or `restore_many` for
    /// the allocation it receives). The staged block is never mutated, so the
    /// measurement stays exact until the entry leaves. It excludes the inline
    /// `Block` value, allocator rounding, and the `serialized` buffer, which
    /// `bytes` already counts.
    decoded_bytes: usize,
    /// Delivering connection, retained so a header-admission fault on the
    /// staged body can blame the right peer.
    source: Option<PeerSource>,
    /// The body staged while the tree could not resolve its hash, so the
    /// arrival gate's missing-header arm passed it without evaluating the
    /// unrequested-admission clauses. Cleared once the clauses run against
    /// the resolved node, or by request evidence (a resolved owned fetch).
    gate_pending: bool,
}

/// A contiguous apply-prefix body drained from staging.
#[derive(Clone, Debug)]
pub(crate) struct DrainedBlock {
    /// Identity of the drained body.
    pub hash: Hash256,
    /// One exact payload: decoded block plus the exact bytes it carries,
    /// drained for apply-without-reserialize.
    payload: BlockPayload,
    received_at: Instant,
    bytes: usize,
    source: Option<PeerSource>,
    /// Carried through a partial-apply restore so an ungated body still owes
    /// the admission clauses afterward.
    gate_pending: bool,
}

impl DrainedBlock {
    /// The connection that delivered this body, or `None` for a locally
    /// injected one.
    #[must_use]
    pub(crate) const fn source(&self) -> Option<PeerSource> {
        self.source
    }

    /// Borrows the drained payload.
    #[must_use]
    pub(crate) const fn payload(&self) -> &BlockPayload {
        &self.payload
    }
}

/// Result of attempting to stage one inbound body.
#[derive(Clone, Debug)]
pub(crate) enum StagedBlock {
    /// The hash is already in the staging set.
    AlreadyStaged,
    /// The body is retained. `dropped` are count-budget evictions caused by
    /// this insert.
    Memory {
        /// Serialized size of the newly staged body.
        bytes: usize,
        /// Bodies evicted so this insert could fit the slot budget.
        dropped: Vec<Hash256>,
    },
    /// The body was refused (byte budget or oversize) and should be
    /// re-requested.
    DroppedForRetry {
        /// The refused body.
        hash: Hash256,
    },
}

impl BlockStager {
    /// Empty stager sized to `budget`.
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

    /// Number of currently staged bodies.
    #[must_use]
    pub(crate) fn received_len(&self) -> usize {
        self.received.len()
    }

    /// Total serialized bytes of currently staged bodies.
    #[must_use]
    pub(crate) fn received_bytes(&self) -> usize {
        self.received_bytes
    }

    /// Decoded heap bytes owned by currently staged blocks (capacity-based,
    /// excluding allocator rounding and the preserved serialized buffers).
    #[must_use]
    pub(crate) const fn decoded_bytes(&self) -> usize {
        self.decoded_bytes
    }

    /// Attributed retained bytes of currently staged bodies: decoded heap
    /// bytes plus the preserved serialized buffers. Excludes allocator
    /// rounding and says nothing about process RSS.
    #[must_use]
    pub(crate) const fn retained_attributed_bytes(&self) -> usize {
        self.decoded_bytes.saturating_add(self.received_bytes)
    }

    /// Highest attributed retained total ever observed this run; feeds the
    /// retained-bytes high-water gauge.
    #[must_use]
    pub(crate) const fn retained_attributed_bytes_high_water(&self) -> usize {
        self.retained_bytes_high_water
    }

    /// Highest staged-block population ever observed this run.
    #[must_use]
    pub(crate) const fn received_high_water(&self) -> usize {
        self.received_blocks_high_water
    }

    /// Highest staged-byte total ever observed this run; feeds the high-water gauge.
    #[must_use]
    pub(crate) const fn received_bytes_high_water(&self) -> usize {
        self.received_bytes_high_water
    }

    /// Staged count when the apply frontier is present, or `None` if empty or
    /// the next expected hash is not staged.
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

    /// PRE: none.
    /// POST: yields the identity of every currently staged body, in map
    ///       order.
    /// INVARIANT: yields no heights; the block tree is the only height
    ///       source.
    pub(crate) fn staged_hashes(&self) -> impl Iterator<Item = Hash256> + '_ {
        self.received.keys().copied()
    }

    /// Stages `payload` or refuses it for retry under the byte budget.
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
        // Byte-budget exhaustion is backpressure, not eviction: refuse the
        // incoming block (it stays re-requestable through the window's
        // drop-for-retry path) instead of evicting already-downloaded staged
        // progress into re-download churn. The next expected block is exempt —
        // it unblocks the apply frontier immediately, and refusing it while
        // staged successors hold the budget would deadlock the window.
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

    /// Whether `hash` is currently staged. Feeds the stall detector's
    /// no-blame guard: a staged next-expected block means the apply side owns
    /// the frontier.
    #[must_use]
    pub(crate) fn contains(&self, hash: &Hash256) -> bool {
        self.received.contains_key(hash)
    }

    /// The connection that delivered the staged body, or `None` for a
    /// locally injected one; `None` also when `hash` is not staged.
    pub(crate) fn staged_source(&self, hash: &Hash256) -> Option<PeerSource> {
        self.received.get(hash).and_then(|entry| entry.source)
    }

    /// How many staged bodies still owe the admission clauses because their
    /// hash was unresolvable at arrival.
    pub(crate) fn gate_pending_count(&self) -> usize {
        self.gate_pending_count
    }

    /// `(hash, embedded header, delivering connection)` for every staged
    /// body. The sync executor retries header admission for bodies whose
    /// headers are still absent from the tree: a staged body can never
    /// become expected until its header lands.
    pub(crate) fn staged_headers(
        &self,
    ) -> impl Iterator<Item = (Hash256, Header, Option<PeerSource>)> + '_ {
        self.received
            .iter()
            .map(|(hash, entry)| (*hash, entry.payload.block().header, entry.source))
    }

    /// Clones one exact staged payload without removing it from the bounded set.
    #[must_use]
    pub(crate) fn staged_body(&self, hash: Hash256) -> Option<BlockPayload> {
        self.received.get(&hash).map(|entry| entry.payload.clone())
    }

    /// Releases one body after that exact block commits during a branch switch.
    pub(crate) fn retire_applied(&mut self, hash: &Hash256) -> bool {
        let removed = self.take_entry(hash).is_some();
        if self.received.is_empty() {
            self.received_order.clear();
            self.next_received_deadline = None;
        }
        removed
    }

    /// Removes the contiguous prefix of `expected_hashes` that is currently
    /// staged. Stops at the first missing hash.
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

    /// Restores previously drained bodies after a partial apply.
    pub(crate) fn restore_many(&mut self, drained: impl IntoIterator<Item = DrainedBlock>) {
        for drained in drained {
            let gate_pending = drained.gate_pending;
            // Measured here instead of carried from the drain: the committer
            // restores clones, and a cloned block's vectors are exactly
            // sized, so the original's measurement would misattribute the
            // allocation this entry now owns.
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

    /// Drops staged bodies whose received deadline has passed.
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

    /// Only the slot-count budget evicts staged blocks. The byte budget is
    /// enforced as admission backpressure in [`Self::insert`] (with a bounded
    /// overshoot for the next expected block), so byte exhaustion can never
    /// trigger evict/re-download churn.
    fn is_over_count_budget(&self) -> bool {
        self.received.len() > self.budget.max_received_blocks
    }

    fn remove(&mut self, hash: &Hash256) -> Option<Hash256> {
        let entry = self.received.remove(hash)?;
        self.release(&entry);
        Some(*hash)
    }

    /// Drops the staged body for `hash`, releasing its staging-budget bytes.
    /// Used for bodies whose embedded header is permanently inadmissible —
    /// they can never become expected, so they are dead inventory.
    pub(crate) fn discard(&mut self, hash: &Hash256) -> bool {
        self.remove(hash).is_some()
    }

    /// Flags a freshly staged body as still owing the unrequested-admission
    /// clauses: it staged while the tree could not resolve its hash, so the
    /// arrival gate's missing-header arm passed it without evaluating them.
    pub(crate) fn set_gate_pending(&mut self, hash: &Hash256) {
        if let Some(entry) = self.received.get_mut(hash)
            && !entry.gate_pending
        {
            entry.gate_pending = true;
            self.gate_pending_count += 1;
        }
    }

    /// Staged bodies that arrived before their headers were tree-known and
    /// have neither faced the admission clauses nor earned request evidence
    /// since.
    pub(crate) fn gate_pending_hashes(&self) -> impl Iterator<Item = Hash256> + '_ {
        self.received
            .iter()
            .filter(|(_, entry)| entry.gate_pending)
            .map(|(hash, _)| *hash)
    }

    /// Settles the owed gate: the clauses held against the resolved node, or
    /// request evidence (a resolved owned fetch) exempted the body.
    pub(crate) fn clear_gate_pending(&mut self, hash: &Hash256) {
        if let Some(entry) = self.received.get_mut(hash)
            && entry.gate_pending
        {
            entry.gate_pending = false;
            self.gate_pending_count = self.gate_pending_count.saturating_sub(1);
        }
    }

    /// Free slots before the count budget forces an eviction; an insert that
    /// finds none must not displace already-staged work for a delivery
    /// nobody asked for.
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

    /// Counts one entry that just entered `received`: adds its serialized and
    /// decoded bytes, then advances the retained high-water mark, so a
    /// restore that refills the set past an earlier peak is observed like an
    /// insert. The serialized high-water marks stay insert-only, as shipped.
    fn count_staged(&mut self, bytes: usize, decoded_bytes: usize) {
        self.received_bytes = self.received_bytes.saturating_add(bytes);
        self.decoded_bytes = self.decoded_bytes.saturating_add(decoded_bytes);
        self.retained_bytes_high_water = self
            .retained_bytes_high_water
            .max(self.retained_attributed_bytes());
    }

    /// Reverses [`Self::count_staged`] and the gate-pending count for an
    /// entry that just left `received`. `prune_expired` batches the same
    /// subtraction over its retained set.
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
mod tests {
    use bitcoin_rs_primitives::{
        Amount, Block, BlockPayload, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx,
        TxIn, TxOut, Witness, consensus_bytes,
    };
    use std::time::{Duration, Instant};

    use super::BlockStager;
    use crate::default_sync_budget;
    use crate::download_window::SyncBudget;

    #[test]
    fn payload_retains_exact_consensus_serialized_len() {
        let block = Network::Regtest.genesis_block();

        let payload = BlockPayload::from_local(block.clone());

        assert_eq!(payload.bytes().len(), consensus_bytes(&block).len());
        assert_eq!(payload.bytes().len(), block.total_size());
    }

    #[test]
    fn drain_expected_prefix_stops_at_first_missing_hash() {
        let block = Network::Regtest.genesis_block();
        let block_bytes = block.total_size();
        let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
        let now = std::time::Instant::now();
        let first = Hash256::from_le_bytes(&[0x01; 32]);
        let missing = Hash256::from_le_bytes(&[0x02; 32]);
        let third = Hash256::from_le_bytes(&[0x03; 32]);
        let fourth = Hash256::from_le_bytes(&[0x04; 32]);

        stager.insert(
            first,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            third,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(fourth, None, BlockPayload::from_local(block), None, now);

        let drained = stager.drain_expected_prefix(&[first, missing, third, fourth]);

        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].hash, first);
        assert_eq!(stager.received_len(), 2);
        assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
        assert!(stager.contains(&third));
        assert!(stager.contains(&fourth));
    }

    #[test]
    fn staged_body_lookup_preserves_the_entry() {
        let block = Network::Regtest.genesis_block();
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        let hash = Hash256::from_le_bytes(&[0x05; 32]);
        let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
        stager.insert(
            hash,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            Instant::now(),
        );

        let Some(loaded) = stager.staged_body(hash) else {
            panic!("inserted body must remain readable");
        };

        assert_eq!(loaded.block(), &block);
        assert_eq!(loaded.bytes(), &serialized);
        assert_eq!(stager.received_len(), 1);
        assert!(stager.contains(&hash));
    }

    #[test]
    fn restore_many_restores_tail_byte_accounting() {
        let block = Network::Regtest.genesis_block();
        let block_bytes = block.total_size();
        let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
        let now = std::time::Instant::now();
        let first = Hash256::from_le_bytes(&[0x11; 32]);
        let second = Hash256::from_le_bytes(&[0x22; 32]);
        let third = Hash256::from_le_bytes(&[0x33; 32]);

        stager.insert(
            first,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            second,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(third, None, BlockPayload::from_local(block), None, now);
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
        let block = Network::Regtest.genesis_block();
        let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
        let now = std::time::Instant::now();
        let staged = Hash256::from_le_bytes(&[0x31; 32]);
        let missing = Hash256::from_le_bytes(&[0x32; 32]);

        assert_eq!(stager.ready_received_len(None), None);

        stager.insert(staged, None, BlockPayload::from_local(block), None, now);

        assert_eq!(stager.ready_received_len(None), Some(1));
        assert_eq!(stager.ready_received_len(Some(staged)), Some(1));
        assert_eq!(stager.ready_received_len(Some(missing)), None);
    }

    #[test]
    fn prune_expired_recomputes_deadline_after_dropping_oldest() {
        let block = Network::Regtest.genesis_block();
        let mut budget = default_sync_budget(Network::Regtest);
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
            BlockPayload::from_local(block.clone()),
            None,
            old_received_at,
        );
        stager.insert(
            fresh,
            None,
            BlockPayload::from_local(block),
            None,
            fresh_received_at,
        );

        let first_drop = stager.prune_expired(now);

        assert_eq!(first_drop.len(), 1);
        assert_eq!(first_drop[0], old);
        assert_eq!(stager.received_len(), 1);
        assert!(stager.contains(&fresh));

        let second_drop = stager.prune_expired(now + Duration::from_secs(1));

        assert_eq!(second_drop, Vec::<Hash256>::new());
        assert!(stager.contains(&fresh));

        let final_drop = stager.prune_expired(now + Duration::from_secs(10));

        assert_eq!(final_drop.len(), 1);
        assert_eq!(final_drop[0], fresh);
        assert_eq!(stager.received_len(), 0);
    }

    #[test]
    fn prune_expired_releases_gate_pending_count() {
        let block = Network::Regtest.genesis_block();
        let mut budget = default_sync_budget(Network::Regtest);
        budget.received_timeout = Duration::from_secs(10);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let stale_received_at = now
            .checked_sub(Duration::from_secs(11))
            .unwrap_or_else(|| panic!("test instant underflow"));
        let hash = Hash256::from_le_bytes(&[0x43; 32]);

        stager.insert(
            hash,
            None,
            BlockPayload::from_local(block),
            None,
            stale_received_at,
        );
        stager.set_gate_pending(&hash);
        assert_eq!(stager.gate_pending_count(), 1);

        let dropped = stager.prune_expired(now);

        assert_eq!(dropped.len(), 1);
        assert_eq!(stager.gate_pending_count(), 0);
        assert_eq!(stager.received_len(), 0);
    }

    #[test]
    fn duplicate_insert_keeps_original_staged_deadline() {
        let block = Network::Regtest.genesis_block();
        let block_bytes = block.total_size();
        let mut budget = default_sync_budget(Network::Regtest);
        budget.received_timeout = Duration::from_secs(10);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let hash = Hash256::from_le_bytes(&[0x43; 32]);

        stager.insert(
            hash,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            hash,
            None,
            BlockPayload::from_local(block),
            None,
            now + Duration::from_secs(5),
        );

        assert_eq!(stager.received_len(), 1);
        assert_eq!(stager.received_bytes(), block_bytes);

        let dropped = stager.prune_expired(now + Duration::from_secs(10));

        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0], hash);
        assert_eq!(stager.received_len(), 0);
        assert_eq!(stager.received_bytes(), 0);
    }

    #[test]
    fn insert_eviction_drops_oldest_unprotected_until_budget_fits() {
        let block = Network::Regtest.genesis_block();
        let block_bytes = block.total_size();
        let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
        let now = Instant::now();
        let protected = Hash256::from_le_bytes(&[0x51; 32]);
        let first = Hash256::from_le_bytes(&[0x52; 32]);
        let second = Hash256::from_le_bytes(&[0x53; 32]);
        let third = Hash256::from_le_bytes(&[0x54; 32]);
        let incoming = Hash256::from_le_bytes(&[0x55; 32]);

        stager.insert(
            protected,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            first,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now + Duration::from_secs(1),
        );
        stager.insert(
            second,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now + Duration::from_secs(2),
        );
        stager.insert(
            third,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now + Duration::from_secs(3),
        );
        stager.budget.max_received_blocks = 2;

        let dropped = match stager.insert(
            incoming,
            Some(protected),
            BlockPayload::from_local(block),
            None,
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
        assert_eq!(dropped[0], first);
        assert_eq!(dropped[1], second);
        assert_eq!(dropped[2], third);
        assert!(stager.contains(&protected));
        assert!(stager.contains(&incoming));
        assert_eq!(stager.received_len(), 2);
        assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
    }

    #[test]
    fn insert_eviction_uses_fifo_order_for_same_instant_blocks() {
        let block = Network::Regtest.genesis_block();
        let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
        let now = Instant::now();
        let first = Hash256::from_le_bytes(&[0x61; 32]);
        let second = Hash256::from_le_bytes(&[0x62; 32]);
        let third = Hash256::from_le_bytes(&[0x63; 32]);
        let incoming = Hash256::from_le_bytes(&[0x64; 32]);

        stager.insert(
            first,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            second,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            third,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.budget.max_received_blocks = 2;

        let dropped =
            match stager.insert(incoming, None, BlockPayload::from_local(block), None, now) {
                super::StagedBlock::AlreadyStaged => {
                    panic!("incoming block should not already be staged")
                }
                super::StagedBlock::Memory { dropped, .. } => dropped,
                super::StagedBlock::DroppedForRetry { .. } => {
                    panic!("incoming block should fit after evicting staged blocks")
                }
            };
        assert_eq!(dropped.len(), 2);
        assert_eq!(dropped[0], first);
        assert_eq!(dropped[1], second);
        assert!(!stager.contains(&first));
        assert!(!stager.contains(&second));
        assert!(stager.contains(&third));
        assert!(stager.contains(&incoming));
    }

    #[test]
    fn insert_eviction_refreshes_received_deadline() {
        let block = Network::Regtest.genesis_block();
        let mut budget = default_sync_budget(Network::Regtest);
        budget.max_received_blocks = 1;
        budget.received_timeout = Duration::from_secs(10);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let old = Hash256::from_le_bytes(&[0x65; 32]);
        let fresh = Hash256::from_le_bytes(&[0x66; 32]);

        stager.insert(
            old,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            fresh,
            None,
            BlockPayload::from_local(block),
            None,
            now + Duration::from_secs(5),
        );

        assert_eq!(
            stager.next_received_deadline,
            Some(now + Duration::from_secs(15))
        );
        let dropped = stager.prune_expired(now + Duration::from_secs(10));

        assert_eq!(dropped, Vec::<Hash256>::new());
        assert!(stager.contains(&fresh));
    }

    #[test]
    fn insert_eviction_skips_stale_order_entries_after_drain() {
        let block = Network::Regtest.genesis_block();
        let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
        let now = Instant::now();
        let first = Hash256::from_le_bytes(&[0x71; 32]);
        let second = Hash256::from_le_bytes(&[0x72; 32]);
        let third = Hash256::from_le_bytes(&[0x73; 32]);
        let incoming = Hash256::from_le_bytes(&[0x74; 32]);

        stager.insert(
            first,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            second,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            third,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        let drained = stager.drain_expected_prefix(&[first]);
        assert_eq!(drained.len(), 1);
        stager.budget.max_received_blocks = 2;

        let dropped =
            match stager.insert(incoming, None, BlockPayload::from_local(block), None, now) {
                super::StagedBlock::AlreadyStaged => {
                    panic!("incoming block should not already be staged")
                }
                super::StagedBlock::Memory { dropped, .. } => dropped,
                super::StagedBlock::DroppedForRetry { .. } => {
                    panic!("incoming block should fit after evicting staged blocks")
                }
            };

        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0], second);
        assert!(!stager.contains(&first));
        assert!(!stager.contains(&second));
        assert!(stager.contains(&third));
        assert!(stager.contains(&incoming));
    }
    fn block_with_total_size(target: usize) -> Block {
        let probe = padded_block(target);
        let probe_size = probe.total_size();
        let padding = target.saturating_mul(2).saturating_sub(probe_size);
        let block = padded_block(padding);
        assert_eq!(block.total_size(), target);
        block
    }

    fn padded_block(script_len: usize) -> Block {
        Block {
            header: Network::Regtest.genesis_block().header,
            txs: vec![Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::default(),
                    script_sig: vec![0_u8; script_len].into(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: Script::new(),
                }],
                lock_time: LockTime::ZERO,
            }],
        }
    }

    #[test]
    fn full_window_of_estimate_sized_blocks_stages_without_eviction() {
        let budget = default_sync_budget(Network::Regtest);
        assert_eq!(
            budget.max_received_bytes,
            budget
                .max_received_blocks
                .saturating_mul(crate::download_window::PENDING_BLOCK_BYTE_ESTIMATE)
        );
        let block = block_with_total_size(crate::download_window::PENDING_BLOCK_BYTE_ESTIMATE);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let window_slots = budget.max_received_blocks;

        for index in 0..window_slots {
            let mut raw = [0xee; 32];
            let index_bytes = index.to_le_bytes();
            raw[..index_bytes.len()].copy_from_slice(&index_bytes);
            let hash = Hash256::from_le_bytes(&raw);
            match stager.insert(
                hash,
                None,
                BlockPayload::from_local(block.clone()),
                None,
                now,
            ) {
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
        let block = Network::Regtest.genesis_block();
        let block_bytes = block.total_size();
        let mut budget = default_sync_budget(Network::Regtest);
        budget.max_received_bytes = block_bytes.saturating_mul(2);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let expected = Hash256::from_le_bytes(&[0x01; 32]);
        let successor = Hash256::from_le_bytes(&[0x02; 32]);

        stager.insert(
            expected,
            Some(expected),
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            successor,
            Some(expected),
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        assert_eq!(stager.received_bytes(), budget.max_received_bytes);

        for byte in [0x03_u8, 0x04] {
            let incoming = Hash256::from_le_bytes(&[byte; 32]);
            match stager.insert(
                incoming,
                Some(expected),
                BlockPayload::from_local(block.clone()),
                None,
                now,
            ) {
                super::StagedBlock::DroppedForRetry { hash } => {
                    assert_eq!(hash, incoming);
                }
                other => panic!("exhausted stager should refuse incoming block: {other:?}"),
            }
            assert_eq!(stager.received_len(), 2);
            assert!(stager.contains(&expected));
            assert!(stager.contains(&successor));
            assert_eq!(stager.received_bytes(), budget.max_received_bytes);
        }
    }

    #[test]
    fn byte_budget_exhaustion_still_accepts_next_expected_block() {
        let block = Network::Regtest.genesis_block();
        let block_bytes = block.total_size();
        let mut budget = default_sync_budget(Network::Regtest);
        budget.max_received_bytes = block_bytes.saturating_mul(2);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let expected = Hash256::from_le_bytes(&[0x0a; 32]);
        let successor_one = Hash256::from_le_bytes(&[0x0b; 32]);
        let successor_two = Hash256::from_le_bytes(&[0x0c; 32]);

        stager.insert(
            successor_one,
            Some(expected),
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        stager.insert(
            successor_two,
            Some(expected),
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        assert_eq!(stager.received_bytes(), budget.max_received_bytes);

        match stager.insert(
            expected,
            Some(expected),
            BlockPayload::from_local(block),
            None,
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
        let block = Network::Regtest.genesis_block();
        let mut budget = default_sync_budget(Network::Regtest);
        budget.max_received_blocks = 1;
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();

        for byte in 0x01_u8..0x60 {
            let hash = Hash256::from_le_bytes(&[byte; 32]);
            stager.insert(
                hash,
                None,
                BlockPayload::from_local(block.clone()),
                None,
                now,
            );
            let drained = stager.drain_expected_prefix(&[hash]);
            assert_eq!(drained.len(), 1);
        }

        assert_eq!(stager.received_len(), 0);
        assert!(stager.received_order_len() <= 32);

        let first = Hash256::from_le_bytes(&[0xa1; 32]);
        let second = Hash256::from_le_bytes(&[0xa2; 32]);
        stager.insert(
            first,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        let dropped = match stager.insert(second, None, BlockPayload::from_local(block), None, now)
        {
            super::StagedBlock::AlreadyStaged => {
                panic!("incoming block should not already be staged")
            }
            super::StagedBlock::Memory { dropped, .. } => dropped,
            super::StagedBlock::DroppedForRetry { .. } => {
                panic!("incoming block should fit after evicting staged blocks")
            }
        };
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0], first);
        assert!(stager.contains(&second));
    }

    #[test]
    fn insert_evicts_same_height_fork_before_expected_hash() {
        let expected_hash = Hash256::from_le_bytes(&[0x11; 32]);
        let fork_hash = Hash256::from_le_bytes(&[0x22; 32]);
        let mut stager = BlockStager::new(SyncBudget {
            max_received_blocks: 1,
            max_received_bytes: usize::MAX,
            ..default_sync_budget(Network::Regtest)
        });
        let now = Instant::now();
        let block = Network::Regtest.genesis_block();

        let super::StagedBlock::Memory { dropped, .. } = stager.insert(
            fork_hash,
            Some(expected_hash),
            BlockPayload::from_local(block.clone()),
            None,
            now,
        ) else {
            panic!("fork block should stage");
        };
        assert_eq!(dropped, Vec::<Hash256>::new());

        let super::StagedBlock::Memory { dropped, .. } = stager.insert(
            expected_hash,
            Some(expected_hash),
            BlockPayload::from_local(block),
            None,
            now,
        ) else {
            panic!("expected block should stage");
        };
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0], fork_hash);
        assert_eq!(stager.received_len(), 1);
        assert!(stager.contains(&expected_hash));
    }

    /// Two bodies with identical consensus bytes and different decoded heap
    /// ownership: `fat` keeps spare `txs` capacity, `lean` is exactly sized.
    fn lean_and_fat_blocks() -> (Block, Block, bytes::Bytes) {
        let genesis = Network::Regtest.genesis_block();
        let serialized = bytes::Bytes::from(consensus_bytes(&genesis));
        let lean = genesis.clone();
        let mut fat = genesis;
        fat.txs.reserve_exact(64);
        assert!(fat.retained_heap_bytes() > lean.retained_heap_bytes());
        (lean, fat, serialized)
    }

    #[test]
    fn decoded_attribution_follows_insert_drain_and_restore_apart_from_serialized_bytes() {
        let (lean, fat, serialized) = lean_and_fat_blocks();
        let wire = serialized.len();
        let lean_bytes = lean.retained_heap_bytes();
        let fat_bytes = fat.retained_heap_bytes();
        let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
        let now = Instant::now();
        let first = Hash256::from_le_bytes(&[0x81; 32]);
        let second = Hash256::from_le_bytes(&[0x82; 32]);
        assert_eq!(stager.decoded_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes_high_water(), 0);

        stager.insert(first, None, BlockPayload::from_local(lean), None, now);
        stager.insert(second, None, BlockPayload::from_local(fat), None, now);

        let peak = lean_bytes + fat_bytes + 2 * wire;
        assert_eq!(stager.received_bytes(), 2 * wire);
        assert_eq!(stager.decoded_bytes(), lean_bytes + fat_bytes);
        assert_eq!(stager.retained_attributed_bytes(), peak);
        assert_eq!(stager.retained_attributed_bytes_high_water(), peak);

        let mut drained = stager.drain_expected_prefix(&[first, second]);
        assert_eq!(drained.len(), 2);
        assert_eq!(stager.received_len(), 0);
        assert_eq!(stager.received_bytes(), 0);
        assert_eq!(stager.decoded_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes_high_water(), peak);

        // The committer restores clones, whose vectors are exactly sized: the
        // stager must attribute the allocation it now owns, not the drained
        // original's.
        let fat_tail = drained.split_off(1);
        let clone = fat_tail[0].clone();
        let clone_bytes = clone.payload().block().retained_heap_bytes();
        assert!(clone_bytes < fat_bytes);
        assert_eq!(
            fat_tail[0].payload().block().retained_heap_bytes(),
            fat_bytes
        );
        stager.restore_many([clone]);
        assert_eq!(stager.received_len(), 1);
        assert_eq!(stager.received_bytes(), wire);
        assert_eq!(stager.decoded_bytes(), clone_bytes);
        assert_eq!(stager.retained_attributed_bytes(), clone_bytes + wire);
        assert_eq!(stager.retained_attributed_bytes_high_water(), peak);

        stager.restore_many(drained);
        assert_eq!(stager.received_len(), 2);
        assert_eq!(stager.received_bytes(), 2 * wire);
        assert_eq!(stager.decoded_bytes(), clone_bytes + lean_bytes);
        assert_eq!(
            stager.retained_attributed_bytes(),
            clone_bytes + lean_bytes + 2 * wire
        );
        assert_eq!(stager.retained_attributed_bytes_high_water(), peak);

        let drained = stager.drain_expected_prefix(&[first, second]);
        assert_eq!(drained.len(), 2);
        assert_eq!(stager.received_bytes(), 0);
        assert_eq!(stager.decoded_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes_high_water(), peak);
    }

    #[test]
    fn restore_refilling_past_the_earlier_peak_advances_only_the_retained_high_water_mark() {
        let (lean, fat, serialized) = lean_and_fat_blocks();
        let wire = serialized.len();
        let lean_bytes = lean.retained_heap_bytes();
        let fat_bytes = fat.retained_heap_bytes();
        let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
        let now = Instant::now();
        let parked = Hash256::from_le_bytes(&[0x91; 32]);
        let refill = Hash256::from_le_bytes(&[0x92; 32]);

        stager.insert(parked, None, BlockPayload::from_local(lean), None, now);
        let drained = stager.drain_expected_prefix(&[parked]);
        stager.insert(refill, None, BlockPayload::from_local(fat), None, now);
        assert_eq!(stager.received_high_water(), 1);
        assert_eq!(stager.received_bytes_high_water(), wire);
        assert_eq!(
            stager.retained_attributed_bytes_high_water(),
            fat_bytes + wire
        );

        stager.restore_many(drained);

        let combined = lean_bytes + fat_bytes + 2 * wire;
        assert_eq!(stager.retained_attributed_bytes(), combined);
        assert_eq!(stager.retained_attributed_bytes_high_water(), combined);
        // The serialized marks are insert-only: restore never moved them.
        assert_eq!(stager.received_bytes(), 2 * wire);
        assert_eq!(stager.received_bytes_high_water(), wire);
        assert_eq!(stager.received_high_water(), 1);
    }

    #[test]
    fn restore_replacing_a_staged_entry_swaps_its_attribution() {
        let (lean, fat, serialized) = lean_and_fat_blocks();
        let wire = serialized.len();
        let lean_bytes = lean.retained_heap_bytes();
        let fat_bytes = fat.retained_heap_bytes();
        let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
        let now = Instant::now();
        let hash = Hash256::from_le_bytes(&[0xa1; 32]);

        stager.insert(hash, None, BlockPayload::from_local(fat), None, now);
        let drained = stager.drain_expected_prefix(&[hash]);
        stager.insert(hash, None, BlockPayload::from_local(lean), None, now);
        assert_eq!(stager.decoded_bytes(), lean_bytes);

        stager.restore_many(drained);

        assert_eq!(stager.received_len(), 1);
        assert_eq!(stager.received_bytes(), wire);
        assert_eq!(stager.decoded_bytes(), fat_bytes);
        assert_eq!(stager.retained_attributed_bytes(), fat_bytes + wire);
        assert_eq!(
            stager.retained_attributed_bytes_high_water(),
            fat_bytes + wire
        );

        let drained = stager.drain_expected_prefix(&[hash]);
        assert_eq!(drained.len(), 1);
        assert_eq!(stager.received_bytes(), 0);
        assert_eq!(stager.decoded_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes(), 0);
    }

    #[test]
    fn prune_expired_releases_decoded_and_serialized_attribution() {
        let (lean, fat, serialized) = lean_and_fat_blocks();
        let wire = serialized.len();
        let lean_bytes = lean.retained_heap_bytes();
        let fat_bytes = fat.retained_heap_bytes();
        let mut budget = default_sync_budget(Network::Regtest);
        budget.received_timeout = Duration::from_secs(10);
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let stale_at = now
            .checked_sub(Duration::from_secs(11))
            .unwrap_or_else(|| panic!("test instant underflow"));
        let stale = Hash256::from_le_bytes(&[0xb1; 32]);
        let fresh = Hash256::from_le_bytes(&[0xb2; 32]);

        stager.insert(stale, None, BlockPayload::from_local(fat), None, stale_at);
        stager.insert(fresh, None, BlockPayload::from_local(lean), None, now);
        let peak = fat_bytes + lean_bytes + 2 * wire;
        assert_eq!(stager.retained_attributed_bytes_high_water(), peak);

        assert_eq!(stager.prune_expired(now), [stale]);
        assert_eq!(stager.received_bytes(), wire);
        assert_eq!(stager.decoded_bytes(), lean_bytes);
        assert_eq!(stager.retained_attributed_bytes(), lean_bytes + wire);

        assert_eq!(stager.prune_expired(now + Duration::from_secs(10)), [fresh]);
        assert_eq!(stager.received_bytes(), 0);
        assert_eq!(stager.decoded_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes_high_water(), peak);
    }

    #[test]
    fn eviction_discard_and_retire_release_attribution() {
        let (lean, fat, serialized) = lean_and_fat_blocks();
        let wire = serialized.len();
        let lean_bytes = lean.retained_heap_bytes();
        let fat_bytes = fat.retained_heap_bytes();
        let mut budget = default_sync_budget(Network::Regtest);
        budget.max_received_blocks = 1;
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let evicted = Hash256::from_le_bytes(&[0xc1; 32]);
        let kept = Hash256::from_le_bytes(&[0xc2; 32]);
        let retired = Hash256::from_le_bytes(&[0xc3; 32]);

        stager.insert(evicted, None, BlockPayload::from_local(fat), None, now);
        let super::StagedBlock::Memory { dropped, .. } = stager.insert(
            kept,
            None,
            BlockPayload::from_local(lean.clone()),
            None,
            now,
        ) else {
            panic!("incoming block should stage after evicting the older one");
        };
        assert_eq!(dropped, [evicted]);
        // Both bodies were resident until the count-budget eviction ran.
        assert_eq!(
            stager.retained_attributed_bytes_high_water(),
            fat_bytes + lean_bytes + 2 * wire
        );
        assert_eq!(stager.received_bytes(), wire);
        assert_eq!(stager.decoded_bytes(), lean_bytes);
        assert_eq!(stager.retained_attributed_bytes(), lean_bytes + wire);

        assert!(stager.discard(&kept));
        assert_eq!(stager.received_bytes(), 0);
        assert_eq!(stager.decoded_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes(), 0);

        stager.insert(retired, None, BlockPayload::from_local(lean), None, now);
        assert_eq!(stager.decoded_bytes(), lean_bytes);
        assert!(stager.retire_applied(&retired));
        assert_eq!(stager.received_bytes(), 0);
        assert_eq!(stager.decoded_bytes(), 0);
        assert_eq!(stager.retained_attributed_bytes(), 0);
    }

    #[test]
    fn duplicate_and_refused_inserts_leave_attribution_untouched() {
        let (lean, fat, serialized) = lean_and_fat_blocks();
        let wire = serialized.len();
        let lean_bytes = lean.retained_heap_bytes();
        let mut budget = default_sync_budget(Network::Regtest);
        budget.max_received_bytes = wire;
        let mut stager = BlockStager::new(budget);
        let now = Instant::now();
        let staged = Hash256::from_le_bytes(&[0xd1; 32]);
        let refused = Hash256::from_le_bytes(&[0xd2; 32]);

        stager.insert(staged, None, BlockPayload::from_local(lean), None, now);
        let settled = (
            stager.decoded_bytes(),
            stager.retained_attributed_bytes(),
            stager.retained_attributed_bytes_high_water(),
        );
        assert_eq!(settled, (lean_bytes, lean_bytes + wire, lean_bytes + wire));

        assert!(matches!(
            stager.insert(
                staged,
                None,
                BlockPayload::from_local(fat.clone()),
                None,
                now,
            ),
            super::StagedBlock::AlreadyStaged
        ));
        assert!(matches!(
            stager.insert(
                refused,
                Some(staged),
                BlockPayload::from_local(fat),
                None,
                now,
            ),
            super::StagedBlock::DroppedForRetry { .. }
        ));
        assert_eq!(
            (
                stager.decoded_bytes(),
                stager.retained_attributed_bytes(),
                stager.retained_attributed_bytes_high_water(),
            ),
            settled
        );
        assert_eq!(stager.received_bytes(), wire);
    }
}
