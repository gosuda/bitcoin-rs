//! Orphan transaction pool for out-of-order relay.
//!
//! Modelled on Bitcoin Core's `TxOrphanage`: when a transaction arrives before
//! its parent, it is stored here until the missing prevout(s) appear.  A parent
//! accepted into the mempool triggers [`OrphanPool::take_ready`], which returns
//! exactly the children whose last missing parent was that transaction.
//!
//! Capacity is bounded by **both** transaction count and total weight, evicting
//! the oldest entry first when either limit is exceeded.  Bounding by count
//! alone lets an attacker pin memory with a few enormous transactions, so both
//! limits are enforced on every insertion.

use alloc::vec::Vec;
use core::time::Duration;

use bitcoin::{Transaction, Txid};
use hashbrown::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Instant;
use thiserror::Error;

/// Default maximum number of orphan transactions.
const DEFAULT_MAX_ORPHAN_COUNT: usize = 100;

/// Default maximum total weight (in weight units) of orphan transactions.
///
/// Roughly 2.5 `MvB` — large enough for legitimate orphan bursts but small enough
/// that a handful of maximum-weight transactions cannot pin memory.
const DEFAULT_MAX_ORPHAN_WEIGHT: u64 = 10_000_000;

/// Default orphan expiry timeout.
const DEFAULT_ORPHAN_TIMEOUT: Duration = Duration::from_mins(2);

/// Orphan pool insertion failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OrphanError {
    /// The transaction id is already present in the orphan pool.
    #[error("transaction already exists in orphan pool")]
    DuplicateOrphan,
    /// The pool is configured to hold no orphans at all.
    #[error("orphan pool is disabled: maximum count is zero")]
    PoolDisabled,
    /// The transaction's weight alone exceeds the pool's weight limit, so it
    /// can never be admitted regardless of eviction.
    #[error("transaction weight {weight} exceeds orphan pool max {max}")]
    TransactionTooLarge {
        /// The transaction's weight in weight units.
        weight: u64,
        /// The configured maximum total weight.
        max: u64,
    },
}

/// A single orphaned transaction awaiting its missing parents.
#[derive(Clone, Debug)]
struct OrphanEntry {
    /// The orphan transaction payload.
    tx: Transaction,
    /// Txids of the missing prevout transactions that caused orphaning.
    /// Deduplicated on insertion.  When this list becomes empty the orphan is
    /// ready for re-evaluation.
    missing_parents: Vec<Txid>,
    /// Peer that sent the transaction, for per-peer eviction on disconnect.
    peer: SocketAddr,
    /// Arrival time injected by the caller, used for expiry and eviction order.
    arrival: Instant,
    /// Cached transaction weight in weight units.
    weight: u64,
}

/// Orphan transaction pool with count and weight bounds.
///
/// All time-sensitive operations take an [`Instant`] parameter rather than
/// reading the system clock internally, so tests are deterministic.
#[derive(Debug)]
pub struct OrphanPool {
    /// Primary store keyed by orphan txid.
    orphans: HashMap<Txid, OrphanEntry>,
    /// Reverse index: missing-parent txid → orphan txids waiting on it.
    by_parent: HashMap<Txid, Vec<Txid>>,
    /// Reverse index: peer → orphan txids, for per-peer eviction.
    by_peer: HashMap<SocketAddr, Vec<Txid>>,
    /// Running total of all orphan weights.
    total_weight: u64,
    /// Maximum number of orphan transactions.
    max_count: usize,
    /// Maximum total weight in weight units.
    max_weight: u64,
    /// Entries older than this duration are expired by [`OrphanPool::expire`].
    timeout: Duration,
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new()
    }
}

impl OrphanPool {
    /// Creates an empty orphan pool with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_MAX_ORPHAN_COUNT,
            DEFAULT_MAX_ORPHAN_WEIGHT,
            DEFAULT_ORPHAN_TIMEOUT,
        )
    }

    /// Creates an empty orphan pool with custom limits.
    #[must_use]
    pub fn with_limits(max_count: usize, max_weight: u64, timeout: Duration) -> Self {
        Self {
            orphans: HashMap::new(),
            by_parent: HashMap::new(),
            by_peer: HashMap::new(),
            total_weight: 0,
            max_count,
            max_weight,
            timeout,
        }
    }

    /// Returns the number of orphan transactions currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.orphans.len()
    }

    /// Returns whether the orphan pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.orphans.is_empty()
    }

    /// Returns the total weight of all orphan transactions in weight units.
    #[must_use]
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Inserts an orphan transaction, evicting older entries if necessary.
    ///
    /// `missing_parents` should contain the txids of the transactions whose
    /// outputs this transaction spends but which are not yet in the mempool.
    /// The list is deduplicated internally.
    ///
    /// Returns the txid of the inserted orphan on success.
    pub fn add(
        &mut self,
        tx: Transaction,
        missing_parents: Vec<Txid>,
        peer: SocketAddr,
        now: Instant,
    ) -> Result<Txid, OrphanError> {
        // Zero means zero. The eviction loop below runs against an empty pool,
        // finds no oldest entry, breaks, and the insert then happens anyway, so
        // a pool configured to hold nothing held one.
        if self.max_count == 0 {
            return Err(OrphanError::PoolDisabled);
        }

        let txid = tx.compute_txid();
        if self.orphans.contains_key(&txid) {
            return Err(OrphanError::DuplicateOrphan);
        }

        let weight = tx.weight().to_wu();
        if weight > self.max_weight {
            return Err(OrphanError::TransactionTooLarge {
                weight,
                max: self.max_weight,
            });
        }

        // Deduplicate missing parents while preserving order.
        //
        // Through a set, not `Vec::contains`. A transaction under the pool's
        // weight limit can still name thousands of distinct parents, and the
        // scan made admission quadratic in that count, so repeated large
        // orphans burned CPU before the eviction logic ever ran.
        let mut seen: HashSet<Txid> = HashSet::with_capacity(missing_parents.len());
        let mut deduped: Vec<Txid> = Vec::with_capacity(missing_parents.len());
        for parent in missing_parents {
            if seen.insert(parent) {
                deduped.push(parent);
            }
        }

        // Evict oldest entries until both bounds can accommodate the new orphan.
        self.evict_until_fits(weight);

        // Insert into primary store.
        let entry = OrphanEntry {
            tx,
            missing_parents: deduped.clone(),
            peer,
            arrival: now,
            weight,
        };
        self.orphans.insert(txid, entry);
        self.total_weight = self.total_weight.saturating_add(weight);

        // Update reverse indexes.
        for parent in &deduped {
            self.by_parent.entry(*parent).or_default().push(txid);
        }
        self.by_peer.entry(peer).or_default().push(txid);

        Ok(txid)
    }

    /// Returns and removes orphans whose last missing parent is `parent_txid`.
    ///
    /// Accepting a parent must release exactly the children it unblocked: an
    /// orphan with two missing parents is only returned when the *second*
    /// parent arrives.
    pub fn take_ready(&mut self, parent_txid: Txid) -> Vec<Transaction> {
        // Take ownership of the list of orphans waiting on this parent.
        let Some(waiting) = self.by_parent.remove(&parent_txid) else {
            return Vec::new();
        };

        let mut ready = Vec::new();
        for orphan_txid in waiting {
            let Some(entry) = self.orphans.get_mut(&orphan_txid) else {
                // Was already removed by remove/expire/evict_by_peer.
                continue;
            };

            // Remove the resolved parent from this orphan's missing list.
            entry.missing_parents.retain(|p| *p != parent_txid);

            if entry.missing_parents.is_empty() {
                // Last missing parent resolved — orphan is ready. The entry is
                // known present: it was just read from this same map.
                let Some(entry) = self.orphans.remove(&orphan_txid) else {
                    continue;
                };
                self.total_weight = self.total_weight.saturating_sub(entry.weight);
                self.remove_from_peer_index(orphan_txid, entry.peer);
                // Clean up any remaining by_parent entries that still reference
                // this orphan (shouldn't exist since missing_parents is empty,
                // but defensive against logic errors).
                ready.push(entry.tx);
            }
            // If still has missing parents, the orphan stays in the pool.  The
            // by_parent entry for parent_txid was already removed above, and
            // entries for the remaining parents still reference this orphan.
        }

        ready
    }

    /// Removes a single orphan by txid, returning the transaction if present.
    pub fn remove(&mut self, txid: Txid) -> Option<Transaction> {
        let entry = self.orphans.remove(&txid)?;
        self.total_weight = self.total_weight.saturating_sub(entry.weight);

        // Clean up by_parent reverse index.
        for parent in &entry.missing_parents {
            if let Some(list) = self.by_parent.get_mut(parent) {
                list.retain(|id| *id != txid);
                if list.is_empty() {
                    self.by_parent.remove(parent);
                }
            }
        }

        self.remove_from_peer_index(txid, entry.peer);
        Some(entry.tx)
    }

    /// Drops entries older than the configured timeout, returning the expired
    /// transactions.
    ///
    /// `now` is injected by the caller — no internal clock read.
    pub fn expire(&mut self, now: Instant) -> Vec<Transaction> {
        let timeout = self.timeout;
        let expired_txids: Vec<Txid> = self
            .orphans
            .iter()
            .filter(|(_, entry)| {
                now.checked_duration_since(entry.arrival)
                    .is_some_and(|elapsed| elapsed > timeout)
            })
            .map(|(txid, _)| *txid)
            .collect();

        let mut expired_txs = Vec::with_capacity(expired_txids.len());
        for txid in expired_txids {
            if let Some(tx) = self.remove(txid) {
                expired_txs.push(tx);
            }
        }
        expired_txs
    }

    /// Removes all orphans sent by `peer`, returning the removed transactions.
    pub fn evict_by_peer(&mut self, peer: SocketAddr) -> Vec<Transaction> {
        let Some(txids) = self.by_peer.remove(&peer) else {
            return Vec::new();
        };

        let mut removed = Vec::with_capacity(txids.len());
        for txid in txids {
            if let Some(entry) = self.orphans.remove(&txid) {
                self.total_weight = self.total_weight.saturating_sub(entry.weight);
                // Clean up by_parent reverse index.
                for parent in &entry.missing_parents {
                    if let Some(list) = self.by_parent.get_mut(parent) {
                        list.retain(|id| *id != txid);
                        if list.is_empty() {
                            self.by_parent.remove(parent);
                        }
                    }
                }
                removed.push(entry.tx);
            }
        }
        removed
    }

    /// Evicts the oldest entries until both count and weight bounds can
    /// accommodate `needed_weight`.
    fn evict_until_fits(&mut self, needed_weight: u64) {
        while self.orphans.len() >= self.max_count
            || self.total_weight.saturating_add(needed_weight) > self.max_weight
        {
            // Find the entry with the earliest arrival time.
            let oldest = self
                .orphans
                .iter()
                .min_by(|(_, a), (_, b)| a.arrival.cmp(&b.arrival))
                .map(|(txid, _)| *txid);

            let Some(txid) = oldest else { break };
            // Remove it and discard the transaction.
            self.remove(txid);
        }
    }

    /// Removes a txid from the per-peer reverse index.
    fn remove_from_peer_index(&mut self, txid: Txid, peer: SocketAddr) {
        if let Some(list) = self.by_peer.get_mut(&peer) {
            list.retain(|id| *id != txid);
            if list.is_empty() {
                self.by_peer.remove(&peer);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use alloc::vec::Vec;

    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    use super::*;

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    /// A pool configured to hold nothing must hold nothing.
    ///
    /// The eviction loop runs against an empty pool, finds no oldest entry, and
    /// breaks; without an explicit guard the insert then happened anyway and
    /// the pool kept one orphan, defeating a zero used to disable retention.
    #[test]
    fn a_zero_count_limit_admits_no_orphans() {
        let mut pool = OrphanPool::with_limits(0, 10_000_000, Duration::from_mins(1));
        let tx = orphan_tx(1, vec![OutPoint::new(Txid::from_byte_array([9_u8; 32]), 0)]);
        let outcome = pool.add(tx, Vec::new(), peer(1), Instant::now());

        assert!(
            matches!(outcome, Err(OrphanError::PoolDisabled)),
            "a zero-count pool must refuse, got {outcome:?}"
        );
        assert_eq!(pool.len(), 0, "and must hold nothing afterwards");
    }

    /// Deduplication must keep first-seen order.
    ///
    /// The set is there for the cost, but order is the contract: parents are
    /// requested in the order given, and a set alone would scramble them.
    #[test]
    fn duplicate_parents_collapse_and_keep_their_order() {
        let mut pool = OrphanPool::with_limits(8, 10_000_000, Duration::from_mins(1));
        let a = Txid::from_byte_array([0xa1; 32]);
        let b = Txid::from_byte_array([0xb2; 32]);
        let c = Txid::from_byte_array([0xc3; 32]);
        let tx = orphan_tx(2, vec![OutPoint::new(a, 0)]);

        let Ok(txid) = pool.add(tx, vec![c, a, b, a, c, b], peer(2), Instant::now()) else {
            panic!("the orphan must be admitted");
        };
        let Some(entry) = pool.orphans.get(&txid) else {
            panic!("the admitted orphan must be retrievable");
        };
        assert_eq!(
            entry.missing_parents,
            vec![c, a, b],
            "duplicates collapse to the first occurrence, in first-seen order"
        );
    }

    /// Builds a transaction with the given label and prevout outpoints.
    fn orphan_tx(label: u8, prevouts: Vec<OutPoint>) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: prevouts
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(5_000 + u64::from(label)),
                script_pubkey: ScriptBuf::from_bytes(vec![label]),
            }],
        }
    }

    /// Builds a large transaction (many outputs) to exceed weight limits.
    fn large_tx(label: u8) -> Transaction {
        let output = TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51; 200]),
        };
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([label; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![output; 50],
        }
    }

    fn dummy_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    #[test]
    fn orphan_released_when_parent_arrives() {
        let mut pool = OrphanPool::new();
        let now = Instant::now();
        let parent = dummy_txid(0xAA);
        let outpoint = OutPoint::new(parent, 0);

        let orphan = orphan_tx(1, vec![outpoint]);
        let orphan_txid = orphan.compute_txid();

        pool.add(orphan, vec![parent], peer(1), now)
            .expect("add orphan");
        assert_eq!(pool.len(), 1);

        // Parent arrives — orphan should be released.
        let ready = pool.take_ready(parent);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].compute_txid(), orphan_txid);

        // Second call returns nothing — orphan already taken.
        let ready2 = pool.take_ready(parent);
        assert!(ready2.is_empty());
        assert!(pool.is_empty());
    }

    #[test]
    fn orphan_with_two_missing_parents_not_released_until_both_arrive() {
        let mut pool = OrphanPool::new();
        let now = Instant::now();
        let parent_a = dummy_txid(0xAA);
        let parent_b = dummy_txid(0xBB);

        let orphan = orphan_tx(
            1,
            vec![OutPoint::new(parent_a, 0), OutPoint::new(parent_b, 0)],
        );
        let orphan_txid = orphan.compute_txid();

        pool.add(orphan, vec![parent_a, parent_b], peer(1), now)
            .expect("add orphan");
        assert_eq!(pool.len(), 1);

        // First parent arrives — orphan still missing parent_b.
        let ready_a = pool.take_ready(parent_a);
        assert!(ready_a.is_empty(), "orphan should not be ready yet");
        assert_eq!(pool.len(), 1, "orphan should still be in pool");

        // Second parent arrives — orphan is now ready.
        let ready_b = pool.take_ready(parent_b);
        assert_eq!(ready_b.len(), 1);
        assert_eq!(ready_b[0].compute_txid(), orphan_txid);
        assert!(pool.is_empty());
    }

    #[test]
    fn count_based_eviction() {
        let mut pool = OrphanPool::with_limits(2, 100_000_000, Duration::from_mins(2));
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let t2 = t0 + Duration::from_secs(2);

        let parent_a = dummy_txid(0xA1);
        let tx1 = orphan_tx(1, vec![OutPoint::new(parent_a, 0)]);
        let tx1_id = tx1.compute_txid();
        pool.add(tx1, vec![parent_a], peer(1), t0).expect("add 1");

        let parent_b = dummy_txid(0xB1);
        let tx2 = orphan_tx(2, vec![OutPoint::new(parent_b, 0)]);
        let tx2_id = tx2.compute_txid();
        pool.add(tx2, vec![parent_b], peer(2), t1).expect("add 2");

        // Pool is at capacity (max_count=2).  Adding a third should evict the
        // oldest (tx1).
        let parent_c = dummy_txid(0xC1);
        let tx3 = orphan_tx(3, vec![OutPoint::new(parent_c, 0)]);
        let tx3_id = tx3.compute_txid();
        pool.add(tx3, vec![parent_c], peer(3), t2).expect("add 3");

        assert_eq!(pool.len(), 2);
        // tx1 (oldest) should have been evicted.
        assert_eq!(pool.remove(tx1_id), None, "oldest orphan should be evicted");
        // tx2 and tx3 should still be present.
        assert!(pool.remove(tx2_id).is_some(), "tx2 should remain");
        assert!(pool.remove(tx3_id).is_some(), "tx3 should remain");
    }

    #[test]
    fn weight_based_eviction() {
        // Set a small weight limit so two large transactions cannot coexist.
        let large = large_tx(1);
        let large_weight = large.weight().to_wu();
        let max_weight = large_weight; // only room for one large tx

        let mut pool = OrphanPool::with_limits(100, max_weight, Duration::from_mins(2));
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);

        let parent_a = dummy_txid(0xA1);
        let tx1 = large_tx(1);
        let tx1_id = tx1.compute_txid();
        pool.add(tx1, vec![parent_a], peer(1), t0).expect("add 1");

        let parent_b = dummy_txid(0xB1);
        let tx2 = large_tx(2);
        let tx2_id = tx2.compute_txid();
        pool.add(tx2, vec![parent_b], peer(2), t1).expect("add 2");

        // tx1 (oldest) should have been evicted to make weight room for tx2.
        assert_eq!(pool.len(), 1);
        assert_eq!(
            pool.remove(tx1_id),
            None,
            "oldest should be evicted by weight"
        );
        assert!(pool.remove(tx2_id).is_some(), "tx2 should remain");
        assert!(pool.total_weight() <= max_weight);
    }

    #[test]
    fn expiry() {
        let timeout = Duration::from_mins(1);
        let mut pool = OrphanPool::with_limits(100, 100_000_000, timeout);
        let t0 = Instant::now();

        let parent = dummy_txid(0xAA);
        let orphan = orphan_tx(1, vec![OutPoint::new(parent, 0)]);
        pool.add(orphan, vec![parent], peer(1), t0)
            .expect("add orphan");
        assert_eq!(pool.len(), 1);

        // 30 seconds later — not expired.
        let expired_early = pool.expire(t0 + Duration::from_secs(30));
        assert!(expired_early.is_empty());
        assert_eq!(pool.len(), 1, "orphan should not expire before timeout");

        // 61 seconds later — expired.
        let expired_late = pool.expire(t0 + Duration::from_secs(61));
        assert_eq!(expired_late.len(), 1);
        assert!(pool.is_empty(), "orphan should be expired");
    }

    #[test]
    fn per_peer_eviction() {
        let mut pool = OrphanPool::new();
        let now = Instant::now();

        let parent_a = dummy_txid(0xAA);
        let tx1 = orphan_tx(1, vec![OutPoint::new(parent_a, 0)]);
        let tx1_id = tx1.compute_txid();
        pool.add(tx1, vec![parent_a], peer(1), now).expect("add 1");

        let parent_b = dummy_txid(0xBB);
        let tx2 = orphan_tx(2, vec![OutPoint::new(parent_b, 0)]);
        let tx2_id = tx2.compute_txid();
        pool.add(tx2, vec![parent_b], peer(2), now).expect("add 2");

        let parent_c = dummy_txid(0xCC);
        let tx3 = orphan_tx(3, vec![OutPoint::new(parent_c, 0)]);
        let tx3_id = tx3.compute_txid();
        pool.add(tx3, vec![parent_c], peer(1), now).expect("add 3");

        assert_eq!(pool.len(), 3);

        // Evict all orphans from peer 1 (tx1 and tx3).
        let evicted = pool.evict_by_peer(peer(1));
        assert_eq!(evicted.len(), 2);
        assert_eq!(pool.len(), 1);

        // tx1 and tx3 should be gone; tx2 (from peer 2) should remain.
        assert_eq!(pool.remove(tx1_id), None);
        assert_eq!(pool.remove(tx3_id), None);
        assert!(pool.remove(tx2_id).is_some(), "peer 2 orphan should remain");
    }

    #[test]
    fn oversized_transaction_rejected_without_emptying_pool() {
        // A transaction whose weight alone exceeds the pool's weight limit must
        // be rejected, not inserted and then evicted in a loop.
        let large = large_tx(1);
        let large_weight = large.weight().to_wu();
        let max_weight = large_weight / 2;

        let mut pool = OrphanPool::with_limits(100, max_weight, Duration::from_mins(2));
        let now = Instant::now();

        // First, add a small orphan so the pool is non-empty.
        let parent_a = dummy_txid(0xAA);
        let small = orphan_tx(1, vec![OutPoint::new(parent_a, 0)]);
        let small_id = small.compute_txid();
        pool.add(small, vec![parent_a], peer(1), now)
            .expect("small orphan should fit");
        assert_eq!(pool.len(), 1);
        let weight_before = pool.total_weight();

        // Attempt to add the oversized transaction.
        let parent_b = dummy_txid(0xBB);
        let result = pool.add(large_tx(2), vec![parent_b], peer(2), now);
        assert!(
            matches!(result, Err(OrphanError::TransactionTooLarge { .. })),
            "oversized transaction should be rejected"
        );

        // Pool state must be unchanged: the small orphan is still there, weight
        // is unchanged, and no eviction loop occurred.
        assert_eq!(pool.len(), 1, "pool should still contain the small orphan");
        assert_eq!(
            pool.total_weight(),
            weight_before,
            "total_weight must be unchanged after rejection"
        );
        assert!(
            pool.remove(small_id).is_some(),
            "small orphan should still be present"
        );
        assert!(pool.is_empty());
        assert_eq!(pool.total_weight(), 0);
    }

    #[test]
    fn indexes_and_weight_consistent_after_all_removal_paths() {
        let timeout = Duration::from_mins(1);
        let mut pool = OrphanPool::with_limits(3, 100_000_000, timeout);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let t2 = t0 + Duration::from_secs(2);

        // --- Phase 1: release via take_ready (including two-parent orphan) ---
        let parent_a = dummy_txid(0xA1);
        let parent_b = dummy_txid(0xB1);

        // Orphan with a single missing parent.
        let tx1 = orphan_tx(1, vec![OutPoint::new(parent_a, 0)]);
        pool.add(tx1, vec![parent_a], peer(1), t0).expect("add 1");

        // Orphan with two missing parents.
        let tx2 = orphan_tx(
            2,
            vec![OutPoint::new(parent_a, 0), OutPoint::new(parent_b, 0)],
        );
        pool.add(tx2, vec![parent_a, parent_b], peer(2), t0)
            .expect("add 2");

        assert_eq!(pool.len(), 2);
        assert!(pool.total_weight() > 0);

        // First parent arrives: tx1 is released, tx2 stays (still missing parent_b).
        let ready_a = pool.take_ready(parent_a);
        assert_eq!(ready_a.len(), 1);
        assert_eq!(pool.len(), 1, "tx2 should still be in pool");
        assert!(pool.total_weight() > 0);
        // by_parent should still have parent_b → [tx2], parent_a should be gone.
        assert!(!pool.by_parent.contains_key(&parent_a));
        assert!(pool.by_parent.contains_key(&parent_b));

        // Second parent arrives: tx2 is released.
        let ready_b = pool.take_ready(parent_b);
        assert_eq!(ready_b.len(), 1);
        assert!(pool.is_empty());
        assert_eq!(
            pool.total_weight(),
            0,
            "weight must be zero after all released"
        );
        assert!(pool.by_parent.is_empty(), "by_parent must be empty");
        assert!(pool.by_peer.is_empty(), "by_peer must be empty");

        // --- Phase 2: capacity eviction ---
        let p1 = dummy_txid(0xC1);
        let p2 = dummy_txid(0xC2);
        let p3 = dummy_txid(0xC3);
        let p4 = dummy_txid(0xC4);

        let tx3 = orphan_tx(3, vec![OutPoint::new(p1, 0)]);
        let tx3_id = tx3.compute_txid();
        pool.add(tx3, vec![p1], peer(1), t0).expect("add 3");
        let tx4 = orphan_tx(4, vec![OutPoint::new(p2, 0)]);
        pool.add(tx4, vec![p2], peer(2), t1).expect("add 4");
        let tx5 = orphan_tx(5, vec![OutPoint::new(p3, 0)]);
        pool.add(tx5, vec![p3], peer(3), t2).expect("add 5");
        assert_eq!(pool.len(), 3);

        // Adding a fourth evicts tx3 (oldest, arrival t0).
        let tx6 = orphan_tx(6, vec![OutPoint::new(p4, 0)]);
        pool.add(tx6, vec![p4], peer(4), t2 + Duration::from_secs(1))
            .expect("add 6");
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.remove(tx3_id), None, "tx3 should have been evicted");
        // by_parent should not reference the evicted orphan's parent.
        assert!(
            !pool.by_parent.contains_key(&p1),
            "evicted orphan's parent index should be clean"
        );

        // --- Phase 3: expiry ---
        // Expire all remaining (they were added at t1, t2, t2+1; timeout is 60s).
        let expired = pool.expire(t0 + Duration::from_mins(2));
        assert_eq!(expired.len(), 3, "all remaining should expire");
        assert!(pool.is_empty());
        assert_eq!(pool.total_weight(), 0, "weight must be zero after expiry");
        assert!(
            pool.by_parent.is_empty(),
            "by_parent must be empty after expiry"
        );
        assert!(
            pool.by_peer.is_empty(),
            "by_peer must be empty after expiry"
        );

        // --- Phase 4: per-peer eviction ---
        let p5 = dummy_txid(0xD1);
        let p6 = dummy_txid(0xD2);
        let tx7 = orphan_tx(7, vec![OutPoint::new(p5, 0)]);
        pool.add(tx7, vec![p5], peer(1), t0).expect("add 7");
        let tx8 = orphan_tx(8, vec![OutPoint::new(p6, 0)]);
        pool.add(tx8, vec![p6], peer(2), t0).expect("add 8");
        assert_eq!(pool.len(), 2);

        let evicted = pool.evict_by_peer(peer(1));
        assert_eq!(evicted.len(), 1);
        assert_eq!(pool.len(), 1);
        // by_parent should not reference the evicted orphan's parent.
        assert!(
            !pool.by_parent.contains_key(&p5),
            "peer-evicted orphan's parent index should be clean"
        );
        assert!(pool.by_peer.contains_key(&peer(2)));

        // Remove the last one to get back to a fully clean state.
        let evicted2 = pool.evict_by_peer(peer(2));
        assert_eq!(evicted2.len(), 1);
        assert!(pool.is_empty());
        assert_eq!(
            pool.total_weight(),
            0,
            "weight must be zero after peer eviction"
        );
        assert!(
            pool.by_parent.is_empty(),
            "by_parent must be empty after peer eviction"
        );
        assert!(
            pool.by_peer.is_empty(),
            "by_peer must be empty after peer eviction"
        );
    }
}
