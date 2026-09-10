//! Gateway-owned peer orphan lifecycle.
//!
//! Retention, exact-body identity, and retry invariants are owned by `MPL-04`
//! in `docs/contracts/mempool-mutations.md`.

use crate::mutation::PeerToken;
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use bitcoin_rs_primitives::{Hash256, Tx, Txid, Wtxid};
use hashbrown::{HashMap, HashSet};

const DEFAULT_ORPHAN_QUOTA: usize = 100;
/// Aggregate BIP141 weight budget for resident orphan bodies.
const DEFAULT_MAX_ORPHAN_WEIGHT: u64 = 10_000_000;
/// Resident peer bodies are reconsidered for at most two minutes.
const DEFAULT_ORPHAN_TIMEOUT_SECS: u64 = 2 * 60;
const DEFAULT_REJECT_CAP: usize = 100_000;

/// Whether a failure applies to the base transaction or only this witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectScope {
    Transaction,
    Witness,
}

#[derive(Clone, Debug)]
pub(crate) struct HeldOrphan {
    pub(crate) tx: Arc<Tx>,
    pub(crate) source: PeerToken,
    /// First-seen wall-clock timestamp supplied by the admission caller.
    arrival_time: u64,
}

#[derive(Debug)]
pub(crate) struct OrphanPool {
    entries: HashMap<Txid, HeldOrphan>,
    by_wtxid: HashMap<Wtxid, Txid>,
    order: VecDeque<Txid>,
    by_parent: HashMap<Txid, HashSet<Txid>>,
    ready: VecDeque<Txid>,
    ready_ids: HashSet<Txid>,
    quota: usize,
    total_weight: u64,
    max_weight: u64,
}

impl OrphanPool {
    pub(crate) fn new(quota: usize) -> Self {
        Self::with_limits(quota, DEFAULT_MAX_ORPHAN_WEIGHT)
    }

    fn with_limits(quota: usize, max_weight: u64) -> Self {
        Self {
            entries: HashMap::new(),
            by_wtxid: HashMap::new(),
            order: VecDeque::new(),
            by_parent: HashMap::new(),
            ready: VecDeque::new(),
            ready_ids: HashSet::new(),
            quota,
            total_weight: 0,
            max_weight,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn contains(&self, txid: &Txid) -> bool {
        self.entries.contains_key(txid)
    }

    pub(crate) fn get(&self, txid: &Txid) -> Option<&HeldOrphan> {
        self.entries.get(txid)
    }

    pub(crate) fn is_current(&self, claim: &HeldOrphan) -> bool {
        self.entries.get(&claim.tx.txid()).is_some_and(|current| {
            current.source == claim.source && Arc::ptr_eq(&current.tx, &claim.tx)
        })
    }

    pub(crate) fn get_by_wtxid(&self, wtxid: &Wtxid) -> Option<&HeldOrphan> {
        self.by_wtxid.get(wtxid).and_then(|id| self.entries.get(id))
    }

    pub(crate) fn insert(&mut self, tx: Arc<Tx>, source: PeerToken, time: u64) {
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        let weight = tx.weight();
        let arrival_time = if let Some(old) = self.entries.remove(&txid) {
            self.total_weight = self.total_weight.saturating_sub(old.tx.weight());
            self.by_wtxid.remove(&old.tx.wtxid());
            self.unindex_parents(txid, &old.tx);
            // A witness/source refresh must not extend an attacker's residency.
            old.arrival_time
        } else {
            self.order.push_back(txid);
            time
        };
        self.clear_ready(txid);
        for input in &tx.inputs {
            let prevout = input.previous_output;
            if !prevout.is_null() {
                self.by_parent.entry(prevout.txid).or_default().insert(txid);
            }
        }
        self.by_wtxid.insert(wtxid, txid);
        self.total_weight = self.total_weight.saturating_add(weight);
        self.entries.insert(
            txid,
            HeldOrphan {
                tx,
                source,
                arrival_time,
            },
        );
        while self.entries.len() > self.quota || self.total_weight > self.max_weight {
            let Some(oldest) = self.order.front().copied() else {
                break;
            };
            self.remove(oldest);
        }
    }

    pub(crate) fn remove(&mut self, txid: Txid) -> Option<HeldOrphan> {
        let entry = self.entries.remove(&txid)?;
        self.total_weight = self.total_weight.saturating_sub(entry.tx.weight());
        self.by_wtxid.remove(&entry.tx.wtxid());
        self.order.retain(|id| *id != txid);
        self.unindex_parents(txid, &entry.tx);
        self.clear_ready(txid);
        Some(entry)
    }

    fn unindex_parents(&mut self, txid: Txid, tx: &Tx) {
        for input in &tx.inputs {
            let parent = input.previous_output.txid;
            if let Some(children) = self.by_parent.get_mut(&parent) {
                children.remove(&txid);
                if children.is_empty() {
                    self.by_parent.remove(&parent);
                }
            }
        }
    }

    fn clear_ready(&mut self, txid: Txid) {
        if self.ready_ids.remove(&txid) {
            self.ready.retain(|id| *id != txid);
        }
    }

    pub(crate) fn mark_ready(&mut self, txid: Txid) {
        if self.entries.contains_key(&txid) && self.ready_ids.insert(txid) {
            self.ready.push_back(txid);
        }
    }

    pub(crate) fn parent_ready(&mut self, parent: Txid) {
        let children = self.by_parent.get(&parent).cloned().unwrap_or_default();
        for child in children {
            self.mark_ready(child);
        }
    }

    /// Removes expired bodies and bodies whose exact delivering connection is gone.
    ///
    /// The caller supplies one identity-bound snapshot of live peers. Comparing the
    /// full token prevents a same-address reconnect from inheriting its predecessor's
    /// orphan allocation.
    pub(crate) fn maintain(&mut self, now: u64, live_peers: &HashSet<PeerToken>) -> usize {
        let stale: Vec<Txid> = self
            .entries
            .iter()
            .filter_map(|(txid, entry)| {
                let expired = now.saturating_sub(entry.arrival_time) > DEFAULT_ORPHAN_TIMEOUT_SECS;
                (expired || !live_peers.contains(&entry.source)).then_some(*txid)
            })
            .collect();
        let removed = stale.len();
        for txid in stale {
            self.remove(txid);
        }
        removed
    }

    /// Claim one bounded snapshot. Bodies remain resident across transient failures.
    pub(crate) fn take_ready(&mut self) -> Vec<HeldOrphan> {
        self.ready_ids.clear();
        self.ready
            .drain(..)
            .filter_map(|id| self.entries.get(&id).cloned())
            .collect()
    }

    #[cfg(test)]
    fn total_weight(&self) -> u64 {
        self.total_weight
    }
}

#[derive(Debug)]
pub(crate) struct AdmissionLifecycle {
    pub(crate) orphans: OrphanPool,
    rejects: HashMap<Hash256, RejectScope>,
    reject_order: VecDeque<Hash256>,
    reject_cap: usize,
}
impl Default for AdmissionLifecycle {
    fn default() -> Self {
        Self {
            orphans: OrphanPool::new(DEFAULT_ORPHAN_QUOTA),
            rejects: HashMap::new(),
            reject_order: VecDeque::new(),
            reject_cap: DEFAULT_REJECT_CAP,
        }
    }
}
impl AdmissionLifecycle {
    pub(crate) fn reject(&mut self, tx: &Tx, scope: RejectScope) {
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        if scope == RejectScope::Transaction
            || self
                .orphans
                .get(&txid)
                .is_some_and(|held| held.tx.wtxid() == wtxid)
        {
            self.orphans.remove(txid);
        }
        self.cache_reject(Hash256::from(wtxid), RejectScope::Witness);
        if scope == RejectScope::Transaction {
            self.cache_reject(Hash256::from(txid), RejectScope::Transaction);
        }
        while self.reject_order.len() > self.reject_cap {
            if let Some(oldest) = self.reject_order.pop_front() {
                self.rejects.remove(&oldest);
            }
        }
    }
    fn cache_reject(&mut self, hash: Hash256, scope: RejectScope) {
        if let Some(existing) = self.rejects.get_mut(&hash) {
            if scope == RejectScope::Transaction {
                *existing = scope;
            }
        } else {
            self.rejects.insert(hash, scope);
            self.reject_order.push_back(hash);
        }
    }
    /// Base-invalid failures suppress all witnesses; other failures suppress
    /// only the body actually checked. A stripped body's wtxid may equal txid.
    pub(crate) fn rejects_transaction(&self, txid: Txid, wtxid: Wtxid) -> bool {
        self.rejects.get(&Hash256::from(txid)) == Some(&RejectScope::Transaction)
            || self.rejects.contains_key(&Hash256::from(wtxid))
    }
    pub(crate) fn rejects_inventory(&self, hash: Hash256, wtxid: bool) -> bool {
        self.rejects
            .get(&hash)
            .is_some_and(|scope| wtxid || *scope == RejectScope::Transaction)
    }
    pub(crate) fn is_rejected(&self, hash: Hash256) -> bool {
        self.rejects.contains_key(&hash)
    }
    pub(crate) fn rejects_len(&self) -> usize {
        self.rejects.len()
    }
    pub(crate) fn clear_rejects(&mut self) {
        self.rejects.clear();
        self.reject_order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::{OutPoint, TxIn, TxOut};
    fn source(id: u64) -> PeerToken {
        PeerToken {
            addr: core::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            connection_id: id,
        }
    }
    fn tx(marker: u8, parent: Txid) -> Arc<Tx> {
        Arc::new(Tx {
            version: 2,
            lock_time: u32::from(marker),
            inputs: vec![TxIn {
                previous_output: OutPoint::new(parent, 0),
                script_sig: vec![],
                sequence: u32::MAX,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
        })
    }
    #[test]
    fn zero_quota_retains_no_body_or_index() {
        let mut pool = OrphanPool::new(0);
        let tx = tx(1, Txid::default());
        pool.insert(Arc::clone(&tx), source(1), 0);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.total_weight(), 0);
        assert!(pool.by_wtxid.is_empty());
        assert!(pool.by_parent.is_empty());
        assert!(pool.order.is_empty());
    }
    #[test]
    fn witness_refresh_keeps_fifo_position_and_source_identity() {
        let parent = tx(9, Txid::default()).txid();
        let mut pool = OrphanPool::new(2);
        let first = tx(1, parent);
        let base_weight = first.weight();
        pool.insert(Arc::clone(&first), source(1), 1);
        pool.insert(tx(2, parent), source(1), 2);
        assert_eq!(pool.total_weight(), base_weight * 2);
        let mut changed = (*first).clone();
        changed.inputs[0].witness = vec![vec![1]];
        let changed = Arc::new(changed);
        pool.insert(Arc::clone(&changed), source(2), 3);
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.total_weight(), changed.weight() + base_weight);
        assert!(pool.get_by_wtxid(&first.wtxid()).is_none());
        assert_eq!(
            pool.get(&first.txid()).map(|held| held.source),
            Some(source(2))
        );
        pool.insert(tx(3, parent), source(3), 4);
        assert!(!pool.contains(&first.txid()));
        assert!(pool.get_by_wtxid(&changed.wtxid()).is_none());
        assert_eq!(pool.total_weight(), base_weight * 2);
    }
    #[test]
    fn readiness_is_deduplicated_and_removed_with_eviction() {
        let parent = tx(9, Txid::default()).txid();
        let mut pool = OrphanPool::new(1);
        let child = tx(1, parent);
        pool.insert(Arc::clone(&child), source(1), 0);
        pool.parent_ready(parent);
        pool.parent_ready(parent);
        assert_eq!(pool.ready.len(), 1);
        assert_eq!(pool.take_ready().len(), 1);
        assert_eq!(pool.len(), 1);
        pool.mark_ready(child.txid());
        pool.insert(tx(2, parent), source(2), 0);
        assert!(pool.ready.is_empty());
        assert!(pool.ready_ids.is_empty());
        pool.mark_ready(child.txid());
        assert!(pool.ready.is_empty());
    }
    // MPL-04: aggregate orphan weight is bounded independently of count.
    #[test]
    fn aggregate_weight_evicts_fifo_even_when_count_quota_has_room() {
        let parent = tx(9, Txid::default()).txid();
        let first = tx(1, parent);
        let second = tx(2, parent);
        let one_weight = first.weight();
        let mut pool = OrphanPool::with_limits(10, one_weight.saturating_add(1));

        pool.insert(Arc::clone(&first), source(1), 0);
        assert_eq!(pool.total_weight(), one_weight);
        pool.parent_ready(parent);
        pool.insert(Arc::clone(&second), source(2), 0);

        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&first.txid()));
        assert!(pool.contains(&second.txid()));
        assert_eq!(pool.total_weight(), second.weight());
        assert!(pool.total_weight() <= one_weight.saturating_add(1));
        assert!(pool.get_by_wtxid(&first.wtxid()).is_none());
        assert!(pool.take_ready().is_empty());
    }

    #[test]
    fn maintenance_expires_old_bodies_and_cleans_every_index() {
        let parent = tx(9, Txid::default()).txid();
        let mut pool = OrphanPool::new(10);
        let expired = tx(1, parent);
        let current = tx(2, parent);
        pool.insert(Arc::clone(&expired), source(1), 10);
        pool.insert(Arc::clone(&current), source(2), 20);
        pool.parent_ready(parent);

        let live = HashSet::from([source(1), source(2)]);
        assert_eq!(pool.maintain(131, &live), 1);
        assert!(!pool.contains(&expired.txid()));
        assert!(pool.get_by_wtxid(&expired.wtxid()).is_none());
        assert!(pool.contains(&current.txid()));
        assert_eq!(pool.take_ready().len(), 1);
        assert_eq!(pool.total_weight(), current.weight());
    }

    #[test]
    fn maintenance_uses_exact_connection_identity() {
        let parent = tx(9, Txid::default()).txid();
        let mut pool = OrphanPool::new(10);
        let predecessor = tx(1, parent);
        let successor = tx(2, parent);
        pool.insert(Arc::clone(&predecessor), source(1), 0);
        pool.insert(Arc::clone(&successor), source(2), 119);

        // Both tokens share one address. Only the replacement connection is live.
        let live = HashSet::from([source(2)]);
        assert_eq!(pool.maintain(120, &live), 1);
        assert!(!pool.contains(&predecessor.txid()));
        assert!(pool.contains(&successor.txid()));

        // The boundary is strict; the body expires once it is older than 120s.
        assert_eq!(pool.maintain(240, &live), 1);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.total_weight(), 0);
        assert!(pool.by_wtxid.is_empty());
        assert!(pool.by_parent.is_empty());
        assert!(pool.order.is_empty());
    }

    #[test]
    fn witness_refresh_does_not_extend_expiry() {
        let parent = tx(9, Txid::default()).txid();
        let mut pool = OrphanPool::new(10);
        let first = tx(1, parent);
        let mut changed = (*first).clone();
        changed.inputs[0].witness = vec![vec![1]];
        let changed = Arc::new(changed);
        pool.insert(first, source(1), 0);
        pool.insert(Arc::clone(&changed), source(1), 119);

        let live = HashSet::from([source(1)]);
        assert_eq!(pool.maintain(120, &live), 0);
        assert_eq!(pool.maintain(121, &live), 1);
        assert!(pool.get_by_wtxid(&changed.wtxid()).is_none());
    }
    #[test]
    fn rejects_are_bounded_and_chain_reset_clears_both_indexes() {
        let mut state = AdmissionLifecycle {
            reject_cap: 2,
            ..AdmissionLifecycle::default()
        };
        let first = tx(1, Txid::default());
        state.reject(&first, RejectScope::Transaction);
        state.reject(&tx(2, Txid::default()), RejectScope::Transaction);
        state.reject(&tx(3, Txid::default()), RejectScope::Transaction);
        assert_eq!(state.rejects_len(), 2);
        assert!(!state.is_rejected(Hash256::from(first.txid())));
        state.clear_rejects();
        assert!(state.rejects.is_empty());
        assert!(state.reject_order.is_empty());
    }
    /// MPL-04 exact-body residency: rejecting a different witness body with
    /// the same txid must preserve the resident claim and its ready marker.
    #[test]
    fn rejecting_another_witness_preserves_the_resident_body_and_ready_work() {
        let parent = tx(9, Txid::default()).txid();
        let resident = tx(1, parent);
        let mut rejected = (*resident).clone();
        rejected.inputs[0].witness = vec![vec![1]];
        assert_eq!(resident.txid(), rejected.txid());
        assert_ne!(resident.wtxid(), rejected.wtxid());

        let mut state = AdmissionLifecycle::default();
        state.orphans.insert(Arc::clone(&resident), source(1), 0);
        state.orphans.parent_ready(parent);
        state.reject(&rejected, RejectScope::Witness);
        assert_eq!(state.orphans.total_weight(), resident.weight());
        assert!(state.is_rejected(Hash256::from(rejected.wtxid())));
        assert!(!state.is_rejected(Hash256::from(resident.wtxid())));
        let ready = state.orphans.take_ready();
        assert_eq!(ready.len(), 1);
        assert!(Arc::ptr_eq(&ready[0].tx, &resident));
        assert_eq!(ready[0].source, source(1));
        assert_eq!(state.orphans.total_weight(), resident.weight());

        state.reject(&resident, RejectScope::Witness);
        assert_eq!(state.orphans.len(), 0);
        assert_eq!(state.orphans.total_weight(), 0);
        assert!(state.orphans.by_wtxid.is_empty());
        assert!(state.orphans.by_parent.is_empty());
        assert!(state.orphans.order.is_empty());
        assert_eq!(state.rejects_len(), 2);
    }

    /// `MPL-04`: a base-invalid rejection retires the resident variant and its
    /// weight even when the submitted witness body has a different size.
    #[test]
    fn transaction_scoped_rejection_releases_the_resident_variants_weight() {
        let parent = tx(9, Txid::default()).txid();
        let resident = tx(1, parent);
        let sibling = tx(2, parent);
        let mut rejected = (*resident).clone();
        rejected.inputs[0].witness = vec![vec![1; 32]];
        assert_ne!(resident.weight(), rejected.weight());
        let mut state = AdmissionLifecycle::default();
        state.orphans.insert(Arc::clone(&resident), source(1), 0);
        state.orphans.insert(Arc::clone(&sibling), source(2), 0);
        state.orphans.parent_ready(parent);
        state.reject(&rejected, RejectScope::Transaction);
        assert_eq!(state.orphans.total_weight(), sibling.weight());
        let ready = state.orphans.take_ready();
        assert_eq!(ready.len(), 1);
        assert!(Arc::ptr_eq(&ready[0].tx, &sibling));
        assert_eq!(state.orphans.len(), 1);
    }
}
