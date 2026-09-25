//! Gateway-owned peer orphan lifecycle.
//!
//! Retention, witness identity, and retry invariants are owned by `MPL-04`
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
/// Announcements one peer may hold before its usage score passes one.
const DEFAULT_PEER_ANNOUNCEMENTS: usize = 100;
/// Orphan weight one peer may reserve before its usage score passes one.
const DEFAULT_PEER_ANNOUNCEMENT_WEIGHT: u128 = 1_000_000;
/// Latency one peer may accumulate before its latency score passes one.
const DEFAULT_PEER_LATENCY: u128 = 1_000;

/// Whether a failure applies to the base transaction or only this witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectScope {
    Transaction,
    Witness,
}

/// One resident orphan body and every peer that announced it.
#[derive(Clone, Debug)]
pub(crate) struct HeldOrphan {
    pub(crate) tx: Arc<Tx>,
    /// Exact-connection tokens that announced this body. A body stays resident
    /// while at least one announcer remains live.
    pub(crate) announcers: HashSet<PeerToken>,
    /// First-seen wall-clock timestamp supplied by the admission caller.
    arrival_time: u64,
}

/// One queued reconsideration of a resident body for one selected announcer.
#[derive(Debug)]
pub(crate) struct OrphanRetryClaim {
    wtxid: Wtxid,
    announcer: PeerToken,
}

/// Per-peer consumption of orphan residency, charged once per announcement.
#[derive(Clone, Copy, Debug, Default)]
struct PeerUsage {
    announcements: usize,
    weight: u64,
    latency: u64,
}

/// One peer's allowance for each resource an announcement consumes. A peer at
/// or below every allowance scores at most one.
#[derive(Clone, Copy, Debug)]
struct PeerAllowance {
    announcements: u128,
    weight: u128,
    latency: u128,
}

impl PeerAllowance {
    fn new(announcements: usize, weight: u128, latency: u128) -> Self {
        Self {
            announcements: u128::try_from(announcements).unwrap_or(1).max(1),
            weight: weight.max(1),
            latency: latency.max(1),
        }
    }
}

impl PeerUsage {
    /// Core's per-peer `DoS` rank: the largest share of any allowance this peer
    /// consumes. Each share is scaled by the other two allowances so the
    /// comparison stays in exact integers.
    fn rank(&self, allowance: &PeerAllowance) -> u128 {
        let announcements = u128::try_from(self.announcements)
            .unwrap_or(u128::MAX)
            .saturating_mul(allowance.weight)
            .saturating_mul(allowance.latency);
        let weight = u128::from(self.weight)
            .saturating_mul(allowance.announcements)
            .saturating_mul(allowance.latency);
        let latency = u128::from(self.latency)
            .saturating_mul(allowance.announcements)
            .saturating_mul(allowance.weight);
        announcements.max(weight).max(latency)
    }
}

#[derive(Debug)]
pub(crate) struct OrphanPool {
    entries: HashMap<Wtxid, HeldOrphan>,
    order: VecDeque<Wtxid>,
    by_parent: HashMap<Txid, HashSet<Wtxid>>,
    ready: VecDeque<OrphanRetryClaim>,
    ready_ids: HashSet<Wtxid>,
    peer_usage: HashMap<PeerToken, PeerUsage>,
    peer_allowance: PeerAllowance,
    quota: usize,
    total_weight: u64,
    max_weight: u64,
}

impl OrphanPool {
    pub(crate) fn new(quota: usize) -> Self {
        Self::with_limits(
            quota,
            DEFAULT_MAX_ORPHAN_WEIGHT,
            DEFAULT_PEER_ANNOUNCEMENTS,
            DEFAULT_PEER_ANNOUNCEMENT_WEIGHT,
            DEFAULT_PEER_LATENCY,
        )
    }

    fn with_limits(
        quota: usize,
        max_weight: u64,
        peer_announcements: usize,
        peer_weight: u128,
        peer_latency: u128,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            by_parent: HashMap::new(),
            ready: VecDeque::new(),
            ready_ids: HashSet::new(),
            peer_usage: HashMap::new(),
            peer_allowance: PeerAllowance::new(peer_announcements, peer_weight, peer_latency),
            quota,
            total_weight: 0,
            max_weight,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Residency of one exact witness identity. A txid never identifies a
    /// resident body: two bodies can share one txid.
    pub(crate) fn get(&self, wtxid: Wtxid) -> Option<&HeldOrphan> {
        self.entries.get(&wtxid)
    }

    /// One arbitrary resident variant of a txid, for tests and retry
    /// selection only. Inventory suppression must never consult it.
    #[cfg(test)]
    pub(crate) fn get_by_txid(&self, txid: Txid) -> Option<&HeldOrphan> {
        self.entries.values().find(|held| held.tx.txid() == txid)
    }

    /// PRE: `claim` and `announcer` name one pair this pool issued.
    /// POST: true only while that exact body is resident and still lists that
    /// announcer.
    /// INVARIANT: a stale claim never reaches a different witness variant.
    pub(crate) fn is_current(&self, claim: &HeldOrphan, announcer: &PeerToken) -> bool {
        self.entries.get(&claim.tx.wtxid()).is_some_and(|current| {
            current.announcers.contains(announcer) && Arc::ptr_eq(&current.tx, &claim.tx)
        })
    }

    /// PRE: `wtxid` may name a resident body; `announcer` is an exact
    /// connection token.
    /// POST: the pair is recorded exactly once. The body, its first-seen time,
    /// its FIFO position and the resident weight stay unchanged. False when
    /// the body is absent or the pair was already recorded.
    pub(crate) fn add_announcer(&mut self, wtxid: Wtxid, announcer: PeerToken) -> bool {
        let charge = {
            let Some(held) = self.entries.get_mut(&wtxid) else {
                return false;
            };
            if !held.announcers.insert(announcer) {
                return false;
            }
            (held.tx.weight(), Self::latency_score(&held.tx))
        };
        self.charge(&announcer, charge.0, charge.1);
        true
    }

    /// Stores one peer-origin body together with the peer that announced it.
    ///
    /// PRE: the body passed `can_hold_orphan`; its txid and wtxid are stable.
    /// POST: one body exists per wtxid; a new `(wtxid, announcer)` pair is
    /// present exactly once; a same wtxid from the same peer changes nothing;
    /// a different wtxid stays resident even when its txid equals another
    /// resident's; the resident weight counts each wtxid once; an existing
    /// wtxid keeps its FIFO position and first-seen time. Both global limits
    /// hold on return.
    /// INVARIANT: no index holds a txid as the resident identity, and the
    /// parent, ready, weight and per-peer counters agree with `entries`.
    pub(crate) fn insert(&mut self, tx: Arc<Tx>, announcer: PeerToken, time: u64) {
        let wtxid = tx.wtxid();
        if self.entries.contains_key(&wtxid) {
            self.add_announcer(wtxid, announcer);
        } else {
            self.order.push_back(wtxid);
            for input in &tx.inputs {
                let prevout = input.previous_output;
                if !prevout.is_null() {
                    self.by_parent
                        .entry(prevout.txid)
                        .or_default()
                        .insert(wtxid);
                }
            }
            let weight = tx.weight();
            let latency = Self::latency_score(&tx);
            self.total_weight = self.total_weight.saturating_add(weight);
            self.entries.insert(
                wtxid,
                HeldOrphan {
                    tx,
                    announcers: HashSet::from([announcer]),
                    arrival_time: time,
                },
            );
            self.charge(&announcer, weight, latency);
        }
        self.evict_to_limits();
    }

    /// Removes the body with this exact witness identity, every announcer of
    /// it, and every index entry that named it.
    pub(crate) fn remove(&mut self, wtxid: Wtxid) -> Option<HeldOrphan> {
        let entry = self.entries.remove(&wtxid)?;
        self.total_weight = self.total_weight.saturating_sub(entry.tx.weight());
        self.order.retain(|id| *id != wtxid);
        self.unindex_parents(wtxid, &entry.tx);
        let weight = entry.tx.weight();
        let latency = Self::latency_score(&entry.tx);
        for announcer in &entry.announcers {
            self.refund(announcer, weight, latency);
        }
        self.clear_ready(wtxid);
        Some(entry)
    }

    /// Removes every resident body whose txid equals `txid`.
    ///
    /// PRE: the caller holds a transaction-wide refusal or has admitted that
    /// txid into the mempool, so no variant can be admitted again.
    /// POST: no resident shares the txid; unrelated residents stay.
    pub(crate) fn remove_transaction_variants(&mut self, txid: Txid) {
        let variants: Vec<Wtxid> = self
            .entries
            .iter()
            .filter(|(_, held)| held.tx.txid() == txid)
            .map(|(wtxid, _)| *wtxid)
            .collect();
        for wtxid in variants {
            self.remove(wtxid);
        }
    }

    /// PRE: `wtxid` may name a resident body; `preferred` may be one of its
    /// announcers.
    /// POST: a resident wtxid holds at most one claim, assigned to a current
    /// announcer; an already-queued wtxid keeps its existing claim.
    /// INVARIANT: readiness is keyed by wtxid, never by txid.
    pub(crate) fn mark_ready(&mut self, wtxid: Wtxid, preferred: PeerToken) {
        let announcer = {
            let Some(held) = self.entries.get(&wtxid) else {
                return;
            };
            if held.announcers.contains(&preferred) {
                preferred
            } else {
                let Some(selected) = Self::select_announcer(&held.announcers) else {
                    return;
                };
                selected
            }
        };
        if self.ready_ids.insert(wtxid) {
            self.ready.push_back(OrphanRetryClaim { wtxid, announcer });
        }
    }

    /// Makes every resident body spending an output of `parent` eligible for
    /// reconsideration.
    ///
    /// PRE: `parent` names an applied, spendable transaction.
    /// POST: every resident wtxid indexed under that parent holds at most one
    /// claim, assigned to one current announcer; each variant is eligible on
    /// its own.
    /// INVARIANT: readiness is keyed by wtxid, not txid.
    pub(crate) fn parent_ready(&mut self, parent: Txid) {
        let claims: Vec<(Wtxid, PeerToken)> = self
            .by_parent
            .get(&parent)
            .map(|children| {
                children
                    .iter()
                    .filter_map(|wtxid| {
                        let held = self.entries.get(wtxid)?;
                        Some((*wtxid, Self::select_announcer(&held.announcers)?))
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (wtxid, announcer) in claims {
            self.mark_ready(wtxid, announcer);
        }
    }

    /// Claim one bounded snapshot. Bodies remain resident across transient
    /// failures.
    ///
    /// POST: each pair names one resident body and one of its current
    /// announcers; a claim whose body was removed is discarded.
    pub(crate) fn take_ready(&mut self) -> Vec<(HeldOrphan, PeerToken)> {
        self.ready_ids.clear();
        self.ready
            .drain(..)
            .filter_map(|claim| {
                let held = self.entries.get(&claim.wtxid)?;
                let announcer = if held.announcers.contains(&claim.announcer) {
                    claim.announcer
                } else {
                    Self::select_announcer(&held.announcers)?
                };
                Some((held.clone(), announcer))
            })
            .collect()
    }

    /// Removes expired bodies and the announcements of departed connections.
    ///
    /// PRE: the caller supplies one identity-bound snapshot of live peers.
    /// POST: expired bodies are removed; otherwise only an announcer absent
    /// from the live set is dropped, and a body goes only after its last
    /// announcer goes. Returns the number of removed bodies.
    /// INVARIANT: a same-address reconnect never inherits the old token, so an
    /// orphan with another live announcer stays resident.
    pub(crate) fn maintain(&mut self, now: u64, live_peers: &HashSet<PeerToken>) -> usize {
        let expired: Vec<Wtxid> = self
            .entries
            .iter()
            .filter_map(|(wtxid, held)| {
                let expired = now.saturating_sub(held.arrival_time) >= DEFAULT_ORPHAN_TIMEOUT_SECS;
                expired.then_some(*wtxid)
            })
            .collect();
        let mut removed = 0;
        for wtxid in expired {
            if self.remove(wtxid).is_some() {
                removed += 1;
            }
        }
        let departed: Vec<(Wtxid, PeerToken)> = self
            .entries
            .iter()
            .flat_map(|(wtxid, held)| {
                held.announcers
                    .iter()
                    .filter(|announcer| !live_peers.contains(*announcer))
                    .map(|announcer| (*wtxid, *announcer))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (wtxid, announcer) in departed {
            if self.remove_announcer(wtxid, announcer) {
                removed += 1;
            }
        }
        removed
    }

    /// Drops one peer's announcement of one body.
    ///
    /// POST: true when the body lost its last announcer and was removed. The
    /// per-peer counters follow the announcement.
    fn remove_announcer(&mut self, wtxid: Wtxid, announcer: PeerToken) -> bool {
        let charge = {
            let Some(held) = self.entries.get_mut(&wtxid) else {
                return false;
            };
            if !held.announcers.remove(&announcer) {
                return false;
            }
            (
                held.tx.weight(),
                Self::latency_score(&held.tx),
                held.announcers.is_empty(),
            )
        };
        self.refund(&announcer, charge.0, charge.1);
        if charge.2 {
            self.remove(wtxid);
            return true;
        }
        false
    }

    /// Restores both global bounds by trimming announcements of the highest
    /// scoring peer.
    ///
    /// POST: each step drops one announcement of the peer with the largest
    /// `DoS` rank; a body goes only with its last announcer. A peer within its
    /// allowance is trimmed only after every peer over its own.
    fn evict_to_limits(&mut self) {
        while self.entries.len() > self.quota || self.total_weight > self.max_weight {
            let Some(victim) = self.highest_scoring_peer() else {
                break;
            };
            if !self.trim_oldest_announcement(victim) {
                break;
            }
        }
    }

    fn highest_scoring_peer(&self) -> Option<PeerToken> {
        self.peer_usage
            .iter()
            .max_by(|(left_peer, left), (right_peer, right)| {
                let rank = left
                    .rank(&self.peer_allowance)
                    .cmp(&right.rank(&self.peer_allowance));
                // A newer connection token wins an exact tie.
                rank.then_with(|| {
                    (left_peer.connection_id, left_peer.addr)
                        .cmp(&(right_peer.connection_id, right_peer.addr))
                })
            })
            .map(|(peer, _)| *peer)
    }

    /// Drops the victim's oldest announcement, preferring work that is not
    /// ready for reconsideration.
    fn trim_oldest_announcement(&mut self, victim: PeerToken) -> bool {
        let target = {
            let mut ready_candidate: Option<Wtxid> = None;
            let mut found = None;
            for wtxid in &self.order {
                let Some(held) = self.entries.get(wtxid) else {
                    continue;
                };
                if !held.announcers.contains(&victim) {
                    continue;
                }
                if self.ready_ids.contains(wtxid) {
                    ready_candidate.get_or_insert(*wtxid);
                    continue;
                }
                found = Some(*wtxid);
                break;
            }
            found.or(ready_candidate)
        };
        let Some(wtxid) = target else {
            return false;
        };
        self.remove_announcer(wtxid, victim);
        true
    }

    fn charge(&mut self, announcer: &PeerToken, weight: u64, latency: u64) {
        let usage = self.peer_usage.entry(*announcer).or_default();
        usage.announcements += 1;
        usage.weight = usage.weight.saturating_add(weight);
        usage.latency = usage.latency.saturating_add(latency);
    }

    fn refund(&mut self, announcer: &PeerToken, weight: u64, latency: u64) {
        let drained = {
            let Some(usage) = self.peer_usage.get_mut(announcer) else {
                return;
            };
            usage.announcements = usage.announcements.saturating_sub(1);
            usage.weight = usage.weight.saturating_sub(weight);
            usage.latency = usage.latency.saturating_sub(latency);
            usage.announcements == 0
        };
        if drained {
            self.peer_usage.remove(announcer);
        }
    }

    /// Core's per-body latency charge: one per body plus one per ten inputs.
    fn latency_score(tx: &Tx) -> u64 {
        u64::try_from(tx.inputs.len() / 10)
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1)
    }

    /// Deterministic announcer choice: the earliest minted connection token.
    fn select_announcer(announcers: &HashSet<PeerToken>) -> Option<PeerToken> {
        announcers
            .iter()
            .copied()
            .min_by_key(|peer| (peer.connection_id, peer.addr))
    }

    fn unindex_parents(&mut self, wtxid: Wtxid, tx: &Tx) {
        for input in &tx.inputs {
            let parent = input.previous_output.txid;
            if let Some(children) = self.by_parent.get_mut(&parent) {
                children.remove(&wtxid);
                if children.is_empty() {
                    self.by_parent.remove(&parent);
                }
            }
        }
    }

    fn clear_ready(&mut self, wtxid: Wtxid) {
        if self.ready_ids.remove(&wtxid) {
            self.ready.retain(|claim| claim.wtxid != wtxid);
        }
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
    /// Caches one refusal and retires the resident work it covers.
    ///
    /// PRE: `tx` is the exact body the failure was observed on.
    /// POST: a witness refusal removes only the resident body with that
    /// wtxid; a transaction refusal removes every resident variant of that
    /// txid. The wtxid is always cached; the txid only for a transaction
    /// refusal.
    /// INVARIANT: a witness refusal never retires another witness variant.
    pub(crate) fn reject(&mut self, tx: &Tx, scope: RejectScope) {
        match scope {
            RejectScope::Witness => {
                self.orphans.remove(tx.wtxid());
            }
            RejectScope::Transaction => {
                self.orphans.remove_transaction_variants(tx.txid());
            }
        }
        self.cache_reject(Hash256::from(tx.wtxid()), RejectScope::Witness);
        if scope == RejectScope::Transaction {
            self.cache_reject(Hash256::from(tx.txid()), RejectScope::Transaction);
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
    use bitcoin_rs_primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, TxIn, TxOut, Witness,
    };
    fn source(id: u64) -> PeerToken {
        PeerToken {
            addr: core::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            connection_id: id,
        }
    }
    fn tx(marker: u8, parent: Txid) -> Arc<Tx> {
        Arc::new(Tx {
            version: 2,
            lock_time: LockTime::from_consensus(u32::from(marker)),
            inputs: vec![TxIn {
                previous_output: OutPoint::new(parent, 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(u32::MAX),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
        })
    }
    /// One body with a different witness keeps its txid and changes its wtxid.
    fn re_witnessed(body: &Tx, item: u8) -> Arc<Tx> {
        let mut changed = (*body).clone();
        changed.inputs[0].witness = Witness::from_stack(vec![vec![item]]);
        Arc::new(changed)
    }
    #[test]
    fn zero_quota_retains_no_body_or_index() {
        let mut pool = OrphanPool::new(0);
        let tx = tx(1, Txid::default());
        pool.insert(Arc::clone(&tx), source(1), 0);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.total_weight(), 0);
        assert!(pool.get(tx.wtxid()).is_none());
        // Nothing is indexed under the parent, so readiness stays empty.
        pool.parent_ready(tx.inputs[0].previous_output.txid);
        assert!(pool.take_ready().is_empty());
        assert!(pool.by_parent.is_empty());
        assert!(pool.order.is_empty());
        assert!(pool.peer_usage.is_empty());
    }
    #[test]
    fn witness_refresh_keeps_fifo_position_and_announcer_set() {
        let parent = tx(9, Txid::default()).txid();
        let mut pool = OrphanPool::new(3);
        let first = tx(1, parent);
        let base_weight = first.weight();
        pool.insert(Arc::clone(&first), source(1), 1);
        pool.insert(tx(2, parent), source(1), 2);
        assert_eq!(pool.total_weight(), base_weight * 2);
        // A different witness with the same txid is a second resident body.
        let changed = re_witnessed(&first, 1);
        pool.insert(Arc::clone(&changed), source(2), 3);
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.total_weight(), changed.weight() + base_weight * 2);
        assert!(pool.get(first.wtxid()).is_some());
        assert!(pool.get(changed.wtxid()).is_some());
        // Re-announcing the same body adds an announcer and changes nothing
        // else: the FIFO position and the first-seen time stay put.
        pool.insert(Arc::clone(&first), source(3), 4);
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.total_weight(), changed.weight() + base_weight * 2);
        assert_eq!(
            pool.get(first.wtxid()).map(|held| held.announcers.len()),
            Some(2)
        );
        assert_eq!(
            pool.get(first.wtxid()).map(|held| held.arrival_time),
            Some(1)
        );
        // The 120-second residency clock stays anchored at first arrival.
        let live = HashSet::from([source(1), source(2), source(3)]);
        assert_eq!(pool.maintain(121, &live), 1);
        assert!(pool.get(first.wtxid()).is_none());
        assert!(pool.get(changed.wtxid()).is_some());
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
        let ready = pool.take_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].1, source(1));
        assert_eq!(pool.len(), 1);
        // Eviction prefers an announcement that is not ready for
        // reconsideration, so the queued claim survives it.
        pool.mark_ready(child.wtxid(), source(1));
        pool.insert(tx(2, parent), source(1), 0);
        assert!(pool.get(child.wtxid()).is_some());
        assert_eq!(pool.take_ready().len(), 1);
        // Removing the body itself clears its queued claim.
        pool.mark_ready(child.wtxid(), source(1));
        assert!(pool.ready_ids.contains(&child.wtxid()));
        pool.remove(child.wtxid());
        assert!(pool.ready.is_empty());
        assert!(pool.ready_ids.is_empty());
    }
    // MPL-04: aggregate orphan weight is bounded independently of count.
    #[test]
    fn aggregate_weight_evicts_fifo_even_when_count_quota_has_room() {
        let parent = tx(9, Txid::default()).txid();
        let first = tx(1, parent);
        let second = tx(2, parent);
        let one_weight = first.weight();
        let mut pool = OrphanPool::with_limits(
            10,
            one_weight.saturating_add(1),
            DEFAULT_PEER_ANNOUNCEMENTS,
            DEFAULT_PEER_ANNOUNCEMENT_WEIGHT,
            DEFAULT_PEER_LATENCY,
        );

        pool.insert(Arc::clone(&first), source(1), 0);
        assert_eq!(pool.total_weight(), one_weight);
        pool.parent_ready(parent);
        pool.insert(Arc::clone(&second), source(1), 0);

        // One peer announced both bodies, so its oldest non-ready announcement
        // is trimmed first and the bound holds again.
        assert_eq!(pool.len(), 1);
        assert!(pool.get(first.wtxid()).is_some());
        assert!(pool.get(second.wtxid()).is_none());
        assert_eq!(pool.total_weight(), first.weight());
        assert!(pool.total_weight() <= one_weight.saturating_add(1));
        let ready = pool.take_ready();
        assert_eq!(ready.len(), 1);
        assert!(Arc::ptr_eq(&ready[0].0.tx, &first));
        // The surviving body stays charged to its one announcer.
        assert_eq!(pool.peer_usage.len(), 1);
        assert_eq!(
            pool.peer_usage
                .get(&source(1))
                .map(|usage| usage.announcements),
            Some(1)
        );
    }

    // MPL-04 contract: docs/contracts/mempool-mutations.md (orphan lifecycle).
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
        assert!(pool.get(expired.wtxid()).is_none());
        assert!(pool.get(current.wtxid()).is_some());
        assert_eq!(pool.take_ready().len(), 1);
        assert_eq!(pool.total_weight(), current.weight());
    }

    // MPL-04 contract: docs/contracts/mempool-mutations.md (orphan lifecycle).
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
        assert!(pool.get(predecessor.wtxid()).is_none());
        assert!(pool.get(successor.wtxid()).is_some());

        // MPL-04: retention expires at the DEFAULT_ORPHAN_TIMEOUT_SECS boundary.
        assert_eq!(pool.maintain(119 + DEFAULT_ORPHAN_TIMEOUT_SECS, &live), 1);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.total_weight(), 0);
        assert!(pool.entries.is_empty());
        assert!(pool.by_parent.is_empty());
        assert!(pool.order.is_empty());
        assert!(pool.peer_usage.is_empty());
    }

    /// `MPL-04`: a base-invalid rejection retires every resident variant of
    /// that txid and its weight; unrelated residents stay.
    #[test]
    fn transaction_scoped_rejection_releases_the_resident_variants_weight() {
        let parent = tx(9, Txid::default()).txid();
        let resident = tx(1, parent);
        let sibling = tx(2, parent);
        let rejected = re_witnessed(&resident, 1);
        assert_ne!(resident.weight(), rejected.weight());
        let mut state = AdmissionLifecycle::default();
        state.orphans.insert(Arc::clone(&resident), source(1), 0);
        state.orphans.insert(Arc::clone(&rejected), source(2), 0);
        state.orphans.insert(Arc::clone(&sibling), source(3), 0);
        state.orphans.parent_ready(parent);
        assert!(state.orphans.get_by_txid(resident.txid()).is_some());
        state.reject(&rejected, RejectScope::Transaction);
        assert_eq!(state.orphans.total_weight(), sibling.weight());
        // No variant of the rejected txid stays selectable by txid.
        assert!(state.orphans.get_by_txid(resident.txid()).is_none());
        assert!(state.orphans.get(resident.wtxid()).is_none());
        assert!(state.orphans.get(rejected.wtxid()).is_none());
        let ready = state.orphans.take_ready();
        assert_eq!(ready.len(), 1);
        assert!(Arc::ptr_eq(&ready[0].0.tx, &sibling));
        assert_eq!(state.orphans.len(), 1);
    }

    // MPL-04 contract: docs/contracts/mempool-mutations.md (orphan lifecycle).
    #[test]
    fn witness_refresh_does_not_extend_expiry() {
        let parent = tx(9, Txid::default()).txid();
        let mut pool = OrphanPool::new(10);
        let first = tx(1, parent);
        pool.insert(Arc::clone(&first), source(1), 0);
        // A second peer re-announces the same body late in the window.
        pool.insert(Arc::clone(&first), source(2), 119);

        let live = HashSet::from([source(1), source(2)]);
        // MPL-04: expiry stays anchored at the first arrival (time 0). The
        // re-announcement must not buy another timeout window, so the body
        // still expires exactly at the timeout boundary.
        assert_eq!(pool.maintain(120, &live), 1);
        assert!(pool.get(first.wtxid()).is_none());
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
    /// the same txid must preserve every resident variant and its ready work.
    #[test]
    fn rejecting_another_witness_preserves_the_resident_body_and_ready_work() {
        let parent = tx(9, Txid::default()).txid();
        let resident = tx(1, parent);
        let rejected = re_witnessed(&resident, 1);
        let sibling = re_witnessed(&resident, 2);
        assert_eq!(resident.txid(), rejected.txid());
        assert_ne!(resident.wtxid(), rejected.wtxid());
        assert_ne!(rejected.wtxid(), sibling.wtxid());

        let mut state = AdmissionLifecycle::default();
        state.orphans.insert(Arc::clone(&resident), source(1), 0);
        state.orphans.insert(Arc::clone(&sibling), source(2), 0);
        state.orphans.parent_ready(parent);
        state.reject(&rejected, RejectScope::Witness);
        assert_eq!(
            state.orphans.total_weight(),
            resident.weight() + sibling.weight()
        );
        assert!(state.is_rejected(Hash256::from(rejected.wtxid())));
        assert!(!state.is_rejected(Hash256::from(resident.wtxid())));
        let ready = state.orphans.take_ready();
        assert_eq!(ready.len(), 2);
        assert!(
            ready
                .iter()
                .any(|(held, _)| Arc::ptr_eq(&held.tx, &resident))
        );
        assert!(
            ready
                .iter()
                .any(|(held, _)| Arc::ptr_eq(&held.tx, &sibling))
        );

        // The exact witness rejection removes only its own body.
        state.reject(&resident, RejectScope::Witness);
        assert_eq!(state.orphans.len(), 1);
        assert!(state.orphans.get(resident.wtxid()).is_none());
        assert!(state.orphans.get(sibling.wtxid()).is_some());
        assert_eq!(state.orphans.total_weight(), sibling.weight());
        assert_eq!(state.rejects_len(), 2);
    }

    /// TXR-06: two peers holding different witnesses of one txid coexist, and
    /// a disconnect removes only the departed peer's announcement.
    #[test]
    fn same_wtxid_keeps_all_announcers_and_disconnect_removes_one() {
        let parent = tx(9, Txid::default()).txid();
        let mut pool = OrphanPool::new(10);
        let body = tx(1, parent);
        pool.insert(Arc::clone(&body), source(1), 0);
        pool.insert(Arc::clone(&body), source(2), 0);
        assert_eq!(pool.len(), 1);
        assert_eq!(
            pool.get(body.wtxid()).map(|held| held.announcers.len()),
            Some(2)
        );

        // One announcer's connection is gone. The body stays with the other.
        let live = HashSet::from([source(1)]);
        assert_eq!(pool.maintain(1, &live), 0);
        assert!(pool.get(body.wtxid()).is_some());
        pool.parent_ready(parent);
        let ready = pool.take_ready();
        assert_eq!(ready.len(), 1);
        assert!(Arc::ptr_eq(&ready[0].0.tx, &body));
        assert_eq!(ready[0].1, source(1));

        // The last announcer leaving removes the body.
        let live = HashSet::new();
        assert_eq!(pool.maintain(2, &live), 1);
        assert!(pool.get(body.wtxid()).is_none());
        assert!(pool.peer_usage.is_empty());
    }

    /// TXR-06: global-limit relief trims the peer with the highest `DoS` score
    /// first, so a peer within its allowance cannot be blamed for another's
    /// reserved usage.
    #[test]
    fn eviction_trims_the_highest_peer_score_before_protected_peer() {
        let parent = tx(9, Txid::default()).txid();
        let protected = tx(1, parent);
        let first = tx(2, parent);
        let second = tx(3, parent);
        let mut pool = OrphanPool::with_limits(
            2,
            DEFAULT_MAX_ORPHAN_WEIGHT,
            1,
            DEFAULT_PEER_ANNOUNCEMENT_WEIGHT,
            DEFAULT_PEER_LATENCY,
        );
        pool.insert(Arc::clone(&protected), source(1), 0);
        pool.insert(Arc::clone(&first), source(2), 1);
        pool.insert(Arc::clone(&second), source(2), 2);

        // Over the count bound. The peer with two announcements is trimmed,
        // and its own oldest announcement goes first; the single-announcement
        // peer keeps its body even though it arrived earliest.
        assert_eq!(pool.len(), 2);
        assert!(pool.get(protected.wtxid()).is_some());
        assert!(pool.get(first.wtxid()).is_none());
        assert!(pool.get(second.wtxid()).is_some());
    }
}
