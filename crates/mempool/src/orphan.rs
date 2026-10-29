use crate::mutation::PeerToken;
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use bitcoin_rs_primitives::{Hash256, Tx, Txid, Wtxid};
use hashbrown::{HashMap, HashSet};

const DEFAULT_ORPHAN_QUOTA: usize = 100;
const DEFAULT_MAX_ORPHAN_WEIGHT: u64 = 10_000_000;
const DEFAULT_ORPHAN_TIMEOUT_SECS: u64 = 2 * 60;
const DEFAULT_REJECT_CAP: usize = 100_000;
const DEFAULT_PEER_ANNOUNCEMENTS: usize = 100;
const DEFAULT_PEER_ANNOUNCEMENT_WEIGHT: u128 = 1_000_000;
const DEFAULT_PEER_LATENCY: u128 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectScope {
    Transaction,
    Witness,
}

#[derive(Clone, Debug)]
pub(crate) struct HeldOrphan {
    pub(crate) tx: Arc<Tx>,
    pub(crate) announcers: HashSet<PeerToken>,
    arrival_time: u64,
}

#[derive(Debug)]
struct OrphanRetryClaim {
    wtxid: Wtxid,
    announcer: PeerToken,
}

#[derive(Clone, Debug, Default)]
struct PeerUsage {
    announcements: usize,
    weight: u64,
    latency: u64,
    announced: VecDeque<Wtxid>,
}

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

    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn get(&self, wtxid: Wtxid) -> Option<&HeldOrphan> {
        self.entries.get(&wtxid)
    }

    #[cfg(test)]
    fn get_by_txid(&self, txid: Txid) -> Option<&HeldOrphan> {
        self.entries.values().find(|held| held.tx.txid() == txid)
    }

    pub(crate) fn is_current(&self, claim: &HeldOrphan, announcer: &PeerToken) -> bool {
        self.entries.get(&claim.tx.wtxid()).is_some_and(|current| {
            current.announcers.contains(announcer) && Arc::ptr_eq(&current.tx, &claim.tx)
        })
    }

    fn add_announcer(&mut self, wtxid: Wtxid, announcer: PeerToken) -> bool {
        let charge = {
            let Some(held) = self.entries.get_mut(&wtxid) else {
                return false;
            };
            if !held.announcers.insert(announcer) {
                return false;
            }
            (held.tx.weight(), Self::latency_score(&held.tx))
        };
        self.charge(&announcer, wtxid, charge.0, charge.1);
        true
    }

    pub(crate) fn insert(&mut self, tx: Arc<Tx>, announcer: PeerToken, time: u64) {
        let wtxid = tx.wtxid();
        if self.entries.contains_key(&wtxid) {
            self.add_announcer(wtxid, announcer);
        } else {
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
            self.charge(&announcer, wtxid, weight, latency);
        }
        self.evict_to_limits();
    }

    pub(crate) fn remove(&mut self, wtxid: Wtxid) -> Option<HeldOrphan> {
        let entry = self.entries.remove(&wtxid)?;
        self.total_weight = self.total_weight.saturating_sub(entry.tx.weight());
        self.unindex_parents(wtxid, &entry.tx);
        let weight = entry.tx.weight();
        let latency = Self::latency_score(&entry.tx);
        for announcer in &entry.announcers {
            self.refund(announcer, weight, latency);
        }
        self.clear_ready(wtxid);
        Some(entry)
    }

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

    pub(crate) fn mark_all_ready(&mut self) {
        let claims: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(wtxid, held)| Some((*wtxid, Self::select_announcer(&held.announcers)?)))
            .collect();
        for (wtxid, announcer) in claims {
            self.mark_ready(wtxid, announcer);
        }
    }

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
                rank.then_with(|| {
                    (left_peer.connection_id, left_peer.endpoint)
                        .cmp(&(right_peer.connection_id, right_peer.endpoint))
                })
            })
            .map(|(peer, _)| *peer)
    }

    fn trim_oldest_announcement(&mut self, victim: PeerToken) -> bool {
        let target = {
            let mut ready_candidate: Option<Wtxid> = None;
            let mut found = None;
            let Some(usage) = self.peer_usage.get(&victim) else {
                return false;
            };
            for wtxid in &usage.announced {
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
        if let Some(usage) = self.peer_usage.get_mut(&victim) {
            let entries = &self.entries;
            usage.announced.retain(|id| {
                entries
                    .get(id)
                    .is_some_and(|h| h.announcers.contains(&victim))
            });
        }
        true
    }

    fn charge(&mut self, announcer: &PeerToken, wtxid: Wtxid, weight: u64, latency: u64) {
        let usage = self.peer_usage.entry(*announcer).or_default();
        usage.announcements += 1;
        usage.weight = usage.weight.saturating_add(weight);
        usage.latency = usage.latency.saturating_add(latency);
        usage.announced.push_back(wtxid);
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

    fn latency_score(tx: &Tx) -> u64 {
        u64::try_from(tx.inputs.len() / 10)
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1)
    }

    fn select_announcer(announcers: &HashSet<PeerToken>) -> Option<PeerToken> {
        announcers
            .iter()
            .copied()
            .min_by_key(|peer| (peer.connection_id, peer.endpoint))
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
    pub(crate) fn rejects_transaction(&self, txid: Txid, wtxid: Wtxid) -> bool {
        self.rejects.get(&Hash256::from(txid)) == Some(&RejectScope::Transaction)
            || self.rejects.contains_key(&Hash256::from(wtxid))
    }
    pub(crate) fn rejects_inventory(&self, hash: Hash256, wtxid: bool) -> bool {
        self.rejects
            .get(&hash)
            .is_some_and(|scope| wtxid || *scope == RejectScope::Transaction)
    }
    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) fn is_rejected(&self, hash: Hash256) -> bool {
        self.rejects.contains_key(&hash)
    }
    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) fn rejects_len(&self) -> usize {
        self.rejects.len()
    }
    pub(crate) fn clear_rejects(&mut self) {
        self.rejects.clear();
        self.reject_order.clear();
    }
}

#[cfg(test)]
mod tests;
