//! Gateway-owned resident peer transactions awaiting another admission attempt.
//! Readiness indexes the same bounded store. The live contract is count-bounded
//! FIFO retention without expiry; witness refresh preserves FIFO position.

use crate::mutation::PeerToken;
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use bitcoin_rs_primitives::{Hash256, Tx, Txid, Wtxid};
use hashbrown::{HashMap, HashSet};

const DEFAULT_ORPHAN_QUOTA: usize = 100;
const DEFAULT_REJECT_CAP: usize = 100_000;

#[derive(Clone, Debug)]
pub(crate) struct HeldOrphan {
    pub(crate) tx: Arc<Tx>,
    pub(crate) source: PeerToken,
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
}

impl OrphanPool {
    pub(crate) fn new(quota: usize) -> Self {
        Self {
            entries: HashMap::new(),
            by_wtxid: HashMap::new(),
            order: VecDeque::new(),
            by_parent: HashMap::new(),
            ready: VecDeque::new(),
            ready_ids: HashSet::new(),
            quota,
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
    pub(crate) fn insert(&mut self, tx: Arc<Tx>, source: PeerToken) {
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        if let Some(old) = self.entries.remove(&txid) {
            self.by_wtxid.remove(&old.tx.wtxid());
            self.unindex_parents(txid, &old.tx);
        } else {
            self.order.push_back(txid);
        }
        self.clear_ready(txid);
        for input in &tx.inputs {
            let prevout = input.previous_output;
            if !prevout.is_null() && prevout != bitcoin_rs_primitives::OutPoint::default() {
                self.by_parent.entry(prevout.txid).or_default().insert(txid);
            }
        }
        self.by_wtxid.insert(wtxid, txid);
        self.entries.insert(txid, HeldOrphan { tx, source });
        while self.entries.len() > self.quota {
            let Some(oldest) = self.order.front().copied() else {
                break;
            };
            self.remove(oldest);
        }
    }
    pub(crate) fn remove(&mut self, txid: Txid) -> Option<HeldOrphan> {
        let entry = self.entries.remove(&txid)?;
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
    /// Claim one bounded snapshot. Bodies remain resident across transient failures.
    pub(crate) fn take_ready(&mut self) -> Vec<HeldOrphan> {
        self.ready_ids.clear();
        self.ready
            .drain(..)
            .filter_map(|id| self.entries.get(&id).cloned())
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct AdmissionLifecycle {
    pub(crate) orphans: OrphanPool,
    rejects: HashSet<Hash256>,
    reject_order: VecDeque<Hash256>,
    reject_cap: usize,
}
impl Default for AdmissionLifecycle {
    fn default() -> Self {
        Self {
            orphans: OrphanPool::new(DEFAULT_ORPHAN_QUOTA),
            rejects: HashSet::new(),
            reject_order: VecDeque::new(),
            reject_cap: DEFAULT_REJECT_CAP,
        }
    }
}
impl AdmissionLifecycle {
    pub(crate) fn reject(&mut self, tx: &Tx) {
        self.orphans.remove(tx.txid());
        for hash in [Hash256::from(tx.txid()), Hash256::from(tx.wtxid())] {
            if self.rejects.insert(hash) {
                self.reject_order.push_back(hash);
            }
        }
        while self.reject_order.len() > self.reject_cap {
            if let Some(oldest) = self.reject_order.pop_front() {
                self.rejects.remove(&oldest);
            }
        }
    }
    pub(crate) fn is_rejected(&self, hash: Hash256) -> bool {
        self.rejects.contains(&hash)
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
        pool.insert(Arc::clone(&tx), source(1));
        assert_eq!(pool.len(), 0);
        assert!(pool.by_wtxid.is_empty());
        assert!(pool.by_parent.is_empty());
        assert!(pool.order.is_empty());
    }
    #[test]
    fn witness_refresh_keeps_fifo_position_and_source_identity() {
        let parent = tx(9, Txid::default()).txid();
        let mut pool = OrphanPool::new(2);
        let first = tx(1, parent);
        pool.insert(Arc::clone(&first), source(1));
        pool.insert(tx(2, parent), source(1));
        let mut changed = (*first).clone();
        changed.inputs[0].witness = vec![vec![1]];
        let changed = Arc::new(changed);
        pool.insert(Arc::clone(&changed), source(2));
        assert_eq!(pool.len(), 2);
        assert!(pool.get_by_wtxid(&first.wtxid()).is_none());
        assert_eq!(
            pool.get(&first.txid()).map(|held| held.source),
            Some(source(2))
        );
        pool.insert(tx(3, parent), source(3));
        assert!(!pool.contains(&first.txid()));
        assert!(pool.get_by_wtxid(&changed.wtxid()).is_none());
    }
    #[test]
    fn readiness_is_deduplicated_and_removed_with_eviction() {
        let parent = tx(9, Txid::default()).txid();
        let mut pool = OrphanPool::new(1);
        let child = tx(1, parent);
        pool.insert(Arc::clone(&child), source(1));
        pool.parent_ready(parent);
        pool.parent_ready(parent);
        assert_eq!(pool.ready.len(), 1);
        assert_eq!(pool.take_ready().len(), 1);
        assert_eq!(pool.len(), 1);
        pool.mark_ready(child.txid());
        pool.insert(tx(2, parent), source(2));
        assert!(pool.ready.is_empty());
        assert!(pool.ready_ids.is_empty());
        pool.mark_ready(child.txid());
        assert!(pool.ready.is_empty());
    }
    #[test]
    fn rejects_are_bounded_and_chain_reset_clears_both_indexes() {
        let mut state = AdmissionLifecycle {
            reject_cap: 2,
            ..AdmissionLifecycle::default()
        };
        let first = tx(1, Txid::default());
        state.reject(&first);
        state.reject(&tx(2, Txid::default()));
        state.reject(&tx(3, Txid::default()));
        assert_eq!(state.rejects_len(), 2);
        assert!(!state.is_rejected(Hash256::from(first.txid())));
        state.clear_rejects();
        assert!(state.rejects.is_empty());
        assert!(state.reject_order.is_empty());
    }
}
