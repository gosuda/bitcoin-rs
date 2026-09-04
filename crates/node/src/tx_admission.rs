//! Inbound P2P transaction admission policy: orphan map and reject cache.
//!
//! These two structures are the node-side admission tracking that Core owns
//! in `TxOrphanage` + `m_recent_rejects`:
//!
//! * **Orphan map** — transactions whose inputs are not yet available
//!   (missing prevouts) are held briefly for parent arrival. Bounded by a
//!   finite count quota; the oldest entry is evicted when the quota is
//!   exceeded, so a peer can never pin unbounded memory by flooding
//!   orphans.
//! * **Recent-rejects** — a set of wtxids/txids that failed acceptance
//!   recently, consulted by the Inv filter to suppress redundant `getdata`
//!   requests for transactions the node has already evaluated and rejected.
//!
//! Both are consulted by the [`TxInventory`] implementation exposed here,
//! which the p2p dispatch path uses to filter inbound `inv` announcements
//! and to answer `getdata` for tx-typed items. The mempool itself is always
//! consulted first through the shared gateway; the orphan map and
//! recent-rejects are the two additional "already have" sources.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use bitcoin_rs_mempool::MempoolGateway;
use bitcoin_rs_p2p::TxInventory;
use bitcoin_rs_primitives::{Hash256, Tx, Txid, Wtxid};
use parking_lot::Mutex;

/// Default maximum number of orphan transactions held for parent arrival.
///
/// Matches Core's historical `-maxorphantx` default of 100.
pub const DEFAULT_ORPHAN_QUOTA: usize = 100;

/// Default maximum number of entries in the recent-rejects cache.
///
/// The cache is a bounded FIFO: once it holds this many hashes the oldest
/// rejection is dropped, so a peer cannot pin unbounded memory by flooding
/// rejections. Core approximates this with a fixed-size bloom filter; a
/// hard FIFO cap gives the same memory bound with exact membership.
pub const DEFAULT_REJECT_CAP: usize = 100_000;

/// The admission policy state: orphan map + recent-rejects, guarded by one
/// mutex.
#[derive(Debug)]
pub struct TxAdmission {
    inner: Mutex<AdmissionInner>,
    gateway: Arc<MempoolGateway>,
    quota: usize,
    reject_cap: usize,
}

#[derive(Debug, Default)]
struct AdmissionInner {
    /// Orphan transactions keyed by txid, stored in insertion order via
    /// [`orphan_order`] for FIFO eviction.
    orphans: hashbrown::HashMap<Txid, Arc<Tx>>,
    /// Secondary index: wtxid → txid, so BIP339 wtxid-typed inventory can
    /// be matched against held orphans without a linear scan.
    orphan_by_wtxid: hashbrown::HashMap<Wtxid, Txid>,
    /// Insertion order for FIFO eviction; the front is the oldest orphan.
    orphan_order: VecDeque<Txid>,
    /// Recent-rejects cache: both wtxid and txid of each rejected
    /// transaction, stored as raw [`Hash256`] so a single lookup answers
    /// both BIP339 and legacy inventory vectors.
    recent_rejects: HashSet<Hash256>,
    /// Insertion order for the recent-rejects FIFO eviction; the front is
    /// the oldest rejection. Kept in lockstep with [`recent_rejects`].
    reject_order: VecDeque<Hash256>,
}

impl TxAdmission {
    /// Creates an empty admission policy over `gateway` with the default
    /// orphan quota.
    #[must_use]
    pub fn new(gateway: Arc<MempoolGateway>) -> Self {
        Self::with_quota(gateway, DEFAULT_ORPHAN_QUOTA)
    }

    /// Creates an empty admission policy over `gateway` with an explicit
    /// orphan count quota.
    #[must_use]
    pub fn with_quota(gateway: Arc<MempoolGateway>, quota: usize) -> Self {
        Self {
            inner: Mutex::new(AdmissionInner::default()),
            gateway,
            quota,
            reject_cap: DEFAULT_REJECT_CAP,
        }
    }

    /// Records an orphan transaction (missing prevouts) for parent arrival.
    ///
    /// If the map is at the quota, the oldest orphan is evicted first
    /// (FIFO), so after `quota + 1` inserts the map size is exactly
    /// `quota`. Re-inserting an already-held orphan (by txid) refreshes its
    /// body without growing the map.
    pub fn record_orphan(&self, tx: &Arc<Tx>) {
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        let mut inner = self.inner.lock();
        if let Some(old) = inner.orphans.insert(txid, Arc::clone(tx)) {
            // Replace: refresh the body without growing the map or
            // reordering. Drop the previous body's wtxid index entry so a
            // changed witness does not leave a stale wtxid → txid mapping.
            let old_wtxid = old.wtxid();
            if old_wtxid != wtxid {
                inner.orphan_by_wtxid.remove(&old_wtxid);
            }
        } else {
            // New entry: append and evict the oldest over the quota.
            inner.orphan_order.push_back(txid);
            while inner.orphan_order.len() > self.quota {
                let Some(evicted) = inner.orphan_order.pop_front() else {
                    break;
                };
                if let Some(evicted_tx) = inner.orphans.remove(&evicted) {
                    inner.orphan_by_wtxid.remove(&evicted_tx.wtxid());
                }
            }
        }
        // Only index the wtxid while the txid is still resident. When
        // `quota == 0` the just-inserted entry is evicted above, so no
        // stale `orphan_by_wtxid` entry survives and `have_tx` reports
        // false for an empty map.
        if inner.orphans.contains_key(&txid) {
            inner.orphan_by_wtxid.insert(wtxid, txid);
        }
    }

    /// Removes an orphan by txid, returning its body if present. Used when a
    /// parent arrives and the orphan is re-evaluated through the gateway.
    pub fn take_orphan(&self, txid: &Txid) -> Option<Arc<Tx>> {
        let mut inner = self.inner.lock();
        let tx = inner.orphans.remove(txid)?;
        inner.orphan_by_wtxid.remove(&tx.wtxid());
        inner.orphan_order.retain(|id| id != txid);
        Some(tx)
    }

    /// Records a rejected transaction in the recent-rejects cache by both
    /// its txid and wtxid, so subsequent `inv` announcements for either
    /// form are suppressed.
    pub fn record_reject(&self, txid: Txid, wtxid: Wtxid) {
        let mut inner = self.inner.lock();
        for hash in [Hash256::from(txid), Hash256::from(wtxid)] {
            if inner.recent_rejects.insert(hash) {
                inner.reject_order.push_back(hash);
            }
        }
        // FIFO eviction: drop the oldest rejections over the cap so the
        // cache stays bounded. Invalidation (`invalidate_recent_rejects`)
        // remains the out-of-band reset on block connect.
        while inner.reject_order.len() > self.reject_cap {
            let Some(stale) = inner.reject_order.pop_front() else {
                break;
            };
            inner.recent_rejects.remove(&stale);
        }
    }

    /// Clears the recent-rejects cache.
    ///
    /// Call this when a block is connected (chain generation advances): a
    /// transaction rejected at an old tip may become valid once its inputs
    /// are confirmed, so stale rejections must not suppress relay of a
    /// re-submission. The one-liner for the apply path:
    ///
    /// ```text
    /// tx_admission.invalidate_recent_rejects();
    /// ```
    ///
    /// Wire it into `crates/node/src/apply.rs` immediately after a
    /// successful block connect, before the next `inv` round trips. This
    /// module deliberately does not edit `apply.rs` (it is outside the
    /// admission leaf's ownership); the parent connects the call.
    pub fn invalidate_recent_rejects(&self) {
        let mut inner = self.inner.lock();
        inner.recent_rejects.clear();
        inner.reject_order.clear();
    }

    /// Returns the number of orphan transactions currently held.
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.inner.lock().orphans.len()
    }

    /// Returns the number of entries in the recent-rejects cache.
    #[must_use]
    pub fn recent_rejects_count(&self) -> usize {
        self.inner.lock().recent_rejects.len()
    }

    /// Returns `true` when the orphan map holds `txid`.
    #[must_use]
    pub fn is_orphan(&self, txid: &Txid) -> bool {
        self.inner.lock().orphans.contains_key(txid)
    }

    /// Returns `true` when `hash` is in the recent-rejects cache.
    #[must_use]
    pub fn is_rejected(&self, hash: Hash256) -> bool {
        self.inner.lock().recent_rejects.contains(&hash)
    }

    /// Looks up a transaction body by txid in the mempool, then the orphan
    /// map. Returns a cloned body for serving over `getdata`.
    fn lookup_tx(&self, txid: &Txid) -> Option<Tx> {
        let arc = self.gateway.read().transaction_by_txid(txid);
        if let Some(arc) = arc {
            return Some((*arc).clone());
        }
        self.inner
            .lock()
            .orphans
            .get(txid)
            .map(|arc| (**arc).clone())
    }

    /// Looks up a transaction body by wtxid by scanning the mempool entries
    /// (the mempool has no wtxid index) then the orphan wtxid index.
    fn lookup_tx_by_wtxid(&self, wtxid: &Wtxid) -> Option<Tx> {
        {
            let pool = self.gateway.read();
            for (_, entry) in &pool.entries {
                if entry.wtxid == *wtxid {
                    return Some((*entry.tx).clone());
                }
            }
        }
        let inner = self.inner.lock();
        let txid = inner.orphan_by_wtxid.get(wtxid)?;
        inner.orphans.get(txid).map(|arc| (**arc).clone())
    }

    fn have_tx(&self, hash: Hash256, wtxid_relay: bool) -> bool {
        let inner = self.inner.lock();
        if inner.recent_rejects.contains(&hash) {
            return true;
        }
        if wtxid_relay {
            let wtxid = Wtxid::from(hash);
            if inner.orphan_by_wtxid.contains_key(&wtxid) {
                return true;
            }
        } else {
            let txid = Txid::from(hash);
            if inner.orphans.contains_key(&txid) {
                return true;
            }
        }
        // Mempool: check by txid when possible (constant-time index); for
        // wtxid-typed inventory scan the entries since the mempool has no
        // wtxid index.
        if wtxid_relay {
            let wtxid = Wtxid::from(hash);
            let pool = self.gateway.read();
            pool.entries.iter().any(|(_, entry)| entry.wtxid == wtxid)
        } else {
            let txid = Txid::from(hash);
            self.gateway.read().contains_txid(&txid)
        }
    }

    fn get_tx(&self, txid: Txid) -> Option<Tx> {
        self.lookup_tx(&txid)
    }

    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        self.lookup_tx_by_wtxid(&wtxid)
    }
}

/// [`TxInventory`] forwarding to the inherent admission lookups so the p2p
/// dispatch path can filter inbound `inv` announcements against the orphan
/// map, recent-rejects cache, and mempool, and serve `getdata` tx bodies.
/// The p2p crate holds this as `&dyn TxInventory`; the node owns the state.
impl TxInventory for TxAdmission {
    fn have_tx(&self, hash: Hash256, wtxid_relay: bool) -> bool {
        self.have_tx(hash, wtxid_relay)
    }

    fn get_tx(&self, txid: Txid) -> Option<Tx> {
        self.get_tx(txid)
    }

    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        self.get_tx_by_wtxid(wtxid)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits};
    use bitcoin_rs_primitives::{OutPoint, TxIn, TxOut};
    use parking_lot::RwLock;

    fn empty_gateway() -> Arc<MempoolGateway> {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        MempoolGateway::shared(pool)
    }

    fn tx_with_marker(byte: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                    vout: 0,
                },
                script_sig: vec![byte],
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x6A],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn orphan_quota_plus_one_evicts_to_quota() {
        let gateway = empty_gateway();
        let admission = TxAdmission::with_quota(gateway, 4);

        // Insert quota + 1 = 5 distinct orphans.
        for byte in 1..=5_u8 {
            let tx = Arc::new(tx_with_marker(byte));
            admission.record_orphan(&tx);
        }

        assert_eq!(
            admission.orphan_count(),
            4,
            "quota+1 inserts must evict back to exactly the quota"
        );
    }

    #[test]
    fn orphan_reinsert_does_not_grow_map() {
        let gateway = empty_gateway();
        let admission = TxAdmission::with_quota(gateway, 4);
        let tx = Arc::new(tx_with_marker(1));

        admission.record_orphan(&tx);
        admission.record_orphan(&tx);
        admission.record_orphan(&tx);

        assert_eq!(
            admission.orphan_count(),
            1,
            "re-inserting the same txid must not grow the map"
        );
    }

    #[test]
    fn recent_rejects_suppresses_have_tx() {
        let gateway = empty_gateway();
        let admission = TxAdmission::new(gateway);

        let tx = tx_with_marker(7);
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        admission.record_reject(txid, wtxid);

        // Legacy (txid) inventory.
        assert!(
            admission.have_tx(Hash256::from(txid), false),
            "recent-rejects must suppress txid-typed inv"
        );
        // BIP339 (wtxid) inventory.
        assert!(
            admission.have_tx(Hash256::from(wtxid), true),
            "recent-rejects must suppress wtxid-typed inv"
        );
    }

    #[test]
    fn invalidate_recent_rejects_clears_cache() {
        let gateway = empty_gateway();
        let admission = TxAdmission::new(gateway);

        let tx = tx_with_marker(9);
        admission.record_reject(tx.txid(), tx.wtxid());
        // The marker fixture carries no witness, so txid and wtxid coincide
        // and the set holds one entry; both hashes are suppressed all the same.
        assert!(admission.is_rejected(Hash256::from(tx.txid())));
        assert!(admission.is_rejected(Hash256::from(tx.wtxid())));
        assert_eq!(admission.recent_rejects_count(), 1);

        admission.invalidate_recent_rejects();
        assert_eq!(
            admission.recent_rejects_count(),
            0,
            "invalidation must clear the cache"
        );

        assert!(
            !admission.have_tx(Hash256::from(tx.txid()), false),
            "after invalidation the rejected txid is no longer suppressed"
        );
    }

    #[test]
    fn orphan_have_tx_by_wtxid() {
        let gateway = empty_gateway();
        let admission = TxAdmission::new(gateway);
        let tx = Arc::new(tx_with_marker(3));
        let wtxid = tx.wtxid();

        admission.record_orphan(&tx);

        assert!(
            admission.have_tx(Hash256::from(wtxid), true),
            "BIP339 inv for a held orphan must be suppressed"
        );
        assert!(
            admission.have_tx(Hash256::from(tx.txid()), false),
            "legacy inv for a held orphan must be suppressed"
        );
    }

    #[test]
    fn get_tx_serves_orphan_body() {
        let gateway = empty_gateway();
        let admission = TxAdmission::new(gateway);
        let tx = Arc::new(tx_with_marker(4));
        let txid = tx.txid();

        admission.record_orphan(&tx);

        let served = admission
            .get_tx(txid)
            .expect("getdata for a held orphan must serve its body");
        assert_eq!(served.txid(), txid);
    }

    #[test]
    fn take_orphan_removes_entry() {
        let gateway = empty_gateway();
        let admission = TxAdmission::new(gateway);
        let tx = Arc::new(tx_with_marker(5));
        let txid = tx.txid();

        admission.record_orphan(&tx);
        assert_eq!(admission.orphan_count(), 1);

        let taken = admission.take_orphan(&txid);
        assert!(taken.is_some(), "take_orphan must return the body");
        assert_eq!(
            admission.orphan_count(),
            0,
            "take_orphan must remove the entry"
        );
    }

    // --- Loopback acceptance criteria tests ---

    /// Loopback accept: inv → getdata → tx → admitted.
    ///
    /// A tx in the mempool is served via `getdata`, and `have_tx` suppresses
    /// the inv for it.
    #[test]
    fn loopback_accept_inv_getdata_tx_admitted() {
        use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry};
        let gateway = empty_gateway();
        let admission = TxAdmission::new(Arc::clone(&gateway));

        let tx = tx_with_marker(0x42);
        let txid = tx.txid();
        let wtxid = tx.wtxid();

        // Admit the tx into the mempool through the gateway.
        // Fund the fixture: a zero-fee entry is correctly rejected below the
        // 1000 sat/kvB min relay rate, which is what the policy must do.
        let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 0);
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry)
            .expect("insert must succeed");

        // inv filter: the tx is in the mempool, so have_tx returns true
        // and no getdata is produced.
        assert!(
            admission.have_tx(Hash256::from(txid), false),
            "mempool tx must be suppressed by the inv filter (txid)"
        );
        assert!(
            admission.have_tx(Hash256::from(wtxid), true),
            "mempool tx must be suppressed by the inv filter (wtxid)"
        );

        // getdata: the tx is served from the mempool.
        let served = admission
            .get_tx(txid)
            .expect("getdata for a mempool tx must serve its body");
        assert_eq!(
            served.txid(),
            txid,
            "served body must match the requested txid"
        );
    }

    /// Loopback reject: invalid tx in recent-rejects; second inv produces
    /// no getdata.
    #[test]
    fn loopback_reject_second_inv_produces_no_getdata() {
        let gateway = empty_gateway();
        let admission = TxAdmission::new(gateway);

        let tx = tx_with_marker(0x99);
        let txid = tx.txid();
        let wtxid = tx.wtxid();

        // Record the reject.
        admission.record_reject(txid, wtxid);

        // First inv: suppressed by recent-rejects.
        assert!(
            admission.have_tx(Hash256::from(txid), false),
            "first inv for a rejected tx must be suppressed"
        );

        // Second inv: still suppressed.
        assert!(
            admission.have_tx(Hash256::from(txid), false),
            "second inv for a rejected tx must still be suppressed"
        );

        // getdata for the rejected tx: not in mempool, not an orphan, so
        // no body is served (the dispatch path will emit notfound).
        assert!(
            admission.get_tx(txid).is_none(),
            "getdata for a rejected tx must not serve a body"
        );
    }
}
