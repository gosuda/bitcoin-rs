//! Connection-bound transaction download policy. Mempool remains the authority
//! for accepted, orphan and rejected bodies; this owner retains identities only.
//!
//! Core v31.1 node/txdownloadman_impl.cpp and p2p_tx_download.py define the
//! reference cases. Unknown txid/wtxid pairs cannot be inferred from hashes:
//! they remain separate until a body supplies the mapping.

use std::time::{Duration, Instant};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use hashbrown::{HashMap, HashSet};

use crate::{Message, PeerSource, PeerTable, TxInventory};
use bitcoin_rs_primitives::{Hash256, Txid, Wtxid};

pub(crate) const MAX_PEER_ANNOUNCEMENTS: usize = 5_000;
pub(crate) const MAX_PEER_IN_FLIGHT: usize = 100;
/// Extra global and per-identity bounds, independent of connection count.
const MAX_ANNOUNCEMENTS: usize = 100_000;
const MAX_ALTERNATES: usize = 8;
const REQUEST_LIFETIME: Duration = Duration::from_secs(60);
const SOURCE_DELAY: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Identity {
    Txid(Hash256),
    Wtxid(Hash256),
}

impl Identity {
    fn from_inventory(item: Inventory) -> Option<Self> {
        match item {
            Inventory::Transaction(id) | Inventory::WitnessTransaction(id) => {
                Some(Self::Txid(Hash256::from_le_bytes(id.as_byte_array())))
            }
            Inventory::WTx(id) => Some(Self::Wtxid(Hash256::from_le_bytes(id.as_byte_array()))),
            _ => None,
        }
    }

    fn known(self, inventory: &dyn TxInventory) -> bool {
        match self {
            Self::Txid(hash) => inventory.have_tx(hash, false),
            Self::Wtxid(hash) => inventory.have_tx(hash, true),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Announcement {
    source: PeerSource,
    item: Inventory,
    ready: Instant,
    preferred: bool,
    priority: u64,
}

#[derive(Debug, Default)]
struct Request {
    candidates: Vec<Announcement>,
    owner: Option<(PeerSource, Instant)>,
}

#[derive(Debug, Default)]
pub(crate) struct TxPolicy {
    requests: HashMap<Identity, Request>,
    /// Derived accounting, updated only by this owner.
    counts: HashMap<PeerSource, usize>,
    announcements: usize,
}

impl TxPolicy {
    fn announce(&mut self, announcement: Announcement) {
        let Some(key) = Identity::from_inventory(announcement.item) else {
            return;
        };
        if self.announcements >= MAX_ANNOUNCEMENTS
            || self.counts.get(&announcement.source).copied().unwrap_or(0) >= MAX_PEER_ANNOUNCEMENTS
        {
            return;
        }
        let request = self.requests.entry(key).or_default();
        if request.candidates.len() >= MAX_ALTERNATES
            || request
                .candidates
                .iter()
                .any(|candidate| candidate.source == announcement.source)
        {
            return;
        }
        request.candidates.push(announcement);
        *self.counts.entry(announcement.source).or_default() += 1;
        self.announcements += 1;
    }

    fn forget(&mut self, key: Identity) {
        if let Some(request) = self.requests.remove(&key) {
            for candidate in request.candidates {
                self.decrement(candidate.source);
            }
        }
    }

    fn decrement(&mut self, source: PeerSource) {
        self.announcements = self.announcements.saturating_sub(1);
        if let Some(count) = self.counts.get_mut(&source) {
            *count -= 1;
            if *count == 0 {
                self.counts.remove(&source);
            }
        }
    }

    /// Only the actual owner may release another source's opportunity.
    fn failed(&mut self, key: Identity, source: PeerSource, now: Instant) {
        let Some(request) = self.requests.get_mut(&key) else {
            return;
        };
        if request.owner.is_none_or(|(owner, _)| owner != source) {
            return;
        }
        request.owner = None;
        request
            .candidates
            .retain(|candidate| candidate.source != source);
        for candidate in &mut request.candidates {
            candidate.ready = now;
        }
        let empty = request.candidates.is_empty();
        self.decrement(source);
        if empty {
            self.requests.remove(&key);
        }
    }

    fn disconnected(&mut self, source: PeerSource, now: Instant) {
        let keys: Vec<_> = self
            .requests
            .iter()
            .filter_map(|(key, request)| {
                request
                    .candidates
                    .iter()
                    .any(|candidate| candidate.source == source)
                    .then_some(*key)
            })
            .collect();
        for key in keys {
            let Some(request) = self.requests.get_mut(&key) else {
                continue;
            };
            if request.owner.is_some_and(|(owner, _)| owner == source) {
                self.failed(key, source, now);
            } else {
                request
                    .candidates
                    .retain(|candidate| candidate.source != source);
                let empty = request.candidates.is_empty();
                self.decrement(source);
                if empty {
                    self.requests.remove(&key);
                }
            }
        }
    }

    fn select(&mut self, now: Instant) -> Vec<(Identity, Announcement)> {
        let expired: Vec<_> = self
            .requests
            .iter()
            .filter_map(|(key, request)| {
                request
                    .owner
                    .filter(|(_, deadline)| now >= *deadline)
                    .map(|(source, _)| (*key, source))
            })
            .collect();
        for (key, source) in expired {
            self.failed(key, source, now);
        }
        let mut in_flight: HashMap<PeerSource, usize> = HashMap::new();
        for request in self.requests.values() {
            if let Some((source, _)) = request.owner {
                *in_flight.entry(source).or_default() += 1;
            }
        }
        let mut selected = Vec::new();
        for (key, request) in &mut self.requests {
            if request.owner.is_some() {
                continue;
            }
            let candidate = request
                .candidates
                .iter()
                .filter(|candidate| {
                    candidate.ready <= now
                        && in_flight.get(&candidate.source).copied().unwrap_or(0)
                            < MAX_PEER_IN_FLIGHT
                })
                .min_by_key(|candidate| (!candidate.preferred, candidate.priority))
                .copied();
            if let Some(candidate) = candidate {
                request.owner = Some((candidate.source, now + REQUEST_LIFETIME));
                *in_flight.entry(candidate.source).or_default() += 1;
                selected.push((*key, candidate));
            }
        }
        selected.sort_by_key(|(_, candidate)| candidate.priority);
        selected
    }
}

impl PeerTable {
    /// Retains missing transaction announcements under the current connection.
    /// The mempool check happens before this call, outside policy/table locks.
    pub fn announce_transactions(&self, source: PeerSource, items: &[Inventory]) {
        use bitcoin::secp256k1::rand::{RngCore as _, SeedableRng as _};
        let sessions = self.usable_peers();
        let Some(session) = sessions.iter().find(|peer| peer.lease.is_current(source)) else {
            return;
        };
        if !session.lease.role().relays_transactions() {
            return;
        }
        let now = Instant::now();
        let has_wtxid_source = sessions.iter().any(|peer| {
            peer.lease.role().relays_transactions()
                && peer.info.as_ref().is_some_and(|info| info.wtxid_relay)
        });
        let preferred = !session.lease.is_inbound();
        // Seed outside the policy lock: the generator used inside cannot
        // reseed from the OS during a state transition.
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::from_entropy();
        let mut policy = self.tx_policy.lock();
        let overloaded = policy
            .requests
            .values()
            .filter(|request| request.owner.is_some_and(|(owner, _)| owner == source))
            .count()
            >= MAX_PEER_IN_FLIGHT;
        for item in items {
            let txid_delay = has_wtxid_source && !matches!(item, Inventory::WTx(_));
            let delay = SOURCE_DELAY
                * (u32::from(!preferred) + u32::from(txid_delay) + u32::from(overloaded));
            policy.announce(Announcement {
                source,
                item: *item,
                ready: now + delay,
                preferred,
                priority: rng.next_u64(),
            });
        }
    }

    /// Orphan-parent requests share download ownership and hard limits. They
    /// preserve the existing immediate source retry, independently of inv delays.
    pub(crate) fn request_parent_transactions(
        &self,
        source: PeerSource,
        items: &[Inventory],
    ) -> bool {
        let now = Instant::now();
        let mut policy = self.tx_policy.lock();
        let before = policy.announcements;
        for (index, item) in items.iter().enumerate() {
            policy.announce(Announcement {
                source,
                item: *item,
                ready: now,
                preferred: true,
                priority: u64::try_from(index).unwrap_or(u64::MAX),
            });
        }
        let retained = policy.announcements > before;
        drop(policy);
        self.send_transaction_requests(now);
        retained
    }

    /// Retires both identities only after acceptance or confirmed knowledge.
    pub fn forget_known_transaction(&self, txid: Txid, wtxid: Wtxid) {
        let mut policy = self.tx_policy.lock();
        policy.forget(Identity::Txid(txid.0));
        policy.forget(Identity::Wtxid(wtxid.0));
    }

    /// Completes only the delivering source's response after admission (or
    /// ingress refusal). Alternate witnesses remain available until the
    /// gateway's identity-scoped accepted/orphan/reject state retires them.
    pub fn transaction_response_completed(&self, source: PeerSource, txid: Txid, wtxid: Wtxid) {
        let now = Instant::now();
        let mut policy = self.tx_policy.lock();
        policy.failed(Identity::Txid(txid.0), source, now);
        policy.failed(Identity::Wtxid(wtxid.0), source, now);
    }

    pub(crate) fn transaction_not_found(&self, source: PeerSource, items: &[Inventory]) {
        let now = Instant::now();
        let mut policy = self.tx_policy.lock();
        for item in items {
            if let Some(key) = Identity::from_inventory(*item) {
                policy.failed(key, source, now);
            }
        }
    }

    /// Reconciles connection/known-state changes and queues bounded requests.
    /// Inventory reads and nonblocking sends never hold a table write lock.
    pub fn poll_transaction_requests(&self, inventory: &dyn TxInventory) {
        let now = Instant::now();
        #[cfg(test)]
        tests::before_poll_lock();
        let keys = {
            let mut policy = self.tx_policy.lock();
            // Lock order is policy -> peer table. A fresh announcement cannot
            // appear between this census and its reconciliation.
            let live: HashSet<_> = self
                .usable_peers()
                .iter()
                .map(|peer| peer.lease.source(peer.addr))
                .collect();
            let gone: Vec<_> = policy
                .counts
                .keys()
                .filter(|source| !live.contains(*source))
                .copied()
                .collect();
            for source in gone {
                policy.disconnected(source, now);
            }
            policy.requests.keys().copied().collect::<Vec<_>>()
        };
        let known: Vec<_> = keys
            .into_iter()
            .filter(|key| key.known(inventory))
            .collect();
        {
            let mut policy = self.tx_policy.lock();
            for key in known {
                policy.forget(key);
            }
        }
        self.send_transaction_requests(now);
    }

    fn send_transaction_requests(&self, now: Instant) {
        // PeerTable::send is a concrete nonblocking channel enqueue: no
        // socket I/O, user callback or mempool lock. Hold policy authority
        // through selection and enqueue so notfound/reannouncement cannot
        // replace a reservation between capture and commit (ABA).
        let mut policy = self.tx_policy.lock();
        let selected = policy.select(now);
        let mut batches: HashMap<PeerSource, Vec<(Identity, Inventory)>> = HashMap::new();
        for (key, announcement) in selected {
            batches
                .entry(announcement.source)
                .or_default()
                .push((key, announcement.item));
        }
        for (source, batch) in batches {
            // Keep the owner reservation stable through the nonblocking enqueue.
            // PeerTable mutation never takes tx_policy while holding entries.
            let items = batch.iter().map(|(_, item)| *item).collect();
            if self.send(source, Message::GetData(items)).is_err() {
                for (key, _) in batch {
                    policy.failed(key, source, now);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static POLL_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    }

    pub(super) fn before_poll_lock() {
        POLL_HOOK.with(|hook| {
            let operation = hook.borrow_mut().take();
            if let Some(operation) = operation {
                operation();
            }
        });
    }

    fn source(port: u16) -> PeerSource {
        PeerSource::for_test(([127, 0, 0, 1], port).into())
    }
    fn item(n: u32) -> Inventory {
        let mut hash = [0; 32];
        hash[..4].copy_from_slice(&n.to_le_bytes());
        Inventory::WTx(bitcoin::Wtxid::from_byte_array(hash))
    }
    fn announce(policy: &mut TxPolicy, source: PeerSource, n: u32, now: Instant, preferred: bool) {
        policy.announce(Announcement {
            source,
            item: item(n),
            ready: now,
            preferred,
            priority: u64::from(n),
        });
    }

    #[test]
    fn single_owner_and_matching_notfound_fall_back_immediately() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let mut policy = TxPolicy::default();
        announce(&mut policy, a, 1, now, true);
        announce(&mut policy, b, 1, now + SOURCE_DELAY, false);
        let selected = policy.select(now);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1.source, a);
        let key = selected[0].0;
        policy.failed(key, b, now);
        assert!(policy.select(now).is_empty());
        policy.failed(key, a, now);
        assert_eq!(policy.select(now)[0].1.source, b);
        assert_eq!(policy.announcements, 1);
    }

    #[test]
    fn disconnect_and_expiry_release_only_the_owner_and_all_its_state() {
        for expired in [false, true] {
            let now = Instant::now();
            let (a, b) = (source(1), source(2));
            let mut policy = TxPolicy::default();
            announce(&mut policy, a, 1, now, true);
            announce(&mut policy, b, 1, now, false);
            announce(&mut policy, a, 2, now, true);
            assert_eq!(policy.select(now).len(), 2);
            if !expired {
                policy.disconnected(a, now);
            }
            let selected = policy.select(if expired { now + REQUEST_LIFETIME } else { now });
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].1.source, b);
            assert!(!policy.counts.contains_key(&a));
            assert_eq!(policy.announcements, 1);
        }
    }

    #[test]
    fn bounds_and_preference_are_resource_policy_not_punishment() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let mut policy = TxPolicy::default();
        for n in 0..6_000 {
            announce(&mut policy, a, n, now, true);
        }
        assert_eq!(policy.announcements, MAX_PEER_ANNOUNCEMENTS);
        assert_eq!(policy.select(now).len(), MAX_PEER_IN_FLIGHT);
        assert!(policy.select(now).is_empty());
        announce(&mut policy, b, 5_001, now, false);
        assert_eq!(policy.select(now)[0].1.source, b);
        let mut policy = TxPolicy::default();
        announce(&mut policy, a, 1, now, false);
        announce(&mut policy, b, 1, now, true);
        assert_eq!(policy.select(now)[0].1.source, b);
    }

    #[test]
    fn known_body_retires_both_identities_without_guessing_unknown_pairs() {
        let now = Instant::now();
        let a = source(1);
        let mut policy = TxPolicy::default();
        announce(&mut policy, a, 1, now, true);
        let hash = Hash256::from_le_bytes(&[9; 32]);
        policy.announce(Announcement {
            source: a,
            item: Inventory::Transaction(bitcoin::Txid::from_byte_array(hash.to_le_bytes())),
            ready: now,
            preferred: true,
            priority: 0,
        });
        assert_eq!(policy.select(now).len(), 2);
        policy.forget(Identity::Txid(hash));
        policy.forget(Identity::from_inventory(item(1)).unwrap_or(Identity::Txid(hash)));
        assert!(policy.requests.is_empty());
        assert!(policy.counts.is_empty());
        assert_eq!(policy.announcements, 0);
    }
    #[test]
    fn alternates_global_cap_and_delay_are_enforced() {
        let now = Instant::now();
        let mut policy = TxPolicy::default();
        for port in 1..=12 {
            announce(&mut policy, source(port), 1, now + SOURCE_DELAY, false);
        }
        assert_eq!(policy.announcements, MAX_ALTERNATES);
        assert!(policy.select(now).is_empty());
        assert_eq!(policy.select(now + SOURCE_DELAY).len(), 1);
        // The global limit is independent of the per-peer and per-identity caps.
        policy = TxPolicy::default();
        for port in 1..=21 {
            let peer = source(port);
            for n in 0..5_000 {
                announce(&mut policy, peer, u32::from(port) * 5_000 + n, now, true);
            }
        }
        assert_eq!(policy.announcements, MAX_ANNOUNCEMENTS);
        assert_eq!(policy.requests.len(), MAX_ANNOUNCEMENTS);
    }

    #[test]
    fn obsolete_connection_cannot_release_a_replacement() {
        let now = Instant::now();
        let (old, current) = (source(1), source(1));
        let mut policy = TxPolicy::default();
        announce(&mut policy, current, 1, now, true);
        let selected = policy.select(now);
        policy.failed(selected[0].0, old, now);
        policy.disconnected(old, now);
        assert!(policy.select(now).is_empty());
        assert_eq!(
            policy.requests[&selected[0].0].owner.map(|(peer, _)| peer),
            Some(current)
        );
    }
    #[test]
    fn known_state_and_external_arrival_retire_requests_before_another_send() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct InventoryView(AtomicBool);
        impl TxInventory for InventoryView {
            fn have_tx(&self, _: Hash256, _: bool) -> bool {
                self.0.load(Ordering::Relaxed)
            }
            fn get_tx(&self, _: Txid) -> Option<bitcoin_rs_primitives::Tx> {
                None
            }
            fn get_tx_by_wtxid(&self, _: Wtxid) -> Option<bitcoin_rs_primitives::Tx> {
                None
            }
        }
        let table = Arc::new(PeerTable::new());
        let (sender, receiver) = crossbeam_channel::bounded(4);
        let lease = crate::PeerLease::new(sender);
        let addr = ([127, 0, 0, 1], 8333).into();
        table.register(addr, lease.clone());
        let version = crate::handshake::version_message(
            1,
            0,
            crate::PeerRole::FullRelay,
            bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
        );
        table.publish_info(
            addr,
            &lease,
            crate::PeerInfo::outbound_from_version(
                addr,
                addr,
                &version,
                0,
                0,
                Arc::new(crate::PeerCounters::default()),
            ),
        );
        let inventory = InventoryView(AtomicBool::new(false));
        table.announce_transactions(lease.source(addr), &[item(1)]);
        table.poll_transaction_requests(&inventory);
        assert!(matches!(receiver.try_recv(), Ok(Message::GetData(_))));
        inventory.0.store(true, Ordering::Relaxed);
        table.poll_transaction_requests(&inventory);
        assert!(table.tx_policy.lock().requests.is_empty());
        assert!(receiver.try_recv().is_err());
        inventory.0.store(false, Ordering::Relaxed);
        table.announce_transactions(lease.source(addr), &[item(1)]);
        let Some(Identity::Wtxid(hash)) = Identity::from_inventory(item(1)) else {
            panic!("wtx fixture")
        };
        table.forget_known_transaction(Txid(hash), Wtxid(hash));
        table.poll_transaction_requests(&inventory);
        assert!(receiver.try_recv().is_err());
        assert_eq!(table.tx_policy.lock().announcements, 0);
        let pending_table = Arc::clone(&table);
        let (new_sender, new_receiver) = crossbeam_channel::bounded(4);
        let new_lease = crate::PeerLease::new(new_sender);
        let new_addr = ([127, 0, 0, 1], 8334).into();
        POLL_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                // A new ready connection and its announcement both appear
                // after poll entered but before policy reconciliation.
                pending_table.register(new_addr, new_lease.clone());
                pending_table.publish_info(
                    new_addr,
                    &new_lease,
                    crate::PeerInfo::outbound_from_version(
                        new_addr,
                        new_addr,
                        &version,
                        0,
                        0,
                        Arc::new(crate::PeerCounters::default()),
                    ),
                );
                pending_table.announce_transactions(new_lease.source(new_addr), &[item(2)]);
            }));
        });
        table.poll_transaction_requests(&inventory);
        assert_eq!(table.tx_policy.lock().announcements, 1);
        // The new announcement's Instant is later than the first poll's
        // captured now, so it becomes eligible on the following poll.
        table.poll_transaction_requests(&inventory);
        assert!(
            matches!(new_receiver.try_recv(), Ok(Message::GetData(items)) if items == vec![item(2)])
        );
    }
}
