//! Connection-bound transaction download policy. Mempool remains the authority
//! for accepted, orphan and rejected bodies; this owner retains identities only.
//!
//! Core v31.1 node/txdownloadman_impl.cpp and p2p_tx_download.py define the
//! reference cases. Different raw txid/wtxid hashes remain independent until
//! a body supplies the mapping. Identical bytes share request ownership only;
//! gateway knowledge and rejection remain scoped by inventory kind.

mod relay;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use hashbrown::{HashMap, HashSet};

use crate::{Message, PeerSource, PeerTable, TxInventory};
use bitcoin_rs_primitives::{Hash256, Txid, Wtxid};

pub(crate) const MAX_PEER_ANNOUNCEMENTS: usize = 5_000;
pub(crate) const MAX_PEER_IN_FLIGHT: usize = 100;
/// Extra global and per-raw-hash bounds, independent of connection count.
const MAX_ANNOUNCEMENTS: usize = 100_000;
const MAX_ALTERNATES: usize = 8;
const REQUEST_LIFETIME: Duration = Duration::from_secs(60);
const SOURCE_DELAY: Duration = Duration::from_secs(2);
const REQUEST_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_KNOWN_CHECKS: usize = 1_024;
const MAX_REQUEST_CHECKS: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

    fn hash_bytes(self) -> Hash256 {
        match self {
            Self::Txid(hash) | Self::Wtxid(hash) => hash,
        }
    }

    /// Same download hash, different inventory kind. This shares request
    /// ownership only; known/reject queries remain typed.
    fn same_hash_other_kind(self) -> Self {
        match self {
            Self::Txid(hash) => Self::Wtxid(hash),
            Self::Wtxid(hash) => Self::Txid(hash),
        }
    }

    fn known(self, inventory: &dyn TxInventory) -> bool {
        match self {
            Self::Txid(hash) => inventory.have_tx(hash, false),
            Self::Wtxid(hash) => inventory.have_tx(hash, true),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Announcement {
    source: PeerSource,
    item: Inventory,
    ready: Instant,
    preferred: bool,
    priority: u64,
}

type EvictionKey = (u64, Identity, u64);

fn eviction_key(key: Identity, candidate: &Announcement) -> EvictionKey {
    (
        candidate.priority,
        key,
        candidate.source.connection_id().get(),
    )
}

#[derive(Debug, Default)]
struct Request {
    candidates: Vec<Announcement>,
    owner: Option<(PeerSource, Instant)>,
}

#[derive(Debug, Default)]
pub(crate) struct TxPolicy {
    requests: BTreeMap<Identity, Request>,
    next_poll: Option<Instant>,
    known_cursor: Option<Identity>,
    ready_cursor: Option<Identity>,
    /// Derived accounting, updated only by this owner.
    counts: HashMap<PeerSource, usize>,
    announcements: usize,
    /// References to exactly the non-preferred candidates that are not owners.
    /// Requests and candidate vectors remain the sole announcement authority.
    evictable: BTreeSet<EvictionKey>,
    relay: HashMap<PeerSource, relay::RelayPeer>,
    /// Shared by remote network class and actual local bind endpoint, never
    /// remote host or connection. Retained across disconnects for this owner's
    /// lifetime so reconnecting cannot redraw an unexpired inbound clock.
    inbound_inv: HashMap<relay::InboundClockKey, Instant>,
}

impl TxPolicy {
    fn announce(&mut self, announcement: Announcement) -> bool {
        let Some(key) = Identity::from_inventory(announcement.item) else {
            return false;
        };
        let kinds = [key, key.same_hash_other_kind()];
        let mut raw_count = 0;
        for kind in kinds {
            if let Some(request) = self.requests.get(&kind) {
                if request
                    .candidates
                    .iter()
                    .any(|candidate| candidate.source == announcement.source)
                {
                    return false;
                }
                raw_count += request.candidates.len();
            }
        }
        if self.counts.get(&announcement.source).copied().unwrap_or(0) >= MAX_PEER_ANNOUNCEMENTS {
            return false;
        }
        if raw_count >= MAX_ALTERNATES || self.announcements >= MAX_ANNOUNCEMENTS {
            if !announcement.preferred {
                return false;
            }
            // A full hash must free its own slot. The same removal also frees
            // the global slot when both limits are reached; never evict twice.
            let victim = if raw_count >= MAX_ALTERNATES {
                kinds
                    .into_iter()
                    .filter_map(|kind| self.requests.get(&kind).map(|request| (kind, request)))
                    .flat_map(|(kind, request)| {
                        request
                            .candidates
                            .iter()
                            .filter(move |candidate| {
                                !candidate.preferred
                                    && request
                                        .owner
                                        .is_none_or(|(owner, _)| owner != candidate.source)
                            })
                            .map(move |candidate| eviction_key(kind, candidate))
                    })
                    .max()
            } else {
                self.evictable.last().copied()
            };
            let Some(victim) = victim else {
                return false;
            };
            let Some(source) = self.eviction_source(victim) else {
                return false;
            };
            // All cap, identity, ownership and accounting checks precede removal.
            if !self.remove_candidate(victim.1, source) {
                return false;
            }
        }
        if !announcement.preferred {
            self.evictable.insert(eviction_key(key, &announcement));
        }
        self.requests
            .entry(key)
            .or_default()
            .candidates
            .push(announcement);
        *self.counts.entry(announcement.source).or_default() += 1;
        self.announcements += 1;
        true
    }

    /// Recheck one derived reference against at most eight authoritative rows.
    /// An inconsistent projection refuses admission; it never scans or repairs
    /// other entries opportunistically and cannot authorize owner eviction.
    fn eviction_source(&self, reference: EvictionKey) -> Option<PeerSource> {
        if !self.evictable.contains(&reference) || self.announcements == 0 {
            return None;
        }
        let request = self.requests.get(&reference.1)?;
        let candidate = request.candidates.iter().find(|candidate| {
            !candidate.preferred
                && eviction_key(reference.1, candidate) == reference
                && request
                    .owner
                    .is_none_or(|(owner, _)| owner != candidate.source)
        })?;
        self.counts
            .get(&candidate.source)
            .is_some_and(|count| *count > 0)
            .then_some(candidate.source)
    }

    /// Orphan admission may expedite an existing source without allocating
    /// another announcement or changing the current in-flight owner. Ordinary
    /// duplicate inv still passes through `announce` and cannot bypass delays.
    fn request_parent(&mut self, announcement: Announcement) -> bool {
        let Some(key) = Identity::from_inventory(announcement.item) else {
            return false;
        };
        for kind in [key, key.same_hash_other_kind()] {
            if let Some(candidate) = self.requests.get_mut(&kind).and_then(|request| {
                request
                    .candidates
                    .iter_mut()
                    .find(|candidate| candidate.source == announcement.source)
            }) {
                self.evictable.remove(&eviction_key(kind, candidate));
                candidate.ready = candidate.ready.min(announcement.ready);
                candidate.preferred = true;
                candidate.priority = candidate.priority.min(announcement.priority);
                // Upgrade TX witness serialization within its typed identity.
                // An existing WTX hint retains its original wire identity.
                if kind == key {
                    candidate.item = announcement.item;
                }
                return true;
            }
        }
        self.announce(announcement)
    }

    fn forget(&mut self, key: Identity) {
        if let Some(request) = self.requests.remove(&key) {
            for candidate in request.candidates {
                self.untrack_candidate(key, candidate);
            }
        }
    }

    /// Remove an unowned candidate without failure/expedition side effects.
    fn remove_candidate(&mut self, key: Identity, source: PeerSource) -> bool {
        let Some(request) = self.requests.get_mut(&key) else {
            return false;
        };
        if request.owner.is_some_and(|(owner, _)| owner == source) {
            return false;
        }
        let Some(index) = request
            .candidates
            .iter()
            .position(|candidate| candidate.source == source)
        else {
            return false;
        };
        let candidate = request.candidates.remove(index);
        let empty = request.candidates.is_empty();
        self.untrack_candidate(key, candidate);
        if empty {
            self.requests.remove(&key);
        }
        true
    }

    fn untrack_candidate(&mut self, key: Identity, candidate: Announcement) {
        self.evictable.remove(&eviction_key(key, &candidate));
        self.announcements = self.announcements.saturating_sub(1);
        if let Some(count) = self.counts.get_mut(&candidate.source) {
            *count -= 1;
            if *count == 0 {
                self.counts.remove(&candidate.source);
            }
        }
    }

    /// Only the actual owner may release another source's opportunity.
    fn failed(&mut self, key: Identity, source: PeerSource, now: Instant) -> bool {
        if self
            .requests
            .get(&key)
            .is_none_or(|request| request.owner.is_none_or(|(owner, _)| owner != source))
        {
            return false;
        }
        // Core's ByPeer/ByTxHash group byte-identical TX/WTX announcements
        // together. Retire only this failed source and expedite other sources,
        // preserving typed known/reject state and unrelated raw hashes.
        for kind in [key, key.same_hash_other_kind()] {
            if let Some(request) = self.requests.get_mut(&kind)
                && request.owner.is_some_and(|(owner, _)| owner == source)
            {
                request.owner = None;
            }
            self.remove_candidate(kind, source);
            if let Some(request) = self.requests.get_mut(&kind) {
                for candidate in &mut request.candidates {
                    candidate.ready = now;
                }
            }
        }
        true
    }

    fn disconnected(&mut self, source: PeerSource, now: Instant) -> Vec<Identity> {
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
        for &key in &keys {
            let Some(request) = self.requests.get_mut(&key) else {
                continue;
            };
            if request.owner.is_some_and(|(owner, _)| owner == source) {
                self.failed(key, source, now);
            } else {
                self.remove_candidate(key, source);
            }
        }
        keys
    }

    fn in_flight(&self) -> (HashMap<PeerSource, usize>, HashSet<Hash256>) {
        let mut counts = HashMap::new();
        let mut hashes = HashSet::new();
        for (key, request) in &self.requests {
            if let Some((source, _)) = request.owner {
                *counts.entry(source).or_default() += 1;
                hashes.insert(key.hash_bytes());
            }
        }
        (counts, hashes)
    }

    fn ready_for_hash(
        &self,
        key: Identity,
        now: Instant,
        in_flight: &HashMap<PeerSource, usize>,
    ) -> Option<(Identity, Announcement)> {
        [key, key.same_hash_other_kind()]
            .into_iter()
            .filter_map(|kind| {
                let request = self.requests.get(&kind)?;
                if request.owner.is_some() {
                    return None;
                }
                ready_candidate(request, now, in_flight).map(|candidate| (kind, candidate))
            })
            .min_by_key(|(kind, candidate)| (!candidate.preferred, candidate.priority, *kind))
    }

    /// Plan bounded inventory checks without reserving an unsent request.
    fn plan(&mut self, now: Instant, keys: Option<&[Identity]>) -> Vec<(Identity, Announcement)> {
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
        let (mut in_flight, mut owned_hashes) = self.in_flight();
        let mut selected = Vec::new();
        let mut last_scanned = None;
        let mut consider = |key: Identity| {
            last_scanned = Some(key);
            if !owned_hashes.contains(&key.hash_bytes()) {
                if let Some((kind, candidate)) = self.ready_for_hash(key, now, &in_flight) {
                    *in_flight.entry(candidate.source).or_default() += 1;
                    owned_hashes.insert(key.hash_bytes());
                    selected.push((kind, candidate));
                }
            }
            selected.len() < MAX_REQUEST_CHECKS
        };
        if let Some(keys) = keys {
            for key in keys {
                if !consider(*key) {
                    break;
                }
            }
        } else {
            use std::ops::Bound::{Excluded, Unbounded};
            let mut full = false;
            for (key, _) in self
                .requests
                .range((self.ready_cursor.map_or(Unbounded, Excluded), Unbounded))
            {
                if !consider(*key) {
                    full = true;
                    break;
                }
            }
            if let Some(cursor) = self.ready_cursor {
                if !full {
                    for (key, _) in self.requests.range(..=cursor) {
                        if !consider(*key) {
                            break;
                        }
                    }
                }
            }
            self.ready_cursor = last_scanned;
        }
        selected.sort_by_key(|(_, candidate)| candidate.priority);
        selected
    }

    /// Recheck the plan after unlocked inventory reads, then reserve only the
    /// unchanged eligible candidates. The caller holds this owner through send.
    fn claim(
        &mut self,
        now: Instant,
        checked: &[(Identity, Announcement)],
    ) -> Vec<(Identity, Announcement)> {
        let (mut in_flight, mut owned_hashes) = self.in_flight();
        let mut selected = Vec::new();
        for &(key, candidate) in checked {
            if owned_hashes.contains(&key.hash_bytes()) {
                continue;
            }
            if self.ready_for_hash(key, now, &in_flight) == Some((key, candidate)) {
                let Some(request) = self.requests.get_mut(&key) else {
                    continue;
                };
                self.evictable.remove(&eviction_key(key, &candidate));
                request.owner = Some((candidate.source, now + REQUEST_LIFETIME));
                *in_flight.entry(candidate.source).or_default() += 1;
                owned_hashes.insert(key.hash_bytes());
                selected.push((key, candidate));
            }
        }
        selected
    }

    /// Ordered owner keys provide a resumable bounded sweep. The derived
    /// admission index is not used here; deletions never invalidate the cursor.
    fn known_batch(&mut self) -> Vec<Identity> {
        use std::ops::Bound::{Excluded, Unbounded};
        let mut keys: Vec<_> = if let Some(cursor) = self.known_cursor {
            self.requests
                .range((Excluded(cursor), Unbounded))
                .take(MAX_KNOWN_CHECKS)
                .map(|(key, _)| *key)
                .collect()
        } else {
            self.requests
                .keys()
                .take(MAX_KNOWN_CHECKS)
                .copied()
                .collect()
        };
        if let Some(cursor) = self.known_cursor {
            let remaining = MAX_KNOWN_CHECKS - keys.len();
            keys.extend(
                self.requests
                    .range(..=cursor)
                    .take(remaining)
                    .map(|(key, _)| *key),
            );
        }
        self.known_cursor = keys.last().copied();
        keys
    }
}

fn ready_candidate(
    request: &Request,
    now: Instant,
    in_flight: &HashMap<PeerSource, usize>,
) -> Option<Announcement> {
    request
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.ready <= now
                && in_flight.get(&candidate.source).copied().unwrap_or(0) < MAX_PEER_IN_FLIGHT
        })
        .min_by_key(|candidate| (!candidate.preferred, candidate.priority))
        .copied()
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
        let mut retained = false;
        for (index, item) in items.iter().enumerate() {
            retained |= policy.request_parent(Announcement {
                source,
                item: *item,
                ready: now,
                preferred: true,
                priority: u64::try_from(index).unwrap_or(u64::MAX),
            });
        }
        drop(policy);
        let keys: Vec<_> = items
            .iter()
            .copied()
            .filter_map(Identity::from_inventory)
            .collect();
        self.send_transaction_requests(now, None, Some(&keys), Instant::now);
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

    pub(crate) fn transaction_not_found(
        &self,
        source: PeerSource,
        items: &[Inventory],
        inventory: &dyn TxInventory,
    ) {
        let now = Instant::now();
        let keys = {
            let mut policy = self.tx_policy.lock();
            items
                .iter()
                .copied()
                .filter_map(Identity::from_inventory)
                .filter(|key| policy.failed(*key, source, now))
                .collect::<Vec<_>>()
        };
        if !keys.is_empty() {
            self.send_transaction_requests(now, Some(inventory), Some(&keys), Instant::now);
        }
    }

    /// Promptly schedules alternatives for the two identities supplied by an
    /// admission result. Known/rejected identity checks remain gateway-owned.
    pub fn poll_transaction_response(&self, inventory: &dyn TxInventory, txid: Txid, wtxid: Wtxid) {
        self.send_transaction_requests(
            Instant::now(),
            Some(inventory),
            Some(&[Identity::Txid(txid.0), Identity::Wtxid(wtxid.0)]),
            Instant::now,
        );
    }

    pub(crate) fn transaction_peer_disconnected(
        &self,
        source: PeerSource,
        inventory: &dyn TxInventory,
    ) {
        let now = Instant::now();
        let keys = self.tx_policy.lock().disconnected(source, now);
        if !keys.is_empty() {
            self.send_transaction_requests(now, Some(inventory), Some(&keys), Instant::now);
        }
    }

    /// Paced, bounded known-state maintenance. Relevant events have separate
    /// scoped paths, so this cadence never delays an owner's failure fallback.
    pub fn poll_transaction_requests(&self, inventory: &dyn TxInventory) {
        self.poll_transaction_requests_at(inventory, Instant::now());
    }

    fn poll_transaction_requests_at(&self, inventory: &dyn TxInventory, now: Instant) {
        #[cfg(test)]
        tests::before_poll_lock();
        let keys = {
            let mut policy = self.tx_policy.lock();
            if policy.next_poll.is_some_and(|next| now < next) {
                return;
            }
            policy.next_poll = Some(now + REQUEST_POLL_INTERVAL);
            // Lock order is policy -> peer table. Fresh announcements cannot
            // appear between this live census and its reconciliation.
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
            policy.known_batch()
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
        self.send_transaction_requests(now, Some(inventory), None, Instant::now);
    }

    fn send_transaction_requests(
        &self,
        now: Instant,
        inventory: Option<&dyn TxInventory>,
        keys: Option<&[Identity]>,
        commit_clock: impl FnOnce() -> Instant,
    ) {
        let planned = self.tx_policy.lock().plan(now, keys);
        // Never reserve ownership around user/gateway callbacks. A premature
        // notfound cannot release a planned-but-unsent request. Every identity
        // about to be sent is checked even when its background sweep is not due.
        let (known, checked): (Vec<_>, Vec<_>) = planned
            .into_iter()
            .partition(|(key, _)| inventory.is_some_and(|inventory| key.known(inventory)));
        let mut policy = self.tx_policy.lock();
        for (key, _) in known {
            policy.forget(key);
        }
        // Revalidation, reservation, grouping and concrete nonblocking enqueue
        // are one policy critical section: no unlocked owner/reservation ABA.
        // Inventory callbacks and lock contention must not consume the peer's
        // response lifetime. Sample at commit, preserving injected event time.
        let committed = now.max(commit_clock());
        let selected = policy.claim(committed, &checked);
        let mut batches: HashMap<PeerSource, Vec<(Identity, Inventory)>> = HashMap::new();
        for (key, announcement) in selected {
            batches
                .entry(announcement.source)
                .or_default()
                .push((key, announcement.item));
        }
        for (source, batch) in batches {
            let items = batch.iter().map(|(_, item)| *item).collect();
            if self.send(source, Message::GetData(items)).is_err() {
                for (key, _) in batch {
                    policy.failed(key, source, committed);
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "transaction owner test assertions")]
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

    pub(super) fn select(policy: &mut TxPolicy, now: Instant) -> Vec<(Identity, Announcement)> {
        let planned = policy.plan(now, None);
        policy.claim(now, &planned)
    }

    pub(super) fn source(port: u16) -> PeerSource {
        PeerSource::for_test(([127, 0, 0, 1], port).into())
    }
    pub(super) fn item(n: u32) -> Inventory {
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
    fn preferred_source_replaces_one_weak_entry_at_the_real_global_cap() {
        let now = Instant::now();
        let mut policy = TxPolicy::default();
        let mut last_source = source(1);
        for port in 1..=20 {
            let peer = source(port);
            last_source = peer;
            for n in 0..5_000 {
                announce(&mut policy, peer, u32::from(port) * 5_000 + n, now, false);
            }
        }
        assert_eq!(policy.announcements, MAX_ANNOUNCEMENTS);
        let preferred = source(21);
        announce(&mut policy, preferred, 200_000, now, true);
        let key = Identity::from_inventory(item(200_000)).unwrap();
        assert!(
            policy.requests.contains_key(&key),
            "preferred arrival must displace one removable weaker candidate"
        );
        assert_eq!(policy.announcements, MAX_ANNOUNCEMENTS);
        assert_eq!(policy.counts[&preferred], 1);
        assert_eq!(policy.counts[&last_source], MAX_PEER_ANNOUNCEMENTS - 1);
        assert!(
            !policy
                .requests
                .contains_key(&Identity::from_inventory(item(104_999)).unwrap())
        );
        let planned = policy.plan(now, Some(&[key]));
        assert_eq!(policy.claim(now, &planned)[0].1.source, preferred);
    }

    #[test]
    fn preferred_source_enters_a_full_shared_hash_without_preempting_its_owner() {
        let now = Instant::now();
        let hash = [42; 32];
        let tx = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(hash));
        let wtx = Inventory::WTx(bitcoin::Wtxid::from_byte_array(hash));
        let mut policy = TxPolicy::default();
        let mut sources = Vec::new();
        for n in 0..8 {
            let peer = source(n + 1);
            sources.push(peer);
            policy.announce(Announcement {
                source: peer,
                item: if n % 2 == 0 { tx } else { wtx },
                ready: now,
                preferred: false,
                priority: u64::from(n),
            });
        }
        let owned = select(&mut policy, now)[0];
        let owner_before = policy.requests[&owned.0].owner;
        let preferred = source(9);
        policy.announce(Announcement {
            source: preferred,
            item: wtx,
            ready: now + SOURCE_DELAY,
            preferred: true,
            priority: 99,
        });
        assert!(
            policy.requests.values().any(|request| request
                .candidates
                .iter()
                .any(|candidate| candidate.source == preferred)),
            "preferred arrival must replace a same-hash weak alternate"
        );
        assert_eq!(policy.announcements, MAX_ALTERNATES);
        assert_eq!(policy.requests[&owned.0].owner, owner_before);
        assert!(!policy.counts.contains_key(&sources[7]));
        assert_eq!(select(&mut policy, now), []);
        assert!(policy.failed(owned.0, owned.1.source, now));
        let selected = select(&mut policy, now);
        assert_eq!(selected[0].1.source, preferred);
        assert_eq!(selected[0].1.item, wtx);
    }

    #[test]
    fn single_owner_and_matching_notfound_fall_back_immediately() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let mut policy = TxPolicy::default();
        announce(&mut policy, a, 1, now, true);
        announce(&mut policy, b, 1, now + SOURCE_DELAY, false);
        let selected = select(&mut policy, now);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1.source, a);
        let key = selected[0].0;
        policy.failed(key, b, now);
        assert_eq!(select(&mut policy, now), []);
        policy.failed(key, a, now);
        assert_eq!(select(&mut policy, now)[0].1.source, b);
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
            assert_eq!(select(&mut policy, now).len(), 2);
            if !expired {
                policy.disconnected(a, now);
            }
            let selected = select(
                &mut policy,
                if expired { now + REQUEST_LIFETIME } else { now },
            );
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
        assert_eq!(select(&mut policy, now).len(), MAX_PEER_IN_FLIGHT);
        assert_eq!(select(&mut policy, now), []);
        announce(&mut policy, b, 5_001, now, false);
        assert_eq!(select(&mut policy, now)[0].1.source, b);
        let mut policy = TxPolicy::default();
        announce(&mut policy, a, 1, now, false);
        announce(&mut policy, b, 1, now, true);
        assert_eq!(select(&mut policy, now)[0].1.source, b);
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
        assert_eq!(select(&mut policy, now).len(), 2);
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
        assert_eq!(select(&mut policy, now), []);
        assert_eq!(select(&mut policy, now + SOURCE_DELAY).len(), 1);
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
        let selected = select(&mut policy, now);
        policy.failed(selected[0].0, old, now);
        policy.disconnected(old, now);
        assert_eq!(select(&mut policy, now), []);
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
        let mut poll_now = Instant::now() + Duration::from_secs(1);
        let inventory = InventoryView(AtomicBool::new(false));
        table.announce_transactions(lease.source(addr), &[item(1)]);
        table.poll_transaction_requests_at(&inventory, poll_now);
        assert!(matches!(receiver.try_recv(), Ok(Message::GetData(_))));
        inventory.0.store(true, Ordering::Relaxed);
        poll_now += REQUEST_POLL_INTERVAL;
        table.poll_transaction_requests_at(&inventory, poll_now);
        assert!(table.tx_policy.lock().requests.is_empty());
        assert!(receiver.try_recv().is_err());
        inventory.0.store(false, Ordering::Relaxed);
        table.announce_transactions(lease.source(addr), &[item(1)]);
        let Some(Identity::Wtxid(hash)) = Identity::from_inventory(item(1)) else {
            panic!("wtx fixture")
        };
        table.forget_known_transaction(Txid(hash), Wtxid(hash));
        poll_now += REQUEST_POLL_INTERVAL;
        table.poll_transaction_requests_at(&inventory, poll_now);
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
        poll_now += REQUEST_POLL_INTERVAL;
        table.poll_transaction_requests_at(&inventory, poll_now);
        assert_eq!(table.tx_policy.lock().announcements, 1);
        // A following paced poll cannot duplicate the newly registered source's request.
        poll_now += REQUEST_POLL_INTERVAL;
        table.poll_transaction_requests_at(&inventory, poll_now);
        assert!(
            matches!(new_receiver.try_recv(), Ok(Message::GetData(items)) if items == vec![item(2)])
        );
    }
    pub(super) fn registered_source(
        table: &PeerTable,
        port: u16,
    ) -> (PeerSource, crossbeam_channel::Receiver<Message>) {
        let (sender, receiver) = crossbeam_channel::bounded(32);
        let lease = crate::PeerLease::new(sender);
        let addr = ([127, 0, 0, 1], port).into();
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
                std::sync::Arc::new(crate::PeerCounters::default()),
            ),
        );
        (lease.source(addr), receiver)
    }

    #[derive(Default)]
    pub(super) struct CountingInventory {
        checked: std::sync::Mutex<Vec<Identity>>,
        known: std::sync::Mutex<HashSet<Identity>>,
    }
    impl TxInventory for CountingInventory {
        fn have_tx(&self, hash: Hash256, is_wtxid: bool) -> bool {
            let key = if is_wtxid {
                Identity::Wtxid(hash)
            } else {
                Identity::Txid(hash)
            };
            self.checked
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(key);
            self.known
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&key)
        }
        fn get_tx(&self, _: Txid) -> Option<bitcoin_rs_primitives::Tx> {
            None
        }
        fn get_tx_by_wtxid(&self, _: Wtxid) -> Option<bitcoin_rs_primitives::Tx> {
            None
        }
    }

    #[test]
    fn only_orphan_parent_requests_expedite_a_retained_announcement() {
        let now = Instant::now();
        let peer = source(1);
        let mut policy = TxPolicy::default();
        let txid = bitcoin::Txid::from_byte_array([1; 32]);
        let delayed = Announcement {
            source: peer,
            item: Inventory::Transaction(txid),
            ready: now + SOURCE_DELAY,
            preferred: false,
            priority: 9,
        };
        policy.announce(delayed);
        policy.announce(Announcement {
            ready: now,
            ..delayed
        });
        assert_eq!(
            select(&mut policy, now).len(),
            0,
            "duplicate inv cannot bypass a delay"
        );
        assert!(policy.request_parent(Announcement {
            item: Inventory::WitnessTransaction(txid),
            ready: now,
            preferred: true,
            priority: 0,
            ..delayed
        }));
        assert_eq!(policy.announcements, 1);
        assert_eq!(policy.counts[&peer], 1);
        let selected = select(&mut policy, now);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1.item, Inventory::WitnessTransaction(txid));
        assert_eq!(selected[0].1.ready, now);
        assert!(policy.request_parent(Announcement {
            ready: now,
            ..delayed
        }));
        assert_eq!(
            select(&mut policy, now).len(),
            0,
            "expedition cannot create a second in-flight owner"
        );
    }

    #[test]
    fn known_sweep_has_a_clock_budget_and_visits_every_retained_identity() {
        let now = Instant::now();
        let table = PeerTable::new();
        let (peer, _receiver) = registered_source(&table, 8333);
        for n in 0..3_000 {
            announce(
                &mut table.tx_policy.lock(),
                peer,
                n,
                now + SOURCE_DELAY,
                true,
            );
        }
        let inventory = CountingInventory::default();
        table.poll_transaction_requests_at(&inventory, now);
        assert_eq!(inventory.checked.lock().unwrap().len(), 1_024);
        for _ in 0..100 {
            table.poll_transaction_requests_at(&inventory, now + Duration::from_millis(99));
        }
        assert_eq!(
            inventory.checked.lock().unwrap().len(),
            1_024,
            "early polls do no additional gateway reads"
        );
        table.poll_transaction_requests_at(&inventory, now + Duration::from_millis(100));
        assert_eq!(inventory.checked.lock().unwrap().len(), 2_048);
        table.poll_transaction_requests_at(&inventory, now + Duration::from_millis(200));
        let checks = inventory.checked.lock().unwrap();
        assert_eq!(checks.len(), 3_072);
        assert_eq!(checks.iter().copied().collect::<HashSet<_>>().len(), 3_000);
    }

    #[test]
    fn every_selected_request_is_checked_even_beyond_the_background_cursor() {
        let now = Instant::now();
        let table = PeerTable::new();
        let (peer, receiver) = registered_source(&table, 8333);
        for n in 0..1_025 {
            announce(
                &mut table.tx_policy.lock(),
                peer,
                n,
                now + SOURCE_DELAY,
                true,
            );
        }
        let last = {
            let mut policy = table.tx_policy.lock();
            let last = *policy.requests.keys().next_back().unwrap();
            policy.requests.get_mut(&last).unwrap().candidates[0].ready = now;
            last
        };
        let inventory = CountingInventory::default();
        inventory.known.lock().unwrap().insert(last);
        table.poll_transaction_requests_at(&inventory, now);
        assert_eq!(inventory.checked.lock().unwrap().len(), 1_025);
        assert!(
            receiver.try_recv().is_err(),
            "known state suppresses sends before its sweep turn"
        );
        assert!(!table.tx_policy.lock().requests.contains_key(&last));
    }

    #[test]
    fn background_and_ready_checks_are_both_bounded_per_tick() {
        let now = Instant::now();
        let table = PeerTable::new();
        let mut receivers = Vec::new();
        for port in 1..=11 {
            let (peer, receiver) = registered_source(&table, 8_000 + port);
            receivers.push(receiver);
            for n in 0..100 {
                announce(
                    &mut table.tx_policy.lock(),
                    peer,
                    u32::from(port) * 100 + n,
                    now,
                    true,
                );
            }
        }
        let inventory = CountingInventory::default();
        table.poll_transaction_requests_at(&inventory, now);
        assert_eq!(inventory.checked.lock().unwrap().len(), 2_048);
        assert_eq!(
            table
                .tx_policy
                .lock()
                .requests
                .values()
                .filter(|request| request.owner.is_some())
                .count(),
            1_024
        );
        assert!(receivers.iter().any(|receiver| !receiver.is_empty()));
    }

    #[test]
    fn matching_failures_and_disconnects_bypass_the_background_cadence() {
        let now = Instant::now();
        for disconnect in [false, true] {
            let table = PeerTable::new();
            let (a, a_rx) = registered_source(&table, 8333);
            let (b, b_rx) = registered_source(&table, 8334);
            announce(&mut table.tx_policy.lock(), a, 1, now, true);
            announce(&mut table.tx_policy.lock(), b, 1, now + SOURCE_DELAY, false);
            let inventory = CountingInventory::default();
            table.poll_transaction_requests_at(&inventory, now);
            assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(_))));
            let checks = inventory.checked.lock().unwrap().len();
            table.transaction_not_found(b, &[item(1)], &inventory);
            assert_eq!(
                inventory.checked.lock().unwrap().len(),
                checks,
                "an unrelated source cannot trigger fallback work"
            );
            if disconnect {
                table.transaction_peer_disconnected(a, &inventory);
            } else {
                table.transaction_not_found(a, &[item(1)], &inventory);
            }
            assert!(
                matches!(b_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![item(1)])
            );
            assert_eq!(inventory.checked.lock().unwrap().len(), checks + 1);
        }
    }

    #[test]
    fn inventory_callbacks_never_observe_an_unsent_owner_reservation() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct ReentrantInventory {
            table: Arc<PeerTable>,
            source: PeerSource,
            calls: AtomicUsize,
        }
        impl TxInventory for ReentrantInventory {
            fn have_tx(&self, _: Hash256, _: bool) -> bool {
                if self.calls.fetch_add(1, Ordering::Relaxed) == 1 {
                    let key = Identity::from_inventory(item(1)).unwrap();
                    let mut policy = self.table.tx_policy.lock();
                    assert!(policy.requests[&key].owner.is_none());
                    assert!(
                        !policy.failed(key, self.source, Instant::now()),
                        "notfound cannot release an unsent plan"
                    );
                }
                false
            }
            fn get_tx(&self, _: Txid) -> Option<bitcoin_rs_primitives::Tx> {
                None
            }
            fn get_tx_by_wtxid(&self, _: Wtxid) -> Option<bitcoin_rs_primitives::Tx> {
                None
            }
        }
        let now = Instant::now();
        let table = Arc::new(PeerTable::new());
        let (peer, receiver) = registered_source(&table, 8333);
        announce(&mut table.tx_policy.lock(), peer, 1, now, true);
        let inventory = ReentrantInventory {
            table: table.clone(),
            source: peer,
            calls: AtomicUsize::new(0),
        };
        table.poll_transaction_requests_at(&inventory, now);
        assert_eq!(inventory.calls.load(Ordering::Relaxed), 2);
        assert!(matches!(receiver.try_recv(), Ok(Message::GetData(_))));
    }
    #[test]
    fn request_lifetime_starts_after_inventory_checks_and_commit_lock() {
        use std::sync::atomic::{AtomicU64, Ordering};
        struct DelayedInventory(AtomicU64);
        impl TxInventory for DelayedInventory {
            fn have_tx(&self, _: Hash256, _: bool) -> bool {
                self.0.store(61, Ordering::Relaxed);
                false
            }
            fn get_tx(&self, _: Txid) -> Option<bitcoin_rs_primitives::Tx> {
                None
            }
            fn get_tx_by_wtxid(&self, _: Wtxid) -> Option<bitcoin_rs_primitives::Tx> {
                None
            }
        }
        let started = Instant::now();
        let table = PeerTable::new();
        let (source, receiver) = registered_source(&table, 8333);
        announce(&mut table.tx_policy.lock(), source, 1, started, true);
        let inventory = DelayedInventory(AtomicU64::new(0));
        table.send_transaction_requests(started, Some(&inventory), None, || {
            started + Duration::from_secs(inventory.0.load(Ordering::Relaxed))
        });
        let key = Identity::from_inventory(item(1)).unwrap();
        assert_eq!(
            table.tx_policy.lock().requests[&key].owner,
            Some((source, started + Duration::from_secs(121)))
        );
        assert!(matches!(receiver.try_recv(), Ok(Message::GetData(_))));
    }
    #[test]
    fn ready_batches_rotate_past_reannounced_lower_keys() {
        let now = Instant::now();
        let mut policy = TxPolicy::default();
        for port in 1..=11 {
            let peer = source(port);
            for n in 0..100 {
                announce(&mut policy, peer, u32::from(port) * 100 + n, now, true);
            }
        }
        let tail = *policy.requests.keys().next_back().unwrap();
        let first = select(&mut policy, now);
        assert_eq!(first.len(), 1_024);
        assert!(!first.iter().any(|(key, _)| *key == tail));
        for (key, announcement) in first {
            policy.forget(key);
            policy.announce(announcement);
        }
        assert!(
            select(&mut policy, now).iter().any(|(key, _)| *key == tail),
            "fresh lower-key announcements cannot starve an older tail request"
        );
    }
    #[test]
    fn equal_txid_wtxid_bytes_share_one_owner_after_both_delays_expire() {
        let now = Instant::now();
        let mut policy = TxPolicy::default();
        let (a, b) = (source(1), source(2));
        let raw = [7; 32];
        let tx = Inventory::Transaction(bitcoin::Txid::from_byte_array(raw));
        let wtx = Inventory::WTx(bitcoin::Wtxid::from_byte_array(raw));
        let original = Announcement {
            source: a,
            item: tx,
            ready: now,
            preferred: true,
            priority: 1,
        };
        policy.announce(original);
        policy.announce(Announcement {
            item: wtx,
            ..original
        });
        assert_eq!(
            policy.announcements, 1,
            "Core deduplicates peer/raw-hash across inventory kinds"
        );
        policy.announce(Announcement {
            source: b,
            item: wtx,
            ready: now + SOURCE_DELAY,
            preferred: false,
            priority: 2,
        });
        let first = select(&mut policy, now);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].1.source, a);
        assert_eq!(select(&mut policy, now + SOURCE_DELAY), []);
        assert_eq!(
            policy
                .requests
                .values()
                .filter(|request| request.owner.is_some())
                .count(),
            1
        );
        assert!(policy.failed(first[0].0, a, now));
        let fallback = select(&mut policy, now);
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0].1.source, b);
        assert_eq!(fallback[0].1.item, wtx);
        assert!(
            !policy.failed(fallback[0].0, a, now),
            "failed source cannot release its successor"
        );
    }

    #[test]
    fn equal_hash_source_preference_is_shared_but_different_hashes_stay_independent() {
        let now = Instant::now();
        let mut policy = TxPolicy::default();
        let (a, b, c) = (source(1), source(2), source(3));
        for (peer, item, preferred) in [
            (
                a,
                Inventory::Transaction(bitcoin::Txid::from_byte_array([1; 32])),
                false,
            ),
            (
                b,
                Inventory::WTx(bitcoin::Wtxid::from_byte_array([1; 32])),
                true,
            ),
            (
                c,
                Inventory::WTx(bitcoin::Wtxid::from_byte_array([2; 32])),
                true,
            ),
        ] {
            policy.announce(Announcement {
                source: peer,
                item,
                ready: now,
                preferred,
                priority: 0,
            });
        }
        let selected = select(&mut policy, now);
        assert_eq!(
            selected.len(),
            2,
            "different raw hashes have independent owners without body evidence"
        );
        assert!(selected.iter().any(|(_, candidate)| candidate.source == b));
        assert!(selected.iter().any(|(_, candidate)| candidate.source == c));
        assert!(!selected.iter().any(|(_, candidate)| candidate.source == a));
    }

    #[test]
    fn notfound_promptly_checks_and_sends_the_other_inventory_kind() {
        let now = Instant::now();
        let table = PeerTable::new();
        let (a, a_rx) = registered_source(&table, 8333);
        let (b, b_rx) = registered_source(&table, 8334);
        let tx = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([7; 32]));
        let wtx = Inventory::WTx(bitcoin::Wtxid::from_byte_array([7; 32]));
        for (source, item, ready, preferred) in
            [(a, tx, now, true), (b, wtx, now + SOURCE_DELAY, false)]
        {
            table.tx_policy.lock().announce(Announcement {
                source,
                item,
                ready,
                preferred,
                priority: 0,
            });
        }
        let inventory = CountingInventory::default();
        table.poll_transaction_requests_at(&inventory, now);
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![tx]));
        assert!(b_rx.try_recv().is_err());
        let before = inventory.checked.lock().unwrap().len();
        table.transaction_not_found(a, &[tx], &inventory);
        assert!(matches!(b_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![wtx]));
        assert_eq!(inventory.checked.lock().unwrap().len(), before + 1);
        assert_eq!(
            inventory.checked.lock().unwrap().last().copied(),
            Identity::from_inventory(wtx)
        );
    }

    #[test]
    fn known_reject_scope_stays_typed_when_download_hashes_match() {
        let now = Instant::now();
        let table = PeerTable::new();
        let (a, a_rx) = registered_source(&table, 8333);
        let (b, b_rx) = registered_source(&table, 8334);
        let tx = Inventory::Transaction(bitcoin::Txid::from_byte_array([8; 32]));
        let wtx = Inventory::WTx(bitcoin::Wtxid::from_byte_array([8; 32]));
        for (source, item) in [(a, tx), (b, wtx)] {
            table.tx_policy.lock().announce(Announcement {
                source,
                item,
                ready: now,
                preferred: true,
                priority: 0,
            });
        }
        let inventory = CountingInventory::default();
        inventory
            .known
            .lock()
            .unwrap()
            .insert(Identity::from_inventory(wtx).unwrap());
        table.poll_transaction_requests_at(&inventory, now);
        assert!(b_rx.try_recv().is_err());
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![tx]));
        assert!(
            table
                .tx_policy
                .lock()
                .requests
                .contains_key(&Identity::from_inventory(tx).unwrap())
        );
    }
}

#[cfg(test)]
#[path = "tx_policy/preferred_tests.rs"]
#[expect(clippy::expect_used, reason = "bounded admission contract assertions")]
mod preferred_tests;
