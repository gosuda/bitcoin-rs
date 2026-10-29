//! Connection-bound transaction download policy. Mempool remains the authority
//! for accepted, orphan and rejected bodies; this owner retains identities only.

mod ingress;
mod relay;

pub use ingress::{
    InboundBody, InboundPackage, MAX_DECODED_PACKAGES_PER_PEER, OpenedPackage, PackageCapacity,
    PackageCharge, PackageOpening, PackagePlan, PackageRefusal, PackageRejection, PackageTeardown,
    PackageToken, plan_package_charge,
};

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use hashbrown::{HashMap, HashSet};

use crate::packages::{
    GetPkgTxns, MAX_GETPKGTXNS, MSG_ANCPKGINFO, MSG_PKGTXNS, combined_package_hash,
};
use crate::{Message, PeerSource, PeerTable, TxInventory};
use bitcoin_rs_primitives::{Hash256, Txid, Wtxid};

pub(crate) const MAX_PEER_ANNOUNCEMENTS: usize = 5_000;
pub(crate) const MAX_PEER_IN_FLIGHT: usize = 100;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackagePhase {
    Awaiting,
    Enqueued,
}

#[derive(Debug, Eq, PartialEq)]
struct PackageClaim {
    combined: [u8; 32],
    wtxids: Vec<Wtxid>,
    state: PackagePhase,
}

#[derive(Debug, Default)]
struct Request {
    candidates: Vec<Announcement>,
    owner: Option<(PeerSource, Instant)>,
    /// INVARIANT: `Some` only while `owner` is `Some`; every path that clears the owner
    /// clears this with it.
    ///
    /// The claim belongs to the owner's exact [`PeerSource`], so a replacement
    /// connection at a reused socket address can neither adopt nor release it.
    package: Option<PackageClaim>,
    /// INVARIANT: `true` only while `owner` is `Some` and `package` is `None`; every
    /// path that clears the owner clears this with it.
    ///
    /// Such a request is exempt from the known sweep like a claimed one, only while
    /// owned and unexpired ([`TxPolicy::forget_known`]).
    package_info: bool,
    /// back to them too. INVARIANT: non-empty only while `package_info` is
    /// `true` or a package claim is held; every owner-clearing path clears
    /// them with it.
    package_parents: Vec<Txid>,
    /// Marks a legacy parent request created or adopted by the package-info fallback.
    ///
    /// Only marked requests get the sender's BIP144 witness flag at the send boundary;
    /// ordinary requests keep their announced form.
    fallback_parent: bool,
}

impl Request {
    fn package_enqueued(&self) -> bool {
        self.package
            .as_ref()
            .is_some_and(|claim| claim.state == PackagePhase::Enqueued)
    }
}

#[derive(Debug, Default)]
pub(crate) struct TxPolicy {
    requests: BTreeMap<Identity, Request>,
    next_poll: Option<Instant>,
    known_cursor: Option<Identity>,
    ready_cursor: Option<Identity>,
    counts: HashMap<PeerSource, usize>,
    announcements: usize,
    evictable: BTreeSet<EvictionKey>,
    relay: HashMap<PeerSource, relay::RelayPeer>,
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

    fn forget_known(&mut self, key: Identity, now: Instant) {
        if self.requests.get(&key).is_some_and(|request| {
            request.package_enqueued()
                || ((request.package.is_some() || request.package_info)
                    && request.owner.is_some_and(|(_, deadline)| now < deadline))
        }) {
            return;
        }
        if let Some((owner, _)) = self.requests.get(&key).and_then(|request| request.owner) {
            let parents = self.package_parents_for(key, owner);
            self.announce_parents(owner, &parents, now);
        }
        self.forget(key);
    }

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

    fn failed(&mut self, key: Identity, source: PeerSource, now: Instant) -> bool {
        if self.requests.get(&key).is_none_or(|request| {
            request.owner.is_none_or(|(owner, _)| owner != source) || request.package_enqueued()
        }) {
            return false;
        }
        for kind in [key, key.same_hash_other_kind()] {
            if let Some(request) = self.requests.get_mut(&kind)
                && request.owner.is_some_and(|(owner, _)| owner == source)
            {
                request.owner = None;
                request.package = None;
                request.package_info = false;
                request.package_parents.clear();
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

    /// INVARIANT: a different owner, or no owner, is left alone, and so is an enqueued
    /// package.
    ///
    /// Only the claimed key is reversed: the same hash under the other identity kind is
    /// excluded from the plan by [`Self::in_flight`] while this key is owned, so it was
    /// never claimed alongside it. An awaiting package claim made since goes with the
    /// owner.
    fn unclaim(&mut self, key: Identity, source: PeerSource) {
        let Some(request) = self.requests.get_mut(&key) else {
            return;
        };
        if request.owner.is_none_or(|(owner, _)| owner != source) || request.package_enqueued() {
            return;
        }
        request.owner = None;
        request.package = None;
        request.package_info = false;
        request.package_parents.clear();
        if let Some(candidate) = request
            .candidates
            .iter()
            .find(|candidate| candidate.source == source && !candidate.preferred)
        {
            self.evictable.insert(eviction_key(key, candidate));
        }
    }

    /// INVARIANT: this adds no state beyond what an ordinary announcement and
    /// claim add, so every existing bound and retirement path applies.
    fn solicit_package_info(
        &mut self,
        source: PeerSource,
        subject: Wtxid,
        parents: &[Txid],
        now: Instant,
    ) -> bool {
        let key = Identity::Wtxid(subject.0);
        let hash_owned = [key, key.same_hash_other_kind()].into_iter().any(|kind| {
            self.requests
                .get(&kind)
                .is_some_and(|request| request.owner.is_some())
        });
        let owned_by_source = self
            .requests
            .values()
            .filter(|request| request.owner.is_some_and(|(owner, _)| owner == source))
            .count();
        if hash_owned || owned_by_source >= MAX_PEER_IN_FLIGHT {
            return false;
        }
        self.announce(Announcement {
            source,
            item: Inventory::WTx(bitcoin::Wtxid::from_byte_array(subject.0.to_le_bytes())),
            ready: now,
            preferred: true,
            priority: 0,
        });
        let Some(request) = self.requests.get_mut(&key) else {
            return false;
        };
        let Some(candidate) = request
            .candidates
            .iter()
            .find(|candidate| candidate.source == source)
        else {
            return false;
        };
        self.evictable.remove(&eviction_key(key, candidate));
        request.owner = Some((source, now + REQUEST_LIFETIME));
        request.package_info = true;
        request.package_parents = Self::dedup_txids(parents);
        true
    }

    fn dedup_txids(parents: &[Txid]) -> Vec<Txid> {
        let mut seen = HashSet::new();
        parents
            .iter()
            .filter(|txid| seen.insert(**txid))
            .copied()
            .collect()
    }

    fn failed_package_info(&mut self, key: Identity, source: PeerSource, now: Instant) -> bool {
        if !self.requests.get(&key).is_some_and(|request| {
            request.package_info && request.owner.is_some_and(|(owner, _)| owner == source)
        }) {
            return false;
        }
        self.failed(key, source, now)
    }

    fn package_parents_for(&self, key: Identity, source: PeerSource) -> Vec<Txid> {
        self.requests
            .get(&key)
            .filter(|request| {
                (request.package_info || request.package.is_some())
                    && request.owner.is_some_and(|(owner, _)| owner == source)
            })
            .map(|request| request.package_parents.clone())
            .unwrap_or_default()
    }

    fn failed_with_parents(
        &mut self,
        key: Identity,
        source: PeerSource,
        now: Instant,
    ) -> Vec<Identity> {
        let parents = self.package_parents_for(key, source);
        if !self.failed(key, source, now) {
            return Vec::new();
        }
        let mut keys = vec![key];
        keys.extend(self.announce_parents(source, &parents, now));
        keys
    }

    fn announce_parents(
        &mut self,
        source: PeerSource,
        parents: &[Txid],
        now: Instant,
    ) -> Vec<Identity> {
        let mut keys = Vec::new();
        for (index, txid) in Self::dedup_txids(parents).iter().enumerate() {
            let item = Inventory::Transaction(bitcoin::Txid::from_byte_array(txid.0.to_le_bytes()));
            let Some(key) = Identity::from_inventory(item) else {
                continue;
            };
            if self.request_parent(Announcement {
                source,
                item,
                ready: now,
                preferred: true,
                priority: u64::try_from(index).unwrap_or(u64::MAX),
            }) {
                if let Some(request) = self.requests.get_mut(&key) {
                    request.fallback_parent = true;
                }
                keys.push(key);
            }
        }
        keys
    }

    fn package_info_owner(&self, key: Identity, now: Instant) -> Option<PeerSource> {
        self.requests.get(&key).and_then(|request| {
            let (owner, deadline) = request.owner?;
            (request.package_info && now < deadline).then_some(owner)
        })
    }

    fn failed_package_claims(
        &mut self,
        source: PeerSource,
        combined: &[[u8; 32]],
        now: Instant,
    ) -> Vec<Identity> {
        if combined.is_empty() {
            return Vec::new();
        }
        let claims: HashMap<[u8; 32], Identity> = self
            .requests
            .iter()
            .filter_map(|(key, request)| {
                let claim = request.package.as_ref()?;
                (claim.state == PackagePhase::Awaiting
                    && request.owner.is_some_and(|(owner, _)| owner == source))
                .then_some((claim.combined, *key))
            })
            .collect();
        combined
            .iter()
            .filter_map(|hash| claims.get(hash).copied())
            .flat_map(|key| self.failed_with_parents(key, source, now))
            .collect()
    }

    /// INVARIANT: owner, deadline and the shared per-peer in-flight count are
    /// untouched: the claim rides the existing request and adds no accounting.
    fn claim_package(
        &mut self,
        source: PeerSource,
        subject: Wtxid,
        wtxids: &[Wtxid],
        now: Instant,
    ) -> bool {
        if wtxids.is_empty() || wtxids.len() > MAX_GETPKGTXNS {
            return false;
        }
        let Some(request) = self.requests.get_mut(&Identity::Wtxid(subject.0)) else {
            return false;
        };
        if !request.package_info
            || request.package.is_some()
            || !request
                .owner
                .is_some_and(|(owner, deadline)| owner == source && now < deadline)
        {
            return false;
        }
        request.package_info = false;
        request.package = Some(PackageClaim {
            combined: combined_package_hash(wtxids),
            wtxids: wtxids.to_vec(),
            state: PackagePhase::Awaiting,
        });
        true
    }

    fn begin_package_resolution(
        &mut self,
        source: PeerSource,
        subject: Wtxid,
        combined: [u8; 32],
        decoded: &[Wtxid],
        now: Instant,
    ) -> bool {
        let Some(request) = self.requests.get_mut(&Identity::Wtxid(subject.0)) else {
            return false;
        };
        let Some((owner, deadline)) = request.owner else {
            return false;
        };
        let Some(claim) = request.package.as_mut() else {
            return false;
        };
        if owner != source
            || now >= deadline
            || claim.state != PackagePhase::Awaiting
            || claim.combined != combined
            || claim.wtxids != decoded
        {
            return false;
        }
        claim.state = PackagePhase::Enqueued;
        true
    }

    fn release_package(
        &mut self,
        source: PeerSource,
        subject: Wtxid,
        now: Instant,
    ) -> Vec<Identity> {
        let key = Identity::Wtxid(subject.0);
        let parents = self.package_parents_for(key, source);
        let Some(request) = self.requests.get_mut(&key) else {
            return Vec::new();
        };
        if request.owner.is_none_or(|(owner, _)| owner != source) || !request.package_enqueued() {
            return Vec::new();
        }
        request.package = None;
        if !self.failed(key, source, now) {
            return Vec::new();
        }
        let mut keys = vec![key];
        keys.extend(self.announce_parents(source, &parents, now));
        keys
    }

    fn teardown_package_claims(&mut self, now: Instant) -> usize {
        let keys: Vec<_> = self
            .requests
            .iter()
            .filter_map(|(key, request)| request.package.is_some().then_some(*key))
            .collect();
        let mut cleared = 0;
        for key in keys {
            let Some(source) = self
                .requests
                .get(&key)
                .and_then(|request| request.owner.map(|(source, _)| source))
            else {
                continue;
            };
            for kind in [key, key.same_hash_other_kind()] {
                let owned = self
                    .requests
                    .get(&kind)
                    .is_some_and(|request| request.owner.is_some_and(|(owner, _)| owner == source));
                if !owned {
                    continue;
                }
                if let Some(request) = self.requests.get_mut(&kind) {
                    request.owner = None;
                    request.package = None;
                    request.package_info = false;
                    request.package_parents.clear();
                }
                self.remove_candidate(kind, source);
                if let Some(request) = self.requests.get_mut(&kind) {
                    for candidate in &mut request.candidates {
                        candidate.ready = now;
                    }
                }
            }
            cleared += 1;
        }
        cleared
    }

    fn disconnected(&mut self, source: PeerSource, now: Instant) -> (Vec<Identity>, Vec<Identity>) {
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
        let mut parent_keys = Vec::new();
        for &key in &keys {
            if !self
                .requests
                .get(&key)
                .is_some_and(|request| request.owner.is_some_and(|(owner, _)| owner == source))
            {
                self.remove_candidate(key, source);
                continue;
            }
            let parents = self.package_parents_for(key, source);
            self.failed(key, source, now);
            if parents.is_empty() {
                continue;
            }
            let alternates: Vec<PeerSource> = self
                .requests
                .get(&key)
                .map(|request| {
                    request
                        .candidates
                        .iter()
                        .map(|candidate| candidate.source)
                        .collect()
                })
                .unwrap_or_default();
            for alternate in alternates {
                parent_keys.extend(self.announce_parents(alternate, &parents, now));
            }
        }
        parent_keys.sort();
        parent_keys.dedup();
        (keys, parent_keys)
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
        let mut expired_parents = Vec::new();
        for (key, source) in expired {
            let parents = self.package_parents_for(key, source);
            self.failed(key, source, now);
            expired_parents.extend(self.announce_parents(source, &parents, now));
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
        for key in expired_parents {
            if !consider(key) {
                break;
            }
        }
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

    pub fn forget_known_transaction(&self, txid: Txid, wtxid: Wtxid) {
        let mut policy = self.tx_policy.lock();
        policy.forget(Identity::Txid(txid.0));
        policy.forget(Identity::Wtxid(wtxid.0));
    }

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
            let mut keys = Vec::new();
            let mut packages = Vec::new();
            for item in items.iter().copied() {
                match item {
                    Inventory::Unknown {
                        inv_type: MSG_ANCPKGINFO,
                        hash,
                    } => {
                        let key = Identity::Wtxid(Hash256::from_le_bytes(&hash));
                        let parents = policy.package_parents_for(key, source);
                        if policy.failed_package_info(key, source, now) {
                            keys.push(key);
                            keys.extend(policy.announce_parents(source, &parents, now));
                        }
                    }
                    Inventory::Unknown {
                        inv_type: MSG_PKGTXNS,
                        hash,
                    } => packages.push(hash),
                    item => keys.extend(
                        Identity::from_inventory(item)
                            .filter(|key| policy.failed(*key, source, now)),
                    ),
                }
            }
            keys.extend(policy.failed_package_claims(source, &packages, now));
            keys
        };
        if !keys.is_empty() {
            self.send_transaction_requests(now, Some(inventory), Some(&keys), Instant::now);
        }
    }

    pub fn poll_transaction_response(&self, inventory: &dyn TxInventory, txid: Txid, wtxid: Wtxid) {
        self.send_transaction_requests(
            Instant::now(),
            Some(inventory),
            Some(&[Identity::Txid(txid.0), Identity::Wtxid(wtxid.0)]),
            Instant::now,
        );
    }

    pub fn request_package_info(
        &self,
        source: PeerSource,
        subject: Wtxid,
        parents: &[Txid],
    ) -> bool {
        let now = Instant::now();
        let key = Identity::Wtxid(subject.0);
        let mut policy = self.tx_policy.lock();
        if !policy.solicit_package_info(source, subject, parents, now) {
            return false;
        }
        let item = Inventory::Unknown {
            inv_type: MSG_ANCPKGINFO,
            hash: subject.0.to_le_bytes(),
        };
        if self.send(source, Message::GetData(vec![item])).is_err() {
            policy.failed(key, source, now);
            return false;
        }
        true
    }

    pub fn has_live_package_solicitation(&self, subject: Wtxid) -> bool {
        let owner = self
            .tx_policy
            .lock()
            .package_info_owner(Identity::Wtxid(subject.0), Instant::now());
        owner.is_some_and(|source| self.lease_source(source).is_some())
    }

    pub fn release_package_info(
        &self,
        source: PeerSource,
        subject: Wtxid,
        inventory: &dyn TxInventory,
    ) -> bool {
        let now = Instant::now();
        let key = Identity::Wtxid(subject.0);
        let released = self.tx_policy.lock().failed_package_info(key, source, now);
        if released {
            self.send_transaction_requests(now, Some(inventory), Some(&[key]), Instant::now);
        }
        released
    }

    pub fn request_package_transactions(
        &self,
        source: PeerSource,
        subject: Wtxid,
        wtxids: Vec<Wtxid>,
    ) -> bool {
        let now = Instant::now();
        let key = Identity::Wtxid(subject.0);
        let mut policy = self.tx_policy.lock();
        if !policy.claim_package(source, subject, &wtxids, now) {
            return false;
        }
        if self
            .send(source, Message::GetPkgTxns(GetPkgTxns { wtxids }))
            .is_err()
        {
            let keys = policy.failed_with_parents(key, source, now);
            drop(policy);
            if !keys.is_empty() {
                self.send_transaction_requests(now, None, Some(&keys), Instant::now);
            }
            return false;
        }
        true
    }

    pub fn begin_package_resolution(
        &self,
        source: PeerSource,
        subject: Wtxid,
        combined: [u8; 32],
        decoded: &[Wtxid],
    ) -> bool {
        self.tx_policy.lock().begin_package_resolution(
            source,
            subject,
            combined,
            decoded,
            Instant::now(),
        )
    }

    pub fn release_package_claim(
        &self,
        source: PeerSource,
        subject: Wtxid,
        inventory: &dyn TxInventory,
    ) -> bool {
        let now = Instant::now();
        let keys = self.tx_policy.lock().release_package(source, subject, now);
        let released = !keys.is_empty();
        if released {
            self.send_transaction_requests(now, Some(inventory), Some(&keys), Instant::now);
        }
        released
    }

    pub(crate) fn transaction_peer_disconnected(
        &self,
        source: PeerSource,
        inventory: &dyn TxInventory,
    ) {
        let now = Instant::now();
        let (mut keys, parents) = self.tx_policy.lock().disconnected(source, now);
        keys.extend(parents);
        if !keys.is_empty() {
            self.send_transaction_requests(now, Some(inventory), Some(&keys), Instant::now);
        }
    }

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
            let live: HashSet<_> = self
                .usable_peers()
                .iter()
                .map(|peer| peer.lease.source(peer.endpoint))
                .collect();
            let gone: Vec<_> = policy
                .counts
                .keys()
                .filter(|source| !live.contains(*source))
                .copied()
                .collect();
            for source in gone {
                let _ = policy.disconnected(source, now);
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
                policy.forget_known(key, now);
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
        let (known, checked): (Vec<_>, Vec<_>) = planned
            .into_iter()
            .partition(|(key, _)| inventory.is_some_and(|inventory| key.known(inventory)));
        let mut policy = self.tx_policy.lock();
        for (key, _) in known {
            policy.forget(key);
        }
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
            let witness = self.transaction_witness(source);
            let items = batch
                .iter()
                .map(|(key, item)| {
                    let mut item = *item;
                    if witness
                        && policy
                            .requests
                            .get(key)
                            .is_some_and(|request| request.fallback_parent)
                        && let Inventory::Transaction(txid) = item
                    {
                        item = Inventory::WitnessTransaction(txid);
                    }
                    item
                })
                .collect();
            match self.send(source, Message::GetData(items)) {
                Ok(()) => {}
                Err(crate::OutboundRefusal::Saturated(_)) => {
                    for (key, _) in batch {
                        policy.unclaim(key, source);
                    }
                }
                Err(crate::OutboundRefusal::Closed(_)) => {
                    for (key, _) in batch {
                        policy.failed(key, source, committed);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "transaction owner test assertions")]
mod tests;

#[cfg(test)]
#[expect(clippy::expect_used, reason = "bounded admission contract assertions")]
mod preferred_tests;
