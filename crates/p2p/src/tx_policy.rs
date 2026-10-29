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
        PeerSource::for_test(([127, 0, 0, 1], port))
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
    #[expect(
        clippy::too_many_lines,
        reason = "Single end-to-end retirement scenario drives request, arrival, and resend phases"
    )]
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
            fn resident_ancestor_package(&self, _: Wtxid) -> Option<Vec<Wtxid>> {
                None
            }
            fn resident_package(
                &self,
                _: &[Wtxid],
            ) -> Option<Vec<std::sync::Arc<bitcoin_rs_primitives::Tx>>> {
                None
            }
        }
        let table = Arc::new(PeerTable::new());
        let (sender, receiver) = crate::test_support::message_channel_bounded(4);
        let lease = crate::PeerLease::new(sender);
        let addr: crate::PeerEndpoint = ([127, 0, 0, 1], 8333).into();
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
                addr.socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
                &version,
                0,
                0,
                Arc::new(crate::PeerCounters::default()),
            ),
        );
        let mut poll_now = Instant::now() + Duration::from_secs(1);
        let inventory = InventoryView(AtomicBool::new(false));
        table.announce_transactions(lease.source(Some(addr)), &[item(1)]);
        table.poll_transaction_requests_at(&inventory, poll_now);
        assert!(matches!(receiver.try_recv(), Ok(Message::GetData(_))));
        inventory.0.store(true, Ordering::Relaxed);
        poll_now += REQUEST_POLL_INTERVAL;
        table.poll_transaction_requests_at(&inventory, poll_now);
        assert!(table.tx_policy.lock().requests.is_empty());
        assert!(receiver.try_recv().is_err());
        inventory.0.store(false, Ordering::Relaxed);
        table.announce_transactions(lease.source(Some(addr)), &[item(1)]);
        let Some(Identity::Wtxid(hash)) = Identity::from_inventory(item(1)) else {
            panic!("wtx fixture")
        };
        table.forget_known_transaction(Txid(hash), Wtxid(hash));
        poll_now += REQUEST_POLL_INTERVAL;
        table.poll_transaction_requests_at(&inventory, poll_now);
        assert!(receiver.try_recv().is_err());
        assert_eq!(table.tx_policy.lock().announcements, 0);
        let pending_table = Arc::clone(&table);
        let (new_sender, new_receiver) = crate::test_support::message_channel_bounded(4);
        let new_lease = crate::PeerLease::new(new_sender);
        let new_addr: crate::PeerEndpoint = ([127, 0, 0, 1], 8334).into();
        POLL_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                pending_table.register(new_addr, new_lease.clone());
                pending_table.publish_info(
                    new_addr,
                    &new_lease,
                    crate::PeerInfo::outbound_from_version(
                        new_addr,
                        new_addr
                            .socket_addr()
                            .unwrap_or_else(|| panic!("expected IP fixture")),
                        &version,
                        0,
                        0,
                        Arc::new(crate::PeerCounters::default()),
                    ),
                );
                pending_table.announce_transactions(new_lease.source(Some(new_addr)), &[item(2)]);
            }));
        });
        poll_now += REQUEST_POLL_INTERVAL;
        table.poll_transaction_requests_at(&inventory, poll_now);
        assert_eq!(table.tx_policy.lock().announcements, 1);
        poll_now += REQUEST_POLL_INTERVAL;
        table.poll_transaction_requests_at(&inventory, poll_now);
        assert!(
            matches!(new_receiver.try_recv(), Ok(Message::GetData(items)) if items == vec![item(2)])
        );
    }
    pub(super) fn registered_source(
        table: &PeerTable,
        port: u16,
    ) -> (PeerSource, crate::test_support::MessageReceiver) {
        let (sender, receiver) = crate::test_support::message_channel_bounded(32);
        let lease = crate::PeerLease::new(sender);
        let source = register_ready(table, port, &lease);
        (source, receiver)
    }

    pub(super) fn register_ready(
        table: &PeerTable,
        port: u16,
        lease: &crate::PeerLease,
    ) -> PeerSource {
        let addr: crate::PeerEndpoint = ([127, 0, 0, 1], port).into();
        table.register(addr, lease.clone());
        let version = crate::handshake::version_message(
            1,
            0,
            crate::PeerRole::FullRelay,
            bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
        );
        table.publish_info(
            addr,
            lease,
            crate::PeerInfo::outbound_from_version(
                addr,
                addr.socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
                &version,
                0,
                0,
                std::sync::Arc::new(crate::PeerCounters::default()),
            ),
        );
        lease.source(Some(addr))
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
        fn resident_ancestor_package(&self, _: Wtxid) -> Option<Vec<Wtxid>> {
            None
        }
        fn resident_package(
            &self,
            _: &[Wtxid],
        ) -> Option<Vec<std::sync::Arc<bitcoin_rs_primitives::Tx>>> {
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
            fn resident_ancestor_package(&self, _: Wtxid) -> Option<Vec<Wtxid>> {
                None
            }
            fn resident_package(
                &self,
                _: &[Wtxid],
            ) -> Option<Vec<std::sync::Arc<bitcoin_rs_primitives::Tx>>> {
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
            fn resident_ancestor_package(&self, _: Wtxid) -> Option<Vec<Wtxid>> {
                None
            }
            fn resident_package(
                &self,
                _: &[Wtxid],
            ) -> Option<Vec<std::sync::Arc<bitcoin_rs_primitives::Tx>>> {
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

    fn wtxid(n: u32) -> Wtxid {
        let mut hash = [0; 32];
        hash[..4].copy_from_slice(&n.to_le_bytes());
        Wtxid(Hash256::from_le_bytes(&hash))
    }

    fn ancestor_info(subject: Wtxid) -> Inventory {
        Inventory::Unknown {
            inv_type: MSG_ANCPKGINFO,
            hash: subject.0.to_le_bytes(),
        }
    }

    fn owned_request(
        policy: &mut TxPolicy,
        owner: PeerSource,
        alternate: PeerSource,
        n: u32,
        now: Instant,
    ) -> (Identity, Wtxid) {
        announce(policy, alternate, n, now, false);
        let subject = wtxid(n);
        assert!(policy.solicit_package_info(owner, subject, &[], now));
        (Identity::Wtxid(subject.0), subject)
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Observed {
        owner: Option<(PeerSource, Instant)>,
        claim: Option<(PackagePhase, [u8; 32], Vec<Wtxid>)>,
        package_info: bool,
        candidates: Vec<PeerSource>,
        in_flight: usize,
        announcements: usize,
    }

    fn observe(policy: &TxPolicy, key: Identity) -> Observed {
        let request = &policy.requests[&key];
        Observed {
            owner: request.owner,
            claim: request
                .package
                .as_ref()
                .map(|claim| (claim.state, claim.combined, claim.wtxids.clone())),
            package_info: request.package_info,
            candidates: request
                .candidates
                .iter()
                .map(|candidate| candidate.source)
                .collect(),
            in_flight: policy.in_flight().0.values().sum(),
            announcements: policy.announcements,
        }
    }

    fn package_state(policy: &TxPolicy, key: Identity) -> Option<PackagePhase> {
        policy.requests[&key]
            .package
            .as_ref()
            .map(|claim| claim.state)
    }

    #[test]
    fn package_claim_rides_the_owned_request_and_records_the_sent_sequence() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let mut policy = TxPolicy::default();
        let (key, subject) = owned_request(&mut policy, a, b, 1, now);
        let sequence = [wtxid(7), wtxid(3), subject];
        let in_flight = policy.in_flight().0;
        let untouched = observe(&policy, key);
        let oversized = vec![wtxid(9); MAX_GETPKGTXNS + 1];
        let refused = [
            ("alternate does not own", b, subject, &sequence[..], now),
            (
                "replacement connection",
                source(1),
                subject,
                &sequence[..],
                now,
            ),
            (
                "expired owner",
                a,
                subject,
                &sequence[..],
                now + REQUEST_LIFETIME,
            ),
            ("empty frame", a, subject, &[][..], now),
            ("oversized frame", a, subject, &oversized[..], now),
            ("no such request", a, wtxid(2), &sequence[..], now),
        ];
        for (case, claimant, subject, wtxids, at) in refused {
            assert!(
                !policy.claim_package(claimant, subject, wtxids, at),
                "{case}"
            );
            assert_eq!(observe(&policy, key), untouched, "{case}");
        }

        assert!(policy.claim_package(a, subject, &sequence, now));
        assert_eq!(
            policy.requests[&key].package,
            Some(PackageClaim {
                combined: combined_package_hash(&sequence),
                wtxids: sequence.to_vec(),
                state: PackagePhase::Awaiting,
            })
        );
        assert_eq!(
            policy.requests[&key].owner,
            Some((a, now + REQUEST_LIFETIME))
        );
        assert_eq!(
            policy.in_flight().0,
            in_flight,
            "a package request shares the per-peer in-flight count"
        );
        assert!(
            !policy.claim_package(a, subject, &sequence, now),
            "one package per request"
        );
        assert!(
            !policy.requests[&key].package_info,
            "the solicitation is consumed by its one ancpkginfo"
        );
    }

    #[test]
    fn package_info_solicitation_is_exclusive_bounded_and_retires_like_any_request() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let subject = wtxid(1);
        let key = Identity::Wtxid(subject.0);

        let mut policy = TxPolicy::default();
        announce(&mut policy, a, 1, now, true);
        assert_eq!(select(&mut policy, now).len(), 1);
        let ordinary = observe(&policy, key);
        assert!(!policy.claim_package(a, subject, &[subject], now));
        assert!(!policy.solicit_package_info(a, subject, &[], now));
        assert!(!policy.solicit_package_info(b, subject, &[], now));
        assert_eq!(observe(&policy, key), ordinary);

        let mut policy = TxPolicy::default();
        policy.announce(Announcement {
            source: a,
            item: Inventory::Transaction(bitcoin::Txid::from_byte_array(subject.0.to_le_bytes())),
            ready: now,
            preferred: true,
            priority: 0,
        });
        assert_eq!(select(&mut policy, now).len(), 1);
        assert!(!policy.solicit_package_info(b, subject, &[], now));
        assert!(!policy.requests.contains_key(&key));
        assert_eq!(policy.announcements, 1);

        let mut policy = TxPolicy::default();
        let full = u32::try_from(MAX_PEER_IN_FLIGHT).unwrap();
        for n in 1..=full {
            announce(&mut policy, a, 1_000 + n, now, true);
        }
        assert_eq!(select(&mut policy, now).len(), MAX_PEER_IN_FLIGHT);
        let announcements = policy.announcements;
        assert!(!policy.solicit_package_info(a, subject, &[], now));
        assert!(!policy.requests.contains_key(&key));
        assert_eq!(policy.announcements, announcements);
        assert!(policy.solicit_package_info(b, subject, &[], now));

        for mode in ["expiry", "disconnect", "notfound"] {
            let mut policy = TxPolicy::default();
            let (key, subject) = owned_request(&mut policy, a, b, 1, now);
            assert_eq!(
                policy.requests[&key].owner,
                Some((a, now + REQUEST_LIFETIME)),
                "{mode}: the deadline is the ordinary one"
            );
            let at = match mode {
                "expiry" => now + REQUEST_LIFETIME,
                "disconnect" => {
                    policy.disconnected(a, now);
                    now
                }
                _ => {
                    assert!(!policy.failed_package_info(key, b, now), "{mode}");
                    assert!(policy.failed_package_info(key, a, now), "{mode}");
                    now
                }
            };
            let selected = select(&mut policy, at);
            assert_eq!(selected.len(), 1, "{mode}");
            assert_eq!(selected[0].1.source, b, "{mode}");
            assert!(!policy.requests[&key].package_info, "{mode}");
            assert!(!policy.counts.contains_key(&a), "{mode}");
            assert!(!policy.claim_package(a, subject, &[subject], at), "{mode}");
        }
    }

    #[test]
    fn package_resolution_compares_claim_hash_sequence_and_deadline_before_any_mutation() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let mut policy = TxPolicy::default();
        let (key, subject) = owned_request(&mut policy, a, b, 1, now);
        let sequence = [wtxid(7), wtxid(3), subject];
        assert!(policy.claim_package(a, subject, &sequence, now));
        let combined = combined_package_hash(&sequence);
        let reordered = [wtxid(3), wtxid(7), subject];
        assert_eq!(
            combined_package_hash(&reordered),
            combined,
            "the hash is blind to order, so the sequence comparison must carry it"
        );
        let different = [wtxid(7), wtxid(4), subject];
        let diff_hash = combined_package_hash(&different);
        let subset = &sequence[..2];
        let subset_hash = combined_package_hash(subset);
        let superset = [wtxid(7), wtxid(3), subject, wtxid(8)];
        let superset_hash = combined_package_hash(&superset);
        let other = source(1);
        let untouched = observe(&policy, key);
        let mismatches = [
            ("foreign peer", b, subject, combined, &sequence[..], now),
            ("replacement", other, subject, combined, &sequence[..], now),
            ("foreign subject", a, wtxid(2), combined, &sequence[..], now),
            ("reordered", a, subject, combined, &reordered[..], now),
            ("different set", a, subject, diff_hash, &different[..], now),
            ("wrong hash", a, subject, diff_hash, &sequence[..], now),
            ("wrong body", a, subject, combined, &different[..], now),
            ("subset", a, subject, subset_hash, subset, now),
            ("superset", a, subject, superset_hash, &superset[..], now),
            (
                "expired",
                a,
                subject,
                combined,
                &sequence[..],
                now + REQUEST_LIFETIME,
            ),
        ];
        for (case, claimant, subject, hash, decoded, at) in mismatches {
            assert!(
                !policy.begin_package_resolution(claimant, subject, hash, decoded, at),
                "{case}"
            );
            assert_eq!(observe(&policy, key), untouched, "{case}");
        }

        let at = now + Duration::from_secs(59);
        assert!(policy.begin_package_resolution(a, subject, combined, &sequence, at));
        assert_eq!(
            policy.requests[&key].package,
            Some(PackageClaim {
                combined,
                wtxids: sequence.to_vec(),
                state: PackagePhase::Enqueued,
            }),
            "the claim keeps the sent sequence; decoded values are only compared"
        );
        let enqueued = observe(&policy, key);
        assert!(
            !policy.begin_package_resolution(a, subject, combined, &sequence, at),
            "a duplicate body is never enqueued twice"
        );
        assert_eq!(observe(&policy, key), enqueued);
    }

    #[test]
    fn awaiting_package_retires_through_failed_expiry_and_disconnect_and_replans_an_alternate() {
        for mode in ["failed", "expiry", "disconnect"] {
            let now = Instant::now();
            let (a, b) = (source(1), source(2));
            let mut policy = TxPolicy::default();
            let (key, subject) = owned_request(&mut policy, a, b, 1, now);
            let sequence = [wtxid(7), subject];
            assert!(policy.claim_package(a, subject, &sequence, now), "{mode}");
            let combined = combined_package_hash(&sequence);
            let at = match mode {
                "failed" => {
                    assert!(policy.failed(key, a, now));
                    now
                }
                "expiry" => now + REQUEST_LIFETIME,
                _ => {
                    policy.disconnected(a, now);
                    now
                }
            };
            let selected = select(&mut policy, at);
            assert_eq!(selected.len(), 1, "{mode}");
            assert_eq!(selected[0].1.source, b, "{mode}");
            assert_eq!(
                policy.requests[&key].owner,
                Some((b, at + REQUEST_LIFETIME)),
                "{mode}"
            );
            assert_eq!(package_state(&policy, key), None, "{mode}");
            assert!(!policy.counts.contains_key(&a), "{mode}");

            let settled = observe(&policy, key);
            for late in [a, b] {
                assert!(
                    !policy.begin_package_resolution(late, subject, combined, &sequence, at),
                    "{mode}"
                );
            }
            assert_eq!(observe(&policy, key), settled, "{mode}");
        }
    }

    #[test]
    fn enqueued_package_is_skipped_by_failure_paths_and_released_exactly_once() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let mut policy = TxPolicy::default();
        let (key, subject) = owned_request(&mut policy, a, b, 1, now);
        let sequence = [wtxid(7), subject];
        assert!(policy.claim_package(a, subject, &sequence, now));
        let combined = combined_package_hash(&sequence);
        let awaiting = observe(&policy, key);
        assert!(
            policy.release_package(a, subject, now).is_empty(),
            "an awaiting claim retires only through failed, expiry or disconnect"
        );
        assert_eq!(observe(&policy, key), awaiting);

        assert!(policy.begin_package_resolution(a, subject, combined, &sequence, now));
        let late = now + REQUEST_LIFETIME * 2;
        assert!(!policy.failed(key, a, late));
        policy.disconnected(a, late);
        policy.unclaim(key, a);
        assert_eq!(
            select(&mut policy, late),
            [],
            "no alternate is planned for a body that is already queued"
        );
        assert_eq!(policy.requests[&key].owner.map(|(owner, _)| owner), Some(a));
        assert_eq!(package_state(&policy, key), Some(PackagePhase::Enqueued));
        assert!(
            !policy.begin_package_resolution(a, subject, combined, &sequence, late),
            "the queued body is submitted once"
        );

        let queued = observe(&policy, key);
        let replacement = source(1);
        for foreign in [replacement, b] {
            assert_eq!(policy.release_package(foreign, subject, late).len(), 0);
            assert!(!policy.begin_package_resolution(foreign, subject, combined, &sequence, now));
        }
        assert_eq!(observe(&policy, key), queued);

        assert_ne!(policy.release_package(a, subject, late).len(), 0);
        assert!(!policy.counts.contains_key(&a));
        assert_eq!(policy.requests[&key].owner, None);
        assert_eq!(package_state(&policy, key), None);
        assert!(
            policy.release_package(a, subject, late).is_empty(),
            "a repeated release is a no-op"
        );
        let selected = select(&mut policy, late);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1.source, b);
    }

    #[test]
    fn queued_package_of_a_disconnected_connection_submits_once_and_a_replacement_cannot_adopt_it()
    {
        let now = Instant::now();
        let table = PeerTable::new();
        let (a, a_rx) = registered_source(&table, 8333);
        let (b, b_rx) = registered_source(&table, 8334);
        let subject = wtxid(1);
        assert!(table.request_package_info(a, subject, &[]));
        assert!(
            matches!(a_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![ancestor_info(subject)])
        );
        table.tx_policy.lock().announce(Announcement {
            source: b,
            item: item(1),
            ready: now,
            preferred: false,
            priority: 0,
        });
        let inventory = CountingInventory::default();
        table.poll_transaction_requests_at(&inventory, now);
        assert!(a_rx.try_recv().is_err());
        assert!(
            b_rx.try_recv().is_err(),
            "the owned hash is not requested twice"
        );

        let sequence = vec![wtxid(5), wtxid(4), subject];
        assert!(table.request_package_transactions(a, subject, sequence.clone()));
        assert!(
            matches!(a_rx.try_recv(), Ok(Message::GetPkgTxns(request)) if request.wtxids == sequence)
        );
        assert!(
            !table.request_package_transactions(a, subject, sequence.clone()),
            "one package per request"
        );
        assert!(a_rx.try_recv().is_err());

        let combined = combined_package_hash(&sequence);
        let reordered = [wtxid(4), wtxid(5), subject];
        assert!(!table.begin_package_resolution(a, subject, combined, &reordered));
        assert!(table.begin_package_resolution(a, subject, combined, &sequence));

        table.transaction_peer_disconnected(a, &inventory);
        assert!(b_rx.try_recv().is_err());
        let replacement = PeerSource::for_test(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        assert!(!table.begin_package_resolution(replacement, subject, combined, &sequence));
        assert!(!table.release_package_claim(replacement, subject, &inventory));
        assert!(!table.begin_package_resolution(a, subject, combined, &sequence));
        assert!(b_rx.try_recv().is_err());

        assert!(table.release_package_claim(a, subject, &inventory));
        assert!(matches!(b_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![item(1)]));
        assert!(!table.release_package_claim(a, subject, &inventory));
        assert!(b_rx.try_recv().is_err());
        let policy = table.tx_policy.lock();
        let request = &policy.requests[&Identity::Wtxid(subject.0)];
        assert_eq!(request.owner.map(|(owner, _)| owner), Some(b));
        assert_eq!(request.package, None);
    }

    #[test]
    fn a_refused_package_send_leaves_no_claim_behind() {
        let now = Instant::now();
        let table = PeerTable::new();
        let gone = source(9);
        let subject = wtxid(1);
        assert!(!table.request_package_info(gone, subject, &[]));
        {
            let policy = table.tx_policy.lock();
            assert!(policy.requests.is_empty());
            assert!(policy.counts.is_empty());
        }
        assert!(
            table
                .tx_policy
                .lock()
                .solicit_package_info(gone, subject, &[], now)
        );
        assert!(!table.request_package_transactions(gone, subject, vec![subject]));
        let policy = table.tx_policy.lock();
        assert!(policy.requests.is_empty());
        assert!(policy.counts.is_empty());
    }

    #[test]
    fn package_info_getdata_names_the_subject_and_its_notfound_retires_only_the_owners_request() {
        let now = Instant::now();
        let table = PeerTable::new();
        let (a, a_rx) = registered_source(&table, 8333);
        let (b, b_rx) = registered_source(&table, 8334);
        let subject = wtxid(1);
        let key = Identity::Wtxid(subject.0);
        assert!(table.request_package_info(a, subject, &[]));
        assert!(
            matches!(a_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![ancestor_info(subject)])
        );
        assert!(
            !table.request_package_info(a, subject, &[]),
            "one solicitation per request"
        );
        assert!(
            !table.request_package_info(b, subject, &[]),
            "one owner per hash"
        );
        assert!(a_rx.try_recv().is_err() && b_rx.try_recv().is_err());

        table.tx_policy.lock().announce(Announcement {
            source: b,
            item: item(1),
            ready: now,
            preferred: false,
            priority: 0,
        });
        let inventory = CountingInventory::default();
        table.transaction_not_found(b, &[ancestor_info(subject)], &inventory);
        assert!(table.tx_policy.lock().requests[&key].package_info);
        assert!(b_rx.try_recv().is_err());
        table.transaction_not_found(a, &[ancestor_info(subject)], &inventory);
        assert!(matches!(b_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![item(1)]));
        assert!(!table.tx_policy.lock().requests[&key].package_info);
    }

    #[test]
    fn unservable_getpkgtxns_notfound_retires_only_the_owners_awaiting_claims_in_one_pass() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let mut policy = TxPolicy::default();
        let mut sequences = Vec::new();
        for (n, owner, other) in [(1, a, b), (2, a, b), (3, b, a), (4, a, b)] {
            let (key, subject) = owned_request(&mut policy, owner, other, n, now);
            let sequence = vec![wtxid(20 + n), subject];
            assert!(policy.claim_package(owner, subject, &sequence, now));
            sequences.push((key, subject, sequence));
        }
        let hash = |index: usize| combined_package_hash(&sequences[index].2);
        assert!(policy.begin_package_resolution(a, sequences[0].1, hash(0), &sequences[0].2, now));

        let retired = policy.failed_package_claims(a, &[hash(0), hash(1), hash(2), [9; 32]], now);
        assert_eq!(retired, [sequences[1].0], "only a's awaiting claim");
        assert_eq!(
            package_state(&policy, sequences[0].0),
            Some(PackagePhase::Enqueued)
        );
        assert_eq!(
            package_state(&policy, sequences[2].0),
            Some(PackagePhase::Awaiting),
            "another source's claim"
        );
        assert_eq!(
            package_state(&policy, sequences[3].0),
            Some(PackagePhase::Awaiting),
            "a hash the message did not name"
        );
        assert_eq!(policy.requests[&sequences[1].0].owner, None);
        assert!(
            policy.failed_package_claims(a, &[hash(1)], now).is_empty(),
            "a repeated notfound is a no-op"
        );
    }

    #[test]
    fn notfound_for_an_unservable_getpkgtxns_offers_the_alternate_and_ignores_foreign_senders() {
        let now = Instant::now();
        let table = PeerTable::new();
        let (a, a_rx) = registered_source(&table, 8333);
        let (b, b_rx) = registered_source(&table, 8334);
        let subject = wtxid(1);
        assert!(table.request_package_info(a, subject, &[]));
        table.tx_policy.lock().announce(Announcement {
            source: b,
            item: item(1),
            ready: now,
            preferred: false,
            priority: 0,
        });
        let sequence = vec![wtxid(5), subject];
        assert!(table.request_package_transactions(a, subject, sequence.clone()));
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(_))));
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetPkgTxns(_))));
        let unservable = Inventory::Unknown {
            inv_type: MSG_PKGTXNS,
            hash: combined_package_hash(&sequence),
        };
        let inventory = CountingInventory::default();
        table.transaction_not_found(b, &[unservable], &inventory);
        assert_eq!(
            package_state(&table.tx_policy.lock(), Identity::Wtxid(subject.0)),
            Some(PackagePhase::Awaiting)
        );
        assert!(b_rx.try_recv().is_err());
        table.transaction_not_found(a, &[unservable], &inventory);
        assert!(matches!(b_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![item(1)]));
        assert_eq!(
            package_state(&table.tx_policy.lock(), Identity::Wtxid(subject.0)),
            None
        );
    }

    #[test]
    fn an_answered_solicitation_that_needs_no_getpkgtxns_is_released_by_its_owner_only() {
        let now = Instant::now();
        let table = PeerTable::new();
        let (a, a_rx) = registered_source(&table, 8333);
        let (b, b_rx) = registered_source(&table, 8334);
        let subject = wtxid(1);
        let key = Identity::Wtxid(subject.0);
        assert!(table.request_package_info(a, subject, &[]));
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(_))));
        table.tx_policy.lock().announce(Announcement {
            source: b,
            item: item(1),
            ready: now,
            preferred: false,
            priority: 0,
        });
        let inventory = CountingInventory::default();
        assert!(!table.release_package_info(b, subject, &inventory));
        assert!(table.tx_policy.lock().requests[&key].package_info);
        assert!(table.release_package_info(a, subject, &inventory));
        assert!(matches!(b_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![item(1)]));
        assert!(!table.release_package_info(a, subject, &inventory));

        let subject = wtxid(2);
        assert!(table.request_package_info(a, subject, &[]));
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(_))));
        assert!(table.request_package_transactions(a, subject, vec![subject]));
        assert!(!table.release_package_info(a, subject, &inventory));
        assert_eq!(
            package_state(&table.tx_policy.lock(), Identity::Wtxid(subject.0)),
            Some(PackagePhase::Awaiting)
        );
    }

    #[test]
    fn the_sweep_exemption_ends_with_the_owned_deadline_unless_the_body_is_queued() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let deadline = now + REQUEST_LIFETIME;
        for stage in ["solicited", "claimed", "enqueued"] {
            let mut policy = TxPolicy::default();
            let (key, subject) = owned_request(&mut policy, a, b, 1, now);
            let sequence = [wtxid(7), subject];
            if stage != "solicited" {
                assert!(policy.claim_package(a, subject, &sequence, now), "{stage}");
            }
            if stage == "enqueued" {
                let combined = combined_package_hash(&sequence);
                assert!(
                    policy.begin_package_resolution(a, subject, combined, &sequence, now),
                    "{stage}"
                );
            }
            policy.forget_known(
                key,
                now + REQUEST_LIFETIME.saturating_sub(Duration::from_secs(1)),
            );
            assert!(policy.requests.contains_key(&key), "{stage}");
            policy.forget_known(key, deadline);
            if stage == "enqueued" {
                assert!(
                    policy.requests.contains_key(&key),
                    "{stage}: its body is already queued"
                );
                assert_ne!(policy.release_package(a, subject, deadline).len(), 0);
                policy.forget_known(key, deadline);
            }
            assert!(policy.requests.is_empty(), "{stage}");
            assert!(policy.counts.is_empty(), "{stage}");
            assert_eq!(policy.announcements, 0, "{stage}");
        }
    }

    #[test]
    fn known_sweep_retires_unclaimed_requests_but_not_a_claimed_package_subject() {
        let now = Instant::now();
        let table = PeerTable::new();
        let (a, a_rx) = registered_source(&table, 8333);
        let (claimed, unclaimed) = (wtxid(1), wtxid(2));
        table.tx_policy.lock().announce(Announcement {
            source: a,
            item: item(2),
            ready: now,
            preferred: true,
            priority: 0,
        });
        let inventory = CountingInventory::default();
        table.poll_transaction_requests_at(&inventory, now);
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![item(2)]));
        assert!(table.request_package_info(a, claimed, &[]));
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(_))));
        let key = Identity::Wtxid(claimed.0);

        for subject in [claimed, unclaimed] {
            inventory
                .known
                .lock()
                .unwrap()
                .insert(Identity::Wtxid(subject.0));
        }
        table.poll_transaction_requests_at(&inventory, now + Duration::from_secs(1));
        {
            let policy = table.tx_policy.lock();
            assert!(!policy.requests.contains_key(&Identity::Wtxid(unclaimed.0)));
            assert!(
                policy.requests[&key].package_info,
                "an unanswered solicitation survives the sweep"
            );
        }

        let sequence = vec![wtxid(5), claimed];
        assert!(table.request_package_transactions(a, claimed, sequence.clone()));
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetPkgTxns(_))));
        table.poll_transaction_requests_at(&inventory, now + Duration::from_secs(2));
        assert_eq!(
            package_state(&table.tx_policy.lock(), key),
            Some(PackagePhase::Awaiting)
        );

        let combined = combined_package_hash(&sequence);
        assert!(table.begin_package_resolution(a, claimed, combined, &sequence));
        assert!(table.release_package_claim(a, claimed, &inventory));
        let policy = table.tx_policy.lock();
        assert!(policy.requests.is_empty());
        assert!(policy.counts.is_empty());
    }

    fn parent_txid(n: u8) -> Txid {
        Txid(Hash256::from_le_bytes(&[n; 32]))
    }

    fn parent_item(n: u8) -> Inventory {
        Inventory::Transaction(bitcoin::Txid::from_byte_array([n; 32]))
    }

    fn parent_witness_item(n: u8) -> Inventory {
        Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([n; 32]))
    }

    #[test]
    fn package_info_notfound_reroutes_riding_parents_to_the_supplier() {
        let now = Instant::now();
        let table = PeerTable::new();
        let (a, a_rx) = registered_source(&table, 8333);
        let (b, b_rx) = registered_source(&table, 8334);
        let subject = wtxid(1);
        let parents = [parent_txid(11), parent_txid(12)];
        let key = Identity::Wtxid(subject.0);
        assert!(table.request_package_info(a, subject, &parents));
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(_))));
        table.tx_policy.lock().announce(Announcement {
            source: b,
            item: item(1),
            ready: now,
            preferred: false,
            priority: 0,
        });
        let inventory = CountingInventory::default();
        table.transaction_not_found(a, &[ancestor_info(subject)], &inventory);
        assert!(matches!(b_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![item(1)]));
        assert!(
            matches!(a_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![parent_witness_item(11), parent_witness_item(12)])
        );
        assert!(a_rx.try_recv().is_err() && b_rx.try_recv().is_err());
        assert!(
            table.tx_policy.lock().requests[&key]
                .owner
                .is_some_and(|(owner, _)| owner == b),
            "the alternate owns the re-offered subject"
        );
    }

    #[test]
    fn unservable_getpkgtxns_reroutes_riding_parents_to_the_supplier() {
        let table = PeerTable::new();
        let (a, a_rx) = registered_source(&table, 8333);
        let subject = wtxid(1);
        let parents = [parent_txid(41), parent_txid(42)];
        assert!(table.request_package_info(a, subject, &parents));
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(_))));
        let sequence = vec![wtxid(43), subject];
        assert!(table.request_package_transactions(a, subject, sequence.clone()));
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetPkgTxns(_))));
        let notfound = Inventory::Unknown {
            inv_type: MSG_PKGTXNS,
            hash: combined_package_hash(&sequence),
        };
        let inventory = CountingInventory::default();
        table.transaction_not_found(a, &[notfound], &inventory);
        assert!(
            matches!(a_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![parent_witness_item(41), parent_witness_item(42)])
        );
        assert!(a_rx.try_recv().is_err());
    }

    #[test]
    fn package_owner_disconnect_reroutes_riding_parents_to_alternates() {
        let now = Instant::now();
        let table = PeerTable::new();
        let (a, a_rx) = registered_source(&table, 8333);
        let (b, b_rx) = registered_source(&table, 8334);
        let subject = wtxid(1);
        let parents = [parent_txid(21), parent_txid(22)];
        assert!(table.request_package_info(a, subject, &parents));
        assert!(matches!(a_rx.try_recv(), Ok(Message::GetData(_))));
        table.tx_policy.lock().announce(Announcement {
            source: b,
            item: item(1),
            ready: now,
            preferred: false,
            priority: 0,
        });
        let inventory = CountingInventory::default();
        table.transaction_peer_disconnected(a, &inventory);
        assert!(a_rx.try_recv().is_err());
        assert!(
            matches!(b_rx.try_recv(), Ok(Message::GetData(items)) if items == vec![item(1), parent_witness_item(21), parent_witness_item(22)])
        );
        assert!(b_rx.try_recv().is_err());
    }

    #[test]
    fn expired_solicitation_plans_riding_parents_from_its_owner() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let mut policy = TxPolicy::default();
        let subject = wtxid(1);
        let parents = [parent_txid(31), parent_txid(32)];
        announce(&mut policy, b, 1, now, false);
        assert!(policy.solicit_package_info(a, subject, &parents, now));
        let at = now + REQUEST_LIFETIME;
        let selected = select(&mut policy, at);
        let owners: Vec<(Identity, PeerSource)> = selected
            .iter()
            .map(|(key, candidate)| (*key, candidate.source))
            .collect();
        assert_eq!(owners.len(), 3);
        assert!(owners.contains(&(Identity::Wtxid(subject.0), b)));
        for (index, parent) in parents.iter().enumerate() {
            assert!(
                owners.contains(&(Identity::Txid(parent.0), a)),
                "parent {index} falls back to its supplier"
            );
        }
        assert!(
            policy.requests[&Identity::Wtxid(subject.0)]
                .package_parents
                .is_empty(),
            "the death consumes the riding parents"
        );
        for parent in &parents {
            let expected = parent_item(parent.0.as_byte_array()[0]);
            assert!(
                selected
                    .iter()
                    .any(|(key, candidate)| *key == Identity::Txid(parent.0)
                        && candidate.item == expected),
                "policy stores canonical items; the send path flags them"
            );
        }
    }

    #[test]
    fn known_sweep_reroutes_a_dead_solicitation_through_its_parents() {
        let now = Instant::now();
        let (a, b) = (source(1), source(2));
        let mut policy = TxPolicy::default();
        let subject = wtxid(1);
        let parents = [parent_txid(41), parent_txid(42)];
        announce(&mut policy, b, 1, now, false);
        assert!(policy.solicit_package_info(a, subject, &parents, now));
        let key = Identity::Wtxid(subject.0);
        let at = now + REQUEST_LIFETIME;
        policy.forget_known(key, at);
        assert!(
            !policy.requests.contains_key(&key),
            "the dead solicitation is retired"
        );
        let selected = select(&mut policy, at);
        let owners: Vec<(Identity, PeerSource)> = selected
            .iter()
            .map(|(key, candidate)| (*key, candidate.source))
            .collect();
        assert_eq!(owners.len(), 2);
        for parent in &parents {
            assert!(
                owners.contains(&(Identity::Txid(parent.0), a)),
                "riding parents survive the known sweep"
            );
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "bounded admission contract assertions")]
mod preferred_tests;
