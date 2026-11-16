#![cfg_attr(not(feature = "fuzzing"), allow(unreachable_pub))]

use bitcoin_rs_consensus::primitives::PeerEndpoint;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::netgroup::NetGroups;
use bitcoin::secp256k1::rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const NEW_BUCKETS: usize = 1024;
const TRIED_BUCKETS: usize = 256;
const BUCKET_SIZE: usize = 64;
const MAX_NEW_REFS: usize = 8;
const MAX_RECORDS: usize = (NEW_BUCKETS + TRIED_BUCKETS) * BUCKET_SIZE;
const EMPTY_SLOT: u32 = u32::MAX;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const STALE_SECS: u64 = 30 * 24 * 60 * 60;
const FUTURE_SKEW_SECS: u64 = 10 * 60;
const MAX_DNS_RESULTS: usize = 64;
const MAX_GOSSIP: usize = 32;
const GOSSIP_CACHE_TTL: Duration = Duration::from_hours(24);
const MAX_TEMP_ATTEMPTS: usize = 8;
const SCHEMA_VERSION: u32 = 1;
const FORMAT: &str = "bitcoin-rs-addrman";
const MAX_COLLISIONS: usize = 10;
const REPLACEMENT_WINDOW: u64 = 4 * 60 * 60;
const COLLISION_TEST_WINDOW: u64 = 40 * 60;
const MAX_ANCHORS: usize = 2;
const ANCHOR_AGE: u64 = 7 * 24 * 60 * 60;
const MAX_SELECTION_PROPOSALS: usize = 45;

fn serialize_endpoint<S: serde::Serializer>(
    endpoint: &PeerEndpoint,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&crate::format_endpoint(*endpoint))
}
fn deserialize_endpoint<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<PeerEndpoint, D::Error> {
    let text = String::deserialize(deserializer)?;
    crate::parse_endpoint(&text).ok_or_else(|| serde::de::Error::custom("invalid endpoint"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Source {
    Ip(IpAddr),
    Overlay(crate::PeerAddress),
    Internal([u8; 10]),
}
impl Source {
    fn dns(seed: &str) -> Self {
        let hash = Sha256::digest(seed.as_bytes());
        let mut bytes = [0; 10];
        bytes.copy_from_slice(&hash[..10]);
        Self::Internal(bytes)
    }
    fn group(&self, groups: &NetGroups) -> Vec<u8> {
        match self {
            Self::Ip(ip) => groups.group(*ip),
            Self::Overlay(address) => groups.group(*address),
            Self::Internal(bytes) => {
                let mut group = vec![6];
                group.extend_from_slice(bytes);
                group
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    #[serde(skip)]
    creation_id: u64,
    #[serde(
        rename = "addr",
        serialize_with = "serialize_endpoint",
        deserialize_with = "deserialize_endpoint"
    )]
    endpoint: PeerEndpoint,
    #[serde(deserialize_with = "required_services")]
    services: Option<u64>,
    source: Source,
    last_seen: u64,
    last_success: u64,
    failures: u32,
    tried: bool,
    #[serde(deserialize_with = "read_new_buckets")]
    new_buckets: Vec<u16>,
    #[serde(skip)]
    last_attempt: u64,
    #[serde(skip)]
    last_count_attempt: u64,
}
impl Candidate {
    fn new(
        creation_id: u64,
        endpoint: PeerEndpoint,
        services: Option<u64>,
        source: Source,
        last_seen: u64,
    ) -> Self {
        Self {
            creation_id,
            endpoint,
            services,
            source,
            last_seen,
            last_success: 0,
            failures: 0,
            tried: false,
            new_buckets: Vec::new(),
            last_attempt: 0,
            last_count_attempt: 0,
        }
    }
    fn allows_unknown_services(&self) -> bool {
        self.last_success == 0 && matches!(self.source, Source::Internal(_))
    }
    fn ordinary_services_eligible(&self, best_block_depth: u64) -> bool {
        self.services.map_or_else(
            || self.allows_unknown_services(),
            |services| {
                crate::listener::has_all_desirable_service_flags(
                    bitcoin::p2p::ServiceFlags::from(services),
                    best_block_depth,
                )
            },
        )
    }
    fn terrible(&self, now: u64) -> bool {
        if now.saturating_sub(self.last_attempt) <= 60 {
            return false;
        }
        self.last_seen > now.saturating_add(FUTURE_SKEW_SECS)
            || now.saturating_sub(self.last_seen) > STALE_SECS
            || self.last_success == 0 && self.failures >= 3
            || now.saturating_sub(self.last_success) > 7 * 24 * 60 * 60 && self.failures >= 10
    }
    fn chance(&self, now: u64) -> f64 {
        let recent = if now.saturating_sub(self.last_attempt) < 600 {
            0.01
        } else {
            1.0
        };
        recent * 0.66_f64.powi(i32::try_from(self.failures.min(8)).unwrap_or(8))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    #[serde(
        rename = "addr",
        serialize_with = "serialize_endpoint",
        deserialize_with = "deserialize_endpoint"
    )]
    endpoint: PeerEndpoint,
    confirmed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingClaim {
    Dial,
    Feeler,
    AnchorReservation(Anchor),
    AnchorQueued(Anchor),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format: String,
    version: u32,
    magic: [u8; 4],
    secret: [u8; 32],
    #[serde(deserialize_with = "read_records")]
    records: Vec<Candidate>,
    asmap_id: Option<[u8; 32]>,
    #[serde(deserialize_with = "read_anchors")]
    anchors: Vec<Anchor>,
}

struct Manager {
    stored: Stored,
    groups: NetGroups,
    by_addr: HashMap<PeerEndpoint, usize>,
    new: Vec<u32>,
    tried: Vec<u32>,
    rng: StdRng,
    last_good: u64,
    next_creation_id: u64,
    #[cfg(test)]
    selection_proposals: usize,
    #[cfg(test)]
    selection_positions: usize,
    allow_local: bool,
    path: Option<PathBuf>,
    writable: bool,
    revision: u64,
    saved_revision: u64,
    published: bool,
    gossip_cursor: usize,
    gossip_cache: Option<(Instant, Vec<GossipRow>)>,
    addrv2_cursor: usize,
    addrv2_cache: Option<(
        Instant,
        bool,
        bool,
        Vec<bitcoin::p2p::address::AddrV2Message>,
    )>,
    pending: HashMap<PeerEndpoint, PendingClaim>,
    collisions: Vec<PeerEndpoint>,
}

#[derive(Clone, Copy, Debug)]
struct GossipRow {
    endpoint: PeerEndpoint,
    last_seen: u32,
    services: u64,
}

pub struct AddressBook {
    state: Mutex<Manager>,
    publication: Mutex<()>,
    addrv2_gossip: [std::sync::atomic::AtomicBool; 2],
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn vector(bytes: &[u8], output: &mut Vec<u8>) {
    output.push(u8::try_from(bytes.len()).unwrap_or(u8::MAX));
    output.extend_from_slice(bytes);
}
fn cheap_hash(bytes: &[u8]) -> u64 {
    let hash = Sha256::digest(Sha256::digest(bytes));
    let mut first = [0; 8];
    first.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(first)
}
fn endpoint_key(addr: PeerEndpoint) -> Vec<u8> {
    let mut bytes = match addr.address() {
        crate::PeerAddress::Ip(IpAddr::V4(ip)) => ip.to_ipv6_mapped().octets().to_vec(),
        crate::PeerAddress::Ip(IpAddr::V6(ip)) => ip.octets().to_vec(),
        crate::PeerAddress::Onion(key) => [vec![4], key.to_vec()].concat(),
        crate::PeerAddress::I2p(key) => [vec![5], key.to_vec()].concat(),
    };
    bytes.extend_from_slice(&addr.port().to_be_bytes());
    bytes
}
fn new_bucket(
    secret: &[u8; 32],
    addr: PeerEndpoint,
    source_group: &[u8],
    groups: &NetGroups,
) -> usize {
    let mut bytes = secret.to_vec();
    vector(&groups.group(addr.address()), &mut bytes);
    vector(source_group, &mut bytes);
    let first = cheap_hash(&bytes) % 64;
    let mut bytes = secret.to_vec();
    vector(source_group, &mut bytes);
    bytes.extend_from_slice(&first.to_le_bytes());
    usize::try_from(cheap_hash(&bytes) % 1024).unwrap_or_default()
}
fn tried_bucket(secret: &[u8; 32], addr: PeerEndpoint, groups: &NetGroups) -> usize {
    let mut bytes = secret.to_vec();
    vector(&endpoint_key(addr), &mut bytes);
    let first = cheap_hash(&bytes) % 8;
    let mut bytes = secret.to_vec();
    vector(&groups.group(addr.address()), &mut bytes);
    bytes.extend_from_slice(&first.to_le_bytes());
    usize::try_from(cheap_hash(&bytes) % 256).unwrap_or_default()
}
pub(crate) fn new_bucket_position(secret: &[u8; 32], addr: PeerEndpoint, bucket: usize) -> usize {
    bucket_position_with_tag(secret, addr, b'N', bucket)
}

pub(crate) fn tried_bucket_position(secret: &[u8; 32], addr: PeerEndpoint, bucket: usize) -> usize {
    bucket_position_with_tag(secret, addr, b'K', bucket)
}

fn bucket_position_with_tag(
    secret: &[u8; 32],
    addr: PeerEndpoint,
    tag: u8,
    bucket: usize,
) -> usize {
    let mut bytes = secret.to_vec();
    bytes.push(tag);
    bytes.extend_from_slice(&i32::try_from(bucket).unwrap_or_default().to_le_bytes());
    vector(&endpoint_key(addr), &mut bytes);
    usize::try_from(cheap_hash(&bytes) % 64).unwrap_or_default()
}

impl Manager {
    fn new(magic: [u8; 4], allow_local: bool, path: Option<PathBuf>, groups: NetGroups) -> Self {
        let mut rng = StdRng::from_entropy();
        let mut secret = [0; 32];
        rng.fill_bytes(&mut secret);
        Self {
            stored: Stored {
                format: FORMAT.to_owned(),
                version: SCHEMA_VERSION,
                magic,
                secret,
                records: Vec::new(),
                asmap_id: groups.identity(),
                anchors: Vec::new(),
            },
            groups,
            by_addr: HashMap::new(),
            new: vec![EMPTY_SLOT; NEW_BUCKETS * BUCKET_SIZE],
            tried: vec![EMPTY_SLOT; TRIED_BUCKETS * BUCKET_SIZE],
            rng,
            last_good: 1,
            next_creation_id: 0,
            #[cfg(test)]
            selection_proposals: 0,
            #[cfg(test)]
            selection_positions: 0,
            allow_local,
            path,
            writable: true,
            revision: 0,
            saved_revision: 0,
            published: false,
            gossip_cursor: 0,
            gossip_cache: None,
            addrv2_cursor: 0,
            addrv2_cache: None,
            pending: HashMap::new(),
            collisions: Vec::new(),
        }
    }
    fn new_slot(&self, addr: PeerEndpoint, bucket: usize) -> usize {
        bucket * BUCKET_SIZE + new_bucket_position(&self.stored.secret, addr, bucket)
    }
    fn tried_slot(&self, addr: PeerEndpoint) -> usize {
        let bucket = tried_bucket(&self.stored.secret, addr, &self.groups);
        bucket * BUCKET_SIZE + tried_bucket_position(&self.stored.secret, addr, bucket)
    }
    fn install_indexes(&mut self) {
        self.by_addr.clear();
        self.new.fill(EMPTY_SLOT);
        self.tried.fill(EMPTY_SLOT);
        for (index, entry) in self.stored.records.iter().enumerate() {
            self.by_addr.insert(entry.endpoint, index);
            let id = u32::try_from(index).unwrap_or(EMPTY_SLOT);
            if entry.tried {
                let slot = self.tried_slot(entry.endpoint);
                self.tried[slot] = id;
            } else {
                for bucket in &entry.new_buckets {
                    let slot = self.new_slot(entry.endpoint, usize::from(*bucket));
                    self.new[slot] = id;
                }
            }
        }
    }
    fn remove_identity(&mut self, index: usize) {
        debug_assert!(
            !self.stored.records[index].tried && self.stored.records[index].new_buckets.is_empty()
        );
        let addr = self.stored.records[index].endpoint;
        self.by_addr.remove(&addr);
        self.collisions.retain(|candidate| *candidate != addr);
        self.stored.anchors.retain(|anchor| anchor.endpoint != addr);
        self.stored.records.swap_remove(index);
        if let Some(moved) = self.stored.records.get(index) {
            let addr = moved.endpoint;
            let tried = moved.tried;
            let buckets = moved.new_buckets.clone();
            self.by_addr.insert(addr, index);
            let id = u32::try_from(index).unwrap_or(EMPTY_SLOT);
            if tried {
                let slot = self.tried_slot(addr);
                self.tried[slot] = id;
            } else {
                for bucket in buckets {
                    let slot = self.new_slot(addr, usize::from(bucket));
                    self.new[slot] = id;
                }
            }
        }
    }
    fn clear_new(&mut self, slot: usize) {
        let id = self.new[slot];
        if id == EMPTY_SLOT {
            return;
        }
        self.new[slot] = EMPTY_SLOT;
        let index = usize::try_from(id).unwrap_or_default();
        self.stored.records[index]
            .new_buckets
            .retain(|bucket| usize::from(*bucket) != slot / BUCKET_SIZE);
        if self.stored.records[index].new_buckets.is_empty() {
            self.remove_identity(index);
        }
    }
    fn promote(&mut self, addr: PeerEndpoint) -> bool {
        let Some(&index) = self.by_addr.get(&addr) else {
            return false;
        };
        if self.stored.records[index].tried {
            return false;
        }
        let slot = self.tried_slot(addr);
        let incumbent = (self.tried[slot] != EMPTY_SLOT).then(|| {
            self.stored.records[usize::try_from(self.tried[slot]).unwrap_or_default()].endpoint
        });
        let demotion = incumbent.map(|old| {
            let entry = &self.stored.records[self.by_addr[&old]];
            let bucket = new_bucket(
                &self.stored.secret,
                old,
                &entry.source.group(&self.groups),
                &self.groups,
            );
            (old, bucket, self.new_slot(old, bucket))
        });
        if self.promotion_blocked(addr) {
            return false;
        }
        for bucket in std::mem::take(&mut self.stored.records[index].new_buckets) {
            let new_slot = self.new_slot(addr, usize::from(bucket));
            self.new[new_slot] = EMPTY_SLOT;
        }
        if let Some((old, bucket, new_slot)) = demotion {
            self.tried[slot] = EMPTY_SLOT;
            self.stored.records[self.by_addr[&old]].tried = false;
            self.clear_new(new_slot);
            let old_index = self.by_addr[&old];
            self.stored.records[old_index]
                .new_buckets
                .push(u16::try_from(bucket).unwrap_or_default());
            self.new[new_slot] = u32::try_from(old_index).unwrap_or(EMPTY_SLOT);
        }
        let index = self.by_addr[&addr];
        self.stored.records[index].tried = true;
        self.tried[slot] = u32::try_from(index).unwrap_or(EMPTY_SLOT);
        true
    }
    fn promotion_blocked(&self, addr: PeerEndpoint) -> bool {
        let incumbent = self.tried[self.tried_slot(addr)];
        if incumbent == EMPTY_SLOT {
            return false;
        }
        let old = &self.stored.records[usize::try_from(incumbent).unwrap_or_default()];
        let bucket = new_bucket(
            &self.stored.secret,
            old.endpoint,
            &old.source.group(&self.groups),
            &self.groups,
        );
        let victim = self.new[self.new_slot(old.endpoint, bucket)];
        if victim == EMPTY_SLOT {
            return false;
        }
        let victim = &self.stored.records[usize::try_from(victim).unwrap_or_default()];
        victim.endpoint != addr
            && victim.new_buckets.len() == 1
            && self.pending.contains_key(&victim.endpoint)
    }
    fn restore_anchors(&mut self, anchors: Vec<Anchor>, now: u64) {
        let before = self.stored.anchors.clone();
        for anchor in anchors {
            if anchor.confirmed_at > now.saturating_add(FUTURE_SKEW_SECS)
                || now.saturating_sub(anchor.confirmed_at) > ANCHOR_AGE
                || self
                    .by_addr
                    .get(&anchor.endpoint)
                    .is_none_or(|index| self.stored.records[*index].last_success == 0)
            {
                continue;
            }
            if let Some(existing) = self
                .stored
                .anchors
                .iter_mut()
                .find(|entry| entry.endpoint == anchor.endpoint)
            {
                if existing.confirmed_at < anchor.confirmed_at {
                    *existing = anchor;
                }
            } else if self.stored.anchors.len() < MAX_ANCHORS {
                self.stored.anchors.push(anchor);
            }
        }
        self.stored.anchors.sort_by_key(|anchor| anchor.endpoint);
        if self.stored.anchors != before {
            self.revision = self.revision.wrapping_add(1);
        }
    }
    fn set_services(&mut self, addr: PeerEndpoint, services: u64) {
        if let Some(index) = self.by_addr.get(&addr).copied()
            && self.stored.records[index].services != Some(services)
        {
            self.stored.records[index].services = Some(services);
            self.revision = self.revision.wrapping_add(1);
        }
    }
    fn good(&mut self, addr: PeerEndpoint, now: u64) -> bool {
        self.good_internal(addr, true, now)
    }
    fn good_replace(&mut self, addr: PeerEndpoint, now: u64) -> bool {
        self.good_internal(addr, false, now)
    }
    fn good_internal(&mut self, addr: PeerEndpoint, test_before_evict: bool, now: u64) -> bool {
        self.last_good = now;
        let Some(index) = self.by_addr.get(&addr).copied() else {
            return false;
        };
        let entry = &mut self.stored.records[index];
        let changed = entry.last_success != now || entry.failures != 0;
        entry.last_success = now;
        entry.last_attempt = now;
        entry.failures = 0;
        if changed {
            self.revision = self.revision.wrapping_add(1);
        }
        if entry.tried {
            return false;
        }
        let slot = self.tried_slot(addr);
        if test_before_evict && self.tried[slot] != EMPTY_SLOT {
            if self.collisions.len() < MAX_COLLISIONS && !self.collisions.contains(&addr) {
                self.collisions.push(addr);
                self.collisions.sort_by_key(|endpoint| {
                    self.stored.records[self.by_addr[endpoint]].creation_id
                });
            }
            return false;
        }
        let promoted = self.promote(addr);
        if promoted {
            self.revision = self.revision.wrapping_add(1);
        }
        promoted
    }
    fn resolve_collisions(
        &mut self,
        protected: &HashSet<PeerEndpoint>,
        allowed: &HashSet<PeerEndpoint>,
        now: u64,
    ) {
        for addr in self.collisions.clone() {
            let Some(&index) = self.by_addr.get(&addr) else {
                self.collisions.retain(|candidate| *candidate != addr);
                continue;
            };
            if self.stored.records[index].tried {
                self.collisions.retain(|candidate| *candidate != addr);
                continue;
            }
            let slot = self.tried_slot(addr);
            let old = self.tried[slot];
            let replace = if old == EMPTY_SLOT {
                true
            } else {
                let old = &self.stored.records[usize::try_from(old).unwrap_or_default()];
                if now.saturating_sub(old.last_success) < REPLACEMENT_WINDOW {
                    self.collisions.retain(|candidate| *candidate != addr);
                    continue;
                }
                if protected.contains(&old.endpoint)
                    || self.pending.contains_key(&old.endpoint)
                    || !allowed.contains(&old.endpoint)
                {
                    continue;
                }
                if now.saturating_sub(old.last_attempt) < REPLACEMENT_WINDOW {
                    now.saturating_sub(old.last_attempt) > 60
                } else {
                    now.saturating_sub(self.stored.records[index].last_success)
                        > COLLISION_TEST_WINDOW
                }
            };
            if replace && allowed.contains(&addr) && !self.promotion_blocked(addr) {
                if self.good_replace(addr, now) {
                    self.collisions.retain(|candidate| *candidate != addr);
                }
            }
        }
    }
    fn update_existing_entry(
        &mut self,
        index: usize,
        services: Option<u64>,
        seen: u64,
        now: u64,
        time_penalty: u64,
    ) -> Option<usize> {
        let entry = &mut self.stored.records[index];
        let before = (entry.last_seen, entry.services);
        let interval = if now.saturating_sub(seen) < 24 * 60 * 60 {
            60 * 60
        } else {
            24 * 60 * 60
        };
        if entry.last_seen < seen.saturating_sub(interval).saturating_sub(time_penalty) {
            entry.last_seen = seen.saturating_sub(time_penalty);
        }
        if let Some(services) = services.filter(|bits| *bits != 0 || entry.services.is_some()) {
            entry.services = Some(entry.services.unwrap_or(0) | services);
        }
        if before != (entry.last_seen, entry.services) {
            self.revision = self.revision.wrapping_add(1);
        }
        if seen <= entry.last_seen || entry.tried || entry.new_buckets.len() >= MAX_NEW_REFS {
            return None;
        }
        let refs = entry.new_buckets.len();
        if refs != 0 && self.rng.gen_range(0..(1_usize << refs)) != 0 {
            return None;
        }
        Some(refs)
    }

    fn can_evict_new_occupant(
        &self,
        occupant: u32,
        addr: PeerEndpoint,
        now: u64,
        refs: usize,
    ) -> bool {
        let old = &self.stored.records[usize::try_from(occupant).unwrap_or_default()];
        if old.endpoint == addr {
            return false;
        }
        let final_pending = old.new_buckets.len() == 1 && self.pending.contains_key(&old.endpoint);
        !final_pending && (old.terrible(now) || old.new_buckets.len() > 1 && refs == 0)
    }

    fn get_or_insert_entry(
        &mut self,
        candidate: Candidate,
        next_creation_id: u64,
    ) -> Option<usize> {
        let addr = candidate.endpoint;
        if let Some(index) = self.by_addr.get(&addr).copied() {
            Some(index)
        } else {
            if self.stored.records.len() >= MAX_RECORDS {
                return None;
            }
            let index = self.stored.records.len();
            self.stored.records.push(candidate);
            self.by_addr.insert(addr, index);
            self.next_creation_id = next_creation_id;
            Some(index)
        }
    }
    fn learn(
        &mut self,
        addr: PeerEndpoint,
        services: Option<u64>,
        source: Source,
        seen: u64,
        now: u64,
        time_penalty: u64,
    ) -> bool {
        let addr = canonical(addr);
        if services.is_none() && matches!(source, Source::Ip(_) | Source::Overlay(_))
            || !routable(addr, self.allow_local)
            || seen > now.saturating_add(FUTURE_SKEW_SECS)
            || now.saturating_sub(seen) > STALE_SECS
        {
            return false;
        }
        let self_source = match &source {
            Source::Ip(ip) => Some(crate::netgroup::canonical_ip(*ip)) == addr.address().ip(),
            Source::Overlay(address) => *address == addr.address(),
            Source::Internal(_) => false,
        };
        let time_penalty = if self_source { 0 } else { time_penalty };
        let existing = self.by_addr.get(&addr).copied();
        let refs = if let Some(index) = existing {
            let Some(existing_refs) =
                self.update_existing_entry(index, services, seen, now, time_penalty)
            else {
                return false;
            };
            existing_refs
        } else {
            0
        };
        let bucket = new_bucket(
            &self.stored.secret,
            addr,
            &source.group(&self.groups),
            &self.groups,
        );
        let slot = self.new_slot(addr, bucket);
        let occupant = self.new[slot];
        if occupant != EMPTY_SLOT && !self.can_evict_new_occupant(occupant, addr, now, refs) {
            return false;
        }
        if existing.is_none() && self.stored.records.len() == MAX_RECORDS && occupant == EMPTY_SLOT
        {
            return false;
        }
        let Some(next_creation_id) = self
            .next_creation_id
            .checked_add(u64::from(existing.is_none()))
        else {
            return false;
        };
        self.clear_new(slot);
        let candidate = Candidate::new(
            self.next_creation_id,
            addr,
            services,
            source,
            seen.saturating_sub(time_penalty),
        );
        let Some(index) = self.get_or_insert_entry(candidate, next_creation_id) else {
            return false;
        };
        self.stored.records[index]
            .new_buckets
            .push(u16::try_from(bucket).unwrap_or_default());
        self.new[slot] = u32::try_from(index).unwrap_or(EMPTY_SLOT);
        self.revision = self.revision.wrapping_add(1);
        true
    }
    fn select(&mut self, eligible: &[bool], now: u64) -> Option<PeerEndpoint> {
        #[cfg(test)]
        {
            self.selection_proposals = 0;
            self.selection_positions = 0;
        }
        let mut new_buckets = [false; NEW_BUCKETS];
        let mut tried_buckets = [false; TRIED_BUCKETS];
        for (entry, eligible) in self.stored.records.iter().zip(eligible) {
            if !eligible {
                continue;
            }
            if entry.tried {
                tried_buckets[tried_bucket(&self.stored.secret, entry.endpoint, &self.groups)] =
                    true;
            } else {
                for bucket in &entry.new_buckets {
                    new_buckets[usize::from(*bucket)] = true;
                }
            }
        }
        let new: Vec<_> = new_buckets
            .iter()
            .enumerate()
            .filter_map(|(i, set)| set.then_some(i))
            .collect();
        let tried: Vec<_> = tried_buckets
            .iter()
            .enumerate()
            .filter_map(|(i, set)| set.then_some(i))
            .collect();
        if new.is_empty() && tried.is_empty() {
            return None;
        }
        let search_tried = new.is_empty() || !tried.is_empty() && self.rng.gen_bool(0.5);
        let buckets = if search_tried { &tried } else { &new };
        let table = if search_tried { &self.tried } else { &self.new };
        let mut factor = 1.0;
        for _ in 0..MAX_SELECTION_PROPOSALS {
            #[cfg(test)]
            {
                self.selection_proposals += 1;
            }
            let bucket = buckets[self.rng.gen_range(0..buckets.len())];
            let start = self.rng.gen_range(0..BUCKET_SIZE);
            let id = (0..BUCKET_SIZE).find_map(|offset| {
                #[cfg(test)]
                {
                    self.selection_positions += 1;
                }
                let id = table[bucket * BUCKET_SIZE + (start + offset) % BUCKET_SIZE];
                if id == EMPTY_SLOT {
                    return None;
                }
                let index = usize::try_from(id).unwrap_or_default();
                eligible[index].then_some(index)
            })?;
            let entry = &self.stored.records[id];
            let draw = f64::from(self.rng.gen_range(0..(1_u32 << 30)));
            if draw < factor * entry.chance(now) * f64::from(1_u32 << 30) {
                return Some(entry.endpoint);
            }
            factor *= 1.2;
        }
        debug_assert!(false, "minimum chance guarantees acceptance by proposal45");
        None
    }
}

pub(crate) fn canonical(addr: PeerEndpoint) -> PeerEndpoint {
    addr.to_canonical()
}

fn routable(addr: PeerEndpoint, allow_local: bool) -> bool {
    if addr.port() == 0 && !matches!(addr.address(), crate::PeerAddress::I2p(_))
        || addr.address().is_unspecified()
        || addr.address().is_multicast()
    {
        return false;
    }
    match addr.address() {
        crate::PeerAddress::Onion(_) | crate::PeerAddress::I2p(_) => true,
        crate::PeerAddress::Ip(IpAddr::V4(ip)) => {
            let octets = ip.octets();
            if ip.is_broadcast() || octets[0] == 0 || octets[0] >= 240 {
                return false;
            }
            if allow_local {
                return true;
            }
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_documentation()
                || octets[0] == 100 && (64..=127).contains(&octets[1])
                || octets[0] == 198 && (18..=19).contains(&octets[1])
                || octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        }
        crate::PeerAddress::Ip(IpAddr::V6(ip)) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return routable(PeerEndpoint::new(IpAddr::V4(ip), addr.port()), allow_local);
            }
            if allow_local {
                return true;
            }
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || segments[0] & 0xe000 != 0x2000
                || segments[0] == 0x2001 && matches!(segments[1], 0 | 2 | 0x10..=0x2f | 0xdb8))
        }
    }
}

impl AddressBook {
    pub fn open(
        path: Option<PathBuf>,
        magic: [u8; 4],
        allow_local: bool,
        asmap_path: Option<&Path>,
    ) -> Arc<Self> {
        let scoped = path.as_deref().map(|base| network_path(base, magic));
        let groups = NetGroups::load(asmap_path);
        let writable = asmap_path.is_none() || groups.identity().is_some();
        let mut manager = Manager::new(magic, allow_local, scoped.clone(), groups);
        manager.writable = writable;
        if let Some(scoped) = scoped {
            let loaded = match read_book(&scoped, Some(magic), allow_local, &manager.groups) {
                Ok(Some(loaded)) => Some((scoped, true, loaded)),
                Ok(None) => path.and_then(|legacy| match read_book(&legacy, None, true, &manager.groups) {
                    Ok(Some(loaded)) if loaded.magic == magic => Some((legacy, false, loaded)),
                    Ok(_) => None,
                    Err(error) => {
                        tracing::warn!(path=%legacy.display(), %error, "legacy address book unavailable; preserving file and disabling writes");
                        manager.writable = false; None
                    }
                }),
                Err(error) => {
                    tracing::warn!(path=%scoped.display(), %error, "address book unavailable; preserving file and disabling writes");
                    manager.writable = false; None
                }
            };
            if let Some((source_path, scoped_source, loaded)) = loaded {
                if let Some(stored) = loaded.stored {
                    if stored
                        .records
                        .iter()
                        .all(|entry| routable(entry.endpoint, allow_local))
                    {
                        manager.stored = stored;
                        manager.published = scoped_source;
                        let rebucket = manager.stored.asmap_id != manager.groups.identity();
                        if rebucket {
                            manager.rebucket();
                            manager.stored.asmap_id = manager.groups.identity();
                            manager.revision = 1;
                        } else {
                            manager.install_indexes();
                        }
                        for (index, entry) in manager.stored.records.iter_mut().enumerate() {
                            entry.creation_id = u64::try_from(index).unwrap_or(u64::MAX);
                        }
                        manager.next_creation_id =
                            u64::try_from(manager.stored.records.len()).unwrap_or(u64::MAX);
                        if !scoped_source {
                            manager.revision = manager.revision.wrapping_add(1);
                        }
                    } else {
                        tracing::warn!(path=%source_path.display(), "address book contains inadmissible addresses; preserving file and disabling writes");
                        manager.writable = false;
                    }
                } else if manager.writable {
                    match preserve_incompatible(&source_path, &loaded.bytes) {
                        Ok(backup) => {
                            tracing::warn!(path=%source_path.display(), backup=%backup.display(), "pre-release address book preserved; starting fresh discovery without migration");
                            manager.published = scoped_source;
                            manager.revision = 1;
                        }
                        Err(error) => {
                            tracing::warn!(path=%source_path.display(), %error, "address book preservation failed; disabling writes");
                            manager.writable = false;
                        }
                    }
                }
            }
        }
        Arc::new(Self {
            state: Mutex::new(manager),
            publication: Mutex::new(()),
            addrv2_gossip: [
                std::sync::atomic::AtomicBool::new(false),
                std::sync::atomic::AtomicBool::new(false),
            ],
        })
    }

    pub(crate) fn set_addrv2_gossip(&self, tor_enabled: bool, i2p_enabled: bool) {
        self.addrv2_gossip[0].store(tor_enabled, std::sync::atomic::Ordering::Release);
        self.addrv2_gossip[1].store(i2p_enabled, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn gossip_addrv2(&self, now: u64) -> Vec<bitcoin::p2p::address::AddrV2Message> {
        self.gossip_addrv2_at(now, Instant::now())
    }
    fn gossip_addrv2_at(
        &self,
        now: u64,
        tick: Instant,
    ) -> Vec<bitcoin::p2p::address::AddrV2Message> {
        let tor = self.addrv2_gossip[0].load(std::sync::atomic::Ordering::Acquire);
        let i2p = self.addrv2_gossip[1].load(std::sync::atomic::Ordering::Acquire);
        let mut manager = self.state.lock();
        if let Some((expires, cached_tor, cached_i2p, response)) = &manager.addrv2_cache {
            if tick < *expires && *cached_tor == tor && *cached_i2p == i2p {
                return response.clone();
            }
        }
        let len = manager.stored.records.len();
        let start = manager.addrv2_cursor.checked_rem(len).unwrap_or_default();
        let mut gossip = Vec::with_capacity(MAX_GOSSIP.min(len));
        for offset in 0..len {
            let index = (start + offset) % len;
            manager.addrv2_cursor = (index + 1) % len;
            let entry = &manager.stored.records[index];
            if entry.terrible(now) {
                continue;
            }
            if !crate::endpoint::addrv2_gossip_enabled(entry.endpoint, tor, i2p) {
                continue;
            }
            gossip.push(crate::endpoint::endpoint_to_addrv2(
                entry.endpoint,
                u32::try_from(entry.last_seen).unwrap_or(u32::MAX),
                bitcoin::p2p::ServiceFlags::from(entry.services.unwrap_or(0)),
            ));
            if gossip.len() == MAX_GOSSIP {
                break;
            }
        }
        manager.addrv2_cache = Some((tick + GOSSIP_CACHE_TTL, tor, i2p, gossip.clone()));
        gossip
    }

    pub(crate) fn connected(&self, addr: PeerEndpoint, now: u64) {
        let addr = canonical(addr);
        let mut manager = self.state.lock();
        if let Some(index) = manager.by_addr.get(&addr).copied() {
            let entry = &mut manager.stored.records[index];
            if now.saturating_sub(entry.last_seen) > 20 * 60 {
                entry.last_seen = now;
                manager.revision = manager.revision.wrapping_add(1);
            }
        }
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().stored.records.len()
    }
    #[cfg_attr(not(feature = "fuzzing"), allow(dead_code))]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    #[cfg_attr(not(feature = "fuzzing"), allow(dead_code))]
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.state.lock().writable
    }
    pub(crate) fn learn_dns(&self, seed: &str, addresses: &[PeerEndpoint], now: u64) {
        let source = Source::dns(seed);
        let mut manager = self.state.lock();
        for &addr in addresses.iter().take(MAX_DNS_RESULTS) {
            manager.learn(addr, None, source.clone(), now, now, 0);
        }
    }
    pub(crate) fn learn_peer(
        &self,
        source: crate::PeerRemote,
        addresses: &[(PeerEndpoint, u64, u64)],
        now: u64,
    ) {
        let source = match source {
            crate::PeerRemote::AnonymousTor(_) => return,
            crate::PeerRemote::Endpoint(endpoint) => endpoint.address(),
        };
        let mut manager = self.state.lock();
        for &(addr, services, seen) in addresses.iter().take(MAX_GOSSIP) {
            manager.learn(
                addr,
                Some(services),
                match source {
                    crate::PeerAddress::Ip(ip) => Source::Ip(ip),
                    address => Source::Overlay(address),
                },
                seen,
                now,
                2 * 60 * 60,
            );
        }
    }
    pub(crate) fn select(
        &self,
        connected: &[PeerEndpoint],
        grouped: &[PeerEndpoint],
        now: u64,
        best_block_depth: u64,
        mut allowed: impl FnMut(PeerEndpoint) -> bool,
    ) -> Option<PeerEndpoint> {
        let connected: HashSet<_> = connected.iter().copied().map(canonical).collect();
        let addresses: Vec<_> = {
            let manager = self.state.lock();
            manager
                .stored
                .records
                .iter()
                .map(|entry| entry.endpoint)
                .collect()
        };
        let allowed: HashSet<_> = addresses
            .into_iter()
            .filter(|addr| allowed(*addr))
            .collect();
        let mut manager = self.state.lock();
        let groups: HashSet<_> = grouped
            .iter()
            .chain(
                manager
                    .pending
                    .iter()
                    .filter_map(|(addr, claim)| (*claim != PendingClaim::Feeler).then_some(addr)),
            )
            .map(|addr| manager.groups.group(addr.address()))
            .collect();
        let eligible: Vec<_> = manager
            .stored
            .records
            .iter()
            .map(|entry| {
                entry.ordinary_services_eligible(best_block_depth)
                    && allowed.contains(&entry.endpoint)
                    && !connected.contains(&entry.endpoint)
                    && !manager.pending.contains_key(&entry.endpoint)
                    && !groups.contains(&manager.groups.group(entry.endpoint.address()))
            })
            .collect();
        manager.select(&eligible, now)
    }
    pub(crate) fn ordinary_services_eligible(
        &self,
        addr: PeerEndpoint,
        best_block_depth: u64,
    ) -> bool {
        let manager = self.state.lock();
        manager.by_addr.get(&canonical(addr)).is_none_or(|index| {
            manager.stored.records[*index].ordinary_services_eligible(best_block_depth)
        })
    }

    pub(crate) fn advertises(
        &self,
        addr: PeerEndpoint,
        services: bitcoin::p2p::ServiceFlags,
    ) -> bool {
        let manager = self.state.lock();
        manager.by_addr.get(&canonical(addr)).is_some_and(|index| {
            manager.stored.records[*index]
                .services
                .is_some_and(|known| bitcoin::p2p::ServiceFlags::from(known).has(services))
        })
    }

    pub(crate) fn count_failure(&self, outbound: &[PeerEndpoint], maximum: usize) -> bool {
        let threshold = maximum.saturating_sub(1).min(2);
        let manager = self.state.lock();
        let mut groups = HashSet::new();
        for address in outbound {
            groups.insert(manager.groups.group(address.address()));
            if groups.len() >= threshold {
                return true;
            }
        }
        threshold == 0
    }

    pub(crate) fn queued(&self, addr: PeerEndpoint) -> bool {
        use std::collections::hash_map::Entry;
        match self.state.lock().pending.entry(canonical(addr)) {
            Entry::Vacant(entry) => {
                entry.insert(PendingClaim::Dial);
                true
            }
            Entry::Occupied(entry) => *entry.get() == PendingClaim::Dial,
        }
    }
    pub(crate) fn queued_feeler(&self, addr: PeerEndpoint) -> bool {
        use std::collections::hash_map::Entry;
        let mut manager = self.state.lock();
        if manager
            .pending
            .values()
            .any(|claim| *claim == PendingClaim::Feeler)
        {
            return false;
        }
        match manager.pending.entry(canonical(addr)) {
            Entry::Vacant(entry) => {
                entry.insert(PendingClaim::Feeler);
                true
            }
            Entry::Occupied(_) => false,
        }
    }
    pub(crate) fn is_pending(&self, addr: PeerEndpoint) -> bool {
        self.state.lock().pending.contains_key(&canonical(addr))
    }
    pub(crate) fn is_feeler(&self, addr: PeerEndpoint) -> bool {
        self.state.lock().pending.get(&canonical(addr)) == Some(&PendingClaim::Feeler)
    }
    pub(crate) fn queue_anchor(&self, addr: PeerEndpoint) -> bool {
        let mut manager = self.state.lock();
        let Some(claim) = manager.pending.get_mut(&canonical(addr)) else {
            return false;
        };
        if let PendingClaim::AnchorReservation(anchor) = claim {
            *claim = PendingClaim::AnchorQueued(anchor.clone());
            true
        } else {
            false
        }
    }
    pub(crate) fn defer_anchor(&self, addr: PeerEndpoint) {
        if let Some(claim) = self.state.lock().pending.get_mut(&canonical(addr))
            && let PendingClaim::AnchorQueued(anchor) = claim
        {
            *claim = PendingClaim::AnchorReservation(anchor.clone());
        }
    }
    pub(crate) fn anchor_dispatched(&self, addr: PeerEndpoint) -> bool {
        if let Some(claim) = self.state.lock().pending.get_mut(&canonical(addr))
            && matches!(claim, PendingClaim::AnchorQueued(_))
        {
            *claim = PendingClaim::Dial;
            true
        } else {
            false
        }
    }
    pub(crate) fn anchor_eligible(
        &self,
        addr: PeerEndpoint,
        active: &[PeerEndpoint],
        now: u64,
    ) -> bool {
        let addr = canonical(addr);
        let manager = self.state.lock();
        manager.by_addr.get(&addr).is_some_and(|index| {
            let entry = &manager.stored.records[*index];
            entry.last_success != 0
                && now.saturating_sub(entry.last_seen) <= STALE_SECS
                && matches!(
                    manager.pending.get(&addr),
                    Some(PendingClaim::AnchorReservation(_))
                )
                && !active.iter().any(|other| {
                    canonical(*other) == addr
                        || manager.groups.group(other.address())
                            == manager.groups.group(addr.address())
                })
        })
    }
    pub(crate) fn reject_queued(&self, addr: PeerEndpoint) {
        self.reject_queued_claim(addr, &PendingClaim::Dial);
    }
    pub(crate) fn reject_queued_feeler(&self, addr: PeerEndpoint) {
        self.reject_queued_claim(addr, &PendingClaim::Feeler);
    }
    fn reject_queued_claim(&self, addr: PeerEndpoint, expected: &PendingClaim) {
        let addr = canonical(addr);
        let mut manager = self.state.lock();
        if manager.pending.get(&addr) == Some(expected) {
            manager.pending.remove(&addr);
        }
    }
    pub(crate) fn unqueue(&self, addr: PeerEndpoint) {
        self.state.lock().pending.remove(&canonical(addr));
    }
    pub(crate) fn pending_count_excluding(&self, active: &[PeerEndpoint]) -> usize {
        let active: HashSet<_> = active.iter().copied().map(canonical).collect();
        self.state
            .lock()
            .pending
            .iter()
            .filter(|(addr, claim)| {
                matches!(claim, PendingClaim::Dial | PendingClaim::AnchorQueued(_))
                    && !active.contains(addr)
            })
            .count()
    }
    pub(crate) fn attempted(&self, addr: PeerEndpoint, now: u64) {
        self.record_attempt(addr, false, now);
    }
    pub(crate) fn attempt_failed(&self, addr: PeerEndpoint, now: u64) {
        self.record_attempt(addr, true, now);
    }
    fn record_attempt(&self, addr: PeerEndpoint, count_failure: bool, now: u64) {
        let addr = canonical(addr);
        let mut manager = self.state.lock();
        let last_good = manager.last_good;
        if let Some(index) = manager.by_addr.get(&addr).copied() {
            let entry = &mut manager.stored.records[index];
            entry.last_attempt = now;
            if count_failure && entry.last_count_attempt < last_good {
                entry.last_count_attempt = now;
                entry.failures = entry.failures.saturating_add(1);
                manager.revision = manager.revision.wrapping_add(1);
            }
        }
    }
    pub(crate) fn set_services(&self, addr: PeerEndpoint, services: u64) {
        self.state.lock().set_services(canonical(addr), services);
    }
    pub(crate) fn netgroup(&self, ip: impl Into<crate::PeerAddress>) -> Vec<u8> {
        self.state.lock().groups.group(ip)
    }
    pub(crate) fn succeeded(&self, addr: PeerEndpoint, services: u64, now: u64) {
        let addr = canonical(addr);
        let mut manager = self.state.lock();
        manager.set_services(addr, services);
        manager.good(addr, now);
    }
    pub(crate) fn resolve_collisions(
        &self,
        active: &[PeerEndpoint],
        now: u64,
        mut allowed: impl FnMut(PeerEndpoint) -> bool,
    ) {
        let addresses = {
            let manager = self.state.lock();
            let mut addresses = HashSet::with_capacity(MAX_COLLISIONS * 2);
            for &addr in &manager.collisions {
                addresses.insert(addr);
                let incumbent = manager.tried[manager.tried_slot(addr)];
                if incumbent != EMPTY_SLOT {
                    addresses.insert(
                        manager.stored.records[usize::try_from(incumbent).unwrap_or_default()]
                            .endpoint,
                    );
                }
            }
            addresses
        };
        let allowed: HashSet<_> = addresses
            .into_iter()
            .filter(|addr| allowed(*addr))
            .collect();
        let protected = active.iter().copied().map(canonical).collect();
        self.state
            .lock()
            .resolve_collisions(&protected, &allowed, now);
    }
    pub(crate) fn feeler(
        &self,
        active: &[PeerEndpoint],
        connected: &[PeerEndpoint],
        now: u64,
        mut allowed: impl FnMut(PeerEndpoint) -> bool,
    ) -> Option<PeerEndpoint> {
        let connected: HashSet<_> = connected
            .iter()
            .map(|addr| canonical(*addr).address())
            .collect();
        let active: HashSet<_> = active.iter().copied().map(canonical).collect();
        let addresses: Vec<_> = {
            let manager = self.state.lock();
            manager
                .stored
                .records
                .iter()
                .map(|entry| entry.endpoint)
                .collect()
        };
        let allowed: HashSet<_> = addresses
            .into_iter()
            .filter(|addr| allowed(*addr))
            .collect();
        let useful_services = (bitcoin::p2p::ServiceFlags::NETWORK
            | bitcoin::p2p::ServiceFlags::NETWORK_LIMITED)
            .to_u64();
        let mut manager = self.state.lock();
        if manager
            .pending
            .values()
            .any(|claim| *claim == PendingClaim::Feeler)
        {
            return None;
        }
        if !manager.collisions.is_empty() {
            let count = manager.collisions.len();
            let chosen = manager.rng.gen_range(0..count);
            let challenger = manager.collisions[chosen];
            let slot = manager.tried_slot(challenger);
            let incumbent = manager.tried[slot];
            if incumbent != EMPTY_SLOT {
                let addr =
                    manager.stored.records[usize::try_from(incumbent).unwrap_or_default()].endpoint;
                if connected.contains(&addr.address()) {
                    manager.good(addr, now);
                } else if manager.stored.records[usize::try_from(incumbent).unwrap_or_default()]
                    .services
                    .unwrap_or(0)
                    & useful_services
                    != 0
                    && allowed.contains(&addr)
                    && !active.contains(&addr)
                    && !manager.pending.contains_key(&addr)
                {
                    return Some(addr);
                }
            }
        }
        let eligible: Vec<_> = manager
            .stored
            .records
            .iter()
            .map(|entry| {
                !entry.tried
                    && entry.services.unwrap_or(0) & useful_services != 0
                    && allowed.contains(&entry.endpoint)
                    && !active.contains(&entry.endpoint)
                    && !manager.pending.contains_key(&entry.endpoint)
            })
            .collect();
        manager.select(&eligible, now)
    }
    pub(crate) fn remember_anchors(&self, demonstrated: &[PeerEndpoint], now: u64) {
        let mut manager = self.state.lock();
        let mut addresses: Vec<_> = demonstrated
            .iter()
            .copied()
            .map(canonical)
            .filter(|addr| {
                manager
                    .stored
                    .records
                    .iter()
                    .any(|entry| entry.endpoint == *addr && entry.last_success != 0)
            })
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        addresses.truncate(MAX_ANCHORS);
        let anchors: Vec<_> = addresses
            .into_iter()
            .map(|addr| {
                manager
                    .stored
                    .anchors
                    .iter()
                    .find(|anchor| {
                        anchor.endpoint == addr && now.saturating_sub(anchor.confirmed_at) < 3600
                    })
                    .cloned()
                    .unwrap_or(Anchor {
                        endpoint: addr,
                        confirmed_at: now,
                    })
            })
            .collect();
        if anchors != manager.stored.anchors {
            manager.stored.anchors = anchors;
            manager.revision = manager.revision.wrapping_add(1);
        }
    }

    pub(crate) fn take_restart_anchors(&self, now: u64) -> Vec<PeerEndpoint> {
        let (reserved, revision, persistent) = {
            let mut manager = self.state.lock();
            let anchors = std::mem::take(&mut manager.stored.anchors);
            if anchors.is_empty() {
                return Vec::new();
            }
            let mut reserved = Vec::new();
            let mut changed = false;
            for anchor in anchors {
                let eligible = anchor.confirmed_at <= now.saturating_add(FUTURE_SKEW_SECS)
                    && now.saturating_sub(anchor.confirmed_at) <= ANCHOR_AGE
                    && manager
                        .by_addr
                        .get(&anchor.endpoint)
                        .is_some_and(|index| manager.stored.records[*index].last_success != 0);
                if !eligible {
                    changed = true;
                    continue;
                }
                if let std::collections::hash_map::Entry::Vacant(entry) =
                    manager.pending.entry(anchor.endpoint)
                {
                    entry.insert(PendingClaim::AnchorReservation(anchor.clone()));
                    reserved.push(anchor);
                    changed = true;
                } else {
                    manager.stored.anchors.push(anchor);
                }
            }
            if changed {
                manager.revision = manager.revision.wrapping_add(1);
            }
            (reserved, manager.revision, manager.path.is_some())
        };
        self.save();
        let mut manager = self.state.lock();
        if persistent && manager.saved_revision < revision {
            for anchor in &reserved {
                if manager.pending.get(&anchor.endpoint)
                    == Some(&PendingClaim::AnchorReservation(anchor.clone()))
                {
                    manager.pending.remove(&anchor.endpoint);
                }
            }
            manager.restore_anchors(reserved, now);
            return Vec::new();
        }
        reserved
            .into_iter()
            .filter_map(|anchor| {
                (manager.pending.get(&anchor.endpoint)
                    == Some(&PendingClaim::AnchorReservation(anchor.clone())))
                .then_some(anchor.endpoint)
            })
            .collect()
    }

    pub(crate) fn return_restart_anchor(&self, addr: PeerEndpoint, now: u64) {
        {
            let addr = canonical(addr);
            let mut manager = self.state.lock();
            let anchor = match manager.pending.get(&addr) {
                Some(
                    PendingClaim::AnchorReservation(anchor) | PendingClaim::AnchorQueued(anchor),
                ) => Some(anchor.clone()),
                _ => None,
            };
            if let Some(anchor) = anchor {
                manager.pending.remove(&addr);
                manager.restore_anchors(vec![anchor], now);
            }
        }
        self.save();
    }

    pub(crate) fn return_restart_anchors(&self, now: u64) {
        {
            let mut manager = self.state.lock();
            let returns: Vec<_> = manager
                .pending
                .iter()
                .filter_map(|(addr, claim)| match claim {
                    PendingClaim::AnchorReservation(anchor)
                    | PendingClaim::AnchorQueued(anchor) => Some((*addr, anchor.clone())),
                    PendingClaim::Dial | PendingClaim::Feeler => None,
                })
                .collect();
            for (addr, _) in &returns {
                manager.pending.remove(addr);
            }
            manager.restore_anchors(returns.into_iter().map(|(_, anchor)| anchor).collect(), now);
        }
        self.save();
    }

    pub(crate) fn gossip(&self, now: u64) -> Vec<bitcoin::p2p::address::AddrV2Message> {
        self.gossip_at(now, Instant::now())
    }
    fn gossip_at(&self, now: u64, tick: Instant) -> Vec<bitcoin::p2p::address::AddrV2Message> {
        let mut manager = self.state.lock();
        Self::shared_rows(&mut manager, now, tick)
            .into_iter()
            .map(|row| {
                crate::endpoint::endpoint_to_addrv2(
                    row.endpoint,
                    row.last_seen,
                    bitcoin::p2p::ServiceFlags::from(row.services),
                )
            })
            .collect()
    }
    fn shared_rows(manager: &mut Manager, now: u64, tick: Instant) -> Vec<GossipRow> {
        if let Some((expires, rows)) = &manager.gossip_cache {
            if tick < *expires {
                return rows.clone();
            }
        }
        let len = manager.stored.records.len();
        let start = manager.gossip_cursor.checked_rem(len).unwrap_or_default();
        let mut rows = Vec::with_capacity(MAX_GOSSIP.min(len));
        for offset in 0..len {
            let index = (start + offset) % len;
            manager.gossip_cursor = (index + 1) % len;
            let entry = &manager.stored.records[index];
            if entry.terrible(now) {
                continue;
            }
            rows.push(GossipRow {
                endpoint: entry.endpoint,
                last_seen: u32::try_from(entry.last_seen).unwrap_or(u32::MAX),
                services: entry.services.unwrap_or(0),
            });
            if rows.len() == MAX_GOSSIP {
                break;
            }
        }
        manager.gossip_cache = Some((tick + GOSSIP_CACHE_TTL, rows.clone()));
        rows
    }
    pub(crate) fn save(&self) {
        let _publication = self.publication.lock();
        let (path, stored, revision, mut published) = {
            let manager = self.state.lock();
            if !manager.writable || manager.revision == manager.saved_revision {
                return;
            }
            let Some(path) = manager.path.clone() else {
                return;
            };
            (
                path,
                manager.stored.clone(),
                manager.revision,
                manager.published,
            )
        };
        let result = publish_book(&path, &stored, &mut published);
        self.state.lock().published = published;
        match result {
            Ok(()) => {
                let mut manager = self.state.lock();
                manager.saved_revision = revision;
                manager.published = true;
            }
            Err(error) => {
                tracing::warn!(path=%path.display(), %error, "address book publication not confirmed durable; retaining dirty state for retry");
            }
        }
    }
}

fn network_path(base: &Path, magic: [u8; 4]) -> PathBuf {
    let mut name = base.file_stem().unwrap_or_default().to_os_string();
    name.push(format!(
        "-{:02x}{:02x}{:02x}{:02x}",
        magic[0], magic[1], magic[2], magic[3]
    ));
    if let Some(extension) = base.extension() {
        name.push(".");
        name.push(extension);
    }
    base.with_file_name(name)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct Loaded {
    stored: Option<Stored>,
    magic: [u8; 4],
    bytes: Vec<u8>,
}

fn required_services<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(deserializer)
}

fn read_new_buckets<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u16>, D::Error> {
    struct Buckets;
    impl<'de> serde::de::Visitor<'de> for Buckets {
        type Value = Vec<u16>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most eight New bucket IDs")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = Vec::new();
            while let Some(bucket) = sequence.next_element()? {
                if result.len() == MAX_NEW_REFS {
                    return Err(serde::de::Error::custom("too many New references"));
                }
                result.push(bucket);
            }
            Ok(result)
        }
    }
    deserializer.deserialize_seq(Buckets)
}
fn read_records<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Records<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Records<T> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded address records")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = Vec::new();
            while let Some(entry) = sequence.next_element()? {
                if result.len() == MAX_RECORDS {
                    return Err(serde::de::Error::custom("too many address records"));
                }
                result.push(entry);
            }
            Ok(result)
        }
    }
    deserializer.deserialize_seq(Records(std::marker::PhantomData))
}

fn read_anchors<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Anchor>, D::Error> {
    struct Anchors;
    impl<'de> serde::de::Visitor<'de> for Anchors {
        type Value = Vec<Anchor>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most two restart anchors")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = Vec::new();
            while let Some(anchor) = sequence.next_element()? {
                if result.len() == MAX_ANCHORS {
                    return Err(serde::de::Error::custom("too many restart anchors"));
                }
                result.push(anchor);
            }
            Ok(result)
        }
    }
    deserializer.deserialize_seq(Anchors)
}

fn validate_anchors(stored: &Stored) -> io::Result<()> {
    let mut anchors = HashSet::new();
    if stored.anchors.len() > MAX_ANCHORS {
        return Err(invalid("too many anchors"));
    }
    for anchor in &stored.anchors {
        if canonical(anchor.endpoint) != anchor.endpoint
            || !anchors.insert(anchor.endpoint)
            || !stored
                .records
                .iter()
                .any(|entry| entry.endpoint == anchor.endpoint && entry.last_success != 0)
        {
            return Err(invalid("invalid anchor subset"));
        }
    }
    Ok(())
}

fn validate_current(
    stored: &Stored,
    allow_local: bool,
    groups: Option<&NetGroups>,
) -> io::Result<()> {
    if stored.format != FORMAT
        || stored.version != SCHEMA_VERSION
        || stored.records.len() > MAX_RECORDS
    {
        return Err(invalid("address book version/count"));
    }
    let mut endpoints = HashSet::new();
    let mut slots = HashSet::new();
    let mut tried_count = 0;
    for entry in &stored.records {
        if !routable(entry.endpoint, allow_local)
            || canonical(entry.endpoint) != entry.endpoint
            || matches!(&entry.source, Source::Overlay(address)
                if !matches!(address, crate::PeerAddress::Onion(_) | crate::PeerAddress::I2p(_)))
            || !endpoints.insert(entry.endpoint)
            || entry.services.is_none() && !entry.allows_unknown_services()
            || entry.new_buckets.len() > MAX_NEW_REFS
            || entry.tried && (entry.last_success == 0 || !entry.new_buckets.is_empty())
            || !entry.tried && entry.new_buckets.is_empty()
        {
            return Err(invalid("invalid address book record"));
        }
        if entry.tried {
            tried_count += 1;
            if tried_count > TRIED_BUCKETS * BUCKET_SIZE {
                return Err(invalid("Tried count exceeds table"));
            }
            if let Some(groups) = groups {
                let bucket = tried_bucket(&stored.secret, entry.endpoint, groups);
                let position = tried_bucket_position(&stored.secret, entry.endpoint, bucket);
                if !slots.insert((false, bucket, position)) {
                    return Err(invalid("Tried bucket collision"));
                }
            }
        } else {
            let mut buckets = HashSet::new();
            for &bucket in &entry.new_buckets {
                let bucket = usize::from(bucket);
                if bucket >= NEW_BUCKETS
                    || !buckets.insert(bucket)
                    || !slots.insert((
                        true,
                        bucket,
                        new_bucket_position(&stored.secret, entry.endpoint, bucket),
                    ))
                {
                    return Err(invalid("invalid/colliding New reference"));
                }
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct AddressBookHeader {
    #[serde(default)]
    format: FormatMarker,
    version: u32,
    magic: [u8; 4],
}

#[derive(Default)]
enum FormatMarker {
    #[default]
    Absent,
    Null,
    Present(String),
}

impl<'de> Deserialize<'de> for FormatMarker {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Option::<String>::deserialize(deserializer)? {
            None => Self::Null,
            Some(value) => Self::Present(value),
        })
    }
}

fn read_address_book_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err(invalid("address book size/type"));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() < 32 || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(invalid("address book length"));
    }
    let payload_len = bytes.len() - 32;
    if Sha256::digest(&bytes[..payload_len])[..] != bytes[payload_len..] {
        return Err(invalid("address book checksum"));
    }
    Ok(Some(bytes))
}

fn read_book(
    path: &Path,
    magic: Option<[u8; 4]>,
    allow_local: bool,
    groups: &NetGroups,
) -> io::Result<Option<Loaded>> {
    let Some(bytes) = read_address_book_file(path)? else {
        return Ok(None);
    };
    let payload_len = bytes.len() - 32;
    let header: AddressBookHeader =
        sonic_rs::from_slice(&bytes[..payload_len]).map_err(io::Error::other)?;
    if matches!(header.format, FormatMarker::Absent) && (1..=9).contains(&header.version) {
        return Ok(Some(Loaded {
            stored: None,
            magic: header.magic,
            bytes,
        }));
    }
    if magic.is_some_and(|magic| magic != header.magic) {
        return Err(invalid("address book network"));
    }
    if !matches!(&header.format, FormatMarker::Present(value) if value == FORMAT)
        || header.version != SCHEMA_VERSION
    {
        return Err(invalid("unsupported address book format/version"));
    }
    let stored: Stored = sonic_rs::from_slice(&bytes[..payload_len]).map_err(io::Error::other)?;
    let prefix = NetGroups::default();
    let classifier = if stored.asmap_id.is_none() {
        Some(&prefix)
    } else if stored.asmap_id == groups.identity() {
        Some(groups)
    } else {
        None
    };
    validate_current(&stored, allow_local, classifier)?;
    validate_anchors(&stored)?;
    Ok(Some(Loaded {
        stored: Some(stored),
        magic: header.magic,
        bytes,
    }))
}

fn preserve_incompatible(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    use bitcoin::hex::DisplayHex as _;
    let digest = Sha256::digest(bytes);
    let backup = path.with_extension(format!(
        "pre-release-{}.bak",
        digest[..].to_lower_hex_string()
    ));
    match fs::symlink_metadata(&backup) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            {
                return Err(invalid("address book backup size/type"));
            }
            let mut file = OpenOptions::new().read(true).write(true).open(&backup)?;
            let mut existing = Vec::new();
            (&mut file)
                .take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut existing)?;
            if existing != bytes {
                return Err(invalid("address book backup differs"));
            }
            file.sync_all()?;
            let parent = backup
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            bitcoin_rs_storage::checkpoint::fs::sync_dir(
                &bitcoin_rs_storage::checkpoint::fs::open_data_dir(parent)?,
            )?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            publish_bytes_with_nonce(&backup, bytes, &mut false, || {
                bitcoin::secp256k1::rand::thread_rng().next_u64()
            })?;
        }
        Err(error) => return Err(error),
    }
    Ok(backup)
}
impl Manager {
    fn rebucket(&mut self) {
        let mut records = std::mem::take(&mut self.stored.records);
        let before = records.len();
        records.sort_by_key(|entry| {
            (
                std::cmp::Reverse(entry.tried),
                std::cmp::Reverse(entry.last_success),
                entry.endpoint,
            )
        });
        self.by_addr.clear();
        self.new.fill(EMPTY_SLOT);
        self.tried.fill(EMPTY_SLOT);
        let mut demoted = 0;
        for mut entry in records {
            entry.new_buckets.clear();
            let tried_slot = self.tried_slot(entry.endpoint);
            if entry.tried && self.tried[tried_slot] == EMPTY_SLOT {
                let index = self.stored.records.len();
                self.tried[tried_slot] = u32::try_from(index).unwrap_or(EMPTY_SLOT);
                self.by_addr.insert(entry.endpoint, index);
                self.stored.records.push(entry);
                continue;
            }
            let bucket = new_bucket(
                &self.stored.secret,
                entry.endpoint,
                &entry.source.group(&self.groups),
                &self.groups,
            );
            let slot = self.new_slot(entry.endpoint, bucket);
            if self.new[slot] != EMPTY_SLOT {
                continue;
            }
            if entry.tried {
                demoted += 1;
                entry.tried = false;
            }
            entry.new_buckets = vec![u16::try_from(bucket).unwrap_or_default()];
            let index = self.stored.records.len();
            self.new[slot] = u32::try_from(index).unwrap_or(EMPTY_SLOT);
            self.by_addr.insert(entry.endpoint, index);
            self.stored.records.push(entry);
        }
        self.stored
            .anchors
            .retain(|anchor| self.by_addr.contains_key(&anchor.endpoint));
        tracing::info!(
            before,
            retained = self.stored.records.len(),
            demoted,
            dropped = before - self.stored.records.len(),
            "regrouped address book with Core placement"
        );
    }
}

fn publish_book(path: &Path, stored: &Stored, replace: &mut bool) -> io::Result<()> {
    publish_book_with_nonce(path, stored, replace, || {
        bitcoin::secp256k1::rand::thread_rng().next_u64()
    })
}

fn publish_book_with_nonce(
    path: &Path,
    stored: &Stored,
    replace: &mut bool,
    nonce: impl FnMut() -> u64,
) -> io::Result<()> {
    let mut bytes = sonic_rs::to_vec(stored).map_err(io::Error::other)?;
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(invalid("address book too large"));
    }
    publish_bytes_with_nonce(path, &bytes, replace, nonce)
}

fn publish_bytes_with_nonce(
    path: &Path,
    bytes: &[u8],
    replace: &mut bool,
    mut nonce: impl FnMut() -> u64,
) -> io::Result<()> {
    let (tmp, mut file) = {
        let mut attempts = 0;
        loop {
            let tmp = path.with_extension(format!("tmp-{}-{:016x}", std::process::id(), nonce()));
            match OpenOptions::new().write(true).create_new(true).open(&tmp) {
                Ok(file) => break (tmp, file),
                Err(error)
                    if error.kind() == io::ErrorKind::AlreadyExists
                        && attempts + 1 < MAX_TEMP_ATTEMPTS =>
                {
                    attempts += 1;
                }
                Err(error) => return Err(error),
            }
        }
    };
    let mut temp_present = true;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if *replace {
            fs::rename(&tmp, path)?;
            temp_present = false;
            *replace = true;
        } else {
            fs::hard_link(&tmp, path)?;
            *replace = true;
            fs::remove_file(&tmp)?;
            temp_present = false;
        }
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(parent)?;
        bitcoin_rs_storage::checkpoint::fs::sync_dir(&dir)?;
        Ok(())
    })();
    if result.is_err() && temp_present {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _};
    use std::net::Ipv4Addr;

    fn addr(n: u8) -> PeerEndpoint {
        PeerEndpoint::new(IpAddr::V4(Ipv4Addr::new(8, n, 1, 1)), 8333)
    }

    trait ParseEndpoint {
        fn parse_endpoint(self) -> PeerEndpoint;
    }
    impl ParseEndpoint for &str {
        fn parse_endpoint(self) -> PeerEndpoint {
            crate::parse_endpoint(self).expect("address")
        }
    }
    fn book() -> Arc<AddressBook> {
        let book = AddressBook::open(None, [1; 4], false, None);
        book.state.lock().stored.secret = [1; 32];
        book
    }

    #[test]
    fn unproven_addresses_need_a_successful_outbound_handshake() {
        let book = book();
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[(addr(1), 9, 10_000)],
            10_000,
        );
        assert!(!book.state.lock().stored.records[0].tried);
        book.queued(addr(1));
        book.attempt_failed(addr(1), 10_001);
        assert_eq!(book.select(&[], &[], 10_002, u64::MAX, |_| true), None);
        book.succeeded(addr(1), 9, 10_003);
        assert!(book.state.lock().stored.records[0].tried);
        assert_eq!(book.state.lock().stored.records[0].failures, 0);
    }

    #[test]
    fn gossip_is_bounded_and_selection_respects_groups_pending_and_exclusion() {
        let book = book();
        for n in 1..200 {
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(200)),
                &[(addr(n), 9, 10_000)],
                10_000,
            );
        }
        assert!(book.len() <= 199);
        let picked = book
            .select(&[], &[], 10_000, u64::MAX, |_| true)
            .expect("candidate");
        book.queued(picked);
        assert_ne!(
            book.select(&[], &[], 10_000, u64::MAX, |_| true),
            Some(picked)
        );
        assert_eq!(book.select(&[], &[], 10_000, u64::MAX, |_| false), None);
        book.unqueue(picked);
        let same_group = PeerEndpoint::new(picked.address(), 8334);
        assert_ne!(
            book.select(&[], &[same_group], 10_000, u64::MAX, |_| true),
            Some(picked)
        );
        assert!(
            book.select(&[same_group], &[], 10_000, u64::MAX, |_| true)
                .is_some()
        );
        assert_ne!(
            book.select(&[picked], &[], 10_000, u64::MAX, |_| true),
            Some(picked)
        );
        assert!(book.gossip(10_000).len() <= MAX_GOSSIP);
    }

    #[test]
    fn invalid_and_duplicate_addresses_do_not_create_records() {
        let book = book();
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[
                (
                    crate::parse_endpoint("127.0.0.1:1").expect("addr"),
                    9,
                    10_000,
                ),
                (addr(1), 9, 20_000),
            ],
            10_000,
        );
        assert_eq!(book.len(), 0);
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[(addr(1), 9, 10_000); 2],
            10_000,
        );
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn restart_roundtrip_and_corruption_preserves_operator_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("peers.dat");
        let book = AddressBook::open(Some(path.clone()), [1; 4], false, None);
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[(addr(1), 9, 10_000)],
            10_000,
        );
        book.succeeded(addr(1), 9, 10_001);
        book.save();
        let restored = AddressBook::open(Some(path.clone()), [1; 4], false, None);
        assert_eq!(restored.len(), 1);
        assert!(restored.state.lock().stored.records[0].tried);
        for corrupt in [b"truncated".to_vec(), vec![0; 40]] {
            fs::write(network_path(&path, [1; 4]), &corrupt).expect("corrupt fixture");
            let recovered = AddressBook::open(Some(path.clone()), [1; 4], false, None);
            recovered.learn_peer(
                crate::PeerRemote::Endpoint(addr(2)),
                &[(addr(3), 9, 10_000)],
                10_000,
            );
            recovered.save();
            assert_eq!(
                fs::read(network_path(&path, [1; 4])).expect("read"),
                corrupt
            );
            assert_eq!(recovered.len(), 1);
        }
    }
    #[test]
    fn promotion_collision_never_overwrites_a_proven_peer() {
        let book = book();
        let first = addr(1);
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[(first, 9, 10_000)],
            10_000,
        );
        book.succeeded(first, 9, 10_001);
        let incumbent = book.state.lock().stored.records[0].clone();
        let challenger = {
            let manager = book.state.lock();
            let target = manager.tried_slot(incumbent.endpoint);
            (1..65535_u16)
                .map(|port| PeerEndpoint::new(first.address(), port))
                .find(|candidate| *candidate != first && manager.tried_slot(*candidate) == target)
                .expect("slot collision")
        };
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(3)),
            &[(challenger, 9, 10_000)],
            10_000,
        );
        book.succeeded(challenger, 9, 10_002);
        let manager = book.state.lock();
        assert!(
            manager
                .stored
                .records
                .iter()
                .find(|entry| entry.endpoint == first)
                .expect("incumbent")
                .tried
        );
        assert!(
            !manager
                .stored
                .records
                .iter()
                .find(|entry| entry.endpoint == challenger)
                .expect("challenger")
                .tried
        );
    }

    #[test]
    fn scoped_network_books_and_stale_temporary_files_are_independent() {
        let dir = tempfile::tempdir().expect("dir");
        let base = dir.path().join("peers.dat");
        let path = network_path(&base, [1; 4]);
        let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
        book.learn_dns("seed", &[addr(1)], 10_000);
        book.save();
        let original = fs::read(&path).expect("read");
        let other = AddressBook::open(Some(base.clone()), [2; 4], false, None);
        other.learn_dns("seed", &[addr(2)], 10_000);
        other.save();
        assert_eq!(fs::read(&path).expect("read"), original);
        assert_eq!(AddressBook::open(Some(base), [2; 4], false, None).len(), 1);
        let stale = path.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&stale, b"operator-owned stale temporary file").expect("fixture");
        book.attempt_failed(addr(1), 10_001);
        book.save();
        assert_ne!(fs::read(&path).expect("read"), original);
        assert_eq!(
            fs::read(&stale).expect("read"),
            b"operator-owned stale temporary file"
        );
        let manager = book.state.lock();
        assert_eq!(manager.revision, manager.saved_revision);
    }

    #[test]
    fn unscoped_current_import_retains_original_and_scoped_state_wins() {
        let dir = tempfile::tempdir().expect("dir");
        let base = dir.path().join("peers.dat");
        let source = book();
        source.learn_dns("seed", &[addr(1)], 10_000);
        let stored = source.state.lock().stored.clone();
        publish_book(&base, &stored, &mut false).expect("legacy fixture");
        let original = fs::read(&base).expect("legacy bytes");
        let migrated = AddressBook::open(Some(base.clone()), [1; 4], false, None);
        assert_eq!(migrated.state.lock().stored.secret, stored.secret);
        assert_eq!(migrated.len(), 1);
        migrated.save();
        assert_eq!(
            fs::read(network_path(&base, [1; 4])).expect("scoped bytes"),
            original
        );
        assert_eq!(fs::read(&base).expect("legacy unchanged"), original);
        fs::write(&base, b"future format unknown to this node").expect("unknown legacy");
        assert_eq!(
            AddressBook::open(Some(base.clone()), [1; 4], false, None).len(),
            1
        );
        let unknown = AddressBook::open(Some(base.clone()), [3; 4], false, None);
        unknown.learn_dns("seed", &[addr(2)], 10_000);
        unknown.save();
        assert!(!network_path(&base, [3; 4]).exists());
        assert_eq!(
            fs::read(&base).expect("unknown retained"),
            b"future format unknown to this node"
        );
    }

    #[test]
    fn valid_foreign_legacy_and_raced_destination_are_never_overwritten() {
        let dir = tempfile::tempdir().expect("dir");
        let base = dir.path().join("peers.dat");
        let source = book();
        source.learn_dns("seed", &[addr(1)], 10_000);
        publish_book(&base, &source.state.lock().stored, &mut false).expect("legacy fixture");
        let original = fs::read(&base).expect("legacy bytes");
        let foreign = AddressBook::open(Some(base.clone()), [2; 4], false, None);
        foreign.learn_dns("seed", &[addr(2)], 10_000);
        foreign.save();
        assert_eq!(
            AddressBook::open(Some(base.clone()), [2; 4], false, None).len(),
            1
        );
        assert_eq!(fs::read(&base).expect("retained"), original);
        let raced = AddressBook::open(Some(base.clone()), [3; 4], false, None);
        raced.learn_dns("seed", &[addr(3)], 10_000);
        let path = network_path(&base, [3; 4]);
        fs::write(&path, b"operator created this after open").expect("raced destination");
        raced.save();
        assert_eq!(
            fs::read(path).expect("preserved"),
            b"operator created this after open"
        );
        assert!(!raced.state.lock().published);
    }

    #[test]
    fn publication_retries_collisions_with_a_bound_and_preserves_unowned_temps() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("peers.dat");
        let stale = path.with_extension(format!("tmp-{}-{:016x}", std::process::id(), 7));
        fs::write(&stale, b"stale").expect("fixture");
        let source = book();
        source.learn_dns("seed", &[addr(1)], 10_000);
        let stored = source.state.lock().stored.clone();
        let mut calls = 0;
        let mut installed = false;
        let error = publish_book_with_nonce(&path, &stored, &mut installed, || {
            calls += 1;
            7
        })
        .expect_err("collision bound");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(calls, MAX_TEMP_ATTEMPTS);
        assert!(!installed);
        calls = 0;
        publish_book_with_nonce(&path, &stored, &mut installed, || {
            calls += 1;
            if calls == 1 { 7 } else { 8 }
        })
        .expect("retry with unique name");
        assert!(installed);
        assert_eq!(calls, 2);
        assert_eq!(fs::read(&stale).expect("stale retained"), b"stale");
        assert_eq!(
            read_book(&path, Some([1; 4]), false, &NetGroups::default())
                .expect("published")
                .expect("exists")
                .stored
                .expect("canonical v1")
                .records
                .len(),
            1
        );
    }

    #[test]
    fn duplicate_hearsay_only_dirties_persisted_fields_that_change() {
        let dir = tempfile::tempdir().expect("dir");
        let book = AddressBook::open(Some(dir.path().join("peers.dat")), [1; 4], false, None);
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[(addr(1), 1, 10_000)],
            10_000,
        );
        book.save();
        let clean = book.state.lock().saved_revision;
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[(addr(1), 1, 9_999); 32],
            10_000,
        );
        assert_eq!(
            book.state.lock().revision,
            clean,
            "unchanged duplicate reports cannot schedule disk writes"
        );
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[(addr(1), 8, 10_000)],
            10_000,
        );
        assert_ne!(
            book.state.lock().revision,
            clean,
            "new service evidence is persisted"
        );
        book.succeeded(addr(1), 9, 10_001);
        book.save();
        let clean = book.state.lock().saved_revision;
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[(addr(1), 64, 10_001)],
            10_001,
        );
        assert_ne!(
            book.state.lock().revision,
            clean,
            "Core merges advertised services even for Tried records"
        );
        book.save();
        let clean = book.state.lock().saved_revision;
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[(addr(1), 9, 13_602)],
            13_602,
        );
        assert_ne!(
            book.state.lock().revision,
            clean,
            "new last-seen evidence is persisted"
        );
    }

    #[test]
    fn gossip_cache_is_shared_stable_until_expiry_and_rotates_new_discoveries() {
        let book = book();
        for n in 1..200 {
            book.learn_dns("seed", &[addr(n)], 10_000);
            if book.len() == 64 {
                break;
            }
        }
        assert_eq!(book.len(), 64);
        let tick = Instant::now();
        let before = book.state.lock().revision;
        let first = book.gossip_at(10_000, tick);
        assert_eq!(first.len(), 32);
        assert_eq!(book.state.lock().revision, before);
        let fresh = (1..=255)
            .map(|n| PeerEndpoint::from(([9, n, 1, 1], 8333)))
            .find(|candidate| {
                book.learn_dns("other-seed", &[*candidate], 10_001);
                book.len() > 64
            })
            .expect("new discovery");
        let updated = PeerEndpoint::from(first[0].socket_addr().expect("endpoint"));
        book.connected(updated, 20_000);
        let before = book.state.lock().revision;
        for seconds in 0..100 {
            assert_eq!(
                book.gossip_at(20_000 + seconds, tick + Duration::from_secs(seconds)),
                first,
                "reconnects and new learning cannot enumerate or invalidate the cached wire response"
            );
        }
        let second = book.gossip_at(20_100, tick + GOSSIP_CACHE_TTL);
        assert_ne!(first, second);
        let third = book.gossip_at(20_100, tick + 2 * GOSSIP_CACHE_TTL);
        assert!(
            second.iter().chain(&third).any(|address| address
                .socket_addr()
                .ok()
                .map(PeerEndpoint::from)
                == Some(fresh))
        );
        assert_eq!(book.state.lock().revision, before, "cache is not persisted");
        assert_eq!(
            book.gossip_at(20_101 + STALE_SECS, tick + 3 * GOSSIP_CACHE_TTL),
            []
        );
    }

    #[test]
    fn gossip_cursor_cache_shared_across_projections() {
        let book = book();
        for n in 1..=5u8 {
            book.learn_dns("seed", &[addr(n)], 10_000);
        }
        let tor = crate::PeerEndpoint::TorV3 {
            key: [7u8; 32],
            port: 8333,
        };
        book.learn_dns("seed", &[tor], 10_000);
        assert_eq!(book.len(), 6);
        book.set_addrv2_gossip(true, false);
        let tick = Instant::now();
        let legacy = book.gossip_at(10_000, tick);
        assert_eq!(
            legacy.len(),
            6,
            "gossip projects the shared cache overlay-inclusive"
        );
        let cursor = book.state.lock().gossip_cursor;
        let v2 = book.gossip_addrv2_at(10_000, tick);
        assert_eq!(
            v2.len(),
            6,
            "addrv2 projects the same cached selection with overlay"
        );
        assert_eq!(
            book.state.lock().gossip_cursor,
            cursor,
            "projecting the cache must not re-rotate the shared cursor"
        );
        assert_eq!(
            book.gossip_at(10_000, tick),
            legacy,
            "shared cache keeps both replies stable until expiry"
        );
        book.set_addrv2_gossip(false, false);
        assert_eq!(book.gossip_addrv2_at(10_000, tick).len(), 5);
        let refreshed = book.gossip_addrv2_at(10_000, tick + GOSSIP_CACHE_TTL);
        assert_eq!(refreshed.len(), 5);
        assert_eq!(book.gossip_at(10_000, tick + GOSSIP_CACHE_TTL).len(), 6);
    }

    #[test]
    fn gossip_addrv2_rotates_successive_replies_and_caches_within_ttl() {
        let book = book();
        for n in 1..200 {
            book.learn_dns("seed", &[addr(n)], 10_000);
            if book.len() == 64 {
                break;
            }
        }
        assert_eq!(book.len(), 64);
        let tick = Instant::now();
        let before = book.state.lock().revision;
        let first = book.gossip_addrv2_at(10_000, tick);
        assert_eq!(first.len(), 32);
        assert_eq!(book.state.lock().revision, before);
        assert_eq!(
            book.gossip_addrv2_at(10_000, tick),
            first,
            "repeats within the TTL are served from the cache without advancing rotation"
        );
        let second = book.gossip_addrv2_at(10_100, tick + GOSSIP_CACHE_TTL);
        assert_ne!(
            first, second,
            "successive addrv2 rounds must rotate, not replay the first insertion-order records"
        );
        let endpoints =
        |rows: &[bitcoin::p2p::address::AddrV2Message]| -> std::collections::HashSet<PeerEndpoint> {
            rows.iter()
                .map(|row| crate::endpoint::endpoint_from_addrv2(row).expect("addrv2 round-trips"))
                .collect()
        };
        let first_set = endpoints(&first);
        let second_set = endpoints(&second);
        assert!(
            first_set.is_disjoint(&second_set),
            "two full 32-row windows over 64 records must not overlap"
        );
        assert_eq!(first_set.len() + second_set.len(), 64);
        assert_eq!(
            book.gossip_addrv2_at(10_100, tick + 2 * GOSSIP_CACHE_TTL),
            first,
            "rotation wraps fairly after a full cycle"
        );
        assert_eq!(book.state.lock().revision, before, "cache is not persisted");
    }

    #[test]
    fn gossip_addrv2_applies_current_overlay_filtering_per_reply() {
        let book = book();
        for n in 1..10 {
            book.learn_dns("seed", &[addr(n)], 10_000);
        }
        let tor = PeerEndpoint::TorV3 {
            key: [7; 32],
            port: 8333,
        };
        let i2p = PeerEndpoint::I2p {
            hash: [9; 32],
            port: 8333,
        };
        book.learn_dns("seed", &[tor, i2p], 10_000);
        assert!(book.state.lock().by_addr.contains_key(&tor));
        assert!(book.state.lock().by_addr.contains_key(&i2p));
        let tick = Instant::now();
        let ip_only = book.gossip_addrv2_at(10_000, tick);
        assert_ne!(ip_only.len(), 0);
        assert!(
            ip_only.iter().all(|row| matches!(
                row.addr,
                bitcoin::p2p::address::AddrV2::Ipv4(_) | bitcoin::p2p::address::AddrV2::Ipv6(_)
            )),
            "without overlay transports only IP rows are gossiped"
        );
        book.set_addrv2_gossip(true, false);
        let with_tor = book.gossip_addrv2_at(10_000, tick);
        assert!(
            with_tor.iter().any(|row| matches!(
                &row.addr,
                bitcoin::p2p::address::AddrV2::TorV3(key) if *key == [7; 32]
            )),
            "enabling Tor applies on the next reply, not after the TTL"
        );
        assert!(
            with_tor
                .iter()
                .all(|row| !matches!(row.addr, bitcoin::p2p::address::AddrV2::I2p(_))),
            "unconfigured I2P stays filtered"
        );
        book.set_addrv2_gossip(true, true);
        let with_both = book.gossip_addrv2_at(10_000, tick);
        assert!(with_both.iter().any(|row| matches!(
            &row.addr,
            bitcoin::p2p::address::AddrV2::TorV3(key) if *key == [7; 32]
        )));
        assert!(with_both.iter().any(|row| matches!(
            &row.addr,
            bitcoin::p2p::address::AddrV2::I2p(hash) if *hash == [9; 32]
        )));
        book.set_addrv2_gossip(false, false);
        let ip_again = book.gossip_addrv2_at(10_000, tick);
        assert!(
            ip_again.iter().all(|row| matches!(
                row.addr,
                bitcoin::p2p::address::AddrV2::Ipv4(_) | bitcoin::p2p::address::AddrV2::Ipv6(_)
            )),
            "disabling overlays drops them on the next reply"
        );
        for reply in [&ip_only, &with_tor, &with_both, &ip_again] {
            assert!(reply.len() <= MAX_GOSSIP, "gossip cap preserved");
        }
    }

    #[test]
    fn pending_attempts_keep_endpoint_and_network_group_ownership_until_released() {
        let book = book();
        book.learn_dns("seed", &[addr(1)], 10_000);
        let other = PeerEndpoint::new(addr(1).address(), 18333);
        let candidate = (1..65535)
            .map(|port| PeerEndpoint::new(other.address(), port))
            .find(|&candidate| {
                if candidate == addr(1) {
                    return false;
                }
                book.learn_dns("seed", &[candidate], 10_000);
                book.len() == 2
            })
            .expect("two same-group endpoints");
        book.queued(addr(1));
        book.attempt_failed(addr(1), 10_001);
        assert_eq!(book.pending_count_excluding(&[]), 1);
        assert_eq!(book.pending_count_excluding(&[addr(1)]), 0);
        assert_eq!(
            book.select(&[], &[], 10_100, u64::MAX, |_| true),
            None,
            "in-flight groups stay exclusive beyond retry time"
        );
        book.unqueue(addr(1));
        assert!(
            book.select(&[], &[], 10_100, u64::MAX, |_| true)
                .is_some_and(|a| a == addr(1) || a == candidate)
        );
    }

    use bitcoin::hex::{DisplayHex as _, FromHex as _};
    const EPOCH: u64 = 1_700_000_000;
    fn oracle_book() -> Arc<AddressBook> {
        let book = book();
        let mut manager = book.state.lock();
        manager.stored.secret = <[u8; 32]>::from_hex(
            "41f758f2e5cc078d3795b4fc0cb60c2d735fa92cc020572bdc982dd2d564d11b",
        )
        .expect("Core key");
        manager.rng = StdRng::seed_from_u64(17);
        drop(manager);
        book
    }
    fn source(n: u8) -> Source {
        Source::Ip(Ipv4Addr::new(1, n, 1, 1).into())
    }
    fn target() -> PeerEndpoint {
        "8.8.8.8:8333".parse().expect("target")
    }
    fn refs(manager: &Manager, addr: PeerEndpoint) -> usize {
        manager
            .by_addr
            .get(&addr)
            .map_or(0, |index| manager.stored.records[*index].new_buckets.len())
    }
    fn add_ref(manager: &mut Manager, addr: PeerEndpoint, source: &Source, seen: u64) {
        for _ in 0..4096 {
            if manager.learn(addr, Some(9), source.clone(), seen, EPOCH, 0) {
                return;
            }
        }
        panic!("fixed-seed reference fixture should find its 1/2^N admission");
    }
    fn assert_indexes(manager: &Manager) {
        validate_current(&manager.stored, manager.allow_local, Some(&manager.groups))
            .expect("membership invariants");
        assert_eq!(manager.by_addr.len(), manager.stored.records.len());
        let mut count = 0;
        for (index, entry) in manager.stored.records.iter().enumerate() {
            assert_eq!(manager.by_addr.get(&entry.endpoint), Some(&index));
            if entry.tried {
                assert_eq!(
                    manager.tried[manager.tried_slot(entry.endpoint)],
                    u32::try_from(index).expect("index")
                );
                count += 1;
            } else {
                for bucket in &entry.new_buckets {
                    assert_eq!(
                        manager.new[manager.new_slot(entry.endpoint, usize::from(*bucket))],
                        u32::try_from(index).expect("index")
                    );
                    count += 1;
                }
            }
        }
        assert_eq!(
            count,
            manager
                .new
                .iter()
                .chain(&manager.tried)
                .filter(|id| **id != EMPTY_SLOT)
                .count()
        );
    }

    #[test]
    fn placement_matches_68_unmodified_core_vectors() {
        let data: sonic_rs::Value = sonic_rs::from_str(include_str!(
            "../../../testdata/wire/data/core-addrman-v31.1.json"
        ))
        .expect("Core vectors");
        for row in data["rows"].as_array().expect("rows") {
            let secret =
                <[u8; 32]>::from_hex(row["secret_raw_hex"].as_str().expect("secret")).expect("key");
            let ip = row["address"]
                .as_str()
                .expect("address")
                .parse::<IpAddr>()
                .expect("IP");
            let addr = canonical(PeerEndpoint::new(
                ip,
                u16::try_from(row["port"].as_u64().expect("port")).expect("port"),
            ));
            let origin = row["source"].as_str().expect("source");
            let source = if let Some(seed) = origin.strip_prefix("internal:") {
                Source::dns(seed)
            } else {
                Source::Ip(origin.parse().expect("source IP"))
            };
            assert_eq!(
                NetGroups::default()
                    .group(addr.address())
                    .to_lower_hex_string(),
                row["address_group_hex"].as_str().expect("group")
            );
            assert_eq!(
                source.group(&NetGroups::default()).to_lower_hex_string(),
                row["source_group_hex"].as_str().expect("source group")
            );
            assert_eq!(
                endpoint_key(addr).to_lower_hex_string(),
                row["endpoint_key_hex"].as_str().expect("wire endpoint")
            );
            let new = new_bucket(
                &secret,
                addr,
                &source.group(&NetGroups::default()),
                &NetGroups::default(),
            );
            let tried = tried_bucket(&secret, addr, &NetGroups::default());
            assert_eq!(u64::try_from(new).expect("bucket"), row["new_bucket"]);
            assert_eq!(u64::try_from(tried).expect("bucket"), row["tried_bucket"]);
            assert_eq!(
                u64::try_from(new_bucket_position(&secret, addr, new)).expect("position"),
                row["new_position"]
            );
            assert_eq!(
                u64::try_from(tried_bucket_position(&secret, addr, tried)).expect("position"),
                row["tried_position"]
            );
            for bucket in [0, 1, 17, 63] {
                assert_eq!(
                    u64::try_from(new_bucket_position(&secret, addr, bucket)).expect("position"),
                    row[format!("new_pos{bucket}").as_str()]
                );
                assert_eq!(
                    u64::try_from(tried_bucket_position(&secret, addr, bucket)).expect("position"),
                    row[format!("tried_pos{bucket}").as_str()]
                );
            }
        }
    }

    #[test]
    fn health_matches_71_actual_core_boundaries_and_probabilities() {
        let data: sonic_rs::Value = sonic_rs::from_str(include_str!(
            "../../../testdata/wire/data/core-addrman-health-v31.1.json"
        ))
        .expect("Core health");
        for row in data["rows"].as_array().expect("rows") {
            let entry = Candidate {
                creation_id: 0,
                endpoint: target(),
                services: Some(9),
                source: source(1),
                last_seen: row["seen"].as_u64().expect("seen"),
                last_success: row["last_success"].as_u64().expect("success"),
                failures: u32::try_from(row["attempts"].as_u64().expect("attempts"))
                    .expect("count"),
                tried: false,
                new_buckets: vec![191],
                last_attempt: row["last_try"].as_u64().expect("try"),
                last_count_attempt: 0,
            };
            let now = row["now"].as_u64().expect("now");
            assert_eq!(
                entry.terrible(now),
                row["terrible"].as_bool().expect("health"),
                "{row}"
            );
            assert!(
                (entry.chance(now) - row["chance"].as_f64().expect("chance")).abs() < 1e-14,
                "{row}"
            );
        }
    }

    #[test]
    fn corroboration_ref_cap_dirty_membership_and_promotion_follow_core() {
        let book = oracle_book();
        let mut manager = book.state.lock();
        assert!(manager.learn(target(), Some(9), source(1), EPOCH - 1000, EPOCH, 0));
        let revision = manager.revision;
        assert!(!manager.learn(target(), Some(9), source(1), EPOCH - 999, EPOCH, 0));
        assert_eq!(refs(&manager, target()), 1);
        for n in 2..=8 {
            add_ref(&mut manager, target(), &source(n), EPOCH - 999);
            assert_eq!(refs(&manager, target()), usize::from(n));
        }
        assert!(manager.revision > revision);
        assert_eq!(manager.stored.records.len(), 1);
        for n in 9..=10 {
            assert!(!manager.learn(target(), Some(9), source(n), EPOCH - 999, EPOCH, 0));
        }
        assert_indexes(&manager);
        assert!(manager.promote(target()));
        assert_eq!(refs(&manager, target()), 0);
        assert!(manager.stored.records[0].tried);
        manager.stored.records[0].last_success = EPOCH;
        assert_indexes(&manager);
        assert!(!manager.learn(target(), Some(32), source(10), EPOCH - 999, EPOCH, 0));
        assert_eq!(manager.stored.records[0].services, Some(41));
    }

    #[test]
    fn new_collision_removes_only_one_reference_and_preserves_pending_identity() {
        let other: PeerEndpoint = "8.8.9.89:8333".parse().expect("Core collision");
        for extra_ref in [false, true] {
            let book = oracle_book();
            let mut manager = book.state.lock();
            manager.learn(target(), Some(9), source(1), EPOCH - 1000, EPOCH, 0);
            assert_eq!(manager.new_slot(target(), 191), 191 * 64 + 59);
            assert_eq!(manager.new_slot(other, 191), 191 * 64 + 59);
            manager.pending.insert(target(), PendingClaim::Dial);
            if extra_ref {
                add_ref(&mut manager, target(), &source(2), EPOCH - 999);
            }
            manager.stored.records[0].failures = 3;
            manager.stored.records[0].last_attempt = EPOCH - 60;
            assert_eq!(
                manager.learn(other, Some(9), source(1), EPOCH - 1000, EPOCH, 0),
                extra_ref
            );
            assert_eq!(refs(&manager, target()), 1);
            assert_indexes(&manager);
            if !extra_ref {
                manager.stored.records[0].last_attempt = EPOCH - 61;
                assert!(
                    !manager.learn(other, Some(9), source(1), EPOCH - 1000, EPOCH, 0),
                    "pending final identity survives"
                );
                manager.pending.remove(&target());
                assert!(manager.learn(other, Some(9), source(1), EPOCH - 1000, EPOCH, 0));
                assert!(!manager.by_addr.contains_key(&target()));
                assert_indexes(&manager);
            }
        }
    }

    #[test]
    fn global_good_epoch_limits_failures_and_good_keeps_advertised_time() {
        let book = oracle_book();
        {
            book.state
                .lock()
                .learn(target(), Some(9), source(1), EPOCH - 1000, EPOCH, 0);
        }
        book.attempt_failed(target(), EPOCH);
        book.unqueue(target());
        book.attempt_failed(target(), EPOCH + 1);
        book.unqueue(target());
        assert_eq!(book.state.lock().stored.records[0].failures, 1);
        book.succeeded(addr(77), 9, EPOCH + 10);
        book.attempt_failed(target(), EPOCH + 12);
        book.unqueue(target());
        assert_eq!(book.state.lock().stored.records[0].failures, 2);
        book.succeeded(target(), 9, EPOCH + 20);
        let manager = book.state.lock();
        let entry = &manager.stored.records[0];
        assert_eq!(entry.failures, 0);
        assert_eq!(entry.last_seen, EPOCH - 1000);
        assert_eq!(entry.last_attempt, EPOCH + 20);
        assert!(entry.tried);
        assert_indexes(&manager);
    }

    #[test]
    fn gossip_time_penalty_and_source_self_exception_follow_core() {
        let book = oracle_book();
        let mut manager = book.state.lock();
        manager.learn(target(), Some(9), source(1), EPOCH, EPOCH, 7200);
        assert_eq!(manager.stored.records[0].last_seen, EPOCH - 7200);
        assert!(!manager.learn(target(), Some(9), source(2), EPOCH + 3601, EPOCH + 3601, 0));
        assert_eq!(
            manager.stored.records[0].last_seen,
            EPOCH + 3601,
            "time update before freshness test"
        );
        let local: PeerEndpoint = "9.9.9.9:8333".parse().expect("addr");
        manager.learn(
            local,
            Some(9),
            Source::Ip(
                local
                    .address()
                    .ip()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            ),
            EPOCH,
            EPOCH,
            7200,
        );
        assert_eq!(
            manager.stored.records[*manager.by_addr.get(&local).expect("self")].last_seen,
            EPOCH
        );
        let floor: PeerEndpoint = "11.11.11.11:8333".parse().expect("addr");
        manager.learn(floor, Some(9), source(3), 100, 100, 7200);
        assert_eq!(
            manager.stored.records[*manager.by_addr.get(&floor).expect("floor")].last_seen,
            0
        );
    }

    #[test]
    fn policy_callbacks_run_unlocked_and_selection_rechecks_pending() {
        let book = oracle_book();
        book.learn_dns("seed", &[target()], EPOCH);
        let mut calls = 0;
        assert_eq!(
            book.select(&[], &[], EPOCH, u64::MAX, |addr| {
                calls += 1;
                assert!(book.state.try_lock().is_some());
                book.queued(addr);
                true
            }),
            None
        );
        assert_eq!(calls, 1);
        book.unqueue(target());
        let before = book.state.lock().rng.clone().next_u64();
        assert_eq!(book.select(&[], &[], EPOCH, u64::MAX, |_| false), None);
        assert_eq!(
            book.state.lock().rng.clone().next_u64(),
            before,
            "all excluded consumes no random proposals"
        );
        assert_eq!(
            book.select(&[], &[], EPOCH, u64::MAX, |_| true),
            Some(target())
        );
    }

    #[test]
    fn one_source_flood_is_bucket_bounded_and_retains_legitimate_peers() {
        let book = oracle_book();
        let mut manager = book.state.lock();
        let retained: PeerEndpoint = "9.9.9.9:8333".parse().expect("peer");
        manager.learn(retained, Some(9), source(2), EPOCH, EPOCH, 0);
        let proven: PeerEndpoint = "7.7.7.7:8333".parse().expect("peer");
        manager.learn(proven, Some(9), source(3), EPOCH, EPOCH, 0);
        let proven_index = *manager.by_addr.get(&proven).expect("known");
        manager.stored.records[proven_index].last_success = EPOCH;
        manager.promote(proven);
        for index in 0..32_768_u32 {
            let bytes = index.to_be_bytes();
            let peer = PeerEndpoint::from(([8, bytes[2], bytes[3], 1], 8333));
            manager.learn(peer, Some(0), source(1), EPOCH, EPOCH, 0);
        }
        let malicious: Vec<_> = manager
            .stored
            .records
            .iter()
            .filter(|entry| entry.source == source(1))
            .collect();
        let buckets: HashSet<_> = malicious
            .iter()
            .flat_map(|entry| entry.new_buckets.iter().copied())
            .collect();
        assert!(buckets.len() <= 64, "Core source footprint");
        assert!(
            malicious.len() > 64,
            "the obsolete endpoint/source quota must be gone"
        );
        assert!(malicious.len() <= 64 * 64);
        assert!(manager.by_addr.contains_key(&retained));
        assert!(manager.stored.records[*manager.by_addr.get(&proven).expect("retained")].tried);
        let accepted = (1..=255).any(|n| {
            manager.learn(
                PeerEndpoint::from(([11, n, 1, 1], 8333)),
                Some(9),
                source(4),
                EPOCH,
                EPOCH,
                0,
            )
        });
        assert!(accepted, "a source cannot fill the global identity budget");
        assert_indexes(&manager);
    }

    fn fixture_bytes(value: &sonic_rs::Value) -> Vec<u8> {
        let mut bytes = sonic_rs::to_vec(value).expect("fixture");
        let hash = Sha256::digest(&bytes);
        bytes.extend_from_slice(&hash);
        bytes
    }
    #[test]
    fn same_layout_restart_retains_all_refs_and_resets_only_runtime_attempt_times() {
        let dir = tempfile::tempdir().expect("dir");
        let base = dir.path().join("peers.dat");
        let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
        {
            let mut manager = book.state.lock();
            manager.rng = StdRng::seed_from_u64(5);
            manager.learn(target(), Some(9), source(1), EPOCH - 1000, EPOCH, 0);
            for n in 2..=8 {
                let origin = Source::Ip(Ipv4Addr::new(n, 1, 1, 1).into());
                let before = refs(&manager, target());
                if before == 8 {
                    break;
                }
                for _ in 0..4096 {
                    if manager.learn(target(), Some(9), origin.clone(), EPOCH - 999, EPOCH, 0) {
                        break;
                    }
                }
            }
        }
        book.attempt_failed(target(), EPOCH);
        book.unqueue(target());
        let (secret, refs) = {
            let manager = book.state.lock();
            (
                manager.stored.secret,
                manager.stored.records[0].new_buckets.clone(),
            )
        };
        assert!(refs.len() > 1);
        book.save();
        let restored = AddressBook::open(Some(base.clone()), [1; 4], false, None);
        let manager = restored.state.lock();
        let entry = &manager.stored.records[0];
        assert_eq!(manager.stored.secret, secret);
        assert_eq!(entry.new_buckets, refs);
        assert_eq!(entry.failures, 1);
        assert_eq!(entry.last_attempt, 0);
        assert_indexes(&manager);
        let mut value = sonic_rs::to_value(&manager.stored).expect("stored");
        drop(manager);
        for bad in [
            sonic_rs::json!([]),
            sonic_rs::json!([0, 0]),
            sonic_rs::json!([1024]),
            sonic_rs::json!([0, 1, 2, 3, 4, 5, 6, 7, 8]),
        ] {
            value["records"][0]["new_buckets"] = bad;
            let bytes = fixture_bytes(&value);
            let path = network_path(&base, [1; 4]);
            fs::write(&path, &bytes).expect("malformed");
            let rejected = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            assert!(!rejected.state.lock().writable);
            rejected.save();
            assert_eq!(fs::read(&path).expect("preserved"), bytes);
        }
    }

    #[test]
    fn stale_future_and_outage_candidates_survive_until_actual_new_slot_replacement() {
        for origin in [source(1), Source::dns("seed")] {
            let book = oracle_book();
            let mut manager = book.state.lock();
            manager.learn(target(), Some(9), origin.clone(), EPOCH, EPOCH, 0);
            let bucket = usize::from(manager.stored.records[0].new_buckets[0]);
            let slot = manager.new_slot(target(), bucket);
            let other = (1..=65535)
                .map(|port| PeerEndpoint::new(target().address(), port))
                .find(|candidate| {
                    *candidate != target() && manager.new_slot(*candidate, bucket) == slot
                })
                .expect("collider");
            for (seen, success, failures) in [
                (EPOCH + 601, 0, 0),
                (EPOCH - STALE_SECS - 1, 0, 0),
                (EPOCH, 0, 3),
                (EPOCH, EPOCH - 8 * 86400, 10),
            ] {
                let entry = &mut manager.stored.records[0];
                entry.last_seen = seen;
                entry.last_success = success;
                entry.failures = failures;
                entry.last_attempt = EPOCH - 61;
                assert!(entry.terrible(EPOCH));
                assert_eq!(manager.select(&[true], EPOCH), Some(target()));
            }
            assert!(!manager.learn(
                PeerEndpoint::from(([0, 0, 0, 0], 0)),
                Some(9),
                origin.clone(),
                EPOCH,
                EPOCH,
                0
            ));
            assert_eq!(manager.stored.records.len(), 1);
            assert!(manager.learn(other, Some(9), origin, EPOCH, EPOCH, 0));
            assert!(!manager.by_addr.contains_key(&target()));
            assert_indexes(&manager);
        }
    }

    #[test]
    fn capacity_and_file_budget_have_explicit_bounded_representations() {
        let entry = Candidate {
            creation_id: 0,
            endpoint: "2fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse::<IpAddr>()
                .map(|ip| PeerEndpoint::new(ip, u16::MAX))
                .expect("IP"),
            services: Some(u64::MAX),
            source: Source::Internal([255; 10]),
            last_seen: u64::MAX,
            last_success: u64::MAX,
            failures: u32::MAX,
            tried: false,
            new_buckets: (1016..1024).collect(),
            last_attempt: u64::MAX,
            last_count_attempt: u64::MAX,
        };
        let size = sonic_rs::to_vec(&entry).expect("max-width fields").len();
        assert!(size <= 512, "fixed-width field serialization bound");
        assert!(MAX_RECORDS * 513 + 512 + 32 < usize::try_from(MAX_FILE_BYTES).expect("file cap"));
        assert_eq!(
            (NEW_BUCKETS + TRIED_BUCKETS) * BUCKET_SIZE * std::mem::size_of::<u32>(),
            327_680
        );
        eprintln!(
            "Candidate={} Source={} max-width JSON={} endpoint_limit={} New-ref_limit={} table_bytes=327680 file_limit={MAX_FILE_BYTES}",
            std::mem::size_of::<Candidate>(),
            std::mem::size_of::<Source>(),
            size,
            MAX_RECORDS,
            NEW_BUCKETS * BUCKET_SIZE
        );
    }

    #[test]
    fn noncounted_manual_or_offline_attempt_updates_try_without_claim_or_failure() {
        let book = oracle_book();
        book.state
            .lock()
            .learn(target(), Some(9), source(1), EPOCH - 1000, EPOCH, 0);
        book.state.lock().stored.records[0].failures = 2;
        book.attempted(target(), EPOCH);
        let manager = book.state.lock();
        let entry = &manager.stored.records[0];
        assert_eq!(entry.failures, 2);
        assert_eq!(entry.last_attempt, EPOCH);
        assert_eq!(entry.last_count_attempt, 0);
        assert!(manager.pending.is_empty());
        assert!(!entry.terrible(EPOCH + 61));
        drop(manager);
        book.attempt_failed(target(), EPOCH + 62);
        assert_eq!(book.state.lock().stored.records[0].failures, 3);
    }

    fn force_reference_draw(manager: &mut Manager, pass: bool) {
        let factor = 1_usize << refs(manager, target());
        let seed = (0..100_000)
            .find(|seed| {
                let mut rng = StdRng::seed_from_u64(*seed);
                (rng.gen_range(0..factor) == 0) == pass
            })
            .expect("deterministic real RNG branch");
        manager.rng = StdRng::seed_from_u64(seed);
    }
    fn assert_core_operation(manager: &Manager, case: &str, accepted: Option<bool>) {
        let data: sonic_rs::Value = sonic_rs::from_str(include_str!(
            "../../../testdata/wire/data/core-addrman-addsingle-v31.1.json"
        ))
        .expect("Core operations");
        let expected = data["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .find(|row| row["case"] == case)
            .expect("case");
        let entry = manager
            .by_addr
            .get(&target())
            .map(|index| &manager.stored.records[*index]);
        if let Some(accepted) = accepted {
            assert_eq!(
                accepted,
                expected["accepted"].as_bool().expect("accepted"),
                "{case}"
            );
            assert_eq!(
                manager.stored.records.len(),
                usize::try_from(expected["records"].as_u64().expect("count")).expect("count"),
                "{case}"
            );
            assert_eq!(
                refs(manager, target()),
                usize::try_from(expected["refs"].as_u64().expect("refs")).expect("refs"),
                "{case}"
            );
            let seen = entry.map_or(-1, |entry| i64::try_from(entry.last_seen).expect("seen"));
            assert_eq!(seen, expected["seen"].as_i64().expect("seen"), "{case}");
            if let Some(present) = expected["other_present"].as_bool() {
                let other = crate::parse_endpoint("8.8.9.89:8333").expect("collider");
                assert_eq!(manager.by_addr.contains_key(&other), present, "{case}");
                assert_eq!(
                    refs(manager, other),
                    usize::try_from(expected["other_refs"].as_u64().expect("refs")).expect("refs"),
                    "{case}"
                );
            }
        } else {
            let entry = entry.expect("health entry");
            let actual = sonic_rs::json!({"case":case,"attempts":entry.failures,"seen":entry.last_seen,"last_try":entry.last_attempt,"last_success":entry.last_success,"tried":entry.tried});
            assert_eq!(&actual, expected, "{case}");
        }
        assert_indexes(manager);
    }

    #[test]
    fn all_24_addsingle_attempt_good_observations_match_actual_core() {
        let book = oracle_book();
        let mut manager = book.state.lock();
        let accepted = manager.learn(target(), Some(0), source(1), EPOCH - 1000, EPOCH, 0);
        assert_core_operation(&manager, "first", Some(accepted));
        force_reference_draw(&mut manager, true);
        let accepted = manager.learn(target(), Some(0), source(1), EPOCH - 999, EPOCH, 0);
        assert_core_operation(&manager, "same-source-repeat", Some(accepted));
        force_reference_draw(&mut manager, false);
        let accepted = manager.learn(target(), Some(0), source(2), EPOCH - 999, EPOCH, 0);
        assert_core_operation(&manager, "other-source-rng-refused", Some(accepted));
        for n in 2..=10 {
            force_reference_draw(&mut manager, true);
            let accepted = manager.learn(target(), Some(0), source(n), EPOCH - 999, EPOCH, 0);
            assert_core_operation(&manager, &format!("source-{n}"), Some(accepted));
        }
        drop(manager);
        let other = crate::parse_endpoint("8.8.9.89:8333").expect("collider");
        let book = oracle_book();
        let mut manager = book.state.lock();
        manager.learn(target(), Some(0), source(1), EPOCH - 1000, EPOCH, 0);
        let accepted = manager.learn(other, Some(0), source(1), EPOCH - 1000, EPOCH, 0);
        assert_core_operation(
            &manager,
            "healthy-single-reference-collision",
            Some(accepted),
        );
        force_reference_draw(&mut manager, true);
        manager.learn(target(), Some(0), source(2), EPOCH - 999, EPOCH, 0);
        let accepted = manager.learn(other, Some(0), source(1), EPOCH - 1000, EPOCH, 0);
        assert_core_operation(
            &manager,
            "fresh-replaces-redundant-reference",
            Some(accepted),
        );
        drop(manager);
        for (age, case) in [
            (200, "failed-gossip-replaced"),
            (60, "recent-attempt-exact60-protected"),
        ] {
            let book = oracle_book();
            let mut manager = book.state.lock();
            manager.learn(target(), Some(0), source(1), EPOCH - 1000, EPOCH, 0);
            manager.stored.records[0].failures = 3;
            manager.stored.records[0].last_attempt = EPOCH - age;
            let accepted = manager.learn(other, Some(0), source(1), EPOCH - 1000, EPOCH, 0);
            assert_core_operation(&manager, case, Some(accepted));
        }
        let book = oracle_book();
        let mut manager = book.state.lock();
        manager.learn(target(), Some(0), source(1), EPOCH - 10000, EPOCH, 0);
        force_reference_draw(&mut manager, true);
        let accepted = manager.learn(target(), Some(0), source(2), EPOCH - 1000, EPOCH, 0);
        assert_core_operation(
            &manager,
            "time-update-zero-penalty-precedes-reference",
            Some(accepted),
        );
        force_reference_draw(&mut manager, true);
        let accepted = manager.learn(target(), Some(0), source(2), EPOCH, EPOCH, 7200);
        assert_core_operation(&manager, "time-penalty-still-new-info", Some(accepted));
        drop(manager);
        let book = oracle_book();
        book.state
            .lock()
            .learn(target(), Some(0), source(1), EPOCH - 1000, EPOCH, 0);
        book.succeeded(target(), 0, EPOCH);
        let mut manager = book.state.lock();
        let accepted = manager.learn(target(), Some(0), source(2), EPOCH - 999, EPOCH, 0);
        assert_core_operation(&manager, "tried-rejects-new-reference", Some(accepted));
        drop(manager);
        actual_core_attempt_good_sequence();
    }

    fn actual_core_attempt_good_sequence() {
        let book = oracle_book();
        let other: PeerEndpoint = "9.9.9.9:8333".parse().expect("peer");
        {
            let mut manager = book.state.lock();
            manager.learn(target(), Some(0), source(1), EPOCH - 1000, EPOCH, 0);
            manager.learn(
                other,
                Some(0),
                Source::Ip("2.2.2.2".parse().expect("source")),
                EPOCH - 1000,
                EPOCH,
                0,
            );
        }
        book.attempt_failed(target(), EPOCH);
        assert_core_operation(&book.state.lock(), "first-attempt-counted", None);
        book.attempt_failed(target(), EPOCH + 1);
        assert_core_operation(
            &book.state.lock(),
            "repeat-same-good-epoch-not-counted",
            None,
        );
        book.succeeded(other, 0, EPOCH + 10);
        book.attempted(target(), EPOCH + 11);
        assert_core_operation(
            &book.state.lock(),
            "noncounted-attempt-updates-only-try",
            None,
        );
        book.attempt_failed(target(), EPOCH + 12);
        assert_core_operation(&book.state.lock(), "attempt-after-other-good-counted", None);
        book.succeeded(target(), 0, EPOCH + 20);
        assert_core_operation(
            &book.state.lock(),
            "good-retains-seen-resets-attempts",
            None,
        );
    }

    fn ring_manager(second_port: u16) -> (Manager, PeerEndpoint, PeerEndpoint) {
        let data: sonic_rs::Value = sonic_rs::from_str(include_str!(
            "../../../testdata/wire/data/core-addrman-ring-v31.1.json"
        ))
        .expect("actual Core ring");
        let mut manager = Manager::new([1; 4], false, None, NetGroups::default());
        manager.stored.secret =
            <[u8; 32]>::from_hex(data["rows"][0]["secret_raw_hex"].as_str().expect("secret"))
                .expect("Core secret");
        manager.rng = StdRng::seed_from_u64(0x1476);
        let mut peers = Vec::new();
        for port in [90, second_port] {
            let row = data["rows"]
                .as_array()
                .expect("rows")
                .iter()
                .find(|row| row["port"] == port)
                .expect("Core endpoint");
            let peer = PeerEndpoint::new(
                row["address"]
                    .as_str()
                    .expect("ip")
                    .parse::<IpAddr>()
                    .expect("ip"),
                port,
            );
            assert!(manager.learn(peer, Some(9), source(1), EPOCH, EPOCH, 0));
            let bucket =
                usize::try_from(row["new_bucket"].as_u64().expect("bucket")).expect("bucket");
            assert_eq!(
                manager.new_slot(peer, bucket) % 64,
                usize::try_from(row["new_position"].as_u64().expect("position")).expect("position")
            );
            peers.push(peer);
        }
        assert_indexes(&manager);
        (manager, peers[0], peers[1])
    }
    fn assert_fraction(hits: u32, samples: u32, expected: f64) {
        let actual = f64::from(hits) / f64::from(samples);
        let tolerance = 6.0_f64.mul_add(
            (expected * (1.0 - expected) / f64::from(samples)).sqrt(),
            1.0 / f64::from(samples),
        );
        assert!(
            (actual - expected).abs() <= tolerance,
            "observed {actual}, independent expected {expected}, tolerance {tolerance}"
        );
    }

    #[test]
    fn randomized_circular_slot_proposals_match_core_ring_bias() {
        for (port, expected) in [(6, 63.0 / 64.0), (88, 0.5)] {
            let (mut manager, first, _) = ring_manager(port);
            let mut hits = 0;
            for _ in 0..100_000 {
                if manager.select(&[true, true], EPOCH) == Some(first) {
                    hits += 1;
                }
            }
            assert_fraction(hits, 100_000, expected);
        }
    }

    #[test]
    fn getchance_distributions_follow_independent_escalation_recurrence() {
        let data: sonic_rs::Value = sonic_rs::from_str(include_str!(
            "../../../testdata/wire/data/core-addrman-selection-v31.1.json"
        ))
        .expect("independent rational recurrence");
        for (name, failures, age) in [
            ("one_failure", 1, 600),
            ("eight_failures", 8, 600),
            ("recent_only", 0, 599),
            ("recent_eight", 8, 599),
        ] {
            let expected = data["mixtures"]
                .as_array()
                .expect("mixtures")
                .iter()
                .find(|row| row["name"] == name)
                .expect("mixture")["expected_fraction"]
                .as_f64()
                .expect("probability");
            let (mut manager, _, bad) = ring_manager(88);
            let index = *manager.by_addr.get(&bad).expect("bad");
            manager.stored.records[index].failures = failures;
            manager.stored.records[index].last_attempt = EPOCH - age;
            let mut hits = 0;
            for _ in 0..250_000 {
                if manager.select(&[true, true], EPOCH) == Some(bad) {
                    hits += 1;
                }
            }
            assert_fraction(hits, 250_000, expected);
        }
    }

    #[test]
    fn table_choice_is_half_even_when_new_health_is_bad_and_selection_work_is_bounded() {
        let (mut manager, good, bad) = ring_manager(88);
        let good_index = *manager.by_addr.get(&good).expect("good");
        manager.stored.records[good_index].last_success = EPOCH;
        assert!(manager.promote(good));
        let bad_index = *manager.by_addr.get(&bad).expect("bad");
        manager.stored.records[bad_index].failures = 255;
        manager.stored.records[bad_index].last_attempt = EPOCH;
        let mut bad_hits = 0;
        for _ in 0..100_000 {
            if manager.select(&[true, true], EPOCH) == Some(bad) {
                bad_hits += 1;
            }
            assert!(manager.selection_proposals <= 45);
            assert!(manager.selection_positions <= 45 * 64);
        }
        assert_fraction(bad_hits, 100_000, 0.5);
        assert_eq!(manager.select(&[false, false], EPOCH), None);
        assert_eq!(
            (manager.selection_proposals, manager.selection_positions),
            (0, 0)
        );
        let eligible: Vec<_> = manager
            .stored
            .records
            .iter()
            .map(|entry| entry.endpoint == bad)
            .collect();
        for _ in 0..1000 {
            assert_eq!(manager.select(&eligible, EPOCH), Some(bad));
            assert!(manager.selection_proposals <= 45);
            assert!(manager.selection_positions <= 45 * 64);
        }
        assert!(manager.stored.records[bad_index].chance(EPOCH) * 1.2_f64.powi(44) > 1.0);
        assert_eq!(
            manager.select(&eligible, EPOCH + 601),
            Some(bad),
            "recovery has no hard failure delay"
        );
    }

    fn core_mapped_alias() -> PeerEndpoint {
        let data: sonic_rs::Value = sonic_rs::from_str(include_str!(
            "../../../testdata/wire/data/core-addrman-v31.1.json"
        ))
        .expect("actual Core identity vectors");
        let rows = data["rows"].as_array().expect("rows");
        let row = |address: &str| {
            rows.iter()
                .find(|row| {
                    row["key_label"] == "hash-int32-1"
                        && row["address"] == address
                        && row["port"] == 8333
                        && row["source"] == "1.1.1.1"
                })
                .expect("Core identity row")
        };
        assert_eq!(
            row("8.8.8.8")["endpoint_key_hex"],
            row("::ffff:8.8.8.8")["endpoint_key_hex"]
        );
        let alias: PeerEndpoint = "[::ffff:8.8.8.8]:8333".parse().expect("mapped endpoint");
        assert_eq!(endpoint_key(alias), endpoint_key(target()));
        alias
    }

    #[test]
    fn mapped_alias_manual_health_and_refresh_use_the_known_core_identity() {
        let alias = core_mapped_alias();
        let book = oracle_book();
        book.learn_dns("seed", &[target()], EPOCH - 2000);
        book.state.lock().stored.records[0].failures = 2;
        book.attempted(alias, EPOCH);
        {
            let manager = book.state.lock();
            let entry = &manager.stored.records[0];
            assert_eq!(
                entry.last_attempt, EPOCH,
                "manual alias must stamp the known peer"
            );
            assert_eq!(entry.failures, 2);
            assert!(manager.pending.is_empty());
        }
        book.succeeded(alias, 73, EPOCH + 1);
        {
            let manager = book.state.lock();
            assert_eq!(manager.stored.records.len(), 1);
            let entry = &manager.stored.records[0];
            assert!(entry.tried);
            assert_eq!(
                (
                    entry.last_success,
                    entry.last_attempt,
                    entry.failures,
                    entry.services
                ),
                (EPOCH + 1, EPOCH + 1, 0, Some(73))
            );
            assert_eq!(
                entry.last_seen,
                EPOCH - 2000,
                "Good retains advertised time"
            );
            assert!(manager.pending.is_empty());
            assert_indexes(&manager);
        }
        book.connected(alias, EPOCH + 2);
        assert_eq!(book.state.lock().stored.records[0].last_seen, EPOCH + 2);
    }

    #[test]
    fn mapped_alias_pending_claims_are_one_identity_and_release_in_either_form() {
        let alias = core_mapped_alias();
        let book = oracle_book();
        book.learn_dns("seed", &[target()], EPOCH);
        book.queued(target());
        book.queued(alias);
        assert_eq!(book.pending_count_excluding(&[]), 1);
        assert_eq!(book.pending_count_excluding(&[alias]), 0);
        assert_eq!(book.pending_count_excluding(&[target()]), 0);
        assert_eq!(book.select(&[], &[], EPOCH, u64::MAX, |_| true), None);
        book.attempted(alias, EPOCH);
        book.succeeded(alias, 9, EPOCH + 1);
        assert_eq!(
            book.pending_count_excluding(&[]),
            1,
            "manual health does not transfer or duplicate a claim"
        );
        book.unqueue(alias);
        assert_eq!(book.pending_count_excluding(&[]), 0);
        book.queued(alias);
        book.unqueue(target());
        assert_eq!(book.pending_count_excluding(&[]), 0);
        assert_eq!(
            book.select(&[], &[], EPOCH + 2, u64::MAX, |_| true),
            Some(target())
        );
    }

    #[test]
    fn mapped_alias_exact_connection_filter_does_not_block_distinct_endpoints() {
        let alias = core_mapped_alias();
        let book = oracle_book();
        book.learn_dns("seed", &[target()], EPOCH);
        assert_eq!(book.select(&[alias], &[], EPOCH, u64::MAX, |_| true), None);
        let different_port = PeerEndpoint::new(alias.address(), 8334);
        assert_eq!(
            book.select(&[different_port], &[], EPOCH, u64::MAX, |_| true),
            Some(target()),
            "inbound exclusion remains exact endpoint only"
        );
        assert_eq!(
            book.select(&[], &[different_port], EPOCH, u64::MAX, |_| true),
            None,
            "outbound diversity still excludes the group"
        );
        let linked: PeerEndpoint = "[2002:0808:0808::1]:8333"
            .parse()
            .expect("different IPv6 transport endpoint");
        assert_ne!(endpoint_key(linked), endpoint_key(target()));
        assert_eq!(
            book.select(&[linked], &[], EPOCH, u64::MAX, |_| true),
            Some(target()),
            "linked IPv4 grouping never rewrites a real IPv6 endpoint identity"
        );
    }

    #[test]
    fn overlay_identity_anonymous_tor_gossip_learns_nothing() {
        let book = book();
        let anon = crate::PeerRemote::AnonymousTor(crate::ConnectionId::for_test_raw(77));
        book.learn_peer(anon, &[(addr(1), 9, 10_000)], 10_000);
        assert_eq!(
            book.len(),
            0,
            "anonymous Tor gossip must learn nothing: no forwarder/proxy source"
        );
        assert!(
            book.state.lock().stored.records.is_empty(),
            "anonymous source consumes no bucket state"
        );
    }

    #[test]
    fn overlay_identity_identified_tor_learns_typed_source() {
        let book = book();
        let tor = PeerEndpoint::TorV3 {
            key: [7u8; 32],
            port: 8333,
        };
        book.learn_peer(
            crate::PeerRemote::Endpoint(tor),
            &[(addr(1), 9, 10_000)],
            10_000,
        );
        assert_eq!(book.len(), 1, "identified Tor gossip must be learned");
        let entry = book.state.lock().stored.records[0].clone();
        assert_eq!(entry.endpoint, addr(1));
        assert_eq!(
            entry.source,
            Source::Overlay(tor.address()),
            "Tor gossip source must be typed Overlay, never proxy Ip"
        );
        assert!(
            !matches!(&entry.source, Source::Ip(ip) if ip.is_loopback()),
            "Tor source must never be a loopback Ip"
        );
    }

    #[test]
    fn overlay_identity_identified_i2p_learns_typed_source() {
        let book = book();
        let i2p = PeerEndpoint::I2p {
            hash: [9u8; 32],
            port: 7656,
        };
        book.learn_peer(
            crate::PeerRemote::Endpoint(i2p),
            &[(addr(1), 9, 10_000)],
            10_000,
        );
        assert_eq!(book.len(), 1, "identified I2P gossip must be learned");
        let entry = book.state.lock().stored.records[0].clone();
        assert_eq!(entry.endpoint, addr(1));
        assert_eq!(
            entry.source,
            Source::Overlay(i2p.address()),
            "I2P gossip source must be SAM-attested Overlay, never proxy Ip"
        );
        assert!(
            !matches!(&entry.source, Source::Ip(ip) if ip.is_loopback()),
            "I2P source must never be a loopback Ip"
        );
    }

    #[test]
    fn overlay_identity_no_loopback_proxy_ip_in_learn() {
        let book = book();
        let loopback: PeerEndpoint =
            std::net::SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8333).into();
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr(2)),
            &[(loopback, 9, 10_000)],
            10_000,
        );
        assert_eq!(
            book.len(),
            0,
            "loopback gossip addresses must never enter learn"
        );
        let anon = crate::PeerRemote::AnonymousTor(crate::ConnectionId::for_test_raw(78));
        book.learn_peer(anon, &[(addr(1), 9, 10_000)], 10_000);
        assert_eq!(
            book.len(),
            0,
            "anonymous Tor gossip must learn nothing even for routable addresses"
        );
    }

    #[test]
    fn i2p_port_zero_is_routable_and_gossiped_while_ip_tor_zero_are_not() {
        use std::time::Instant;
        let book = book();
        let i2p_zero = PeerEndpoint::I2p {
            hash: [9u8; 32],
            port: 0,
        };
        let tor_zero = PeerEndpoint::TorV3 {
            key: [3u8; 32],
            port: 0,
        };
        let ip_zero: PeerEndpoint = PeerEndpoint::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0);
        book.learn_dns("seed", &[i2p_zero, tor_zero, ip_zero], 10_000);
        assert!(
            book.state.lock().by_addr.contains_key(&i2p_zero),
            "Core-form I2P :0 must be admitted"
        );
        assert!(
            !book.state.lock().by_addr.contains_key(&tor_zero),
            "TorV3 :0 must stay unroutable"
        );
        assert!(
            !book.state.lock().by_addr.contains_key(&ip_zero),
            "IP :0 must stay unroutable"
        );
        book.set_addrv2_gossip(false, true);
        let tick = Instant::now();
        let rows = book.gossip_addrv2_at(10_000, tick);
        assert!(
        rows.iter().any(|row| matches!(&row.addr, bitcoin::p2p::address::AddrV2::I2p(hash) if *hash == [9u8; 32]) && row.port == 0),
        "admitted I2P :0 must be gossiped with its explicit zero port"
    );
    }
    mod asmap_tests {
        use super::*;

        const QUOTA_MAP: &[u8] =
            include_bytes!("../../../testdata/wire/data/asmap-source-quota-core-v31.1.raw");

        fn map_file(directory: &Path, bytes: &[u8]) -> PathBuf {
            let path = directory.join("asmap.raw");
            fs::write(&path, bytes).expect("map fixture");
            path
        }
        fn backups(directory: &Path) -> Vec<PathBuf> {
            fs::read_dir(directory)
                .expect("directory")
                .map(|entry| entry.expect("entry").path())
                .filter(|path| path.extension().is_some_and(|extension| extension == "bak"))
                .collect()
        }

        #[test]
        fn asmap_placement_matches_224_actual_core_vectors() {
            let data: sonic_rs::Value = sonic_rs::from_str(include_str!(
                "../../../testdata/wire/data/core-addrman-asmap-v31.1.json"
            ))
            .expect("Core reference");
            let directory = tempfile::tempdir().expect("directory");
            let mut classifiers = HashMap::new();
            for (name, info) in data["map_files"].as_object().expect("maps") {
                let bytes =
                    Vec::<u8>::from_hex(info["raw_hex"].as_str().expect("map bytes")).expect("hex");
                let path = directory.path().join(name);
                fs::write(&path, bytes).expect("map");
                let groups = NetGroups::load(Some(&path));
                assert_eq!(
                    groups
                        .identity()
                        .expect("valid Core map")
                        .to_lower_hex_string(),
                    info["sha256"].as_str().expect("digest")
                );
                classifiers.insert(name, groups);
            }
            assert_eq!(data["rows"].as_array().expect("rows").len(), 224);
            for row in data["rows"].as_array().expect("rows") {
                let groups = &classifiers[row["map"].as_str().expect("map")];
                let secret = <[u8; 32]>::from_hex(row["secret_raw_hex"].as_str().expect("secret"))
                    .expect("key");
                let addr = canonical(PeerEndpoint::new(
                    row["address"]
                        .as_str()
                        .expect("address")
                        .parse::<IpAddr>()
                        .expect("IP"),
                    u16::try_from(row["port"].as_u64().expect("port")).expect("port"),
                ));
                let origin = row["source"].as_str().expect("source");
                let source = origin.strip_prefix("internal:").map_or_else(
                    || Source::Ip(origin.parse().expect("source IP")),
                    Source::dns,
                );
                assert_eq!(
                    groups.group(addr.address()).to_lower_hex_string(),
                    row["address_group_hex"].as_str().expect("group"),
                    "{row}"
                );
                assert_eq!(
                    source.group(groups).to_lower_hex_string(),
                    row["source_group_hex"].as_str().expect("source group"),
                    "{row}"
                );
                assert_eq!(
                    endpoint_key(addr).to_lower_hex_string(),
                    row["endpoint_key_hex"].as_str().expect("endpoint")
                );
                let new = new_bucket(&secret, addr, &source.group(groups), groups);
                let tried = tried_bucket(&secret, addr, groups);
                assert_eq!(
                    u64::try_from(new).expect("bucket"),
                    row["new_bucket"],
                    "{row}"
                );
                assert_eq!(
                    u64::try_from(tried).expect("bucket"),
                    row["tried_bucket"],
                    "{row}"
                );
                assert_eq!(
                    u64::try_from(new_bucket_position(&secret, addr, new)).expect("position"),
                    row["new_position"],
                    "{row}"
                );
                assert_eq!(
                    u64::try_from(tried_bucket_position(&secret, addr, tried)).expect("position"),
                    row["tried_position"],
                    "{row}"
                );
            }
        }

        #[test]
        fn incoming_source_asn_controls_corroboration_without_rewriting_primary_source() {
            let directory = tempfile::tempdir().expect("directory");
            let map = map_file(directory.path(), QUOTA_MAP);
            let book = AddressBook::open(None, [1; 4], false, Some(&map));
            let mut manager = book.state.lock();
            manager.stored.secret = <[u8; 32]>::from_hex(
                "41f758f2e5cc078d3795b4fc0cb60c2d735fa92cc020572bdc982dd2d564d11b",
            )
            .expect("Core secret");
            manager.rng = StdRng::seed_from_u64(17);
            let addr = "4.4.4.4:8333".parse::<PeerEndpoint>().expect("peer");
            let primary = Source::Ip("8.8.0.1".parse::<std::net::IpAddr>().expect("source"));
            add_ref(&mut manager, addr, &primary, EPOCH - 1);
            for _ in 0..512 {
                assert!(!manager.learn(
                    addr,
                    Some(9),
                    Source::Ip("9.9.0.1".parse::<std::net::IpAddr>().expect("same ASN")),
                    EPOCH,
                    EPOCH,
                    0
                ));
            }
            add_ref(
                &mut manager,
                addr,
                &Source::Ip(
                    "8.8.1.1"
                        .parse::<std::net::IpAddr>()
                        .expect("different ASN"),
                ),
                EPOCH,
            );
            let entry = &manager.stored.records[manager.by_addr[&addr]];
            assert_eq!(entry.source, primary);
            assert_eq!(entry.new_buckets, vec![53, 602]);
            assert_indexes(&manager);
        }

        #[test]
        fn failed_configured_map_preserves_original_without_backup() {
            for malformed in [false, true] {
                let directory = tempfile::tempdir().expect("directory");
                let base = directory.path().join("peers.dat");
                let path = network_path(&base, [1; 4]);
                let seed = AddressBook::open(Some(base.clone()), [1; 4], false, None);
                seed.learn_dns("seed", &[target()], EPOCH);
                seed.save();
                let original = fs::read(&path).expect("canonical original");
                let map = directory.path().join("asmap.raw");
                if malformed {
                    fs::write(&map, b"invalid").expect("malformed map");
                }
                let fallback = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
                assert!(!fallback.state.lock().writable);
                assert_eq!(fallback.len(), 1);
                fallback.learn_dns("unpersisted", &[addr(13)], EPOCH);
                fallback.save();
                assert_eq!(fs::read(&path).expect("preserved"), original);
                assert_eq!(backups(directory.path()), Vec::<PathBuf>::new());
                fs::write(&map, QUOTA_MAP).expect("restored map");
                let restored = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
                assert!(restored.state.lock().writable);
                assert_eq!(restored.len(), 1);
                assert!(restored.state.lock().stored.asmap_id.is_some());
                assert_eq!(backups(directory.path()), Vec::<PathBuf>::new());
                restored.save();
                let rebucketed = fs::read(&path).expect("rebucketed");
                assert_ne!(rebucketed, original);
                fs::remove_file(&map).expect("map unavailable again");
                let fallback = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
                assert!(!fallback.state.lock().writable);
                fallback.save();
                assert_eq!(fs::read(&path).expect("rebucketed retained"), rebucketed);
                assert_eq!(backups(directory.path()), Vec::<PathBuf>::new());
            }
        }

        #[test]
        fn asmap_change_rebuckets_without_backup_and_restart_keeps_refs() {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let map = map_file(directory.path(), QUOTA_MAP);
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
            {
                let mut manager = book.state.lock();
                manager.stored.secret = [7; 32];
                manager.rng = StdRng::seed_from_u64(17);
                assert!(manager.learn(
                    target(),
                    Some(9),
                    Source::Internal([1; 10]),
                    EPOCH - 1,
                    EPOCH,
                    0
                ));
                for n in 2..=32 {
                    if refs(&manager, target()) == 8 {
                        break;
                    }
                    for _ in 0..4096 {
                        if manager.learn(
                            target(),
                            Some(9),
                            Source::Internal([n; 10]),
                            EPOCH,
                            EPOCH,
                            0,
                        ) {
                            break;
                        }
                    }
                }
                assert_eq!(refs(&manager, target()), 8);
            }
            book.save();
            let path = network_path(&base, [1; 4]);
            let original = fs::read(&path).expect("canonical original");
            let restored = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
            assert_eq!(refs(&restored.state.lock(), target()), 8);
            assert_eq!(backups(directory.path()), Vec::<PathBuf>::new());
            fs::write(&map, crate::netgroup::LINKED_ASMAP).expect("changed valid map");
            let changed = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
            assert!(changed.state.lock().writable);
            assert_eq!(refs(&changed.state.lock(), target()), 1);
            assert_eq!(backups(directory.path()), Vec::<PathBuf>::new());
            changed.save();
            let rebucketed = fs::read(&path).expect("rebucketed");
            assert_ne!(rebucketed, original);
            let again = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
            assert_eq!(refs(&again.state.lock(), target()), 1);
            assert_eq!(backups(directory.path()), Vec::<PathBuf>::new());
            assert_indexes(&again.state.lock());
            let prefix = AddressBook::open(Some(base), [1; 4], false, None);
            assert!(
                prefix.state.lock().writable,
                "intentional map omission permits current-format rebucketing"
            );
            assert_eq!(prefix.state.lock().stored.asmap_id, None);
            assert_eq!(backups(directory.path()), Vec::<PathBuf>::new());
            assert_indexes(&prefix.state.lock());
        }
    }

    mod probe_tests {
        use super::*;

        fn challenger() -> PeerEndpoint {
            "8.8.8.8:412".parse().expect("actual Core collision")
        }
        fn collision_book() -> Arc<AddressBook> {
            let book = oracle_book();
            {
                let mut manager = book.state.lock();
                assert!(manager.learn(target(), Some(9), source(1), EPOCH - 1000, EPOCH, 0));
                assert!(manager.good(target(), EPOCH - 20_000));
                assert!(manager.learn(challenger(), Some(9), source(1), EPOCH - 1000, EPOCH, 0));
                assert!(!manager.good(challenger(), EPOCH - 2401));
                assert_eq!(manager.tried_slot(target()), 82 * 64 + 29);
                assert_eq!(
                    manager.tried_slot(challenger()),
                    manager.tried_slot(target())
                );
                assert_eq!(manager.collisions, [challenger()]);
            }
            book
        }
        fn state(book: &AddressBook, addr: PeerEndpoint) -> Candidate {
            let manager = book.state.lock();
            manager.stored.records[manager.by_addr[&addr]].clone()
        }

        #[test]
        fn collision_pending_active_policy_and_callback_bounds_recheck_current_state() {
            for protection in 0..4 {
                let book = collision_book();
                book.attempted(target(), EPOCH - 61);
                if protection == 0 {
                    book.queued(target());
                }
                let active = if protection == 1 {
                    vec![target()]
                } else {
                    vec![]
                };
                let before = state(&book, challenger());
                let mut calls = 0;
                book.resolve_collisions(&active, EPOCH, |addr| {
                    calls += 1;
                    assert!(book.state.try_lock().is_some(), "policy executes unlocked");
                    if protection == 3 {
                        book.queued(target());
                    }
                    protection != 2 || addr != target()
                });
                assert_eq!(calls, 2, "only challenger and incumbent policy decisions");
                let after = state(&book, challenger());
                assert!(!after.tried);
                assert_eq!(after.last_success, before.last_success);
                assert_eq!(after.last_attempt, before.last_attempt);
            }
        }

        #[test]
        fn make_tried_clears_all_refs_demotes_and_removes_only_colliding_new_reference() {
            for victim_refs in [1, 2] {
                let book = collision_book();
                let victim: PeerEndpoint =
                    "8.8.9.89:8333".parse().expect("actual Core New collider");
                {
                    let mut manager = book.state.lock();
                    for n in 2..=8 {
                        add_ref(&mut manager, challenger(), &source(n), EPOCH);
                    }
                    assert_eq!(refs(&manager, challenger()), 8);
                    assert!(manager.learn(victim, Some(9), source(1), EPOCH - 1000, EPOCH, 0));
                    if victim_refs == 2 {
                        add_ref(&mut manager, victim, &source(2), EPOCH);
                    }
                    manager.stored.anchors.push(Anchor {
                        endpoint: target(),
                        confirmed_at: EPOCH - 10,
                    });
                }
                book.attempted(target(), EPOCH - 61);
                book.resolve_collisions(&[], EPOCH, |_| true);
                let manager = book.state.lock();
                assert!(manager.stored.records[manager.by_addr[&challenger()]].tried);
                assert_eq!(refs(&manager, challenger()), 0);
                assert_eq!(refs(&manager, target()), 1);
                assert_eq!(refs(&manager, victim), victim_refs - 1);
                assert_eq!(
                    manager.stored.anchors[0].endpoint,
                    target(),
                    "demotion retains anchor identity"
                );
                assert_indexes(&manager);
            }
        }

        #[test]
        fn pending_final_demotion_victim_defers_all_membership_and_good_health() {
            let book = collision_book();
            let victim: PeerEndpoint = "8.8.9.89:8333".parse().expect("collider");
            {
                let mut manager = book.state.lock();
                manager.learn(victim, Some(9), source(1), EPOCH - 1000, EPOCH, 0);
            }
            book.queued(victim);
            book.attempted(target(), EPOCH - 61);
            let before = state(&book, challenger());
            let global_good = book.state.lock().last_good;
            book.resolve_collisions(&[], EPOCH, |_| true);
            let after = state(&book, challenger());
            assert_eq!(
                (after.last_success, after.last_attempt, after.failures),
                (before.last_success, before.last_attempt, before.failures)
            );
            assert_eq!(book.state.lock().last_good, global_good);
            assert!(!after.tried);
            assert_indexes(&book.state.lock());
            book.unqueue(victim);
            book.resolve_collisions(&[], EPOCH, |_| true);
            assert!(state(&book, challenger()).tried);
        }

        #[test]
        fn feeler_connected_incumbent_gets_good_but_pending_attempt_does_not() {
            let book = collision_book();
            let mapped: PeerEndpoint = "[::ffff:8.8.8.8]:8333".parse().expect("alias");
            assert_eq!(
                book.feeler(&[mapped], &[mapped], EPOCH, |_| true),
                Some(challenger())
            );
            assert_eq!(state(&book, target()).last_success, EPOCH);
            book.resolve_collisions(&[], EPOCH + 1, |_| true);
            assert_eq!(book.state.lock().collisions, Vec::<PeerEndpoint>::new());
            let book = collision_book();
            book.queued(mapped);
            let before = state(&book, target()).last_success;
            assert_eq!(
                book.feeler(&[mapped], &[], EPOCH, |_| true),
                Some(challenger())
            );
            assert_eq!(state(&book, target()).last_success, before);
            assert!(book.queued_feeler(challenger()));
            assert!(!book.queued_feeler(addr(2)));
            assert_eq!(
                book.pending_count_excluding(&[]),
                1,
                "feeler consumes no steady slot"
            );
            assert_eq!(book.feeler(&[], &[], EPOCH, |_| true), None);
        }

        #[test]
        fn connected_collision_good_uses_ip_not_port_but_not_linked_ipv6_group() {
            let book = collision_book();
            let other_port: PeerEndpoint = "[::ffff:8.8.8.8]:18444".parse().expect("TCP alias");
            book.feeler(&[other_port], &[other_port], EPOCH, |_| true);
            assert_eq!(state(&book, target()).last_success, EPOCH);
            let book = collision_book();
            let linked: PeerEndpoint = "[2002:808:808::1]:8333".parse().expect("linked IPv6");
            assert_eq!(
                book.feeler(&[linked], &[linked], EPOCH, |_| true),
                Some(target())
            );
            assert_eq!(state(&book, target()).last_success, EPOCH - 20_000);
            let book = collision_book();
            book.feeler(&[other_port], &[], EPOCH, |_| true);
            assert_eq!(state(&book, target()).last_success, EPOCH - 20_000);
        }

        #[test]
        fn anchors_consume_durably_and_return_original_metadata_only_before_dispatch() {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            book.learn_dns("seed", &[target(), addr(2)], EPOCH);
            book.succeeded(target(), 9, EPOCH);
            book.succeeded(addr(2), 9, EPOCH);
            book.remember_anchors(&[target(), addr(2)], EPOCH);
            book.save();
            let anchors = book.take_restart_anchors(EPOCH + 1);
            assert_eq!(anchors.len(), 2);
            assert_eq!(
                AddressBook::open(Some(base.clone()), [1; 4], false, None)
                    .state
                    .lock()
                    .stored
                    .anchors,
                Vec::<Anchor>::new()
            );
            assert!(book.queue_anchor(target()));
            book.defer_anchor(target());
            assert!(book.queue_anchor(target()));
            assert!(book.anchor_dispatched(target()));
            assert!(!book.anchor_dispatched(target()));
            book.return_restart_anchors(EPOCH + 100);
            let restored = AddressBook::open(Some(base), [1; 4], false, None);
            let manager = restored.state.lock();
            assert_eq!(
                manager.stored.anchors,
                [Anchor {
                    endpoint: addr(2),
                    confirmed_at: EPOCH
                }]
            );
            assert!(
                !book.anchor_dispatched(addr(2)),
                "a stale channel item cannot consume returned metadata"
            );
        }

        #[test]
        fn failed_anchor_consumption_exposes_no_claims_and_newer_confirmation_wins_return() {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            book.learn_dns("seed", &[target()], EPOCH);
            book.succeeded(target(), 9, EPOCH);
            book.remember_anchors(&[target()], EPOCH);
            book.save();
            let path = network_path(&base, [1; 4]);
            fs::remove_file(&path).expect("file");
            fs::create_dir(&path).expect("failed replace");
            assert_eq!(
                book.take_restart_anchors(EPOCH + 1),
                Vec::<PeerEndpoint>::new()
            );
            assert!(book.state.lock().pending.is_empty());
            assert_eq!(
                book.state.lock().stored.anchors,
                [Anchor {
                    endpoint: target(),
                    confirmed_at: EPOCH
                }]
            );
            fs::remove_dir(&path).expect("repair publication path");
            book.save();
            assert_eq!(
                AddressBook::open(Some(base), [1; 4], false, None)
                    .state
                    .lock()
                    .stored
                    .anchors,
                [Anchor {
                    endpoint: target(),
                    confirmed_at: EPOCH
                }]
            );
            let book = super::book();
            book.learn_dns("seed", &[target()], EPOCH);
            book.succeeded(target(), 9, EPOCH);
            book.remember_anchors(&[target()], EPOCH);
            assert_eq!(book.take_restart_anchors(EPOCH + 1), [target()]);
            book.remember_anchors(&[target()], EPOCH + 100);
            book.return_restart_anchors(EPOCH + 101);
            assert_eq!(
                book.state.lock().stored.anchors,
                [Anchor {
                    endpoint: target(),
                    confirmed_at: EPOCH + 100
                }]
            );
        }

        fn collision_oracle() -> sonic_rs::Value {
            sonic_rs::from_str(include_str!(
                "../../../testdata/wire/data/core-addrman-collisions-v31.1.json"
            ))
            .expect("independent Core output")
        }
        fn manager_from_collision_snapshot(row: &sonic_rs::Value) -> Manager {
            let mut manager = Manager::new([1; 4], false, None, NetGroups::default());
            manager.stored.secret = <[u8; 32]>::from_hex(
                "41f758f2e5cc078d3795b4fc0cb60c2d735fa92cc020572bdc982dd2d564d11b",
            )
            .expect("Core secret");
            for name in ["incumbent", "victim", "challenger", "second_challenger"] {
                let entry = &row[name];
                if entry["present"] != true {
                    continue;
                }
                manager.stored.records.push(Candidate {
                    creation_id: u64::try_from(manager.stored.records.len()).expect("creation ID"),
                    endpoint: entry["endpoint"]
                        .as_str()
                        .expect("endpoint")
                        .parse_endpoint(),
                    services: Some(9),
                    source: Source::Ip(
                        entry["primary_source"]
                            .as_str()
                            .expect("source")
                            .parse()
                            .expect("IP"),
                    ),
                    last_seen: entry["seen"].as_u64().expect("seen"),
                    last_success: entry["last_success"].as_u64().expect("success"),
                    last_attempt: entry["last_try"].as_u64().expect("try"),
                    failures: u32::try_from(entry["attempts"].as_u64().expect("failures"))
                        .expect("u32"),
                    last_count_attempt: 0,
                    tried: entry["tried"].as_bool().expect("membership"),
                    new_buckets: entry["new_slots"]
                        .as_array()
                        .expect("slots")
                        .iter()
                        .map(|slot| u16::try_from(slot[0].as_u64().expect("bucket")).expect("u16"))
                        .collect(),
                });
            }
            manager.install_indexes();
            manager.collisions.push(challenger());
            if row["queue"] == 2 {
                manager.collisions.push(
                    row["second_challenger"]["endpoint"]
                        .as_str()
                        .expect("second")
                        .parse_endpoint(),
                );
            }
            manager.last_good = row["last_good"].as_u64().expect("good");
            manager
        }
        fn assert_collision_snapshot(manager: &Manager, row: &sonic_rs::Value) {
            assert_eq!(
                u64::try_from(manager.stored.records.len()).expect("bounded count"),
                row["records"],
                "{} records",
                row["case"]
            );
            assert_eq!(
                u64::try_from(manager.collisions.len()).expect("bounded count"),
                row["queue"],
                "{} queue",
                row["case"]
            );
            assert_eq!(
                manager.last_good, row["last_good"],
                "{} global Good",
                row["case"]
            );
            for name in ["incumbent", "victim", "challenger", "second_challenger"] {
                let entry = &row[name];
                if entry.is_null() {
                    continue;
                }
                let endpoint: PeerEndpoint = entry["endpoint"]
                    .as_str()
                    .expect("endpoint")
                    .parse_endpoint();
                let actual = manager
                    .by_addr
                    .get(&endpoint)
                    .map(|index| &manager.stored.records[*index]);
                assert_eq!(
                    actual.is_some(),
                    entry["present"],
                    "{} {name} presence",
                    row["case"]
                );
                let Some(actual) = actual else { continue };
                assert_eq!(actual.tried, entry["tried"]);
                assert_eq!(
                    u64::try_from(actual.new_buckets.len()).expect("bounded count"),
                    entry["refs"]
                );
                assert_eq!(actual.last_seen, entry["seen"]);
                assert_eq!(
                    actual.last_success, entry["last_success"],
                    "{} {name} success",
                    row["case"]
                );
                assert_eq!(actual.last_attempt, entry["last_try"]);
                assert_eq!(actual.failures, entry["attempts"]);
                assert_eq!(
                    actual.source,
                    Source::Ip(
                        entry["primary_source"]
                            .as_str()
                            .expect("source")
                            .parse()
                            .expect("IP")
                    )
                );
                let mut slots: Vec<_> = actual
                    .new_buckets
                    .iter()
                    .map(|bucket| {
                        vec![
                            usize::from(*bucket),
                            manager.new_slot(endpoint, usize::from(*bucket)) % 64,
                        ]
                    })
                    .collect();
                slots.sort();
                assert_eq!(
                    sonic_rs::to_value(&slots).expect("slots"),
                    entry["new_slots"]
                );
            }
            assert_indexes(manager);
        }

        #[test]
        fn collision_transitions_match_actual_core_snapshots() {
            let oracle = collision_oracle();
            let rows = oracle["rows"].as_array().expect("rows");
            let mut compared = 0;
            for before in rows {
                let Some(label) = before["case"]
                    .as_str()
                    .and_then(|name| name.strip_suffix("-before"))
                else {
                    continue;
                };
                let Some(after) = rows
                    .iter()
                    .find(|row| row["case"] == format!("{label}-after"))
                else {
                    continue;
                };
                let mut manager = manager_from_collision_snapshot(before);
                let allowed = manager
                    .stored
                    .records
                    .iter()
                    .map(|entry| entry.endpoint)
                    .collect();
                manager.resolve_collisions(&HashSet::new(), &allowed, EPOCH);
                assert_collision_snapshot(&manager, after);
                compared += 1;
            }
            assert!(
                compared >= 21,
                "all timing, demotion and defensive-state cases"
            );
        }

        #[test]
        fn collision_queue_counts_challengers_and_caps_ten_even_for_one_incumbent() {
            let oracle = collision_oracle();
            let rows = oracle["rows"].as_array().expect("rows");
            let book = oracle_book();
            let mut manager = book.state.lock();
            manager.learn(target(), Some(9), source(1), EPOCH - 100_000, EPOCH, 0);
            manager.good_replace(target(), EPOCH - 20_000);
            for (index, endpoint) in rows[0]["colliders"]
                .as_array()
                .expect("colliders")
                .iter()
                .take(11)
                .enumerate()
            {
                let endpoint: PeerEndpoint = endpoint.as_str().expect("endpoint").parse_endpoint();
                assert!(manager.learn(
                    endpoint,
                    Some(9),
                    source(u8::try_from(index + 2).expect("source")),
                    EPOCH - 100_000,
                    EPOCH,
                    0
                ));
                assert!(!manager.good(endpoint, EPOCH - 30));
                let expected = rows
                    .iter()
                    .find(|row| row["case"] == format!("queue-add-{}", index + 1))
                    .expect("Core row");
                assert_eq!(
                    u64::try_from(manager.collisions.len()).expect("bounded count"),
                    expected["queue"]
                );
                assert_eq!(
                    u64::try_from(manager.stored.records.len()).expect("bounded count"),
                    expected["records"]
                );
                assert_eq!(manager.last_good, expected["last_good"]);
                assert_indexes(&manager);
            }
            manager.good(challenger(), EPOCH);
            assert_eq!(manager.collisions.len(), 10);
            assert_eq!(
                manager.stored.records[manager.by_addr[&challenger()]].last_success,
                EPOCH
            );
        }

        #[test]
        fn connected_collision_good_and_new_selection_match_actual_core() {
            let oracle = collision_oracle();
            let rows = oracle["rows"].as_array().expect("rows");
            let expected_good = rows
                .iter()
                .find(|row| row["case"] == "already-connected-after-good")
                .expect("Core Good");
            let expected_resolved = rows
                .iter()
                .find(|row| row["case"] == "already-connected-after-resolve")
                .expect("Core Resolve");
            let mut manager = manager_from_collision_snapshot(expected_good);
            let old = manager.by_addr[&target()];
            manager.stored.records[old].last_success = EPOCH - 20_000;
            manager.stored.records[old].last_attempt = EPOCH - 1234;
            manager.last_good = EPOCH - 30;
            let book = AddressBook {
                state: Mutex::new(manager),
                publication: Mutex::new(()),
                addrv2_gossip: [
                    std::sync::atomic::AtomicBool::new(false),
                    std::sync::atomic::AtomicBool::new(false),
                ],
            };
            assert_eq!(
                book.feeler(&[target()], &[target()], EPOCH, |_| true),
                Some(challenger())
            );
            assert_collision_snapshot(&book.state.lock(), expected_good);
            book.resolve_collisions(&[], EPOCH, |_| true);
            assert_collision_snapshot(&book.state.lock(), expected_resolved);
        }

        #[test]
        fn successful_connected_challenger_can_promote_without_losing_pending_identity() {
            let book = collision_book();
            book.queued(challenger());
            book.attempted(target(), EPOCH - 61);
            book.resolve_collisions(&[challenger()], EPOCH, |_| true);
            assert!(state(&book, challenger()).tried);
            assert!(book.is_pending(challenger()));
            assert_indexes(&book.state.lock());
        }

        #[test]
        fn current_anchors_obey_configured_map_and_orphan_shape_barriers() {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            book.learn_dns("seed", &[target(), addr(2)], EPOCH);
            book.succeeded(target(), 9, EPOCH);
            book.succeeded(addr(2), 9, EPOCH);
            book.remember_anchors(&[target(), addr(2)], EPOCH);
            book.save();
            let current = fs::read(&path).expect("current");
            let map = directory.path().join("map.raw");
            fs::write(&map, b"invalid map").expect("invalid map");
            let invalid = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
            assert!(!invalid.state.lock().writable);
            assert_eq!(
                invalid.take_restart_anchors(EPOCH + 10),
                Vec::<PeerEndpoint>::new()
            );
            assert_eq!(invalid.state.lock().stored.anchors.len(), 2);
            invalid.save();
            assert_eq!(fs::read(&path).expect("preserved"), current);
            assert_eq!(
                fs::read_dir(directory.path()).expect("directory").count(),
                2,
                "invalid map creates no backup"
            );
            fs::write(
                &map,
                include_bytes!("../../../testdata/wire/data/asmap-linked-ipv4-core-v31.1.raw"),
            )
            .expect("restore map");
            let restored = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
            assert!(restored.state.lock().writable);
            assert_eq!(restored.state.lock().stored.anchors.len(), 2);
            assert_indexes(&restored.state.lock());
            restored.save();
            let prefix = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            assert!(prefix.state.lock().writable);
            assert_eq!(prefix.state.lock().stored.anchors.len(), 2);
            assert_indexes(&prefix.state.lock());
            prefix.save();
            let current = fs::read(&path).expect("current");
            let mut value: sonic_rs::Value =
                sonic_rs::from_slice(&current[..current.len() - 32]).expect("JSON");
            value["anchors"] = sonic_rs::json!([{"addr":"9.9.9.9:8333","confirmed_at":EPOCH}]);
            let malformed = fixture_bytes(&value);
            fs::write(&path, &malformed).expect("orphan anchor");
            let rejected = AddressBook::open(Some(base), [1; 4], false, None);
            assert!(!rejected.state.lock().writable);
            rejected.save();
            assert_eq!(fs::read(path).expect("rejected preserved"), malformed);
        }

        #[test]
        fn anchor_reservation_precedes_publication_and_failed_commit_rolls_it_back() {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let book = AddressBook::open(Some(base), [1; 4], false, None);
            book.learn_dns("seed", &[target()], EPOCH);
            book.succeeded(target(), 9, EPOCH);
            book.remember_anchors(&[target()], EPOCH);
            book.save();
            let publication = book.publication.lock();
            let taker = Arc::clone(&book);
            let worker = std::thread::spawn(move || taker.take_restart_anchors(EPOCH + 1));
            let deadline = Instant::now() + Duration::from_secs(5);
            while !book.is_pending(target()) {
                assert!(Instant::now() < deadline, "take reached pending transfer");
                std::thread::yield_now();
            }
            assert!(!book.queued_feeler(target()));
            book.queued(target());
            assert!(matches!(
                book.state.lock().pending.get(&target()),
                Some(PendingClaim::AnchorReservation(_))
            ));
            drop(publication);
            assert_eq!(worker.join().expect("take"), [target()]);
            book.return_restart_anchors(EPOCH + 2);
            assert_eq!(
                book.state.lock().stored.anchors,
                [Anchor {
                    endpoint: target(),
                    confirmed_at: EPOCH
                }]
            );
            book.queued(target());
            assert_eq!(
                book.take_restart_anchors(EPOCH + 3),
                Vec::<PeerEndpoint>::new()
            );
            assert_eq!(
                book.state.lock().stored.anchors,
                [Anchor {
                    endpoint: target(),
                    confirmed_at: EPOCH
                }],
                "preexisting dial cannot consume an unused anchor"
            );
        }

        #[test]
        fn collision_resolution_uses_creation_order_not_reversed_good_order() {
            let book = oracle_book();
            let second: PeerEndpoint = "8.8.8.8:1343".parse().expect("second actual Core collider");
            let mut manager = book.state.lock();
            manager.learn(target(), Some(9), source(1), EPOCH - 1000, EPOCH, 0);
            manager.good(target(), EPOCH - 20_000);
            manager.learn(challenger(), Some(9), source(2), EPOCH - 1000, EPOCH, 0);
            manager.learn(second, Some(9), source(3), EPOCH - 1000, EPOCH, 0);
            manager.good(second, EPOCH - 30);
            manager.good(challenger(), EPOCH - 30);
            assert_eq!(manager.collisions, [challenger(), second]);
            let old = manager.by_addr[&target()];
            manager.stored.records[old].last_attempt = EPOCH - 61;
            let allowed = manager
                .stored
                .records
                .iter()
                .map(|entry| entry.endpoint)
                .collect();
            manager.resolve_collisions(&HashSet::new(), &allowed, EPOCH);
            assert!(manager.stored.records[manager.by_addr[&challenger()]].tried);
            assert!(!manager.stored.records[manager.by_addr[&second]].tried);
            assert_eq!(manager.collisions, Vec::<PeerEndpoint>::new());
            assert_indexes(&manager);
        }

        #[test]
        fn feelers_use_advertised_address_database_services_without_inventing_dns_bits() {
            let book = book();
            book.learn_dns("seed", &[target()], EPOCH);
            assert_eq!(book.feeler(&[], &[], EPOCH, |_| true), None);
            assert_eq!(
                book.select(&[], &[], EPOCH, u64::MAX, |_| true),
                Some(target())
            );
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(2)),
                &[(target(), 1, EPOCH)],
                EPOCH,
            );
            assert_eq!(book.feeler(&[], &[], EPOCH, |_| true), Some(target()));
            book.state.lock().stored.records[0].services = Some(1024);
            assert_eq!(book.feeler(&[], &[], EPOCH, |_| true), Some(target()));
            book.state.lock().stored.records[0].services = Some(8);
            assert_eq!(book.feeler(&[], &[], EPOCH, |_| true), None);
        }

        #[test]
        fn regular_queue_admission_never_takes_probe_or_anchor_claims() {
            let book = book();
            let alias: PeerEndpoint = "[::ffff:8.8.8.8]:8333".parse().expect("alias");
            assert!(book.queued_feeler(target()));
            assert!(!book.queued(alias));
            assert!(book.is_feeler(target()));
            book.unqueue(alias);
            book.learn_dns("seed", &[target()], EPOCH);
            book.succeeded(target(), 9, EPOCH);
            book.remember_anchors(&[target()], EPOCH);
            assert_eq!(book.take_restart_anchors(EPOCH + 1), [target()]);
            assert!(!book.queued(alias));
            assert!(book.queue_anchor(alias));
            assert!(!book.queued(target()));
            assert!(book.anchor_dispatched(alias));
            assert!(
                book.queued(target()),
                "the same ordinary Dial purpose is compatible"
            );
            assert!(book.is_pending(alias));
        }

        #[test]
        fn returned_anchor_releases_same_as_group_and_rejection_preserves_other_purposes() {
            let directory = tempfile::tempdir().expect("directory");
            let map = directory.path().join("asmap.raw");
            fs::write(
                &map,
                include_bytes!("../../../testdata/wire/data/asmap-source-quota-core-v31.1.raw"),
            )
            .expect("Core map");
            let book = AddressBook::open(None, [1; 4], false, Some(&map));
            book.state.lock().stored.secret = [1; 32];
            let anchor: PeerEndpoint = "8.8.0.1:8333".parse().expect("anchor");
            let other: PeerEndpoint = "9.9.0.1:8333".parse().expect("same Core ASN");
            book.learn_dns("seed", &[anchor, other], EPOCH);
            assert_eq!(book.len(), 2);
            book.succeeded(anchor, 9, EPOCH);
            book.remember_anchors(&[anchor], EPOCH);
            assert_eq!(book.take_restart_anchors(EPOCH + 1), [anchor]);
            book.reject_queued(anchor);
            assert!(book.is_pending(anchor));
            assert_eq!(
                book.select(&[], &[], EPOCH + 2, u64::MAX, |addr| addr == other),
                None
            );
            book.return_restart_anchor(anchor, EPOCH + 2);
            assert!(!book.is_pending(anchor));
            assert_eq!(
                book.select(&[], &[], EPOCH + 2, u64::MAX, |addr| addr == other),
                Some(other)
            );
            assert_eq!(
                book.state.lock().stored.anchors,
                [Anchor {
                    endpoint: anchor,
                    confirmed_at: EPOCH
                }]
            );
            assert!(book.queued_feeler(other));
            book.reject_queued(other);
            assert!(book.is_feeler(other));
            book.reject_queued_feeler(other);
            assert!(!book.is_pending(other));
        }
    }

    mod eligibility_tests {
        use super::*;

        #[test]
        fn ordinary_selection_uses_existing_service_contract_for_new_and_tried() {
            for tried in [false, true] {
                for (services, depth, expected) in [
                    (0, 143, false),
                    (1, 143, false),
                    (8, 143, false),
                    (9, u64::MAX, true),
                    (1024, 143, false),
                    (1032, 143, true),
                    (1032, 144, false),
                    (1032, u64::MAX, false),
                    (1033, u64::MAX, true),
                ] {
                    let book = book();
                    book.learn_peer(
                        crate::PeerRemote::Endpoint(addr(2)),
                        &[(target(), services, EPOCH)],
                        EPOCH,
                    );
                    if tried {
                        book.succeeded(target(), services, EPOCH + 1);
                    }
                    assert_eq!(
                        book.ordinary_services_eligible(target(), depth),
                        expected,
                        "services={services} depth={depth} tried={tried}"
                    );
                    assert_eq!(
                        book.select(&[], &[], EPOCH + 2, depth, |_| true),
                        expected.then_some(target())
                    );
                    assert_eq!(
                        book.state.lock().stored.records[0].tried,
                        tried,
                        "eligibility never rewrites Core membership"
                    );
                }
            }
        }

        #[test]
        fn current_services_are_rechecked_after_unlocked_policy_callback() {
            let book = book();
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(2)),
                &[(target(), 9, EPOCH)],
                EPOCH,
            );
            assert_eq!(
                book.select(&[], &[], EPOCH, u64::MAX, |endpoint| {
                    assert!(book.state.try_lock().is_some());
                    book.set_services(endpoint, 1);
                    true
                }),
                None
            );
            assert_eq!(
                book.select(&[], &[], EPOCH, u64::MAX, |endpoint| {
                    book.set_services(endpoint, 9);
                    true
                }),
                Some(target())
            );
        }

        #[test]
        fn accepted_version_service_update_is_metadata_only_canonical_and_idempotent() {
            let book = book();
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(2)),
                &[(target(), 9, EPOCH)],
                EPOCH,
            );
            book.attempt_failed(target(), EPOCH + 1);
            let (before, revision, last_good) = {
                let manager = book.state.lock();
                (
                    manager.stored.records[0].clone(),
                    manager.revision,
                    manager.last_good,
                )
            };
            let mapped: PeerEndpoint = "[::ffff:8.8.8.8]:8333".parse().expect("alias");
            book.set_services(mapped, 1);
            assert!(!book.ordinary_services_eligible(mapped, u64::MAX));
            {
                let manager = book.state.lock();
                let after = &manager.stored.records[0];
                assert_eq!(after.services, Some(1));
                assert_eq!(
                    (
                        after.last_seen,
                        after.last_success,
                        after.last_attempt,
                        after.last_count_attempt,
                        after.failures
                    ),
                    (
                        before.last_seen,
                        before.last_success,
                        before.last_attempt,
                        before.last_count_attempt,
                        before.failures
                    )
                );
                assert_eq!(
                    (&after.source, after.tried, &after.new_buckets),
                    (&before.source, before.tried, &before.new_buckets)
                );
                assert_eq!(manager.last_good, last_good);
                assert_eq!(manager.revision, revision + 1);
            }
            book.set_services(target(), 1);
            book.set_services(addr(99), 0);
            assert_eq!(book.state.lock().revision, revision + 1);
            assert_eq!(book.len(), 1);
            assert!(
                book.ordinary_services_eligible(addr(99), u64::MAX),
                "missing metadata is not invented evidence"
            );
        }

        #[test]
        fn only_unknown_dns_services_keep_native_bootstrap_exception() {
            for source in [
                Source::dns("seed"),
                Source::Overlay(
                    "fivcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivjcrid.onion:8334"
                        .parse::<PeerEndpoint>()
                        .expect("overlay")
                        .address(),
                ),
                Source::Ip(
                    addr(2)
                        .address()
                        .ip()
                        .unwrap_or_else(|| panic!("expected IP fixture")),
                ),
            ] {
                let directory = tempfile::tempdir().expect("directory");
                let path = directory.path().join("peers.dat");
                let book = AddressBook::open(Some(path.clone()), [1; 4], false, None);
                let dns = matches!(source, Source::Internal(_));
                let services = if dns { None } else { Some(0) };
                book.state
                    .lock()
                    .learn(target(), services, source.clone(), EPOCH, EPOCH, 0);
                assert_eq!(book.ordinary_services_eligible(target(), u64::MAX), dns);
                book.set_services(target(), 0);
                assert!(
                    !book.ordinary_services_eligible(target(), u64::MAX),
                    "an accepted VERSION0 is known even without Good"
                );
                book.succeeded(target(), 0, EPOCH + 1);
                assert!(
                    book.state.lock().stored.records[0].tried,
                    "feeler Good is not gated on WITNESS"
                );
                assert!(!book.ordinary_services_eligible(target(), u64::MAX));
                book.learn_dns("fresh-seed", &[target()], EPOCH + 7200);
                assert!(!book.ordinary_services_eligible(target(), u64::MAX));
                book.save();
                let restored = AddressBook::open(Some(path), [1; 4], false, None);
                assert!(!restored.ordinary_services_eligible(target(), u64::MAX));
                assert_eq!(
                    restored.select(&[], &[], EPOCH + 7201, u64::MAX, |_| true),
                    None
                );
            }
        }

        #[test]
        fn later_gossip_service_upgrade_uses_the_single_current_field() {
            let book = book();
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(2)),
                &[(target(), 1, EPOCH)],
                EPOCH,
            );
            book.succeeded(target(), 1, EPOCH + 1);
            assert!(!book.ordinary_services_eligible(target(), u64::MAX));
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(3)),
                &[(target(), 8, EPOCH + 2)],
                EPOCH + 2,
            );
            assert!(book.ordinary_services_eligible(target(), u64::MAX));
            assert_eq!(
                book.select(&[], &[], EPOCH + 2, u64::MAX, |_| true),
                Some(target())
            );
            book.set_services(target(), 1);
            assert!(!book.ordinary_services_eligible(target(), u64::MAX));
        }
    }

    mod services_tests {
        use super::*;
        use sonic_rs::JsonValueMutTrait as _;

        fn stored_value(path: &Path) -> sonic_rs::Value {
            let bytes = fs::read(path).expect("book bytes");
            sonic_rs::from_slice(&bytes[..bytes.len() - 32]).expect("book JSON")
        }

        #[test]
        fn unmarked_v8_book_is_preserved_without_migration() {
            use bitcoin::hex::DisplayHex as _;
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            book.learn_dns("seed", &[target()], EPOCH);
            book.save();
            let v9_payload = fs::read(&path).expect("saved book");
            let mut value: sonic_rs::Value =
                sonic_rs::from_slice(&v9_payload[..v9_payload.len() - 32]).expect("saved JSON");
            let records_before = value["records"].clone();
            value.as_object_mut().expect("object").remove(&"format");
            value["version"] = sonic_rs::json!(8);
            let mut v8_bytes = sonic_rs::to_vec(&value).expect("v8 payload");
            let checksum = Sha256::digest(&v8_bytes);
            v8_bytes.extend_from_slice(&checksum);
            fs::write(&path, &v8_bytes).expect("write v8 book");

            let preserved = AddressBook::open(Some(base), [1; 4], false, None);
            assert!(preserved.state.lock().writable);
            assert!(
                preserved.state.lock().stored.records.is_empty(),
                "pre-release records are never imported"
            );
            let backup = path.with_extension(format!(
                "pre-release-{}.bak",
                Sha256::digest(&v8_bytes)[..].to_lower_hex_string()
            ));
            assert_eq!(fs::read(&backup).expect("preservation backup"), v8_bytes);
            assert_eq!(fs::read(&path).expect("source before publish"), v8_bytes);
            preserved.save();
            let canonical = stored_value(&path);
            assert_eq!(canonical["version"], sonic_rs::json!(1));
            assert_eq!(
                canonical["records"],
                sonic_rs::json!([]),
                "no pre-release record is migrated"
            );
            assert_ne!(canonical["records"], records_before);
        }

        #[test]
        fn unknown_dns_zero_version_is_durable_metadata_without_good() {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            book.learn_dns("seed", &[target()], EPOCH);
            book.attempt_failed(target(), EPOCH + 1);
            book.save();
            assert_eq!(
                stored_value(&path)["records"][0]["services"],
                sonic_rs::json!(null)
            );
            assert!(
                AddressBook::open(Some(base.clone()), [1; 4], false, None)
                    .ordinary_services_eligible(target(), u64::MAX)
            );
            let (before, revision, last_good) = {
                let manager = book.state.lock();
                (
                    manager.stored.records[0].clone(),
                    manager.revision,
                    manager.last_good,
                )
            };
            book.set_services(target(), 0);
            {
                let manager = book.state.lock();
                let after = &manager.stored.records[0];
                assert_eq!(after.services, Some(0));
                assert_eq!(
                    (
                        after.last_success,
                        after.last_seen,
                        after.last_attempt,
                        after.last_count_attempt,
                        after.failures,
                        after.tried
                    ),
                    (
                        before.last_success,
                        before.last_seen,
                        before.last_attempt,
                        before.last_count_attempt,
                        before.failures,
                        before.tried
                    )
                );
                assert_eq!(
                    (&after.source, &after.new_buckets),
                    (&before.source, &before.new_buckets)
                );
                assert_eq!(manager.last_good, last_good);
                assert_eq!(manager.revision, revision + 1);
            }
            book.set_services(target(), 0);
            assert_eq!(
                book.state.lock().revision,
                revision + 1,
                "known zero overwrite is idempotent"
            );
            assert!(!book.ordinary_services_eligible(target(), u64::MAX));
            book.learn_dns("another-seed", &[target()], EPOCH + 7200);
            assert_eq!(book.state.lock().stored.records[0].services, Some(0));
            book.save();
            assert_eq!(stored_value(&path)["format"], "bitcoin-rs-addrman");
            assert_eq!(stored_value(&path)["version"], SCHEMA_VERSION);
            assert_eq!(stored_value(&path)["records"][0]["services"], 0);
            let restored = AddressBook::open(Some(base), [1; 4], false, None);
            assert_eq!(restored.state.lock().stored.records[0].services, Some(0));
            assert_eq!(restored.state.lock().stored.records[0].last_success, 0);
            assert_eq!(
                restored.select(&[], &[], EPOCH + 7201, u64::MAX, |_| true),
                None
            );
        }

        #[test]
        fn incoming_known_gossip_and_unknown_dns_merge_without_losing_observation() {
            let book = book();
            book.learn_dns("seed", &[target()], EPOCH);
            let revision = book.state.lock().revision;
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(2)),
                &[(target(), 0, EPOCH)],
                EPOCH,
            );
            assert_eq!(book.state.lock().stored.records[0].services, None);
            assert_eq!(
                book.state.lock().revision,
                revision,
                "zero-bit gossip and same-time ref refusal add no new information"
            );
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(3)),
                &[(target(), 1, EPOCH)],
                EPOCH,
            );
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(4)),
                &[(target(), 8, EPOCH)],
                EPOCH,
            );
            assert_eq!(book.state.lock().stored.records[0].services, Some(9));
            book.learn_dns("seed", &[target()], EPOCH + 7200);
            assert_eq!(book.state.lock().stored.records[0].services, Some(9));
            book.succeeded(target(), 0, EPOCH + 7201);
            book.learn_dns("seed", &[target()], EPOCH + 14_400);
            assert_eq!(book.state.lock().stored.records[0].services, Some(0));
            assert_eq!(
                book.state.lock().stored.records[0].last_seen,
                EPOCH + 14_400,
                "unknown incoming advertisement still refreshes known peer time"
            );
            let ip_origin = addr(5);
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(6)),
                &[(ip_origin, 9, EPOCH)],
                EPOCH,
            );
            book.succeeded(ip_origin, 9, EPOCH + 1);
            book.learn_dns("seed", &[ip_origin], EPOCH + 14_400);
            let manager = book.state.lock();
            let entry = &manager.stored.records[manager.by_addr[&ip_origin]];
            assert_eq!(entry.services, Some(9));
            assert_eq!(
                entry.source,
                Source::Ip(
                    addr(6)
                        .address()
                        .ip()
                        .unwrap_or_else(|| panic!("expected IP fixture"))
                )
            );
            assert_eq!(entry.last_seen, EPOCH + 14_400);
        }

        #[test]
        fn current_services_field_is_required_nullable_or_u64_and_unknown_has_valid_provenance() {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            book.learn_dns("seed", &[target()], EPOCH);
            book.save();
            let original = stored_value(&path);
            for scalar in ["null", "0", "18446744073709551615"] {
                let payload = sonic_rs::to_string(&original)
                    .expect("JSON")
                    .replace("\"services\":null", &format!("\"services\":{scalar}"));
                let mut bytes = payload.into_bytes();
                let checksum = Sha256::digest(&bytes);
                bytes.extend_from_slice(&checksum);
                fs::write(&path, bytes).expect("fixture");
                let restored = AddressBook::open(Some(base.clone()), [1; 4], false, None);
                assert!(restored.state.lock().writable, "{scalar}");
                assert_eq!(
                    restored.state.lock().stored.records[0].services,
                    match scalar {
                        "null" => None,
                        "0" => Some(0),
                        _ => Some(u64::MAX),
                    }
                );
            }
            for scalar in ["false", "-1", "1.5", "\"0\"", "18446744073709551616"] {
                let payload = sonic_rs::to_string(&original)
                    .expect("JSON")
                    .replace("\"services\":null", &format!("\"services\":{scalar}"));
                let mut bytes = payload.into_bytes();
                let checksum = Sha256::digest(&bytes);
                bytes.extend_from_slice(&checksum);
                assert_preserved_invalid(&base, &path, &bytes);
            }
            for mutation in 0..4 {
                let mut invalid = original.clone();
                match mutation {
                    0 => {
                        invalid["records"][0]
                            .as_object_mut()
                            .expect("record")
                            .remove(&"services");
                    }
                    1 => invalid["records"][0]["source"] = sonic_rs::json!({"ip":"1.1.1.1"}),
                    2 => invalid["records"][0]["last_success"] = 1.into(),
                    _ => invalid["version"] = 99.into(),
                }
                assert_preserved_invalid(&base, &path, &fixture_bytes(&invalid));
            }
        }

        fn assert_preserved_invalid(base: &Path, path: &Path, bytes: &[u8]) {
            fs::write(path, bytes).expect("invalid fixture");
            let book = AddressBook::open(Some(base.to_path_buf()), [1; 4], false, None);
            assert!(!book.state.lock().writable);
            book.learn_dns("other", &[addr(99)], EPOCH);
            book.save();
            assert_eq!(fs::read(path).expect("untouched"), bytes);
        }

        #[test]
        fn zero_gossip_preserves_unknown_dns_bootstrap_but_version_zero_is_known() {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            book.state.lock().stored.secret = [1; 32];
            book.learn_dns("seed", &[target()], EPOCH);
            let revision = book.state.lock().revision;
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(2)),
                &[(target(), 0, EPOCH)],
                EPOCH,
            );
            assert_eq!(book.state.lock().stored.records[0].services, None);
            assert_eq!(book.state.lock().revision, revision);
            assert_eq!(
                book.select(&[], &[], EPOCH, u64::MAX, |_| true),
                Some(target())
            );
            book.save();
            assert_eq!(
                stored_value(&path)["records"][0]["services"],
                sonic_rs::json!(null)
            );
            let restored = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            restored.learn_dns("seed", &[target()], EPOCH + 7200);
            restored.learn_peer(
                crate::PeerRemote::Endpoint(addr(3)),
                &[(target(), 0, EPOCH + 7200)],
                EPOCH + 7200,
            );
            restored.save();
            let restored = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            assert!(restored.ordinary_services_eligible(target(), u64::MAX));
            let revision = restored.state.lock().revision;
            restored.set_services(target(), 0);
            assert_eq!(restored.state.lock().revision, revision + 1);
            restored.learn_peer(
                crate::PeerRemote::Endpoint(addr(3)),
                &[(target(), 0, EPOCH + 7200)],
                EPOCH + 7200,
            );
            restored.learn_dns("seed", &[target()], EPOCH + 14_400);
            assert_eq!(restored.state.lock().stored.records[0].services, Some(0));
            assert!(!restored.ordinary_services_eligible(target(), u64::MAX));
            assert_eq!(restored.state.lock().stored.records[0].last_success, 0);
            restored.save();
            let restored = AddressBook::open(Some(base), [1; 4], false, None);
            assert!(!restored.ordinary_services_eligible(target(), u64::MAX));
            let fresh = addr(9);
            restored.learn_peer(
                crate::PeerRemote::Endpoint(addr(7)),
                &[(fresh, 0, EPOCH + 14_400)],
                EPOCH + 14_400,
            );
            let manager = restored.state.lock();
            assert_eq!(
                manager.stored.records[manager.by_addr[&fresh]].services,
                Some(0)
            );
            drop(manager);
            assert!(!restored.ordinary_services_eligible(fresh, u64::MAX));
        }
    }

    mod overlay_destinations {
        use super::*;

        #[test]
        fn ip_source_disguised_as_overlay_is_rejected_without_rewriting_the_book() {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr(2)),
                &[(addr(1), 9, EPOCH)],
                EPOCH,
            );
            book.save();
            let original = fs::read(&path).expect("valid book");
            let mut value = sonic_rs::to_value(&book.state.lock().stored).expect("state");
            value["records"][0]["source"] =
                sonic_rs::json!({"overlay": addr(2).address().to_string()});
            let mut bytes = sonic_rs::to_vec(&value).expect("invalid source payload");
            let checksum = Sha256::digest(&bytes);
            bytes.extend_from_slice(&checksum);
            fs::write(&path, &bytes).expect("write alias");
            let rejected = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            assert!(!rejected.state.lock().writable);
            rejected.save();
            assert_eq!(fs::read(&path).expect("preserved bytes"), bytes);
            fs::write(&path, original).expect("restore valid book");
            let restored = AddressBook::open(Some(base), [1; 4], false, None);
            assert!(restored.state.lock().writable);
            assert_eq!(restored.len(), 1);
        }

        #[test]
        fn overlay_self_announcements_keep_the_advertised_time() {
            for address in [
                crate::PeerAddress::Onion([3; 32]),
                crate::PeerAddress::I2p([4; 32]),
            ] {
                let book = AddressBook::open(None, [1; 4], false, None);
                let own = PeerEndpoint::new(address, 8333);
                book.learn_peer(crate::PeerRemote::Endpoint(own), &[(own, 9, EPOCH)], EPOCH);
                assert_eq!(
                    last_seen(&book, own),
                    EPOCH,
                    "self announcement keeps its time"
                );
            }

            let book = AddressBook::open(None, [1; 4], false, None);
            let source = PeerEndpoint::new(crate::PeerAddress::Onion([3; 32]), 8333);
            let gossiped = PeerEndpoint::new(crate::PeerAddress::Onion([5; 32]), 8333);
            book.learn_peer(
                crate::PeerRemote::Endpoint(source),
                &[(gossiped, 9, EPOCH)],
                EPOCH,
            );
            assert_eq!(
                last_seen(&book, gossiped),
                EPOCH - 2 * 60 * 60,
                "a gossiped address pays the relay penalty"
            );
        }

        /// Reads an endpoint's advertised time, naming every stored record when the
        /// endpoint is absent.
        fn last_seen(book: &AddressBook, endpoint: PeerEndpoint) -> u64 {
            let state = book.state.lock();
            state
                .stored
                .records
                .iter()
                .find(|entry| entry.endpoint == endpoint)
                .unwrap_or_else(|| {
                    panic!(
                        "{endpoint:?} is not stored; book holds {:#?}",
                        state
                            .stored
                            .records
                            .iter()
                            .map(|entry| (entry.endpoint, entry.last_seen))
                            .collect::<Vec<_>>()
                    )
                })
                .last_seen
        }

        /// Pins the table secret so bucket placement is a fixed property of the test
        /// rather than an entropy draw: these assertions need both endpoints admitted.
        fn pin_layout(book: &AddressBook) {
            book.state.lock().stored.secret = [7; 32];
        }

        #[test]
        fn overlay_endpoints_sources_and_anchors_survive_restart_and_addrv2_gossip() {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            pin_layout(&book);
            let onion = PeerEndpoint::new(crate::PeerAddress::Onion([1; 32]), 8333);
            let i2p = PeerEndpoint::new(crate::PeerAddress::I2p([2; 32]), 8333);
            book.learn_peer(
                crate::PeerRemote::Endpoint(onion),
                &[(onion, 9, EPOCH), (i2p, 9, EPOCH)],
                EPOCH,
            );
            book.succeeded(onion, 9, EPOCH + 1);
            book.succeeded(i2p, 9, EPOCH + 1);
            book.remember_anchors(&[onion, i2p], EPOCH + 2);
            let rows = book.gossip(EPOCH + 3);
            assert!(rows.iter().any(
        |row| matches!(row.addr, bitcoin::p2p::address::AddrV2::TorV3(key) if key == [1; 32])
    ));
            assert!(rows.iter().any(
                |row| matches!(row.addr, bitcoin::p2p::address::AddrV2::I2p(key) if key == [2; 32])
            ));
            book.save();
            let restored = AddressBook::open(Some(base), [1; 4], false, None);
            assert_ne!(
                restored.netgroup(onion.address()),
                restored.netgroup(i2p.address())
            );
            assert_eq!(
                restored.select(&[onion], &[], EPOCH + 10, u64::MAX, |_| true),
                Some(i2p)
            );
        }
    }

    mod persistence {
        use super::*;
        use sonic_rs::JsonValueMutTrait as _;

        fn rejected_backup(path: &Path, bytes: &[u8]) -> PathBuf {
            path.with_extension(format!(
                "pre-release-{}.bak",
                Sha256::digest(bytes)[..].to_lower_hex_string()
            ))
        }

        #[test]
        fn pre_release_version_is_frozen_and_the_format_marker_is_required() {
            assert_eq!(SCHEMA_VERSION, 1);
            let value = sonic_rs::to_value(&book().state.lock().stored).expect("schema");
            assert_eq!(value["format"], "bitcoin-rs-addrman");
            assert_eq!(value["version"], 1);
            assert_eq!(value["magic"], sonic_rs::json!([1, 1, 1, 1]));
            assert_eq!(value["records"], sonic_rs::json!([]));
            assert_eq!(value["anchors"], sonic_rs::json!([]));
            assert!(value["asmap_id"].is_null());
        }

        #[test]
        fn canonical_fixture_pins_endpoint_source_anchor_and_netgroup_semantics() {
            let payload = include_str!("../../../testdata/wire/canonical-v1.json");
            let expected: sonic_rs::Value = sonic_rs::from_str(payload).expect("canonical fixture");
            let mut bytes = payload.as_bytes().to_vec();
            bytes.extend_from_slice(&Sha256::digest(payload.as_bytes()));
            let dir = tempfile::tempdir().expect("directory");
            let base = dir.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            fs::write(&path, bytes).expect("fixture");
            let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
            assert!(book.state.lock().writable);
            assert_eq!(book.len(), 3);
            assert_eq!(
                sonic_rs::to_value(&book.state.lock().stored).expect("state"),
                expected
            );
            let onion = PeerEndpoint::new(crate::PeerAddress::Onion([0; 32]), 8333);
            let i2p = PeerEndpoint::new(crate::PeerAddress::I2p([0; 32]), 8333);
            assert_eq!(book.netgroup(onion.address()), vec![4, 15]);
            assert_eq!(book.netgroup(i2p.address()), vec![5, 15]);
            assert_eq!(
                Source::Internal([0; 10]).group(&NetGroups::default()),
                vec![6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            );
            for (endpoint, tag) in [(onion, 4), (i2p, 5)] {
                let mut key = vec![tag];
                key.extend_from_slice(&[0; 32]);
                key.extend_from_slice(&8333_u16.to_be_bytes());
                assert_eq!(endpoint_key(endpoint), key);
            }
            let mut installed = true;
            publish_book(&path, &book.state.lock().stored, &mut installed)
                .expect("canonical write");
            let restored = AddressBook::open(Some(base), [1; 4], false, None);
            assert_eq!(
                sonic_rs::to_value(&restored.state.lock().stored).expect("round trip"),
                expected
            );
            assert_indexes(&restored.state.lock());
        }

        #[test]
        fn incompatible_snapshots_are_preserved_without_decoding_or_migration() {
            for scoped in [false, true] {
                for version in 1..=9 {
                    let dir = tempfile::tempdir().expect("directory");
                    let base = dir.path().join("peers.dat");
                    let path = network_path(&base, [1; 4]);
                    let source = if scoped { &path } else { &base };
                    let bytes = fixture_bytes(&sonic_rs::json!({
                        "version": version, "magic": [1, 1, 1, 1],
                        "records": [{"obsolete_layout": "not a canonical candidate"}]
                    }));
                    fs::write(source, &bytes).expect("old snapshot");
                    let fresh = AddressBook::open(Some(base.clone()), [1; 4], false, None);
                    assert!(fresh.state.lock().writable);
                    assert_eq!(fresh.len(), 0, "no historical records are imported");
                    assert_eq!(fs::read(source).expect("source before save"), bytes);
                    let backup = rejected_backup(source, &bytes);
                    assert_eq!(fs::read(&backup).expect("durable preservation"), bytes);
                    assert!(
                        AddressBook::open(Some(base.clone()), [1; 4], false, None)
                            .state
                            .lock()
                            .writable
                    );
                    fresh.learn_dns("seed", &[target()], EPOCH);
                    fresh.save();
                    assert_eq!(fs::read(&backup).expect("preserved after save"), bytes);
                    let restored = AddressBook::open(Some(base), [1; 4], false, None);
                    assert!(restored.state.lock().writable);
                    assert_eq!(restored.len(), 1);
                    assert_indexes(&restored.state.lock());
                }
            }
        }

        #[test]
        fn missing_marker_never_aliases_canonical_v1() {
            let dir = tempfile::tempdir().expect("directory");
            let base = dir.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            let known = book();
            known.learn_dns("seed", &[target()], EPOCH);
            let mut value = sonic_rs::to_value(&known.state.lock().stored).expect("schema");
            value.as_object_mut().expect("object").remove(&"format");
            let bytes = fixture_bytes(&value);
            fs::write(&path, &bytes).expect("unmarked v1");
            let fresh = AddressBook::open(Some(base), [1; 4], false, None);
            assert_eq!(fresh.len(), 0);
            assert!(fresh.state.lock().writable);
            fresh.save();
            assert_eq!(
                fs::read(rejected_backup(&path, &bytes)).expect("backup"),
                bytes
            );
            assert_ne!(fs::read(path).expect("fresh canonical snapshot"), bytes);
        }

        #[test]
        fn failed_preservation_never_replaces_the_source_and_can_be_retried() {
            for directory_obstruction in [false, true] {
                let dir = tempfile::tempdir().expect("directory");
                let base = dir.path().join("peers.dat");
                let path = network_path(&base, [1; 4]);
                let bytes = fixture_bytes(&sonic_rs::json!({"version": 9, "magic": [1, 1, 1, 1]}));
                fs::write(&path, &bytes).expect("old snapshot");
                let backup = rejected_backup(&path, &bytes);
                if directory_obstruction {
                    fs::create_dir(&backup).expect("unsafe backup type");
                } else {
                    fs::write(&backup, vec![b'x'; bytes.len()]).expect("conflicting backup");
                }
                let rejected = AddressBook::open(Some(base.clone()), [1; 4], false, None);
                assert!(!rejected.state.lock().writable);
                rejected.learn_dns("seed", &[target()], EPOCH);
                rejected.save();
                assert_eq!(fs::read(&path).expect("source intact"), bytes);
                if directory_obstruction {
                    fs::remove_dir(&backup).expect("remove obstruction");
                } else {
                    fs::remove_file(&backup).expect("remove obstruction");
                }
                let fresh = AddressBook::open(Some(base), [1; 4], false, None);
                assert!(fresh.state.lock().writable);
                fresh.save();
                assert_ne!(fs::read(path).expect("fresh snapshot"), bytes);
                assert_eq!(fs::read(backup).expect("backup"), bytes);
            }
        }

        #[test]
        fn corrupt_unknown_and_wrong_network_files_are_not_disposable_snapshots() {
            let dir = tempfile::tempdir().expect("directory");
            let base = dir.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            let current = sonic_rs::to_value(&book().state.lock().stored).expect("schema");
            let mut cases = vec![b"corrupt bytes".to_vec()];
            let mut bad_checksum = fixture_bytes(&current);
            bad_checksum[0] ^= 1;
            cases.push(bad_checksum);
            let mut wrong_network = current.clone();
            wrong_network["magic"] = sonic_rs::json!([2, 2, 2, 2]);
            cases.push(fixture_bytes(&wrong_network));
            let mut wrong_format = current.clone();
            wrong_format["format"] = "another-format".into();
            cases.push(fixture_bytes(&wrong_format));
            for marker in [sonic_rs::json!(null), "".into()] {
                let mut malformed_marker = current.clone();
                malformed_marker["format"] = marker;
                cases.push(fixture_bytes(&malformed_marker));
            }
            let mut wrong_version = current.clone();
            wrong_version["version"] = 2.into();
            cases.push(fixture_bytes(&wrong_version));
            let mut orphan_anchor = current.clone();
            orphan_anchor["anchors"] = sonic_rs::json!([
                {"addr": "8.8.8.8:8333", "confirmed_at": EPOCH}
            ]);
            cases.push(fixture_bytes(&orphan_anchor));
            let mut invalid_record = current;
            invalid_record["records"] = sonic_rs::json!([{"broken": true}]);
            cases.push(fixture_bytes(&invalid_record));
            cases.push(fixture_bytes(
                &sonic_rs::json!({"version": 99, "magic": [1, 1, 1, 1]}),
            ));
            for bytes in cases {
                fs::write(&path, &bytes).expect("rejected input");
                let rejected = AddressBook::open(Some(base.clone()), [1; 4], false, None);
                assert!(!rejected.state.lock().writable);
                rejected.learn_dns("seed", &[target()], EPOCH);
                rejected.save();
                assert_eq!(fs::read(&path).expect("source intact"), bytes);
                assert!(!rejected_backup(&path, &bytes).exists());
            }
        }

        #[test]
        fn invalid_configured_map_preserves_current_and_pre_release_files_until_repaired() {
            for stale in [false, true] {
                let dir = tempfile::tempdir().expect("directory");
                let base = dir.path().join("peers.dat");
                let path = network_path(&base, [1; 4]);
                let map = dir.path().join("map.raw");
                let current = book();
                current.learn_dns("seed", &[target()], EPOCH);
                let mut value = sonic_rs::to_value(&current.state.lock().stored).expect("schema");
                if stale {
                    value.as_object_mut().expect("object").remove(&"format");
                    value["version"] = 9.into();
                }
                let bytes = fixture_bytes(&value);
                fs::write(&path, &bytes).expect("snapshot");
                fs::write(&map, b"invalid map").expect("invalid map");
                let rejected = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
                assert!(!rejected.state.lock().writable);
                rejected.save();
                assert_eq!(fs::read(&path).expect("source intact"), bytes);
                assert!(!rejected_backup(&path, &bytes).exists());
                fs::write(&map, crate::netgroup::LINKED_ASMAP).expect("valid map");
                let restored = AddressBook::open(Some(base), [1; 4], false, Some(&map));
                assert!(restored.state.lock().writable);
                assert_eq!(restored.len(), usize::from(!stale));
                assert_indexes(&restored.state.lock());
            }
        }

        #[test]
        fn rejects_truncated_and_corrupt_files_and_invalid_entry_bounds() {
            let dir = tempfile::tempdir().expect("directory");
            let base = dir.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);

            let mut cases: Vec<Vec<u8>> = Vec::new();
            cases.push(Vec::new());
            cases.push(vec![0x42]);
            cases.push(vec![0x55; 31]);
            let empty_payload_checksum = Sha256::digest([])[..].to_vec();
            cases.push(empty_payload_checksum);
            let mut one_byte_payload = vec![0x7b];
            one_byte_payload.extend_from_slice(&Sha256::digest([0x7b]));
            cases.push(one_byte_payload);
            let valid_book = book();
            let a1 = addr(1);
            let a2 = addr(2);
            valid_book.learn_dns("seed", &[a1, a2], EPOCH);
            valid_book.succeeded(a1, 9, EPOCH + 1);
            valid_book.succeeded(a2, 9, EPOCH + 1);
            let valid_json =
                sonic_rs::to_value(&valid_book.state.lock().stored).expect("valid schema");

            let mut duplicate_records = valid_json.clone();
            let record0 = duplicate_records["records"][0].clone();
            duplicate_records["records"]
                .as_array_mut()
                .expect("arr")
                .push(record0);
            cases.push(fixture_bytes(&duplicate_records));

            let mut duplicate_buckets = valid_json.clone();
            duplicate_buckets["records"][0]["tried"] = false.into();
            duplicate_buckets["records"][0]["new_buckets"] = sonic_rs::json!([1, 1]);
            cases.push(fixture_bytes(&duplicate_buckets));

            let mut over_new_refs = valid_json.clone();
            over_new_refs["records"][0]["tried"] = false.into();
            over_new_refs["records"][0]["new_buckets"] =
                sonic_rs::json!([0, 1, 2, 3, 4, 5, 6, 7, 8]);
            cases.push(fixture_bytes(&over_new_refs));

            let mut duplicate_anchors = valid_json.clone();
            duplicate_anchors["anchors"] = sonic_rs::json!([
                {"addr": a1.to_string(), "confirmed_at": EPOCH + 1},
                {"addr": a1.to_string(), "confirmed_at": EPOCH + 2}
            ]);
            cases.push(fixture_bytes(&duplicate_anchors));

            let a3 = addr(3);
            let mut over_anchors = valid_json;
            over_anchors["anchors"] = sonic_rs::json!([
                {"addr": a1.to_string(), "confirmed_at": EPOCH + 1},
                {"addr": a2.to_string(), "confirmed_at": EPOCH + 2},
                {"addr": a3.to_string(), "confirmed_at": EPOCH + 3}
            ]);
            cases.push(fixture_bytes(&over_anchors));

            for (index, bytes) in cases.iter().enumerate() {
                fs::write(&path, bytes).expect("write case");
                let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
                assert!(
                    !book.state.lock().writable,
                    "case {index} must fail closed and be non-writable"
                );
                assert_eq!(book.len(), 0, "case {index} must import zero records");
                book.save();
                assert_eq!(
                    &fs::read(&path).expect("source intact"),
                    bytes,
                    "case {index} must preserve source file intact"
                );
            }
        }

        #[test]
        fn anchor_handling_bounds_expiration_and_recovery() {
            let book = book();
            let a1 = addr(1);
            let a2 = addr(2);
            let a3 = addr(3);
            let unconfirmed = addr(4);

            book.learn_dns("seed", &[a1, a2, a3, unconfirmed], EPOCH);
            book.succeeded(a1, 9, EPOCH);
            book.succeeded(a2, 9, EPOCH);
            book.succeeded(a3, 9, EPOCH);

            book.remember_anchors(&[unconfirmed], EPOCH);
            assert_eq!(book.state.lock().stored.anchors.len(), 0);

            book.remember_anchors(&[a1, a2, a3], EPOCH);
            assert_eq!(book.state.lock().stored.anchors.len(), MAX_ANCHORS);

            book.remember_anchors(&[], EPOCH);
            assert_eq!(book.state.lock().stored.anchors.len(), 0);

            book.remember_anchors(&[a1, a2], EPOCH);
            let way_future = EPOCH + 8 * 24 * 3600;
            let expired_anchors = book.take_restart_anchors(way_future);
            assert_eq!(
                expired_anchors.len(),
                0,
                "expired anchors must not be taken"
            );

            book.remember_anchors(&[a1], EPOCH + 1000);
            let skewed_anchors = book.take_restart_anchors(EPOCH);
            assert_eq!(
                skewed_anchors.len(),
                0,
                "future-skewed anchors must not be taken"
            );

            book.remember_anchors(&[a1, a2], EPOCH);
            let taken = book.take_restart_anchors(EPOCH + 1);
            assert_eq!(taken.len(), 2);
            assert_eq!(book.state.lock().stored.anchors.len(), 0);

            book.return_restart_anchor(a1, EPOCH + 2);
            assert_eq!(book.state.lock().stored.anchors.len(), 1);
            assert_eq!(book.state.lock().stored.anchors[0].endpoint, a1);

            book.return_restart_anchors(EPOCH + 3);
            assert_eq!(book.state.lock().stored.anchors.len(), 2);
        }

        fn old_v1_shape() -> sonic_rs::Value {
            sonic_rs::json!({"version":1,"magic":[1,1,1,1],"secret":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"records":[{
                "addr":"8.8.8.8:8333","services":9,"source_group":(1_u64<<48)|0x0101,"source_ip":"1.1.1.1",
                "last_seen":EPOCH,"last_attempt":EPOCH-1,"last_success":0,"failures":3,"tried":false
            }]})
        }

        fn old_v8_shape() -> sonic_rs::Value {
            sonic_rs::json!({"version":8,"magic":[1,1,1,1],"secret":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"records":[{
        "addr":"8.8.8.8:8333","services":9,"source":{"ip":"1.1.1.1"},
        "last_seen":EPOCH,"last_success":EPOCH,"failures":0,"tried":true,"new_buckets":[]
    }],"asmap_id":null,"anchors":[]})
        }

        // RCV-11
        #[test]
        fn synthetic_old_shapes_are_preserved_without_decoding() {
            for (version, shape) in [(1, old_v1_shape()), (8, old_v8_shape())] {
                for scoped in [false, true] {
                    let dir = tempfile::tempdir().expect("directory");
                    let base = dir.path().join("peers.dat");
                    let path = network_path(&base, [1; 4]);
                    let source = if scoped { &path } else { &base };
                    let bytes = fixture_bytes(&shape);
                    fs::write(source, &bytes).expect("old snapshot");
                    let fresh = AddressBook::open(Some(base.clone()), [1; 4], false, None);
                    assert!(fresh.state.lock().writable, "version {version}");
                    assert_eq!(fresh.len(), 0, "no historical records are imported");
                    assert_eq!(fs::read(source).expect("source before save"), bytes);
                    let backup = rejected_backup(source, &bytes);
                    assert_eq!(fs::read(&backup).expect("durable preservation"), bytes);
                    fresh.learn_dns("seed", &[target()], EPOCH);
                    fresh.save();
                    assert_eq!(fs::read(&backup).expect("preserved after save"), bytes);
                    if scoped {
                        assert_ne!(fs::read(&path).expect("fresh publication"), bytes);
                    } else {
                        assert_eq!(fs::read(&base).expect("base retained"), bytes);
                        let published = fs::read(&path).expect("fresh scoped publication");
                        assert_ne!(published, bytes);
                        let book: sonic_rs::Value =
                            sonic_rs::from_slice(&published[..published.len() - 32])
                                .expect("canonical JSON");
                        assert_eq!(book["format"], "bitcoin-rs-addrman");
                        assert_eq!(book["version"], 1);
                    }
                    let restored = AddressBook::open(Some(base), [1; 4], false, None);
                    assert!(restored.state.lock().writable);
                    assert_eq!(restored.len(), 1);
                    assert_indexes(&restored.state.lock());
                }
            }
        }
    }
}
