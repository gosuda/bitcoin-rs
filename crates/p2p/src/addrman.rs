//! P2P's single bounded AddrMan owner, following Core31.1 placement and selection.
//! Membership is persisted with each endpoint; lookup tables are derived indexes.
use bitcoin_rs_primitives::PeerEndpoint;
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
// Frozen until the first official release; pre-release layouts are not migrated.
// The canonical v1 record shape is owned here; PR #1684 must adopt this same
// shape (FORMAT plus SCHEMA_VERSION) before its merge.
const SCHEMA_VERSION: u32 = 1;
const FORMAT: &str = "bitcoin-rs-addrman";
const MAX_COLLISIONS: usize = 10;
const REPLACEMENT_WINDOW: u64 = 4 * 60 * 60;
const COLLISION_TEST_WINDOW: u64 = 40 * 60;
const MAX_ANCHORS: usize = 2;
const ANCHOR_AGE: u64 = 7 * 24 * 60 * 60;
// min GetChance=.01*.66^8; at zero-based proposal44 its product with1.2^44>1.
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
fn endpoint_group(groups: &NetGroups, endpoint: PeerEndpoint) -> Vec<u8> {
    match endpoint {
        PeerEndpoint::Ip(socket) => groups.group(socket.ip()),
        PeerEndpoint::TorV3 { .. } | PeerEndpoint::I2p { .. } => {
            crate::endpoint::overlay_netgroup(endpoint.host()).unwrap_or_else(|| vec![0])
        }
    }
}
fn endpoint_ip(endpoint: PeerEndpoint) -> Option<IpAddr> {
    endpoint.as_ip().map(|socket| socket.ip())
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
    /// Shared gossip selection backing both wire projections: the raw
    /// rows picked on the last rotation, cached until `GOSSIP_CACHE_TTL`.
    /// [`AddressBook::gossip`] projects IP rows as legacy `addr`;
    /// [`AddressBook::gossip_addrv2`] projects enabled transports as `addrv2`.
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

/// One transport-neutral gossip row: the shared selection both wire
/// projections filter. Raw endpoint identity is kept so each reply can
/// project without re-rotating the cursor.
#[derive(Clone, Copy, Debug)]
struct GossipRow {
    endpoint: PeerEndpoint,
    last_seen: u32,
    services: u64,
}

pub(crate) struct AddressBook {
    state: Mutex<Manager>,
    publication: Mutex<()>,
    /// Which overlay transports `addrv2` gossip may carry, wired from
    /// resolved config at service start: `[tor_enabled, i2p_enabled]`.
    addrv2_gossip: [std::sync::atomic::AtomicBool; 2],
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Core HashWriter framing. These vectors are all shorter than253 bytes.
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
fn bucket_position(secret: &[u8; 32], addr: PeerEndpoint, new: bool, bucket: usize) -> usize {
    let mut bytes = secret.to_vec();
    bytes.push(if new { b'N' } else { b'K' });
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
        bucket * BUCKET_SIZE + bucket_position(&self.stored.secret, addr, true, bucket)
    }
    fn tried_slot(&self, addr: PeerEndpoint) -> usize {
        let bucket = tried_bucket(&self.stored.secret, addr, &self.groups);
        bucket * BUCKET_SIZE + bucket_position(&self.stored.secret, addr, false, bucket)
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
    // Core MakeTried, with the local pending-identity guard checked before any
    // reference is changed. Indices are reloaded after ClearNew can swap_remove.
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
    fn good(&mut self, addr: PeerEndpoint, test_before_evict: bool, now: u64) -> bool {
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
                // Core's set is ordered by lifetime-stable creation ID, not
                // Good/enqueue order or the mutable swap_remove index.
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
        // At most ten entries; snapshot endpoint identities, never Vec indices.
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
                // Good(false) is part of Core's resolution, including health and
                // global failure epoch updates, not just table movement.
                if self.good(addr, false, now) {
                    self.collisions.retain(|candidate| *candidate != addr);
                }
            }
        }
    }
    #[expect(
        clippy::too_many_lines,
        reason = "One learn pass owns admission, bucket placement, and eviction in table order"
    )]
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
        let mut refs = 0;
        if let Some(index) = existing {
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
            // Zero-bit gossip adds no service knowledge to an unknown DNS record.
            if let Some(services) = services.filter(|bits| *bits != 0 || entry.services.is_some()) {
                entry.services = Some(entry.services.unwrap_or(0) | services);
            }
            if before != (entry.last_seen, entry.services) {
                self.revision = self.revision.wrapping_add(1);
            }
            if seen <= entry.last_seen || entry.tried || entry.new_buckets.len() >= MAX_NEW_REFS {
                return false;
            }
            refs = entry.new_buckets.len();
            if refs != 0 && self.rng.gen_range(0..(1_usize << refs)) != 0 {
                return false;
            }
        }
        let bucket = new_bucket(
            &self.stored.secret,
            addr,
            &source.group(&self.groups),
            &self.groups,
        );
        let slot = self.new_slot(addr, bucket);
        let occupant = self.new[slot];
        if occupant != EMPTY_SLOT {
            let old = &self.stored.records[usize::try_from(occupant).unwrap_or_default()];
            if old.endpoint == addr {
                return false;
            }
            let final_pending =
                old.new_buckets.len() == 1 && self.pending.contains_key(&old.endpoint);
            if final_pending || !(old.terrible(now) || old.new_buckets.len() > 1 && refs == 0) {
                return false;
            }
        }
        // Slot geometry bounds identities without a competing global/source quota.
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
        let index = if let Some(index) = self.by_addr.get(&addr).copied() {
            index
        } else {
            if self.stored.records.len() >= MAX_RECORDS {
                return false;
            }
            let index = self.stored.records.len();
            self.stored.records.push(Candidate {
                creation_id: self.next_creation_id,
                endpoint: addr,
                services,
                source,
                last_seen: seen.saturating_sub(time_penalty),
                last_success: 0,
                failures: 0,
                tried: false,
                new_buckets: Vec::new(),
                last_attempt: 0,
                last_count_attempt: 0,
            });
            self.by_addr.insert(addr, index);
            self.next_creation_id = next_creation_id;
            index
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
    if addr.port() == 0 && !matches!(addr.address(), crate::PeerAddress::I2p(_)) || addr.address().is_unspecified() || addr.address().is_multicast() {
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
    pub(crate) fn open(
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
                        // Rebucketing here is a current-format runtime invariant
                        // (ASMap change), never a historical schema migration.
                        let rebucket = manager.stored.asmap_id != manager.groups.identity();
                        if rebucket {
                            manager.rebucket();
                            manager.stored.asmap_id = manager.groups.identity();
                            manager.revision = 1;
                        } else {
                            manager.install_indexes();
                        }
                        // Collision state is empty on restart, so persisted record
                        // order establishes fresh runtime IDs without a disk field.
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
                            // Keep the old scoped file until atomic publication succeeds.
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

    /// Wire which overlay transports `addrv2` gossip may carry.
    pub(crate) fn set_addrv2_gossip(&self, tor_enabled: bool, i2p_enabled: bool) {
        self.addrv2_gossip[0].store(tor_enabled, std::sync::atomic::Ordering::Release);
        self.addrv2_gossip[1].store(i2p_enabled, std::sync::atomic::Ordering::Release);
    }

    /// One `addrv2` gossip round: every non-terrible record whose
    /// transport is enabled, as BIP155 rows. IP is always carried;
    /// overlay endpoints only when their transport is configured.
    /// Rotation and caching mirror [`AddressBook::gossip`]: successive
    /// rounds continue from the `addrv2` cursor instead of replaying the
    /// first insertion-order records, and the wire reply is stable until
    /// its TTL expires. The overlay flags are read fresh on every call
    /// and key the cache, so a reconfigured transport is applied on the
    /// next reply rather than served stale.
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

    /// Failure count recorded for `addr` (test observability for dial
    /// accounting proofs).
    #[cfg(test)]
    pub(crate) fn failure_count(&self, addr: PeerEndpoint) -> Option<u32> {
        let addr = canonical(addr);
        let manager = self.state.lock();
        manager
            .by_addr
            .get(&addr)
            .map(|index| manager.stored.records[*index].failures)
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
    pub(crate) fn len(&self) -> usize {
        self.state.lock().stored.records.len()
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
        // Anonymous Tor inbound has no dialable address: its loopback
        // forwarder/proxy socket is never a source. Return early so no
        // proxy/loopback IP enters `Source` or the bucket groups.
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
    /// Exact endpoint exclusion includes inbound; diversity excludes only outbound
    /// and currently pending work. Policy callbacks run outside the state lock.
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
        // Membership, health and pending state may have changed during callback
        // evaluation. Only the pure per-address policy decisions were captured.
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
    /// Ordinary admission rejects only currently known insufficient services.
    /// Missing metadata remains permissive for non-book connection consumers.
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

    /// Whether `addr`'s last known service claim includes every flag in
    /// `services`. An unknown address or service claim answers `false`.
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

    /// Applies Core's failure-count connectivity threshold to the caller's
    /// persistent outbound TCP snapshot using this book's configured classifier.
    /// Connection roles and leases remain owned by the caller.
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
    /// At-most-once dispatch: acceptance by the outbound worker consumes the
    /// reservation even if spawning/connect subsequently fails. Health Attempt
    /// remains at actual TCP completion and is independent of this boundary.
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
    /// Queue rejection releases only the attempted purpose, never a reservation
    /// or a probe that won concurrent admission for the same canonical endpoint.
    pub(crate) fn reject_queued(&self, addr: PeerEndpoint, feeler: bool) {
        let addr = canonical(addr);
        let mut manager = self.state.lock();
        let expected = if feeler {
            PendingClaim::Feeler
        } else {
            PendingClaim::Dial
        };
        if manager.pending.get(&addr) == Some(&expected) {
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
    pub(crate) fn attempted(&self, addr: PeerEndpoint, count_failure: bool, now: u64) {
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
    /// Record an accepted VERSION's current service claim (peer handshake version,
    /// unrelated to the on-disk schema) without certifying
    /// success, promoting membership or changing any health timestamp.
    pub(crate) fn set_services(&self, addr: PeerEndpoint, services: u64) {
        self.state.lock().set_services(canonical(addr), services);
    }
    /// The netgroup of `ip` under this book's classifier, `ASMap` or IP prefix.
    pub(crate) fn netgroup(&self, ip: impl Into<crate::PeerAddress>) -> Vec<u8> {
        self.state.lock().groups.group(ip)
    }
    pub(crate) fn succeeded(&self, addr: PeerEndpoint, services: u64, now: u64) {
        let addr = canonical(addr);
        let mut manager = self.state.lock();
        manager.set_services(addr, services);
        manager.good(addr, true, now);
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
        // Core AlreadyConnectedToAddress takes CNetAddr: TCP presence at the
        // same canonical IP is sufficient even at a different port.
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
        }; // Release the state lock before invoking policy callbacks.
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
                    manager.good(addr, true, now);
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

    /// Consume before dialing; if publication fails, ordinary selection remains
    /// available but no restart anchor is reused without durable consumption.
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
                    // Other work owns this claim; preserve undispatched metadata.
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
            // Failed consumption never transfers or discards original metadata.
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

    /// A skipped reservation returns immediately rather than retaining group
    /// exclusion until shutdown. An already dispatched Dial cannot be returned.
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

    /// Return only reservations that never crossed `anchor_dispatched`. The one
    /// pending owner retains their original confirmation time until that point.
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
    /// Single rotating selection backing both wire projections. The cursor
    /// advances only on a cache miss; cache hits project the stored rows
    /// without touching rotation. Holds one state lock; callers project.
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

// Keep the supplied basename as the legacy path and add a magic suffix to
// its stem without interpreting an existing suffix or requiring UTF-8 names.
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
            // A changed map cannot reproduce the old Tried slots. Validate all
            // map-independent structure, then rebucket at open.
            if let Some(groups) = groups {
                let bucket = tried_bucket(&stored.secret, entry.endpoint, groups);
                let position = bucket_position(&stored.secret, entry.endpoint, false, bucket);
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
                        bucket_position(&stored.secret, entry.endpoint, true, bucket),
                    ))
                {
                    return Err(invalid("invalid/colliding New reference"));
                }
            }
        }
    }
    Ok(())
}

fn read_book(
    path: &Path,
    magic: Option<[u8; 4]>,
    allow_local: bool,
    groups: &NetGroups,
) -> io::Result<Option<Loaded>> {
    #[derive(Deserialize)]
    struct Header {
        #[serde(default, deserialize_with = "present_format")]
        format: Option<String>,
        version: u32,
        magic: [u8; 4],
    }
    fn present_format<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<String>, D::Error> {
        String::deserialize(deserializer).map(Some)
    }
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
    let header: Header = serde_json::from_slice(&bytes[..payload_len]).map_err(io::Error::other)?;
    // Only the checked envelope identifies disposable development snapshots.
    // Their records are never decoded or converted into the current schema.
    // Identification runs before scope: a cross-network pre-release file is
    // preserved and superseded, never misreported as a network refusal.
    if header.format.is_none() && (1..=9).contains(&header.version) {
        return Ok(Some(Loaded {
            stored: None,
            magic: header.magic,
            bytes,
        }));
    }
    if magic.is_some_and(|magic| magic != header.magic) {
        return Err(invalid("address book network"));
    }

    if header.format.as_deref() != Some(FORMAT) || header.version != SCHEMA_VERSION {
        return Err(invalid("unsupported address book format/version"));
    }
    let stored: Stored = serde_json::from_slice(&bytes[..payload_len]).map_err(io::Error::other)?;
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

// Preserve rejected bytes before allowing replacement. Exclusive atomic
// publication cannot clobber an existing backup, including an unsafe file type.
// An interrupted first save can reuse only a byte-identical, flushed backup.
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
    let mut bytes = serde_json::to_vec(stored).map_err(io::Error::other)?;
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
        // Close before publication for Windows. Initial publication must not
        // clobber an operator file created since open observed absence.
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
    // Once installation vacates the name, it no longer identifies our file.
    if result.is_err() && temp_present {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
