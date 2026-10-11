//! P2P's single bounded AddrMan owner, following Core31.1 placement and selection.
//! Membership is persisted with each endpoint; lookup tables are derived indexes.
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
const VERSION: u32 = 5;
// min GetChance=.01*.66^8; at zero-based proposal44 its product with1.2^44>1.
const MAX_SELECTION_PROPOSALS: usize = 45;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Source {
    Ip(IpAddr),
    Internal([u8; 10]),
    // v1 did not retain the original seed name or its full Core internal hash.
    LegacyDns(u64),
}
impl Source {
    fn dns(seed: &str) -> Self {
        let hash = Sha256::digest(seed.as_bytes());
        let mut bytes = [0; 10];
        bytes.copy_from_slice(&hash[..10]);
        Self::Internal(bytes)
    }
    fn group(&self) -> Vec<u8> {
        match self {
            Self::Ip(ip) => crate::netgroup::group(*ip),
            Self::Internal(bytes) => {
                let mut group = vec![6];
                group.extend_from_slice(bytes);
                group
            }
            Self::LegacyDns(id) => {
                let mut hasher = Sha256::new();
                hasher.update(b"bitcoin-rs v1 DNS source");
                hasher.update(id.to_le_bytes());
                let hash = hasher.finalize();
                let mut group = vec![6];
                group.extend_from_slice(&hash[..10]);
                group
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    addr: SocketAddr,
    services: u64,
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    magic: [u8; 4],
    secret: [u8; 32],
    #[serde(deserialize_with = "read_records")]
    records: Vec<Candidate>,
}

struct Manager {
    stored: Stored,
    by_addr: HashMap<SocketAddr, usize>,
    new: Vec<u32>,
    tried: Vec<u32>,
    rng: StdRng,
    last_good: u64,
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
    gossip_cache: Option<(Instant, Vec<(u32, bitcoin::p2p::address::Address)>)>,
    pending: HashSet<SocketAddr>,
}

pub(crate) struct AddressBook {
    state: Mutex<Manager>,
    publication: Mutex<()>,
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
fn endpoint_key(addr: SocketAddr) -> Vec<u8> {
    let mut bytes = match addr.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    bytes.extend_from_slice(&addr.port().to_be_bytes());
    bytes
}
fn new_bucket(secret: &[u8; 32], addr: SocketAddr, source_group: &[u8]) -> usize {
    let mut bytes = secret.to_vec();
    vector(&crate::netgroup::group(addr.ip()), &mut bytes);
    vector(source_group, &mut bytes);
    let first = cheap_hash(&bytes) % 64;
    let mut bytes = secret.to_vec();
    vector(source_group, &mut bytes);
    bytes.extend_from_slice(&first.to_le_bytes());
    usize::try_from(cheap_hash(&bytes) % 1024).unwrap_or_default()
}
fn tried_bucket(secret: &[u8; 32], addr: SocketAddr) -> usize {
    let mut bytes = secret.to_vec();
    vector(&endpoint_key(addr), &mut bytes);
    let first = cheap_hash(&bytes) % 8;
    let mut bytes = secret.to_vec();
    vector(&crate::netgroup::group(addr.ip()), &mut bytes);
    bytes.extend_from_slice(&first.to_le_bytes());
    usize::try_from(cheap_hash(&bytes) % 256).unwrap_or_default()
}
fn bucket_position(secret: &[u8; 32], addr: SocketAddr, new: bool, bucket: usize) -> usize {
    let mut bytes = secret.to_vec();
    bytes.push(if new { b'N' } else { b'K' });
    bytes.extend_from_slice(&i32::try_from(bucket).unwrap_or_default().to_le_bytes());
    vector(&endpoint_key(addr), &mut bytes);
    usize::try_from(cheap_hash(&bytes) % 64).unwrap_or_default()
}

impl Manager {
    fn new(magic: [u8; 4], allow_local: bool, path: Option<PathBuf>) -> Self {
        let mut rng = StdRng::from_entropy();
        let mut secret = [0; 32];
        rng.fill_bytes(&mut secret);
        Self {
            stored: Stored {
                version: VERSION,
                magic,
                secret,
                records: Vec::new(),
            },
            by_addr: HashMap::new(),
            new: vec![EMPTY_SLOT; NEW_BUCKETS * BUCKET_SIZE],
            tried: vec![EMPTY_SLOT; TRIED_BUCKETS * BUCKET_SIZE],
            rng,
            last_good: 1,
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
            pending: HashSet::new(),
        }
    }
    fn new_slot(&self, addr: SocketAddr, bucket: usize) -> usize {
        bucket * BUCKET_SIZE + bucket_position(&self.stored.secret, addr, true, bucket)
    }
    fn tried_slot(&self, addr: SocketAddr) -> usize {
        let bucket = tried_bucket(&self.stored.secret, addr);
        bucket * BUCKET_SIZE + bucket_position(&self.stored.secret, addr, false, bucket)
    }
    fn install_indexes(&mut self) {
        self.by_addr.clear();
        self.new.fill(EMPTY_SLOT);
        self.tried.fill(EMPTY_SLOT);
        for (index, entry) in self.stored.records.iter().enumerate() {
            self.by_addr.insert(entry.addr, index);
            let id = u32::try_from(index).unwrap_or(EMPTY_SLOT);
            if entry.tried {
                let slot = self.tried_slot(entry.addr);
                self.tried[slot] = id;
            } else {
                for bucket in &entry.new_buckets {
                    let slot = self.new_slot(entry.addr, usize::from(*bucket));
                    self.new[slot] = id;
                }
            }
        }
    }
    fn remove_identity(&mut self, index: usize) {
        debug_assert!(
            !self.stored.records[index].tried && self.stored.records[index].new_buckets.is_empty()
        );
        let addr = self.stored.records[index].addr;
        self.by_addr.remove(&addr);
        self.stored.records.swap_remove(index);
        if let Some(moved) = self.stored.records.get(index) {
            let addr = moved.addr;
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
    fn promote(&mut self, addr: SocketAddr) -> bool {
        let Some(&index) = self.by_addr.get(&addr) else {
            return false;
        };
        if self.stored.records[index].tried {
            return false;
        }
        let slot = self.tried_slot(addr);
        if self.tried[slot] != EMPTY_SLOT {
            return false;
        }
        let buckets = std::mem::take(&mut self.stored.records[index].new_buckets);
        for bucket in buckets {
            let slot = self.new_slot(addr, usize::from(bucket));
            self.new[slot] = EMPTY_SLOT;
        }
        self.stored.records[index].tried = true;
        self.tried[slot] = u32::try_from(index).unwrap_or(EMPTY_SLOT);
        true
    }
    fn learn(
        &mut self,
        addr: SocketAddr,
        services: u64,
        source: Source,
        seen: u64,
        now: u64,
        time_penalty: u64,
    ) -> bool {
        let addr = canonical(addr);
        if !routable(addr, self.allow_local)
            || seen > now.saturating_add(FUTURE_SKEW_SECS)
            || now.saturating_sub(seen) > STALE_SECS
        {
            return false;
        }
        let time_penalty = if matches!(&source, Source::Ip(ip) if crate::netgroup::canonical_ip(*ip) == addr.ip())
        {
            0
        } else {
            time_penalty
        };
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
            entry.services |= services;
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
        let bucket = new_bucket(&self.stored.secret, addr, &source.group());
        let slot = self.new_slot(addr, bucket);
        let occupant = self.new[slot];
        if occupant != EMPTY_SLOT {
            let old = &self.stored.records[usize::try_from(occupant).unwrap_or_default()];
            if old.addr == addr {
                return false;
            }
            let final_pending = old.new_buckets.len() == 1 && self.pending.contains(&old.addr);
            if final_pending || !(old.terrible(now) || old.new_buckets.len() > 1 && refs == 0) {
                return false;
            }
        }
        // Slot geometry bounds identities without a competing global/source quota.
        if existing.is_none() && self.stored.records.len() == MAX_RECORDS && occupant == EMPTY_SLOT
        {
            return false;
        }
        self.clear_new(slot);
        let index = if let Some(index) = self.by_addr.get(&addr).copied() {
            index
        } else {
            if self.stored.records.len() >= MAX_RECORDS {
                return false;
            }
            let index = self.stored.records.len();
            self.stored.records.push(Candidate {
                addr,
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
            index
        };
        self.stored.records[index]
            .new_buckets
            .push(u16::try_from(bucket).unwrap_or_default());
        self.new[slot] = u32::try_from(index).unwrap_or(EMPTY_SLOT);
        self.revision = self.revision.wrapping_add(1);
        true
    }
    fn select(&mut self, eligible: &[bool], now: u64) -> Option<SocketAddr> {
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
                tried_buckets[tried_bucket(&self.stored.secret, entry.addr)] = true;
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
                return Some(entry.addr);
            }
            factor *= 1.2;
        }
        debug_assert!(false, "minimum chance guarantees acceptance by proposal45");
        None
    }
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(addr, |ip| SocketAddr::new(ip.into(), addr.port())),
        IpAddr::V4(_) => addr,
    }
}

fn routable(addr: SocketAddr, allow_local: bool) -> bool {
    if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(ip) => {
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
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return routable(SocketAddr::new(ip.into(), addr.port()), allow_local);
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

fn legacy_prefix(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(ip) => {
            let bytes = ip.octets();
            (1_u64 << 48) | u64::from(u16::from_be_bytes([bytes[0], bytes[1]]))
        }
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return legacy_prefix(ip.into());
            }
            let bytes = ip.octets();
            (2_u64 << 48) | u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
    }
}

impl AddressBook {
    pub(crate) fn open(path: Option<PathBuf>, magic: [u8; 4], allow_local: bool) -> Arc<Self> {
        let scoped = path.as_deref().map(|base| network_path(base, magic));
        let mut manager = Manager::new(magic, allow_local, scoped.clone());
        if let Some(scoped) = scoped {
            let loaded = match read_book(&scoped, Some(magic), allow_local) {
                Ok(Some(loaded)) => Some((scoped, true, loaded)),
                Ok(None) => path.and_then(|legacy| match read_book(&legacy, None, true) {
                    Ok(Some(loaded)) if loaded.stored.magic == magic => Some((legacy, false, loaded)),
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
                if loaded
                    .stored
                    .records
                    .iter()
                    .all(|entry| routable(entry.addr, allow_local))
                {
                    manager.stored = loaded.stored;
                    manager.published = scoped_source;
                    if loaded.legacy {
                        if let Err(error) = backup_legacy(&source_path, &loaded.bytes) {
                            tracing::warn!(path=%source_path.display(), %error, "address book migration backup failed; preserving source and disabling writes");
                            manager.writable = false;
                        }
                        manager.rebucket_legacy();
                        manager.revision = 1;
                    } else {
                        manager.install_indexes();
                    }
                    if !scoped_source {
                        manager.revision = manager.revision.wrapping_add(1);
                    }
                } else {
                    tracing::warn!(path=%source_path.display(), "legacy address book contains inadmissible addresses; preserving file and disabling writes");
                    manager.writable = false;
                }
            }
        }
        Arc::new(Self {
            state: Mutex::new(manager),
            publication: Mutex::new(()),
        })
    }
    pub(crate) fn connected(&self, addr: SocketAddr, now: u64) {
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
    pub(crate) fn learn_dns(&self, seed: &str, addresses: &[SocketAddr], now: u64) {
        let source = Source::dns(seed);
        let mut manager = self.state.lock();
        for &addr in addresses.iter().take(MAX_DNS_RESULTS) {
            manager.learn(addr, 0, source.clone(), now, now, 0);
        }
    }
    pub(crate) fn learn_peer(
        &self,
        source: IpAddr,
        addresses: &[(SocketAddr, u64, u64)],
        now: u64,
    ) {
        let mut manager = self.state.lock();
        for &(addr, services, seen) in addresses.iter().take(MAX_GOSSIP) {
            manager.learn(addr, services, Source::Ip(source), seen, now, 2 * 60 * 60);
        }
    }
    /// Exact endpoint exclusion includes inbound; diversity excludes only outbound
    /// and currently pending work. Policy callbacks run outside the state lock.
    pub(crate) fn select(
        &self,
        connected: &[SocketAddr],
        grouped: &[SocketAddr],
        now: u64,
        mut allowed: impl FnMut(SocketAddr) -> bool,
    ) -> Option<SocketAddr> {
        let connected: HashSet<_> = connected.iter().copied().map(canonical).collect();
        let addresses: Vec<_> = {
            let manager = self.state.lock();
            manager
                .stored
                .records
                .iter()
                .map(|entry| entry.addr)
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
            .chain(&manager.pending)
            .map(|addr| crate::netgroup::group(addr.ip()))
            .collect();
        let eligible: Vec<_> = manager
            .stored
            .records
            .iter()
            .map(|entry| {
                allowed.contains(&entry.addr)
                    && !connected.contains(&entry.addr)
                    && !manager.pending.contains(&entry.addr)
                    && !groups.contains(&crate::netgroup::group(entry.addr.ip()))
            })
            .collect();
        manager.select(&eligible, now)
    }
    pub(crate) fn queued(&self, addr: SocketAddr) {
        let addr = canonical(addr);
        self.state.lock().pending.insert(addr);
    }
    pub(crate) fn unqueue(&self, addr: SocketAddr) {
        let addr = canonical(addr);
        self.state.lock().pending.remove(&addr);
    }
    pub(crate) fn pending_count_excluding(&self, active: &[SocketAddr]) -> usize {
        let active: HashSet<_> = active.iter().copied().map(canonical).collect();
        self.state
            .lock()
            .pending
            .iter()
            .filter(|addr| !active.contains(addr))
            .count()
    }
    pub(crate) fn attempted(&self, addr: SocketAddr, count_failure: bool, now: u64) {
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
    pub(crate) fn succeeded(&self, addr: SocketAddr, services: u64, now: u64) {
        let addr = canonical(addr);
        let mut manager = self.state.lock();
        manager.last_good = now;
        let Some(index) = manager.by_addr.get(&addr).copied() else {
            return;
        };
        let entry = &mut manager.stored.records[index];
        let changed =
            entry.last_success != now || entry.failures != 0 || entry.services != services;
        entry.last_success = now;
        entry.last_attempt = now;
        entry.failures = 0;
        entry.services = services;
        let promoted = manager.promote(addr);
        if changed || promoted {
            manager.revision = manager.revision.wrapping_add(1);
        }
    }
    pub(crate) fn gossip(&self, now: u64) -> Vec<(u32, bitcoin::p2p::address::Address)> {
        self.gossip_at(now, Instant::now())
    }
    fn gossip_at(&self, now: u64, tick: Instant) -> Vec<(u32, bitcoin::p2p::address::Address)> {
        let mut manager = self.state.lock();
        if let Some((expires, response)) = &manager.gossip_cache {
            if tick < *expires {
                return response.clone();
            }
        }
        let len = manager.stored.records.len();
        let start = manager.gossip_cursor.checked_rem(len).unwrap_or_default();
        let mut gossip = Vec::with_capacity(MAX_GOSSIP.min(len));
        for offset in 0..len {
            let index = (start + offset) % len;
            manager.gossip_cursor = (index + 1) % len;
            let entry = &manager.stored.records[index];
            if entry.terrible(now) {
                continue;
            }
            gossip.push((
                u32::try_from(entry.last_seen).unwrap_or(u32::MAX),
                bitcoin::p2p::address::Address::new(
                    &entry.addr,
                    bitcoin::p2p::ServiceFlags::from(entry.services),
                ),
            ));
            if gossip.len() == MAX_GOSSIP {
                break;
            }
        }
        manager.gossip_cache = Some((tick + GOSSIP_CACHE_TTL, gossip.clone()));
        gossip
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
    stored: Stored,
    legacy: bool,
    bytes: Vec<u8>,
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
fn read_records<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Candidate>, D::Error> {
    struct Records;
    impl<'de> serde::de::Visitor<'de> for Records {
        type Value = Vec<Candidate>;
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
    deserializer.deserialize_seq(Records)
}

// The current public v1 format is read only for validated, backed-up migration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCandidate {
    addr: SocketAddr,
    services: u64,
    source_group: u64,
    source_ip: Option<IpAddr>,
    last_seen: u64,
    last_attempt: u64,
    last_success: u64,
    failures: u8,
    tried: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyStored {
    version: u32,
    magic: [u8; 4],
    secret: [u8; 32],
    records: Vec<LegacyCandidate>,
}

fn validate_current(stored: &Stored, allow_local: bool) -> io::Result<()> {
    if stored.version != VERSION || stored.records.len() > MAX_RECORDS {
        return Err(invalid("address book version/count"));
    }
    let mut endpoints = HashSet::new();
    let mut slots = HashSet::new();
    for entry in &stored.records {
        if !routable(entry.addr, allow_local)
            || canonical(entry.addr) != entry.addr
            || !endpoints.insert(entry.addr)
            || entry.new_buckets.len() > MAX_NEW_REFS
            || entry.tried && (entry.last_success == 0 || !entry.new_buckets.is_empty())
            || !entry.tried && entry.new_buckets.is_empty()
        {
            return Err(invalid("invalid address book record"));
        }
        if entry.tried {
            let bucket = tried_bucket(&stored.secret, entry.addr);
            let position = bucket_position(&stored.secret, entry.addr, false, bucket);
            if !slots.insert((false, bucket, position)) {
                return Err(invalid("Tried bucket collision"));
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
                        bucket_position(&stored.secret, entry.addr, true, bucket),
                    ))
                {
                    return Err(invalid("invalid/colliding New reference"));
                }
            }
        }
    }
    Ok(())
}
fn legacy_slot(secret: &[u8; 32], entry: &LegacyCandidate) -> u64 {
    let mut hash = Sha256::new();
    hash.update(secret);
    hash.update(legacy_prefix(entry.addr.ip()).to_le_bytes());
    if !entry.tried {
        hash.update(entry.source_group.to_le_bytes());
    }
    let mut first = [0; 8];
    first.copy_from_slice(&hash.finalize()[..8]);
    let bucket = u64::from_le_bytes(first);
    let endpoint = Sha256::digest(entry.addr.to_string().as_bytes());
    let offset = u64::from(endpoint[0] & 15);
    if entry.tried {
        3072 + bucket % 64 * 16 + offset
    } else {
        bucket % 192 * 16 + offset
    }
}
fn convert_legacy(old: LegacyStored, allow_local: bool) -> io::Result<Stored> {
    if old.version != 1 || old.records.len() > 4096 {
        return Err(invalid("legacy address book version/count"));
    }
    let mut addresses = HashSet::new();
    let mut sources = HashMap::new();
    let mut slots = HashSet::new();
    for entry in &old.records {
        if !routable(entry.addr, allow_local)
            || canonical(entry.addr) != entry.addr
            || !addresses.insert(entry.addr)
            || entry
                .source_ip
                .is_some_and(|ip| legacy_prefix(ip) != entry.source_group)
            || entry.tried && entry.last_success == 0
            || !slots.insert(legacy_slot(&old.secret, entry))
        {
            return Err(invalid("invalid legacy address record"));
        }
        let count = sources.entry(entry.source_group).or_insert(0_usize);
        *count += 1;
        if *count > 64 {
            return Err(invalid("legacy source limit"));
        }
    }
    let records = old
        .records
        .into_iter()
        .map(|entry| {
            // Core's local attempt timestamps are deliberately not restored.
            let _ = entry.last_attempt;
            Candidate {
                addr: entry.addr,
                services: entry.services,
                source: entry
                    .source_ip
                    .map_or(Source::LegacyDns(entry.source_group), Source::Ip),
                last_seen: entry.last_seen,
                last_success: entry.last_success,
                failures: u32::from(entry.failures),
                tried: entry.tried,
                new_buckets: Vec::new(),
                last_attempt: 0,
                last_count_attempt: 0,
            }
        })
        .collect();
    Ok(Stored {
        version: VERSION,
        magic: old.magic,
        secret: old.secret,
        records,
    })
}
fn read_book(path: &Path, magic: Option<[u8; 4]>, allow_local: bool) -> io::Result<Option<Loaded>> {
    #[derive(Deserialize)]
    struct Header {
        version: u32,
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
    let legacy = header.version == 1;
    let stored = if legacy {
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(invalid("legacy address book size"));
        }
        let old = serde_json::from_slice(&bytes[..payload_len]).map_err(io::Error::other)?;
        convert_legacy(old, allow_local)?
    } else if header.version == VERSION {
        let stored: Stored =
            serde_json::from_slice(&bytes[..payload_len]).map_err(io::Error::other)?;
        validate_current(&stored, allow_local)?;
        stored
    } else {
        return Err(invalid("unsupported address book schema"));
    };
    if magic.is_some_and(|magic| magic != stored.magic) {
        return Err(invalid("address book network"));
    }
    Ok(Some(Loaded {
        stored,
        legacy,
        bytes,
    }))
}
fn backup_legacy(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use bitcoin::hex::DisplayHex as _;
    let digest = Sha256::digest(bytes);
    let backup = path.with_extension(format!("v1-{}.bak", digest[..].to_lower_hex_string()));
    match fs::symlink_metadata(&backup) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            {
                return Err(invalid("migration backup size/type"));
            }
            // Read, revalidate and flush the same handle. Windows requires
            // GENERIC_WRITE for FlushFileBuffers even when bytes are unchanged.
            let mut file = OpenOptions::new().read(true).write(true).open(&backup)?;
            let mut existing = Vec::new();
            (&mut file)
                .take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut existing)?;
            if existing != bytes {
                return Err(invalid("migration backup differs"));
            }
            file.sync_all()?;
            let parent = backup
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            bitcoin_rs_storage::checkpoint::fs::sync_dir(
                &bitcoin_rs_storage::checkpoint::fs::open_data_dir(parent)?,
            )
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            publish_bytes_with_nonce(&backup, bytes, &mut false, || {
                bitcoin::secp256k1::rand::thread_rng().next_u64()
            })
        }
        Err(error) => Err(error),
    }
}
impl Manager {
    fn rebucket_legacy(&mut self) {
        let mut records = std::mem::take(&mut self.stored.records);
        let before = records.len();
        records.sort_by_key(|entry| {
            (
                std::cmp::Reverse(entry.tried),
                std::cmp::Reverse(entry.last_success),
                entry.addr,
            )
        });
        self.by_addr.clear();
        self.new.fill(EMPTY_SLOT);
        self.tried.fill(EMPTY_SLOT);
        let mut demoted = 0;
        for mut entry in records {
            let tried_slot = self.tried_slot(entry.addr);
            if entry.tried && self.tried[tried_slot] == EMPTY_SLOT {
                let index = self.stored.records.len();
                self.tried[tried_slot] = u32::try_from(index).unwrap_or(EMPTY_SLOT);
                self.by_addr.insert(entry.addr, index);
                self.stored.records.push(entry);
                continue;
            }
            let bucket = new_bucket(&self.stored.secret, entry.addr, &entry.source.group());
            let slot = self.new_slot(entry.addr, bucket);
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
            self.by_addr.insert(entry.addr, index);
            self.stored.records.push(entry);
        }
        tracing::info!(
            before,
            retained = self.stored.records.len(),
            demoted,
            dropped = before - self.stored.records.len(),
            "migrated backed-up address book to Core placement"
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
        // clobber an operator file created since open/migration observed absence.
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
