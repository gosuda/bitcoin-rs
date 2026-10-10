//! Bounded, non-consensus peer knowledge. DNS and wire gossip feed this one owner.
//!
//! Bucket placement is keyed and source-limited; gossip cannot replace retained
//! peer knowledge. DNS recovery replaces only eligible same-source records.
//! The on-disk book is auxiliary: unreadable/corrupt data is preserved and
//! disables writes for this run, while in-memory discovery works.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::secp256k1::rand::RngCore;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_RECORDS: usize = 4096;
const MAX_SOURCE_GROUP: usize = 64;
const NEW_SLOTS: u64 = 3072;
const TRIED_SLOTS: u64 = 1024;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const STALE_SECS: u64 = 30 * 24 * 60 * 60;
const FUTURE_SKEW_SECS: u64 = 10 * 60;
const RETRY_SECS: u64 = 60;
const MAX_GOSSIP: usize = 32;
// A shared response survives reconnects, as Core's response cache does. The
// fixed 24-hour window is a bounded policy, not Core's randomized 21-27 hours.
const GOSSIP_CACHE_TTL: Duration = Duration::from_hours(24);
const MAX_TEMP_ATTEMPTS: usize = 8;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    magic: [u8; 4],
    secret: [u8; 32],
    records: Vec<Candidate>,
}

struct Manager {
    stored: Stored,
    allow_local: bool,
    path: Option<PathBuf>,
    writable: bool,
    revision: u64,
    saved_revision: u64,
    published: bool,
    cursor: u64,
    gossip_cursor: usize,
    gossip_cache: Option<(Instant, Vec<(u32, bitcoin::p2p::address::Address)>)>,
    pending: HashSet<SocketAddr>,
}

/// Shared peer-discovery owner; no chainstate or connection leases are stored.
pub(crate) struct AddressBook {
    state: Mutex<Manager>,
    // Serialize publication without holding the in-memory state lock across I/O.
    publication: Mutex<()>,
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

fn prefix_group(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(ip) => {
            let bytes = ip.octets();
            (1_u64 << 48) | u64::from(u16::from_be_bytes([bytes[0], bytes[1]]))
        }
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return prefix_group(ip.into());
            }
            let bytes = ip.octets();
            (2_u64 << 48) | u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
    }
}

impl Manager {
    fn expire(&mut self, now: u64) {
        let before = self.stored.records.len();
        self.stored.records.retain(|entry| {
            now.saturating_sub(entry.last_seen) <= STALE_SECS || self.pending.contains(&entry.addr)
        });
        if before != self.stored.records.len() {
            self.revision = self.revision.wrapping_add(1);
        }
    }

    fn slot(&self, candidate: &Candidate, tried: bool) -> u64 {
        let mut hash = Sha256::new();
        hash.update(self.stored.secret);
        hash.update(prefix_group(candidate.addr.ip()).to_le_bytes());
        if !tried {
            hash.update(candidate.source_group.to_le_bytes());
        }
        // Limit each target/source pair to sixteen positions, spread by the endpoint.
        let bucket = u64::from_le_bytes(hash.finalize()[..8].try_into().unwrap_or_default());
        let endpoint = Sha256::digest(candidate.addr.to_string().as_bytes());
        let offset = u64::from(endpoint[0] & 15);
        if tried {
            NEW_SLOTS + (bucket % (TRIED_SLOTS / 16)) * 16 + offset
        } else {
            (bucket % (NEW_SLOTS / 16)) * 16 + offset
        }
    }

    fn learn(
        &mut self,
        addr: SocketAddr,
        services: u64,
        source_group: u64,
        source_ip: Option<IpAddr>,
        seen: u64,
        now: u64,
    ) -> bool {
        self.expire(now);
        let addr = canonical(addr);
        if !routable(addr, self.allow_local)
            || seen > now.saturating_add(FUTURE_SKEW_SECS)
            || now.saturating_sub(seen) > STALE_SECS
        {
            return false;
        }
        if let Some(existing) = self
            .stored
            .records
            .iter_mut()
            .find(|entry| entry.addr == addr)
        {
            let before = (existing.last_seen, existing.services);
            existing.last_seen = existing.last_seen.max(seen);
            // Hearsay must not rewrite a proven peer's services.
            if !existing.tried {
                existing.services |= services;
            }
            if (existing.last_seen, existing.services) != before {
                self.revision = self.revision.wrapping_add(1);
            }
            return false;
        }
        let candidate = Candidate {
            addr,
            services,
            source_group,
            source_ip,
            last_seen: seen,
            last_attempt: 0,
            last_success: 0,
            failures: 0,
            tried: false,
        };
        let slot = self.slot(&candidate, false);
        // Adapt Core's IsTerrible health thresholds for replacement admission:
        // future timestamps beyond the admission skew are eligible; otherwise
        // never-success candidates need three failures, old successes need ten
        // and a week without success. Retain peer knowledge until an actual
        // admissible same-seed replacement exists (including with DNS disabled).
        // Pending and last-minute attempts are never replacement victims.
        let replaceable = |old: &Candidate| {
            source_ip.is_none()
                && old.source_group == source_group
                && now.saturating_sub(old.last_attempt) > RETRY_SECS
                && (old.last_seen > now.saturating_add(FUTURE_SKEW_SECS)
                    || (old.last_success == 0 && old.failures >= 3)
                    || (old.last_success != 0
                        && now.saturating_sub(old.last_success) > 7 * 24 * 60 * 60
                        && old.failures >= 10))
                && !self.pending.contains(&old.addr)
        };
        let mut victim = self
            .stored
            .records
            .iter()
            .position(|entry| self.slot(entry, entry.tried) == slot);
        if victim.is_some_and(|index| !replaceable(&self.stored.records[index])) {
            return false;
        }
        let source_full = self
            .stored
            .records
            .iter()
            .filter(|entry| entry.source_group == source_group)
            .count()
            >= MAX_SOURCE_GROUP;
        if victim.is_none() && (source_full || self.stored.records.len() >= MAX_RECORDS) {
            victim = self
                .stored
                .records
                .iter()
                .enumerate()
                .filter(|(_, old)| replaceable(old))
                .max_by_key(|(_, old)| (old.failures, std::cmp::Reverse(old.last_attempt)))
                .map(|(index, _)| index);
            if victim.is_none() {
                return false;
            }
        }
        if let Some(index) = victim {
            self.stored.records.swap_remove(index);
        }
        self.stored.records.push(candidate);
        self.revision = self.revision.wrapping_add(1);
        true
    }
}

impl AddressBook {
    pub(crate) fn open(path: Option<PathBuf>, magic: [u8; 4], allow_local: bool) -> Arc<Self> {
        let mut secret = [0; 32];
        bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut secret);
        let mut manager = Manager {
            stored: Stored {
                version: 1,
                magic,
                secret,
                records: Vec::new(),
            },
            allow_local,
            path: path.as_deref().map(|base| network_path(base, magic)),
            writable: true,
            revision: 0,
            saved_revision: 0,
            published: false,
            cursor: 0,
            gossip_cursor: 0,
            gossip_cache: None,
            pending: HashSet::new(),
        };
        if let Some(scoped) = &manager.path {
            match read_book(scoped, Some(magic), allow_local) {
                Ok(Some(stored)) => {
                    manager.stored = stored;
                    manager.published = true;
                }
                Ok(None) => {
                    // The old unscoped file is a read-only migration source.
                    // Never overwrite it, including for a different P2P magic.
                    if let Some(legacy) = path {
                        match read_book(&legacy, None, true) {
                            Ok(Some(stored)) if stored.magic == magic => {
                                if stored
                                    .records
                                    .iter()
                                    .all(|entry| routable(entry.addr, allow_local))
                                {
                                    manager.stored = stored;
                                    manager.revision = 1;
                                } else {
                                    tracing::warn!(path = %legacy.display(), "legacy address book contains inadmissible addresses; preserving file and using memory discovery");
                                    manager.writable = false;
                                }
                            }
                            Ok(_) => {}
                            Err(error) => {
                                tracing::warn!(path = %legacy.display(), %error, "legacy address book unavailable; preserving file and using memory discovery until the operator resolves it");
                                manager.writable = false;
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(path = %scoped.display(), %error, "address book unavailable; preserving file, using memory discovery without overwriting it");
                    manager.writable = false;
                }
            }
        }
        Arc::new(Self {
            state: Mutex::new(manager),
            publication: Mutex::new(()),
        })
    }

    pub(crate) fn refresh_connected(&self, active: &[SocketAddr], now: u64) {
        let mut manager = self.state.lock();
        let mut changed = false;
        for entry in &mut manager.stored.records {
            if active.contains(&entry.addr) && now.saturating_sub(entry.last_seen) >= 3600 {
                entry.last_seen = now;
                changed = true;
            }
        }
        if changed {
            manager.revision = manager.revision.wrapping_add(1);
        }
    }

    pub(crate) fn expire(&self, now: u64) {
        self.state.lock().expire(now);
    }

    pub(crate) fn len(&self) -> usize {
        self.state.lock().stored.records.len()
    }

    pub(crate) fn learn_dns(&self, seed: &str, addresses: &[SocketAddr], now: u64) {
        let hash = Sha256::digest(seed.as_bytes());
        let source = u64::from_le_bytes(hash[..8].try_into().unwrap_or_default());
        let mut manager = self.state.lock();
        for &addr in addresses.iter().take(MAX_SOURCE_GROUP) {
            manager.learn(addr, 0, source, None, now, now);
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
            manager.learn(
                addr,
                services,
                prefix_group(source),
                Some(source),
                seen,
                now,
            );
        }
    }

    // The maintenance worker selects, claims, then enqueues each automatic dial.
    // A failed enqueue releases the claim; the drain retains it through the
    // connection thread's lifetime. Callbacks must not do I/O or acquire locks.
    /// `connected` suppresses exact endpoints in any direction (Core
    /// `setConnected` covers inbound too). `grouped` suppresses whole network
    /// groups and must carry outbound sessions only: inbound peers inject
    /// their source groups voluntarily and could otherwise suppress arbitrary
    /// candidate groups from automatic selection.
    pub(crate) fn select(
        &self,
        connected: &[SocketAddr],
        grouped: &[SocketAddr],
        now: u64,
        mut allowed: impl FnMut(SocketAddr) -> bool,
    ) -> Option<SocketAddr> {
        let mut manager = self.state.lock();
        manager.cursor = manager.cursor.wrapping_add(1);
        let prefer_new = manager.cursor.is_multiple_of(4);
        let groups: HashSet<_> = grouped
            .iter()
            .chain(&manager.pending)
            .map(|addr| prefix_group(addr.ip()))
            .collect();
        let cursor = manager.cursor;
        manager
            .stored
            .records
            .iter()
            .filter(|entry| {
                !connected.contains(&entry.addr)
                    && !manager.pending.contains(&entry.addr)
                    && !groups.contains(&prefix_group(entry.addr.ip()))
                    && now.saturating_sub(entry.last_seen) <= STALE_SECS
                    && (entry.last_attempt == 0
                        || now.saturating_sub(entry.last_attempt)
                            >= RETRY_SECS.saturating_mul(u64::from(entry.failures).max(1)))
                    && allowed(entry.addr)
            })
            .max_by_key(|entry| {
                let mixed = manager
                    .slot(entry, entry.tried)
                    .wrapping_add(cursor.wrapping_mul(1_103_515_245));
                (
                    entry.tried != prefer_new,
                    std::cmp::Reverse(entry.failures),
                    mixed % u64::try_from(MAX_RECORDS).unwrap_or(u64::MAX),
                )
            })
            .map(|entry| entry.addr)
    }

    pub(crate) fn queued(&self, addr: SocketAddr) {
        self.state.lock().pending.insert(addr);
    }
    pub(crate) fn unqueue(&self, addr: SocketAddr) {
        self.state.lock().pending.remove(&addr);
    }
    /// Outstanding automatic claims not already counted as live sessions.
    pub(crate) fn pending_count_excluding(&self, active: &[SocketAddr]) -> usize {
        self.state
            .lock()
            .pending
            .iter()
            .filter(|addr| !active.contains(addr))
            .count()
    }

    pub(crate) fn attempted(&self, addr: SocketAddr, now: u64) {
        let mut manager = self.state.lock();
        manager.pending.insert(addr);
        if let Some(entry) = manager
            .stored
            .records
            .iter_mut()
            .find(|entry| entry.addr == addr)
        {
            entry.last_attempt = now;
            entry.failures = entry.failures.saturating_add(1);
            manager.revision = manager.revision.wrapping_add(1);
        }
    }

    pub(crate) fn succeeded(&self, addr: SocketAddr, services: u64, now: u64) {
        let mut manager = self.state.lock();
        let Some(index) = manager
            .stored
            .records
            .iter()
            .position(|entry| entry.addr == addr)
        else {
            return;
        };
        let target = manager.slot(&manager.stored.records[index], true);
        let vacant = !manager
            .stored
            .records
            .iter()
            .enumerate()
            .any(|(other, entry)| other != index && manager.slot(entry, entry.tried) == target);
        let entry = &mut manager.stored.records[index];
        entry.services = services;
        entry.last_success = now;
        entry.last_attempt = 0;
        entry.last_seen = now;
        entry.failures = 0;
        entry.tried = entry.tried || vacant;
        manager.revision = manager.revision.wrapping_add(1);
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
            if now.saturating_sub(entry.last_seen) > STALE_SECS {
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
                tracing::warn!(path = %path.display(), %error, "address book publication not confirmed durable; retaining dirty state for retry");
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

fn read_book(
    path: &std::path::Path,
    magic: Option<[u8; 4]>,
    allow_local: bool,
) -> io::Result<Option<Stored>> {
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
    let stored: Stored = serde_json::from_slice(&bytes[..payload_len]).map_err(io::Error::other)?;
    if stored.version != 1
        || magic.is_some_and(|magic| stored.magic != magic)
        || stored.records.len() > MAX_RECORDS
    {
        return Err(invalid("address book version/network/count"));
    }
    let mut addresses = HashSet::new();
    let mut source_counts = std::collections::HashMap::new();
    for entry in &stored.records {
        if !routable(entry.addr, allow_local)
            || canonical(entry.addr) != entry.addr
            || !addresses.insert(entry.addr)
            || entry
                .source_ip
                .is_some_and(|ip| prefix_group(ip) != entry.source_group)
            || entry.tried && entry.last_success == 0
        {
            return Err(invalid("invalid/duplicate address book record"));
        }
        let count = source_counts.entry(entry.source_group).or_insert(0_usize);
        *count += 1;
        if *count > MAX_SOURCE_GROUP {
            return Err(invalid("address book source limit"));
        }
    }
    let view = Manager {
        stored,
        allow_local,
        path: None,
        writable: false,
        revision: 0,
        saved_revision: 0,
        published: false,
        cursor: 0,
        gossip_cursor: 0,
        gossip_cache: None,
        pending: HashSet::new(),
    };
    let mut slots = HashSet::new();
    for entry in &view.stored.records {
        if !slots.insert(view.slot(entry, entry.tried)) {
            return Err(invalid("address book bucket collision"));
        }
    }
    Ok(Some(view.stored))
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
    mut nonce: impl FnMut() -> u64,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(stored).map_err(io::Error::other)?;
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(invalid("address book too large"));
    }
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
        file.write_all(&bytes)?;
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
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::new(8, n, 1, 1).into(), 8333)
    }
    fn book() -> Arc<AddressBook> {
        AddressBook::open(None, [1; 4], false)
    }

    #[test]
    fn unproven_addresses_need_a_successful_outbound_handshake() {
        let book = book();
        book.learn_peer(addr(2).ip(), &[(addr(1), 9, 10_000)], 10_000);
        assert!(!book.state.lock().stored.records[0].tried);
        book.attempted(addr(1), 10_001);
        assert_eq!(book.select(&[], &[], 10_002, |_| true), None);
        book.succeeded(addr(1), 9, 10_003);
        assert!(book.state.lock().stored.records[0].tried);
        assert_eq!(book.state.lock().stored.records[0].failures, 0);
    }

    #[test]
    fn gossip_is_bounded_and_selection_respects_groups_pending_and_exclusion() {
        let book = book();
        for n in 1..200 {
            book.learn_peer(addr(200).ip(), &[(addr(n), 9, 10_000)], 10_000);
        }
        assert!(book.len() <= MAX_SOURCE_GROUP);
        let picked = book.select(&[], &[], 10_000, |_| true).expect("candidate");
        book.queued(picked);
        assert_ne!(book.select(&[], &[], 10_000, |_| true), Some(picked));
        assert_eq!(book.select(&[], &[], 10_000, |_| false), None);
        book.unqueue(picked);
        let same_group = SocketAddr::new(picked.ip(), 8334);
        assert_ne!(
            book.select(&[], &[same_group], 10_000, |_| true),
            Some(picked)
        );
        // Inbound connections suppress the exact endpoint but never its group.
        assert!(book.select(&[same_group], &[], 10_000, |_| true).is_some());
        assert_ne!(book.select(&[picked], &[], 10_000, |_| true), Some(picked));
        assert!(book.gossip(10_000).len() <= MAX_GOSSIP);
    }

    #[test]
    fn invalid_and_duplicate_addresses_do_not_create_records() {
        let book = book();
        book.learn_peer(
            addr(2).ip(),
            &[
                ("127.0.0.1:1".parse().expect("addr"), 9, 10_000),
                (addr(1), 9, 20_000),
            ],
            10_000,
        );
        assert_eq!(book.len(), 0);
        book.learn_peer(addr(2).ip(), &[(addr(1), 9, 10_000); 2], 10_000);
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn restart_roundtrip_and_corruption_preserves_operator_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("peers.dat");
        let book = AddressBook::open(Some(path.clone()), [1; 4], false);
        book.learn_peer(addr(2).ip(), &[(addr(1), 9, 10_000)], 10_000);
        book.succeeded(addr(1), 9, 10_001);
        book.save();
        let restored = AddressBook::open(Some(path.clone()), [1; 4], false);
        assert_eq!(restored.len(), 1);
        assert!(restored.state.lock().stored.records[0].tried);
        for corrupt in [b"truncated".to_vec(), vec![0; 40]] {
            fs::write(network_path(&path, [1; 4]), &corrupt).expect("corrupt fixture");
            let recovered = AddressBook::open(Some(path.clone()), [1; 4], false);
            recovered.learn_peer(addr(2).ip(), &[(addr(3), 9, 10_000)], 10_000);
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
        book.learn_peer(addr(2).ip(), &[(first, 9, 10_000)], 10_000);
        book.succeeded(first, 9, 10_001);
        let incumbent = book.state.lock().stored.records[0].clone();
        let challenger = {
            let manager = book.state.lock();
            let target = manager.slot(&incumbent, true);
            (1..65535_u16)
                .map(|port| SocketAddr::new(first.ip(), port))
                .find(|candidate| {
                    *candidate != first
                        && manager.slot(
                            &Candidate {
                                addr: *candidate,
                                ..incumbent.clone()
                            },
                            true,
                        ) == target
                })
                .expect("slot collision")
        };
        book.learn_peer(addr(3).ip(), &[(challenger, 9, 10_000)], 10_000);
        book.succeeded(challenger, 9, 10_002);
        let manager = book.state.lock();
        assert!(
            manager
                .stored
                .records
                .iter()
                .find(|entry| entry.addr == first)
                .expect("incumbent")
                .tried
        );
        assert!(
            !manager
                .stored
                .records
                .iter()
                .find(|entry| entry.addr == challenger)
                .expect("challenger")
                .tried
        );
    }

    #[test]
    fn scoped_network_books_and_stale_temporary_files_are_independent() {
        let dir = tempfile::tempdir().expect("dir");
        let base = dir.path().join("peers.dat");
        let path = network_path(&base, [1; 4]);
        let book = AddressBook::open(Some(base.clone()), [1; 4], false);
        book.learn_dns("seed", &[addr(1)], 10_000);
        book.save();
        let original = fs::read(&path).expect("read");
        let other = AddressBook::open(Some(base.clone()), [2; 4], false);
        other.learn_dns("seed", &[addr(2)], 10_000);
        other.save();
        assert_eq!(fs::read(&path).expect("read"), original);
        assert_eq!(AddressBook::open(Some(base), [2; 4], false).len(), 1);
        let stale = path.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&stale, b"operator-owned stale temporary file").expect("fixture");
        book.attempted(addr(1), 10_001);
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
    fn legacy_import_retains_original_and_scoped_state_wins() {
        let dir = tempfile::tempdir().expect("dir");
        let base = dir.path().join("peers.dat");
        let source = book();
        source.learn_dns("seed", &[addr(1)], 10_000);
        let stored = source.state.lock().stored.clone();
        publish_book(&base, &stored, &mut false).expect("legacy fixture");
        let original = fs::read(&base).expect("legacy bytes");
        let migrated = AddressBook::open(Some(base.clone()), [1; 4], false);
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
            AddressBook::open(Some(base.clone()), [1; 4], false).len(),
            1
        );
        let unknown = AddressBook::open(Some(base.clone()), [3; 4], false);
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
        let foreign = AddressBook::open(Some(base.clone()), [2; 4], false);
        foreign.learn_dns("seed", &[addr(2)], 10_000);
        foreign.save();
        assert_eq!(
            AddressBook::open(Some(base.clone()), [2; 4], false).len(),
            1
        );
        assert_eq!(fs::read(&base).expect("retained"), original);
        let raced = AddressBook::open(Some(base.clone()), [3; 4], false);
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
            read_book(&path, Some([1; 4]), false)
                .expect("published")
                .expect("exists")
                .records
                .len(),
            1
        );
    }

    #[test]
    fn failed_fresh_seed_quota_admits_a_recovery_candidate_without_evicting_proven_or_pending() {
        let book = book();
        for n in 1..=255 {
            book.learn_dns("seed", &[addr(n)], 10_000);
        }
        assert_eq!(book.len(), MAX_SOURCE_GROUP);
        let retained: Vec<_> = book
            .state
            .lock()
            .stored
            .records
            .iter()
            .map(|entry| entry.addr)
            .collect();
        for &candidate in &retained {
            book.attempted(candidate, 10_001);
            book.unqueue(candidate);
            book.attempted(candidate, 10_062);
            book.unqueue(candidate);
            book.attempted(candidate, 10_123);
            book.unqueue(candidate);
        }
        let proven = retained[0];
        let collision_proven = retained[1];
        let pending = retained[2];
        book.succeeded(proven, 9, 10_183);
        // Success with a tried-slot collision is still proven, even in new.
        book.state
            .lock()
            .stored
            .records
            .iter_mut()
            .find(|entry| entry.addr == collision_proven)
            .expect("retained")
            .last_success = 10_183;
        book.queued(pending);
        let fresh = (1..=255)
            .map(|n| SocketAddr::from(([9, n, 1, 1], 8333)))
            .find(|candidate| {
                book.learn_dns("seed", &[*candidate], 10_184);
                book.state
                    .lock()
                    .stored
                    .records
                    .iter()
                    .any(|entry| entry.addr == *candidate)
            })
            .expect("fresh seed endpoint admitted despite a full source quota");
        assert_eq!(book.len(), MAX_SOURCE_GROUP);
        assert_eq!(
            book.select(&[], &[], 10_184, |candidate| candidate == fresh),
            Some(fresh)
        );
        let manager = book.state.lock();
        for protected in [proven, collision_proven, pending] {
            assert!(
                manager
                    .stored
                    .records
                    .iter()
                    .any(|entry| entry.addr == protected)
            );
        }
    }
    #[test]
    fn restarted_future_dated_seed_quota_allows_bounded_replacement_after_clock_rollback() {
        // Core 31.1 AddrInfo::IsTerrible admits future-dated records as victims
        // beyond ten minutes, but still protects attempts in the last minute.
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("peers.dat");
        let book = AddressBook::open(Some(path.clone()), [1; 4], false);
        for n in 1..=255 {
            book.learn_dns("seed", &[addr(n)], 10_601);
        }
        assert_eq!(book.len(), MAX_SOURCE_GROUP);
        let protected = {
            let mut manager = book.state.lock();
            let entries = &mut manager.stored.records;
            entries[0].last_seen = 10_600;
            entries[1].last_attempt = 9_940;
            [entries[0].addr, entries[1].addr, entries[2].addr]
        };
        book.save();
        drop(book);
        let book = AddressBook::open(Some(path), [1; 4], false);
        book.queued(protected[2]);
        book.expire(10_000);
        assert_eq!(
            book.len(),
            MAX_SOURCE_GROUP,
            "clock rollback alone must retain peer data"
        );
        book.learn_dns("seed", &[SocketAddr::from(([0, 0, 0, 0], 0))], 10_000);
        assert_eq!(
            book.len(),
            MAX_SOURCE_GROUP,
            "invalid replacement must retain peer data"
        );
        let fresh = (1..=255)
            .map(|n| SocketAddr::from(([9, n, 1, 1], 8333)))
            .find(|candidate| {
                book.learn_dns("seed", &[*candidate], 10_000);
                book.state
                    .lock()
                    .stored
                    .records
                    .iter()
                    .any(|entry| entry.addr == *candidate)
            })
            .expect("future-dated source quota must admit a valid same-seed replacement");
        assert_eq!(book.len(), MAX_SOURCE_GROUP);
        assert_eq!(
            book.select(&[], &[], 10_000, |candidate| candidate == fresh),
            Some(fresh)
        );
        let manager = book.state.lock();
        for protected in protected {
            assert!(
                manager
                    .stored
                    .records
                    .iter()
                    .any(|entry| entry.addr == protected)
            );
        }
    }

    #[test]
    fn old_successes_need_local_failure_evidence_and_an_admissible_replacement() {
        let book = book();
        for n in 1..=255 {
            book.learn_dns("seed", &[addr(n)], 10_000);
        }
        assert_eq!(book.len(), MAX_SOURCE_GROUP);
        let retained: Vec<_> = book
            .state
            .lock()
            .stored
            .records
            .iter()
            .map(|entry| entry.addr)
            .collect();
        let now = 10_000 + 8 * 24 * 60 * 60;
        for &candidate in &retained {
            book.succeeded(candidate, 9, 10_001);
            for attempt in 0..10 {
                book.attempted(candidate, now - 500 + attempt * 10);
                book.unqueue(candidate);
            }
        }
        let recent = retained[0];
        let pending = retained[1];
        let just_tried = retained[2];
        book.succeeded(recent, 9, now - 100);
        // Even repeated failures do not discredit a success within the week.
        book.state
            .lock()
            .stored
            .records
            .iter_mut()
            .find(|entry| entry.addr == recent)
            .expect("recent")
            .failures = 10;
        book.queued(pending);
        book.attempted(just_tried, now - 1);
        book.unqueue(just_tried);
        book.expire(now);
        assert_eq!(
            book.len(),
            MAX_SOURCE_GROUP,
            "without fresh DNS input, a local outage must not erase retained peer knowledge"
        );
        book.learn_dns("seed", &[SocketAddr::from(([0, 0, 0, 0], 0))], now);
        assert_eq!(
            book.len(),
            MAX_SOURCE_GROUP,
            "invalid DNS input cannot retire candidates"
        );
        let fresh = (1..=255)
            .map(|n| SocketAddr::from(([9, n, 1, 1], 8333)))
            .find(|candidate| {
                book.learn_dns("seed", &[*candidate], now);
                book.state
                    .lock()
                    .stored
                    .records
                    .iter()
                    .any(|entry| entry.addr == *candidate)
            })
            .expect("fresh endpoint admitted over a locally discredited old success");
        assert_eq!(book.len(), MAX_SOURCE_GROUP);
        assert_eq!(
            book.select(&[], &[], now, |candidate| candidate == fresh),
            Some(fresh)
        );
        let manager = book.state.lock();
        for protected in [recent, pending, just_tried] {
            assert!(
                manager
                    .stored
                    .records
                    .iter()
                    .any(|entry| entry.addr == protected)
            );
        }
    }

    #[test]
    fn a_populated_stale_book_can_bootstrap_and_reuse_source_quota_after_restart() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("peers.dat");
        let book = AddressBook::open(Some(path.clone()), [1; 4], false);
        for n in 1..200 {
            book.learn_dns("seed", &[addr(n)], 10_000);
        }
        assert_eq!(book.len(), MAX_SOURCE_GROUP);
        book.save();
        let restored = AddressBook::open(Some(path), [1; 4], false);
        restored.expire(10_001 + STALE_SECS);
        assert_eq!(
            restored.len(),
            0,
            "stale records cannot suppress DNS replenishment"
        );
        restored.learn_dns("seed", &[addr(201)], 10_001 + STALE_SECS);
        assert_eq!(
            restored.select(&[], &[], 10_001 + STALE_SECS, |_| true),
            Some(addr(201))
        );
        book.learn_dns("seed", &[addr(202)], 10_001 + STALE_SECS);
        assert_eq!(book.len(), 1, "learn also releases a stale source quota");
    }
    #[test]
    fn a_long_lived_ready_connection_keeps_its_candidate_while_offline_peers_expire() {
        let book = book();
        book.learn_dns("seed", &[addr(1)], 10_000);
        for candidate in (2..=255).map(addr) {
            book.learn_dns("seed", &[candidate], 10_000);
            if book.len() == 2 {
                break;
            }
        }
        assert_eq!(book.len(), 2, "fixture needs a distinct offline candidate");
        book.succeeded(addr(1), 9, 10_001);
        let later = 10_002 + STALE_SECS;
        book.refresh_connected(&[addr(1)], later);
        book.expire(later);
        let manager = book.state.lock();
        assert_eq!(manager.stored.records.len(), 1);
        assert_eq!(manager.stored.records[0].addr, addr(1));
        assert!(manager.stored.records[0].tried);
    }
    #[test]
    fn duplicate_hearsay_only_dirties_persisted_fields_that_change() {
        let dir = tempfile::tempdir().expect("dir");
        let book = AddressBook::open(Some(dir.path().join("peers.dat")), [1; 4], false);
        book.learn_peer(addr(2).ip(), &[(addr(1), 1, 10_000)], 10_000);
        book.save();
        let clean = book.state.lock().saved_revision;
        book.learn_peer(addr(3).ip(), &[(addr(1), 1, 9_999); 32], 10_000);
        assert_eq!(
            book.state.lock().revision,
            clean,
            "unchanged duplicate reports cannot schedule disk writes"
        );
        book.learn_peer(addr(2).ip(), &[(addr(1), 8, 10_000)], 10_000);
        assert_ne!(
            book.state.lock().revision,
            clean,
            "new service evidence is persisted"
        );
        book.succeeded(addr(1), 9, 10_001);
        book.save();
        let clean = book.state.lock().saved_revision;
        book.learn_peer(addr(2).ip(), &[(addr(1), 64, 10_001)], 10_001);
        assert_eq!(
            book.state.lock().revision,
            clean,
            "hearsay cannot replace proven services"
        );
        book.learn_peer(addr(2).ip(), &[(addr(1), 9, 10_002)], 10_002);
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
        }
        assert_eq!(book.len(), 64);
        let tick = Instant::now();
        let before = book.state.lock().revision;
        let first = book.gossip_at(10_000, tick);
        assert_eq!(first.len(), 32);
        assert_eq!(book.state.lock().revision, before);
        let fresh = (1..=255)
            .map(|n| SocketAddr::from(([9, n, 1, 1], 8333)))
            .find(|candidate| {
                book.learn_dns("other-seed", &[*candidate], 10_001);
                book.len() > 64
            })
            .expect("new discovery");
        let updated = first[0].1.socket_addr().expect("endpoint");
        book.refresh_connected(&[updated], 20_000);
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
            second
                .iter()
                .chain(&third)
                .any(|(_, address)| address.socket_addr().ok() == Some(fresh))
        );
        assert_eq!(book.state.lock().revision, before, "cache is not persisted");
        assert_eq!(
            book.gossip_at(20_101 + STALE_SECS, tick + 3 * GOSSIP_CACHE_TTL),
            []
        );
    }

    #[test]
    fn pending_attempts_keep_endpoint_and_network_group_ownership_until_released() {
        let book = book();
        book.learn_dns("seed", &[addr(1)], 10_000);
        let other = SocketAddr::new(addr(1).ip(), 18333);
        // A vacant different new slot is needed for both same-group records.
        let candidate = (1..65535)
            .map(|port| SocketAddr::new(other.ip(), port))
            .find(|&candidate| {
                if candidate == addr(1) {
                    return false;
                }
                book.learn_dns("seed", &[candidate], 10_000);
                book.len() == 2
            })
            .expect("two same-group endpoints");
        book.queued(addr(1));
        book.attempted(addr(1), 10_001);
        assert_eq!(book.pending_count_excluding(&[]), 1);
        assert_eq!(book.pending_count_excluding(&[addr(1)]), 0);
        assert_eq!(
            book.select(&[], &[], 10_100, |_| true),
            None,
            "in-flight groups stay exclusive beyond retry time"
        );
        book.unqueue(addr(1));
        assert!(
            book.select(&[], &[], 10_100, |_| true)
                .is_some_and(|a| a == addr(1) || a == candidate)
        );
    }
}
