//! Bounded, non-consensus peer knowledge. DNS and wire gossip feed this one owner.
//!
//! Bucket placement is keyed and source-limited; a learned address never replaces
//! a proven address. The on-disk book is auxiliary: unreadable/corrupt data is
//! preserved and disables writes for this run, while in-memory discovery works.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
const RETRY_SECS: u64 = 60;
const MAX_GOSSIP: usize = 32;

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
    cursor: u64,
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
            || seen > now.saturating_add(600)
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
            existing.last_seen = existing.last_seen.max(seen);
            // Hearsay must not rewrite a proven peer's services.
            if !existing.tried {
                existing.services |= services;
            }
            self.revision = self.revision.wrapping_add(1);
            return false;
        }
        if self
            .stored
            .records
            .iter()
            .filter(|entry| entry.source_group == source_group)
            .count()
            >= MAX_SOURCE_GROUP
        {
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
        if let Some(index) = self
            .stored
            .records
            .iter()
            .position(|entry| self.slot(entry, entry.tried) == slot)
        {
            let old = &self.stored.records[index];
            if old.tried
                || self.pending.contains(&old.addr)
                || now.saturating_sub(old.last_seen) < STALE_SECS
            {
                return false;
            }
            self.stored.records.swap_remove(index);
        }
        if self.stored.records.len() >= MAX_RECORDS {
            return false;
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
            path,
            writable: true,
            revision: 0,
            saved_revision: 0,
            cursor: 0,
            pending: HashSet::new(),
        };
        if let Some(path) = &manager.path {
            match read_book(path, magic, allow_local) {
                Ok(Some(stored)) => manager.stored = stored,
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "address book unavailable; preserving file, using memory discovery without overwriting it");
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

    // Selection claims pending ownership only after successful enqueue, in the same
    // short state critical section. No callback performs I/O or locks PeerTable.
    pub(crate) fn select(
        &self,
        active: &[SocketAddr],
        now: u64,
        mut allowed: impl FnMut(SocketAddr) -> bool,
    ) -> Option<SocketAddr> {
        let mut manager = self.state.lock();
        manager.cursor = manager.cursor.wrapping_add(1);
        let prefer_new = manager.cursor.is_multiple_of(4);
        let groups: HashSet<_> = active.iter().map(|addr| prefix_group(addr.ip())).collect();
        let cursor = manager.cursor;
        manager
            .stored
            .records
            .iter()
            .filter(|entry| {
                !active.contains(&entry.addr)
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
    pub(crate) fn attempted(&self, addr: SocketAddr, now: u64) {
        let mut manager = self.state.lock();
        manager.pending.remove(&addr);
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
        let manager = self.state.lock();
        manager
            .stored
            .records
            .iter()
            .filter(|entry| now.saturating_sub(entry.last_seen) <= STALE_SECS)
            .take(MAX_GOSSIP)
            .map(|entry| {
                (
                    u32::try_from(entry.last_seen).unwrap_or(u32::MAX),
                    bitcoin::p2p::address::Address::new(
                        &entry.addr,
                        bitcoin::p2p::ServiceFlags::from(entry.services),
                    ),
                )
            })
            .collect()
    }

    pub(crate) fn save(&self) {
        let _publication = self.publication.lock();
        let (path, stored, revision) = {
            let manager = self.state.lock();
            if !manager.writable || manager.revision == manager.saved_revision {
                return;
            }
            let Some(path) = manager.path.clone() else {
                return;
            };
            (path, manager.stored.clone(), manager.revision)
        };
        match publish_book(&path, &stored) {
            Ok(()) => self.state.lock().saved_revision = revision,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "address book save failed; keeping previous file and retrying later");
            }
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_book(
    path: &std::path::Path,
    magic: [u8; 4],
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
    if stored.version != 1 || stored.magic != magic || stored.records.len() > MAX_RECORDS {
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
        cursor: 0,
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

fn publish_book(path: &std::path::Path, stored: &Stored) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(stored).map_err(io::Error::other)?;
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(invalid("address book too large"));
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
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
        assert_eq!(book.select(&[], 10_002, |_| true), None);
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
        let picked = book.select(&[], 10_000, |_| true).expect("candidate");
        book.queued(picked);
        assert_ne!(book.select(&[], 10_000, |_| true), Some(picked));
        assert_eq!(book.select(&[], 10_000, |_| false), None);
        book.unqueue(picked);
        let same_group = SocketAddr::new(picked.ip(), 8334);
        assert_ne!(book.select(&[same_group], 10_000, |_| true), Some(picked));
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
            fs::write(&path, &corrupt).expect("corrupt fixture");
            let recovered = AddressBook::open(Some(path.clone()), [1; 4], false);
            recovered.learn_peer(addr(2).ip(), &[(addr(3), 9, 10_000)], 10_000);
            recovered.save();
            assert_eq!(fs::read(&path).expect("read"), corrupt);
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
    fn wrong_network_and_failed_publication_preserve_existing_files() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("peers.dat");
        let book = AddressBook::open(Some(path.clone()), [1; 4], false);
        book.learn_dns("seed", &[addr(1)], 10_000);
        book.save();
        let original = fs::read(&path).expect("read");
        let other_network = AddressBook::open(Some(path.clone()), [2; 4], false);
        other_network.learn_dns("seed", &[addr(2)], 10_000);
        other_network.save();
        assert_eq!(fs::read(&path).expect("read"), original);
        let temp = path.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&temp, b"operator-owned stale temporary file").expect("fixture");
        book.learn_dns("seed", &[addr(3)], 10_000);
        book.save();
        assert_eq!(fs::read(&path).expect("read"), original);
        assert_eq!(
            fs::read(&temp).expect("read"),
            b"operator-owned stale temporary file"
        );
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
            restored.select(&[], 10_001 + STALE_SECS, |_| true),
            Some(addr(201))
        );
        book.learn_dns("seed", &[addr(202)], 10_001 + STALE_SECS);
        assert_eq!(book.len(), 1, "learn also releases a stale source quota");
    }
    #[test]
    fn a_long_lived_ready_connection_keeps_its_candidate_while_offline_peers_expire() {
        let book = book();
        book.learn_dns("seed", &[addr(1), addr(2)], 10_000);
        book.succeeded(addr(1), 9, 10_001);
        let later = 10_002 + STALE_SECS;
        book.refresh_connected(&[addr(1)], later);
        book.expire(later);
        let manager = book.state.lock();
        assert_eq!(manager.stored.records.len(), 1);
        assert_eq!(manager.stored.records[0].addr, addr(1));
        assert!(manager.stored.records[0].tried);
    }
}
