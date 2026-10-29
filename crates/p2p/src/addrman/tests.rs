use super::*;
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
    AddressBook::open(None, [1; 4], false, None)
}

#[test]
fn unproven_addresses_need_a_successful_outbound_handshake() {
    let book = book();
    book.learn_peer(crate::PeerRemote::Endpoint(addr(2)), &[(addr(1), 9, 10_000)], 10_000);
    assert!(!book.state.lock().stored.records[0].tried);
    book.queued(addr(1));
    book.attempted(addr(1), true, 10_001);
    assert_eq!(book.select(&[], &[], 10_002, u64::MAX, |_| true), None);
    book.succeeded(addr(1), 9, 10_003);
    assert!(book.state.lock().stored.records[0].tried);
    assert_eq!(book.state.lock().stored.records[0].failures, 0);
}

#[test]
fn gossip_is_bounded_and_selection_respects_groups_pending_and_exclusion() {
    let book = book();
    for n in 1..200 {
        book.learn_peer(crate::PeerRemote::Endpoint(addr(200)), &[(addr(n), 9, 10_000)], 10_000);
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
    // Inbound connections suppress the exact endpoint but never its group.
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
    book.learn_peer(crate::PeerRemote::Endpoint(addr(2)), &[(addr(1), 9, 10_000); 2], 10_000);
    assert_eq!(book.len(), 1);
}

#[test]
fn restart_roundtrip_and_corruption_preserves_operator_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("peers.dat");
    let book = AddressBook::open(Some(path.clone()), [1; 4], false, None);
    book.learn_peer(crate::PeerRemote::Endpoint(addr(2)), &[(addr(1), 9, 10_000)], 10_000);
    book.succeeded(addr(1), 9, 10_001);
    book.save();
    let restored = AddressBook::open(Some(path.clone()), [1; 4], false, None);
    assert_eq!(restored.len(), 1);
    assert!(restored.state.lock().stored.records[0].tried);
    for corrupt in [b"truncated".to_vec(), vec![0; 40]] {
        fs::write(network_path(&path, [1; 4]), &corrupt).expect("corrupt fixture");
        let recovered = AddressBook::open(Some(path.clone()), [1; 4], false, None);
        recovered.learn_peer(crate::PeerRemote::Endpoint(addr(2)), &[(addr(3), 9, 10_000)], 10_000);
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
    book.learn_peer(crate::PeerRemote::Endpoint(addr(2)), &[(first, 9, 10_000)], 10_000);
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
    book.learn_peer(crate::PeerRemote::Endpoint(addr(3)), &[(challenger, 9, 10_000)], 10_000);
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
    book.attempted(addr(1), true, 10_001);
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
    book.learn_peer(crate::PeerRemote::Endpoint(addr(2)), &[(addr(1), 1, 10_000)], 10_000);
    book.save();
    let clean = book.state.lock().saved_revision;
    book.learn_peer(crate::PeerRemote::Endpoint(addr(2)), &[(addr(1), 1, 9_999); 32], 10_000);
    assert_eq!(
        book.state.lock().revision,
        clean,
        "unchanged duplicate reports cannot schedule disk writes"
    );
    book.learn_peer(crate::PeerRemote::Endpoint(addr(2)), &[(addr(1), 8, 10_000)], 10_000);
    assert_ne!(
        book.state.lock().revision,
        clean,
        "new service evidence is persisted"
    );
    book.succeeded(addr(1), 9, 10_001);
    book.save();
    let clean = book.state.lock().saved_revision;
    book.learn_peer(crate::PeerRemote::Endpoint(addr(2)), &[(addr(1), 64, 10_001)], 10_001);
    assert_ne!(
        book.state.lock().revision,
        clean,
        "Core merges advertised services even for Tried records"
    );
    book.save();
    let clean = book.state.lock().saved_revision;
    book.learn_peer(crate::PeerRemote::Endpoint(addr(2)), &[(addr(1), 9, 13_602)], 13_602);
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
    assert_eq!(legacy.len(), 6, "gossip projects the shared cache overlay-inclusive");
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
    // Same cached rows, overlay disabled: IP-only projection.
    book.set_addrv2_gossip(false, false);
    assert_eq!(book.gossip_addrv2_at(10_000, tick).len(), 5);
    // After TTL expiry both projections refresh from one new selection.
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
    // A vacant different new slot is needed for both same-group records.
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
    book.attempted(addr(1), true, 10_001);
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
    manager.stored.secret =
        <[u8; 32]>::from_hex("41f758f2e5cc078d3795b4fc0cb60c2d735fa92cc020572bdc982dd2d564d11b")
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
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/data/core-addrman-v31.1.json"))
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
            u64::try_from(bucket_position(&secret, addr, true, new)).expect("position"),
            row["new_position"]
        );
        assert_eq!(
            u64::try_from(bucket_position(&secret, addr, false, tried)).expect("position"),
            row["tried_position"]
        );
        for bucket in [0, 1, 17, 63] {
            assert_eq!(
                u64::try_from(bucket_position(&secret, addr, true, bucket)).expect("position"),
                row[format!("new_pos{bucket}")]
            );
            assert_eq!(
                u64::try_from(bucket_position(&secret, addr, false, bucket)).expect("position"),
                row[format!("tried_pos{bucket}")]
            );
        }
    }
}

#[test]
fn health_matches_71_actual_core_boundaries_and_probabilities() {
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/data/core-addrman-health-v31.1.json"
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
            failures: u32::try_from(row["attempts"].as_u64().expect("attempts")).expect("count"),
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
    book.attempted(target(), true, EPOCH);
    book.unqueue(target());
    book.attempted(target(), true, EPOCH + 1);
    book.unqueue(target());
    assert_eq!(book.state.lock().stored.records[0].failures, 1);
    book.succeeded(addr(77), 9, EPOCH + 10); // Core updates the epoch even when the address is absent.
    book.attempted(target(), true, EPOCH + 12);
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

fn fixture_bytes(value: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("fixture");
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
            } // Colliding source buckets do not manufacture a reference.
            for _ in 0..4096 {
                if manager.learn(target(), Some(9), origin.clone(), EPOCH - 999, EPOCH, 0) {
                    break;
                }
            }
        }
    }
    book.attempted(target(), true, EPOCH);
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
    let mut value = serde_json::to_value(&manager.stored).expect("stored");
    drop(manager);
    for bad in [
        serde_json::json!([]),
        serde_json::json!([0, 0]),
        serde_json::json!([1024]),
        serde_json::json!([0, 1, 2, 3, 4, 5, 6, 7, 8]),
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
    let size = serde_json::to_vec(&entry).expect("max-width fields").len();
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
    book.attempted(target(), false, EPOCH);
    let manager = book.state.lock();
    let entry = &manager.stored.records[0];
    assert_eq!(entry.failures, 2);
    assert_eq!(entry.last_attempt, EPOCH);
    assert_eq!(entry.last_count_attempt, 0);
    assert!(manager.pending.is_empty());
    assert!(!entry.terrible(EPOCH + 61));
    drop(manager);
    book.attempted(target(), true, EPOCH + 62);
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
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/data/core-addrman-addsingle-v31.1.json"
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
        let actual = serde_json::json!({"case":case,"attempts":entry.failures,"seen":entry.last_seen,"last_try":entry.last_attempt,"last_success":entry.last_success,"tried":entry.tried});
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
    book.attempted(target(), true, EPOCH);
    assert_core_operation(&book.state.lock(), "first-attempt-counted", None);
    book.attempted(target(), true, EPOCH + 1);
    assert_core_operation(
        &book.state.lock(),
        "repeat-same-good-epoch-not-counted",
        None,
    );
    book.succeeded(other, 0, EPOCH + 10);
    book.attempted(target(), false, EPOCH + 11);
    assert_core_operation(
        &book.state.lock(),
        "noncounted-attempt-updates-only-try",
        None,
    );
    book.attempted(target(), true, EPOCH + 12);
    assert_core_operation(&book.state.lock(), "attempt-after-other-good-counted", None);
    book.succeeded(target(), 0, EPOCH + 20);
    assert_core_operation(
        &book.state.lock(),
        "good-retains-seen-resets-attempts",
        None,
    );
}

fn ring_manager(second_port: u16) -> (Manager, PeerEndpoint, PeerEndpoint) {
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/data/core-addrman-ring-v31.1.json"
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
        )
        .into();
        assert!(manager.learn(peer, Some(9), source(1), EPOCH, EPOCH, 0));
        let bucket = usize::try_from(row["new_bucket"].as_u64().expect("bucket")).expect("bucket");
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
    // Six binomial standard deviations plus one observation for quantization.
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
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/data/core-addrman-selection-v31.1.json"
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
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/data/core-addrman-v31.1.json"))
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
    book.attempted(alias, false, EPOCH);
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
    book.attempted(alias, false, EPOCH);
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
    let anon =
        crate::PeerRemote::AnonymousTor(crate::ConnectionId::for_test_raw(77));
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
        std::net::SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8333).into();
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
    let anon =
        crate::PeerRemote::AnonymousTor(crate::ConnectionId::for_test_raw(78));
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
mod asmap_tests;

mod probe_tests;

mod eligibility_tests;

mod services_tests;

mod overlay_destinations;

mod persistence;
