use super::*;

const QUOTA_MAP: &[u8] = include_bytes!("../../../tests/data/asmap-source-quota-core-v31.1.raw");

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
        "../../../tests/data/core-addrman-asmap-v31.1.json"
    ))
    .expect("Core reference");
    let directory = tempfile::tempdir().expect("directory");
    let mut classifiers = HashMap::new();
    for (name, info) in data["map_files"].as_object().expect("maps") {
        let bytes = Vec::<u8>::from_hex(info["raw_hex"].as_str().expect("map bytes")).expect("hex");
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
        let secret =
            <[u8; 32]>::from_hex(row["secret_raw_hex"].as_str().expect("secret")).expect("key");
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
            u64::try_from(bucket_position(&secret, addr, true, new)).expect("position"),
            row["new_position"],
            "{row}"
        );
        assert_eq!(
            u64::try_from(bucket_position(&secret, addr, false, tried)).expect("position"),
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
    manager.stored.secret =
        <[u8; 32]>::from_hex("41f758f2e5cc078d3795b4fc0cb60c2d735fa92cc020572bdc982dd2d564d11b")
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
