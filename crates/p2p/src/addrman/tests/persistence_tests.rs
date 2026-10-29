use super::*;

/// Hand-written canonical v1 payload offered to PR #1684, which must adopt it
/// before its merge: three tried records (IP, non-zero Tor v3, non-zero I2P)
/// and two anchors. Written in `Stored` field order so `serde_json::to_vec`
/// reproduces it byte for byte; the test appends the trailing 32-byte SHA-256
/// of the payload, the same checksum envelope `publish_book` writes. No
/// historical schema lives in this file.
const SHARED_FIXTURE: &str = include_str!("../../../tests/data/addrman-canonical-v1-shared.json");
const TOR_ADDR: &str = "fivcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivjcrid.onion:8334";
const TOR_HOST: &str = "fivcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivjcrid.onion";
const I2P_ADDR: &str = "gmztgmztgmztgmztgmztgmztgmztgmztgmztgmztgmztgmztgmzq.b32.i2p:8335";
const I2P_HOST: &str = "gmztgmztgmztgmztgmztgmztgmztgmztgmztgmztgmztgmztgmzq.b32.i2p";

fn rejected_backup(path: &Path, bytes: &[u8]) -> PathBuf {
    use bitcoin::hex::DisplayHex as _;
    path.with_extension(format!(
        "pre-release-{}.bak",
        Sha256::digest(bytes)[..].to_lower_hex_string()
    ))
}

fn tor_endpoint() -> PeerEndpoint {
    TOR_ADDR.parse_endpoint()
}

fn i2p_endpoint() -> PeerEndpoint {
    I2P_ADDR.parse_endpoint()
}

#[test]
fn pre_release_version_is_frozen_and_the_format_marker_is_required() {
    // #1688: edit the canonical v1 directly until the first official release.
    assert_eq!(SCHEMA_VERSION, 1);
    assert_eq!(FORMAT, "bitcoin-rs-addrman");
    let value = serde_json::to_value(&book().state.lock().stored).expect("schema");
    assert_eq!(value["format"], "bitcoin-rs-addrman");
    assert_eq!(value["version"], 1);
    assert_eq!(value["records"], serde_json::json!([]));
    assert_eq!(value["anchors"], serde_json::json!([]));
}

#[test]
fn shared_fixture_round_trips_ip_tor_i2p_and_anchors() {
    let expected: serde_json::Value = serde_json::from_str(SHARED_FIXTURE).expect("shared fixture");
    let mut bytes = SHARED_FIXTURE.as_bytes().to_vec();
    bytes.extend_from_slice(&Sha256::digest(SHARED_FIXTURE.as_bytes()));
    let dir = tempfile::tempdir().expect("directory");
    let base = dir.path().join("peers.dat");
    let path = network_path(&base, [1; 4]);
    fs::write(&path, &bytes).expect("shared fixture");
    let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    assert!(book.state.lock().writable);
    assert_eq!(book.len(), 3);
    assert_eq!(
        serde_json::to_value(&book.state.lock().stored).expect("state"),
        expected
    );
    let tor = tor_endpoint();
    let i2p = i2p_endpoint();
    // Guard the fixture itself: a malformed onion name would parse as neither.
    assert_eq!(tor.host().to_string(), TOR_HOST);
    assert_eq!(i2p.host().to_string(), I2P_HOST);
    {
        let manager = book.state.lock();
        for endpoint in [tor, i2p] {
            assert!(manager.by_addr.contains_key(&endpoint));
        }
        let tor_record = &manager.stored.records[manager.by_addr[&tor]];
        assert_eq!(
            tor_record.source,
            Source::Overlay(
                bitcoin_rs_primitives::EndpointHost::parse_host(TOR_HOST).expect("host")
            )
        );
    }
    assert_eq!(
        crate::endpoint::overlay_netgroup(tor.host()),
        Some(vec![4, 0x2f])
    );
    assert_eq!(
        crate::endpoint::overlay_netgroup(i2p.host()),
        Some(vec![5, 0x3f])
    );
    assert_eq!(
        book.state.lock().stored.anchors,
        vec![
            Anchor {
                endpoint: tor,
                confirmed_at: 1_700_000_002,
            },
            Anchor {
                endpoint: i2p,
                confirmed_at: 1_700_000_002,
            },
        ]
    );
    assert_indexes(&book.state.lock());
    book.save();
    assert_eq!(fs::read(&path).expect("stable publication"), bytes);
    let restored = AddressBook::open(Some(base), [1; 4], false, None);
    assert_eq!(
        serde_json::to_value(&restored.state.lock().stored).expect("round trip"),
        expected
    );
    assert_indexes(&restored.state.lock());
}

fn old_v1_shape() -> serde_json::Value {
    serde_json::json!({"version":1,"magic":[1,1,1,1],"secret":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"records":[{
        "addr":"8.8.8.8:8333","services":9,"source_group":(1_u64<<48)|0x0101,"source_ip":"1.1.1.1",
        "last_seen":EPOCH,"last_attempt":EPOCH-1,"last_success":0,"failures":3,"tried":false
    }]})
}

fn old_v8_shape() -> serde_json::Value {
    serde_json::json!({"version":8,"magic":[1,1,1,1],"secret":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"records":[{
        "addr":"8.8.8.8:8333","services":9,"source":{"ip":"1.1.1.1"},
        "last_seen":EPOCH,"last_success":EPOCH,"failures":0,"tried":true,"new_buckets":[]
    }],"asmap_id":null,"anchors":[]})
}

fn divergent_v9_shape() -> serde_json::Value {
    serde_json::json!({
        "version": 9, "magic": [1, 1, 1, 1],
        "records": [{"obsolete_layout": "not a canonical candidate"}]
    })
}

// A genuine pre-release v9 file: every record is a real canonical `Candidate`
// and only the format marker is absent, so this is the shape an old writer
// could actually have produced.
fn unmarked_v9_bytes() -> Vec<u8> {
    let source = book();
    {
        let mut manager = source.state.lock();
        // Distinct sources spread the records over different New buckets, so
        // the old file holds several genuine candidates rather than one.
        for n in 1..=8 {
            manager.learn(
                target(),
                Some(9),
                Source::Ip(Ipv4Addr::new(1, n, 1, 1).into()),
                EPOCH,
                EPOCH,
                0,
            );
            manager.learn(
                addr(n),
                Some(9),
                Source::Ip(Ipv4Addr::new(2, n, 1, 1).into()),
                EPOCH,
                EPOCH,
                0,
            );
            if manager.stored.records.len() >= 3 {
                break;
            }
        }
    }
    source.succeeded(target(), 9, EPOCH + 1);
    let mut value = serde_json::to_value(&source.state.lock().stored).expect("canonical schema");
    assert!(
        value["records"].as_array().expect("records").len() >= 3,
        "the old writer must have produced several real records"
    );
    value.as_object_mut().expect("object").remove("format");
    value["version"] = 9.into();
    fixture_bytes(&value)
}

#[test]
fn faithful_old_v9_without_marker_is_preserved_and_never_decoded() {
    for scoped in [false, true] {
        let dir = tempfile::tempdir().expect("directory");
        let base = dir.path().join("peers.dat");
        let path = network_path(&base, [1; 4]);
        let source = if scoped { &path } else { &base };
        let bytes = unmarked_v9_bytes();
        fs::write(source, &bytes).expect("old v9 snapshot");
        let fresh = AddressBook::open(Some(base.clone()), [1; 4], false, None);
        assert!(fresh.state.lock().writable);
        assert_eq!(fresh.len(), 0, "old records are never decoded");
        assert_eq!(fs::read(source).expect("source before save"), bytes);
        let backup = rejected_backup(source, &bytes);
        assert_eq!(fs::read(&backup).expect("exact preserved bytes"), bytes);
        fresh.learn_dns("fresh-seed", &[addr(9)], EPOCH);
        fresh.save();
        assert_eq!(fs::read(&backup).expect("preserved after save"), bytes);
        if !scoped {
            assert_eq!(fs::read(&base).expect("base never overwritten"), bytes);
        }
        let restored = AddressBook::open(Some(base), [1; 4], false, None);
        assert!(restored.state.lock().writable);
        assert_eq!(restored.len(), 1, "only the fresh discovery survives");
        assert_eq!(
            restored.state.lock().stored.records[0].endpoint,
            addr(9),
            "a fresh record rather than a preserved old one"
        );
        assert_indexes(&restored.state.lock());
    }
}

#[test]
fn synthetic_old_shapes_are_preserved_without_decoding() {
    for version in [1, 8, 9] {
        for scoped in [false, true] {
            let dir = tempfile::tempdir().expect("directory");
            let base = dir.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            let source = if scoped { &path } else { &base };
            // Only the old envelope matters. The v1 legacy-DNS fields, the v8
            // numeric-services records, and the divergent v9 layout never pass
            // through a decoder or converter.
            let bytes = fixture_bytes(&match version {
                1 => old_v1_shape(),
                8 => old_v8_shape(),
                _ => divergent_v9_shape(),
            });
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
                // The old scoped file is only replaced by the fresh canonical
                // publication; the backup keeps the exact pre-release bytes.
                assert_ne!(fs::read(&path).expect("fresh publication"), bytes);
            } else {
                // The unscoped base file is never overwritten; the fresh
                // scoped publication is distinct from both base and backup.
                assert_eq!(fs::read(&base).expect("base retained"), bytes);
                assert_eq!(fs::read(&backup).expect("backup"), bytes);
                let published = fs::read(&path).expect("fresh scoped publication");
                assert_ne!(published, bytes);
                let book: serde_json::Value =
                    serde_json::from_slice(&published[..published.len() - 32])
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

#[test]
fn stripped_canonical_payload_is_an_unmarked_pre_release_file() {
    let dir = tempfile::tempdir().expect("directory");
    let base = dir.path().join("peers.dat");
    let path = network_path(&base, [1; 4]);
    let known = book();
    known.learn_dns("seed", &[target()], EPOCH);
    let mut value = serde_json::to_value(&known.state.lock().stored).expect("schema");
    value.as_object_mut().expect("object").remove("format");
    let bytes = fixture_bytes(&value);
    fs::write(&path, &bytes).expect("unmarked v1");
    let fresh = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    assert_eq!(fresh.len(), 0, "the unmarked payload is never decoded");
    assert!(fresh.state.lock().writable);
    fresh.learn_dns("fresh-seed", &[addr(9)], EPOCH);
    fresh.save();
    assert_eq!(
        fs::read(rejected_backup(&path, &bytes)).expect("backup"),
        bytes
    );
    let published = fs::read(&path).expect("fresh canonical snapshot");
    assert_ne!(published, bytes);
    let book: serde_json::Value =
        serde_json::from_slice(&published[..published.len() - 32]).expect("canonical JSON");
    assert_eq!(book["format"], "bitcoin-rs-addrman");
    assert_eq!(book["version"], 1);
    let restored = AddressBook::open(Some(base), [1; 4], false, None);
    assert_eq!(restored.len(), 1, "the fresh record is what persists");
    assert_eq!(restored.state.lock().stored.records[0].endpoint, addr(9));
    assert_indexes(&restored.state.lock());
}

#[test]
fn failed_preservation_never_replaces_the_source_and_can_be_retried() {
    for directory_obstruction in [false, true] {
        let dir = tempfile::tempdir().expect("directory");
        let base = dir.path().join("peers.dat");
        let path = network_path(&base, [1; 4]);
        let bytes = fixture_bytes(&divergent_v9_shape());
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
        let fresh = AddressBook::open(Some(base.clone()), [1; 4], false, None);
        assert!(fresh.state.lock().writable);
        fresh.save();
        assert_ne!(fs::read(&path).expect("fresh snapshot"), bytes);
        assert_eq!(fs::read(backup).expect("backup"), bytes);
    }
}

#[test]
fn corrupt_unknown_and_wrong_network_files_fail_closed() {
    let dir = tempfile::tempdir().expect("directory");
    let base = dir.path().join("peers.dat");
    let path = network_path(&base, [1; 4]);
    let current = serde_json::to_value(&book().state.lock().stored).expect("schema");
    let mut cases = vec![b"corrupt bytes".to_vec()];
    let mut bad_checksum = fixture_bytes(&current);
    bad_checksum[0] ^= 1;
    cases.push(bad_checksum);
    let mut wrong_network = current.clone();
    wrong_network["magic"] = serde_json::json!([2, 2, 2, 2]);
    cases.push(fixture_bytes(&wrong_network));
    let mut wrong_format = current.clone();
    wrong_format["format"] = "another-format".into();
    cases.push(fixture_bytes(&wrong_format));
    for marker in [serde_json::Value::Null, "".into()] {
        let mut malformed_marker = current.clone();
        malformed_marker["format"] = marker;
        cases.push(fixture_bytes(&malformed_marker));
    }
    let mut wrong_version = current.clone();
    wrong_version["version"] = 2.into();
    cases.push(fixture_bytes(&wrong_version));
    let mut orphan_anchor = current.clone();
    orphan_anchor["anchors"] = serde_json::json!([{"addr": "8.8.8.8:8333", "confirmed_at": EPOCH}]);
    cases.push(fixture_bytes(&orphan_anchor));
    let mut invalid_record = current;
    invalid_record["records"] = serde_json::json!([{"broken": true}]);
    cases.push(fixture_bytes(&invalid_record));
    cases.push(fixture_bytes(
        &serde_json::json!({"version": 99, "magic": [1, 1, 1, 1]}),
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
fn cross_network_pre_release_is_preserved_and_superseded() {
    // Identification runs before scope: an unmarked pre-release file from
    // another network is preserved and replaced, never misreported as a
    // network refusal that disables writes.
    for version in [1, 8, 9] {
        let dir = tempfile::tempdir().expect("directory");
        let base = dir.path().join("peers.dat");
        let path = network_path(&base, [1; 4]);
        let bytes = fixture_bytes(&serde_json::json!({"version": version, "magic": [2, 2, 2, 2]}));
        fs::write(&path, &bytes).expect("foreign pre-release snapshot");
        let fresh = AddressBook::open(Some(base.clone()), [1; 4], false, None);
        assert!(fresh.state.lock().writable, "version {version}");
        assert_eq!(fresh.len(), 0, "no historical records are imported");
        assert_eq!(fs::read(&path).expect("source before save"), bytes);
        let backup = rejected_backup(&path, &bytes);
        assert_eq!(fs::read(&backup).expect("durable preservation"), bytes);
        fresh.learn_dns("seed", &[target()], EPOCH);
        fresh.save();
        assert_eq!(fs::read(&backup).expect("preserved after save"), bytes);
        assert_ne!(fs::read(&path).expect("fresh publication"), bytes);
        let restored = AddressBook::open(Some(base), [1; 4], false, None);
        assert!(restored.state.lock().writable);
        assert_eq!(restored.len(), 1);
        assert_indexes(&restored.state.lock());
    }
}

#[test]
fn ipv6_and_overlay_source_round_trip_with_anchors() {
    let dir = tempfile::tempdir().expect("directory");
    let base = dir.path().join("peers.dat");
    let path = network_path(&base, [1; 4]);
    let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    let v6: PeerEndpoint = "[2002:808:808::1]:8333".parse_endpoint();
    let tor = tor_endpoint();
    let i2p = i2p_endpoint();
    book.learn_dns("seed", &[v6, target()], EPOCH);
    {
        let mut manager = book.state.lock();
        assert!(manager.learn(tor, Some(9), Source::Overlay(tor.host()), EPOCH, EPOCH, 0));
        assert!(manager.learn(i2p, Some(9), Source::Overlay(i2p.host()), EPOCH, EPOCH, 0));
    }
    book.succeeded(v6, 9, EPOCH + 1);
    book.succeeded(tor, 9, EPOCH + 1);
    book.succeeded(i2p, 9, EPOCH + 1);
    book.remember_anchors(&[tor, i2p], EPOCH + 1);
    book.save();
    let expected = serde_json::to_value(&book.state.lock().stored).expect("state");
    assert_eq!(expected["format"], "bitcoin-rs-addrman");
    assert_eq!(expected["version"], 1);
    let restored = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    assert!(restored.state.lock().writable);
    assert_eq!(
        serde_json::to_value(&restored.state.lock().stored).expect("round trip"),
        expected
    );
    let manager = restored.state.lock();
    for endpoint in [v6, target(), tor, i2p] {
        assert!(manager.by_addr.contains_key(&endpoint), "{endpoint}");
    }
    assert_eq!(manager.stored.anchors.len(), 2);
    assert_eq!(
        crate::endpoint::overlay_netgroup(tor.host()),
        Some(vec![4, 0x2f])
    );
    assert_indexes(&manager);
    drop(manager);
    let published = fs::read(&path).expect("published");
    let decoded: serde_json::Value =
        serde_json::from_slice(&published[..published.len() - 32]).expect("canonical JSON");
    assert_eq!(
        decoded,
        serde_json::to_value(&restored.state.lock().stored).expect("stored")
    );
    // Mutate, save, reopen, then a no-op save must not republish: a clean
    // loader leaves the file untouched and its bytes byte-identical.
    restored.attempted(target(), true, EPOCH + 100);
    restored.save();
    let mutated = fs::read(&path).expect("mutated publication");
    assert_ne!(mutated, published, "a dirty revision must republish");
    let reopened = AddressBook::open(Some(base), [1; 4], false, None);
    assert!(reopened.state.lock().writable);
    assert_eq!(reopened.len(), restored.len());
    assert_eq!(
        fs::read(&path).expect("unchanged after reopen"),
        mutated,
        "opening a canonical book must not rewrite it"
    );
    {
        let manager = reopened.state.lock();
        assert_eq!(
            manager.revision, manager.saved_revision,
            "a reopened canonical book has no pending publication"
        );
    }
    reopened.save();
    assert_eq!(
        fs::read(&path).expect("no-op save"),
        mutated,
        "a clean save leaves the canonical bytes untouched"
    );
    assert_indexes(&reopened.state.lock());
}
