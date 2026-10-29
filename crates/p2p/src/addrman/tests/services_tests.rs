use super::*;

fn stored_value(path: &Path) -> serde_json::Value {
    let bytes = fs::read(path).expect("book bytes");
    serde_json::from_slice(&bytes[..bytes.len() - 32]).expect("book JSON")
}

#[test]
fn v8_book_migrates_to_v9_with_backup_and_byte_identical_ip_records() {
    use bitcoin::hex::DisplayHex as _;
    let directory = tempfile::tempdir().expect("directory");
    let base = directory.path().join("peers.dat");
    let path = network_path(&base, [1; 4]);
    // Save a current (v9) book, then rewrite only the version field to
    // fabricate the exact v8 payload its predecessor would have written:
    // IP record strings are identical in both schemas.
    let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    book.learn_dns("seed", &[target()], EPOCH);
    book.learn_peer(
        crate::PeerRemote::Endpoint(addr(2)),
        &[(addr(1), 9, EPOCH)],
        EPOCH,
    );
    book.save();
    let v9_payload = fs::read(&path).expect("saved book");
    let mut value: serde_json::Value =
        serde_json::from_slice(&v9_payload[..v9_payload.len() - 32]).expect("saved JSON");
    value["version"] = serde_json::json!(8);
    let mut v8_bytes = serde_json::to_vec(&value).expect("v8 payload");
    let checksum = Sha256::digest(&v8_bytes);
    v8_bytes.extend_from_slice(&checksum);
    fs::write(&path, &v8_bytes).expect("write v8 book");
    let records_before = value["records"].clone();

    let migrated = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    assert!(migrated.state.lock().writable);
    // The backup-before-migration file holds the exact v8 bytes.
    let backup = path.with_extension(format!(
        "v8-{}.bak",
        Sha256::digest(&v8_bytes)[..].to_lower_hex_string()
    ));
    assert_eq!(fs::read(&backup).expect("migration backup"), v8_bytes);
    assert_eq!(fs::read(&path).expect("source before publish"), v8_bytes);
    migrated.save();
    let migrated_value = stored_value(&path);
    assert_eq!(migrated_value["version"], 9);
    assert_eq!(
        migrated_value["records"], records_before,
        "IP records must be byte-identical across v8->v9 migration"
    );
    // A Tor record persists under its canonical endpoint string in v9.
    let tor = crate::PeerEndpoint::TorV3 {
        key: [7u8; 32],
        port: 8333,
    };
    migrated.learn_peer(
        crate::PeerRemote::Endpoint(addr(2)),
        &[(tor, 9, EPOCH)],
        EPOCH,
    );
    migrated.save();
    let with_tor = stored_value(&path);
    assert!(
        with_tor["records"]
            .as_array()
            .expect("records")
            .iter()
            .any(|record| record["addr"]
                .as_str()
                .is_some_and(|addr| addr.ends_with(".onion:8333"))),
        "tor endpoint must persist as canonical onion string: {with_tor}"
    );
    let reopened = AddressBook::open(Some(base), [1; 4], false, None);
    assert!(
        reopened
            .state
            .lock()
            .stored
            .records
            .iter()
            .any(|record| record.endpoint == tor)
    );
}

#[test]
fn unknown_dns_zero_version_is_durable_metadata_without_good() {
    let directory = tempfile::tempdir().expect("directory");
    let base = directory.path().join("peers.dat");
    let path = network_path(&base, [1; 4]);
    let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    book.learn_dns("seed", &[target()], EPOCH);
    book.attempted(target(), true, EPOCH + 1);
    book.save();
    assert_eq!(
        stored_value(&path)["records"][0]["services"],
        serde_json::Value::Null
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
        let payload = serde_json::to_string(&original)
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
        let payload = serde_json::to_string(&original)
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
                    .remove("services");
            }
            1 => invalid["records"][0]["source"] = serde_json::json!({"ip":"1.1.1.1"}),
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
        serde_json::Value::Null
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
