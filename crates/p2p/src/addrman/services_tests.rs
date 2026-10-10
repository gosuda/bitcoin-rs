use super::*;

fn stored_value(path: &Path) -> serde_json::Value {
    let bytes = fs::read(path).expect("book bytes");
    serde_json::from_slice(&bytes[..bytes.len() - 32]).expect("book JSON")
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
    assert_eq!(stored_value(&path)["version"], 8);
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
    book.learn_peer(addr(2).ip(), &[(target(), 0, EPOCH)], EPOCH);
    assert_eq!(book.state.lock().stored.records[0].services, Some(0));
    assert_eq!(
        book.state.lock().revision,
        revision + 1,
        "metadata changes before same-time ref refusal"
    );
    book.learn_peer(addr(3).ip(), &[(target(), 1, EPOCH)], EPOCH);
    book.learn_peer(addr(4).ip(), &[(target(), 8, EPOCH)], EPOCH);
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
    book.learn_peer(addr(6).ip(), &[(ip_origin, 9, EPOCH)], EPOCH);
    book.succeeded(ip_origin, 9, EPOCH + 1);
    book.learn_dns("seed", &[ip_origin], EPOCH + 14_400);
    let manager = book.state.lock();
    let entry = &manager.stored.records[manager.by_addr[&ip_origin]];
    assert_eq!(entry.services, Some(9));
    assert_eq!(entry.source, Source::Ip(addr(6).ip()));
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

const V1_SERVICES: &[u8] = include_bytes!("../../tests/data/addrman-historical-v1-services.dat");
const V7_SERVICES: &[u8] = include_bytes!("../../tests/data/addrman-historical-v7-services.dat");
const V7_SERVICES_ASMAP: &[u8] =
    include_bytes!("../../tests/data/addrman-historical-v7-services-asmap.dat");
const SERVICE_MAP: &[u8] = include_bytes!("../../tests/data/asmap-linked-ipv4-core-v31.1.raw");

#[test]
fn every_historical_schema_requires_numeric_services_before_conversion() {
    let fixtures: [&[u8]; 7] = [
        V1_SERVICES,
        include_bytes!("../../tests/data/addrman-historical-v2.dat"),
        include_bytes!("../../tests/data/addrman-historical-v3.dat"),
        include_bytes!("../../tests/data/addrman-historical-v4-anchors.dat"),
        include_bytes!("../../tests/data/addrman-core-v5-eight-refs.dat"),
        include_bytes!("../../tests/data/addrman-core-v6-eight-refs.dat"),
        V7_SERVICES,
    ];
    for bytes in fixtures {
        let directory = tempfile::tempdir().expect("directory");
        let base = directory.path().join("peers.dat");
        let path = network_path(&base, [1; 4]);
        let old: serde_json::Value =
            serde_json::from_slice(&bytes[..bytes.len() - 32]).expect("genuine old writer");
        fs::write(&path, bytes).expect("old bytes");
        let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
        assert!(book.state.lock().writable, "schema {}", old["version"]);
        assert_eq!(
            book.len(),
            old["records"].as_array().expect("records").len()
        );
        let schema = old["version"].as_u64().expect("version");
        let backup = path.with_extension(format!(
            "v{schema}-{}.bak",
            Sha256::digest(bytes)[..].to_lower_hex_string()
        ));
        assert_eq!(fs::read(backup).expect("exact backup"), bytes);
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!("0"),
            serde_json::json!(false),
            serde_json::json!(-1),
            serde_json::json!(0.5),
        ] {
            let mut changed = old.clone();
            changed["records"][0]["services"] = invalid;
            assert_preserved_invalid(&base, &path, &fixture_bytes(&changed));
        }
        let mut missing = old.clone();
        missing["records"][0]
            .as_object_mut()
            .expect("record")
            .remove("services");
        assert_preserved_invalid(&base, &path, &fixture_bytes(&missing));
        let mut overflow = old.clone();
        overflow["records"][0]["services"] = serde_json::json!("OUT_OF_RANGE");
        let payload = serde_json::to_string(&overflow)
            .expect("JSON")
            .replace("\"OUT_OF_RANGE\"", "18446744073709551616");
        let mut overflow = payload.into_bytes();
        let checksum = Sha256::digest(&overflow);
        overflow.extend_from_slice(&checksum);
        assert_preserved_invalid(&base, &path, &overflow);
        let mut impossible = old.clone();
        impossible["records"][0]["tried"] = true.into();
        impossible["records"][0]["last_success"] = 0.into();
        if schema >= 5 {
            impossible["records"][0]["new_buckets"] = serde_json::json!([]);
        }
        assert_preserved_invalid(&base, &path, &fixture_bytes(&impossible));
    }
}

#[test]
fn actual_v7_writer_migrates_ambiguous_zero_honestly_and_preserves_all_membership() {
    for (bytes, configured) in [(V7_SERVICES, false), (V7_SERVICES_ASMAP, true)] {
        for scoped in [false, true] {
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let path = network_path(&base, [1; 4]);
            let source = if scoped { path.clone() } else { base.clone() };
            fs::write(&source, bytes).expect("actual v7 writer");
            let map = directory.path().join("map.raw");
            fs::write(&map, SERVICE_MAP).expect("map");
            let old: serde_json::Value =
                serde_json::from_slice(&bytes[..bytes.len() - 32]).expect("old JSON");
            let book = AddressBook::open(
                Some(base.clone()),
                [1; 4],
                false,
                configured.then_some(map.as_path()),
            );
            {
                let manager = book.state.lock();
                assert!(manager.writable);
                assert_eq!(manager.stored.records.len(), 7);
                let current = serde_json::to_value(&manager.stored).expect("current");
                for field in ["magic", "secret", "asmap_id", "anchors"] {
                    assert_eq!(current[field], old[field], "{field}");
                }
                for entry in old["records"].as_array().expect("records") {
                    let address: SocketAddr = entry["addr"]
                        .as_str()
                        .expect("address")
                        .parse()
                        .expect("endpoint");
                    let record = &manager.stored.records[manager.by_addr[&address]];
                    let ambiguous = matches!(
                        address.to_string().as_str(),
                        "8.8.8.8:8333" | "8.8.4.4:8333"
                    );
                    assert_eq!(
                        record.services,
                        if ambiguous {
                            None
                        } else {
                            Some(entry["services"].as_u64().expect("services"))
                        }
                    );
                    let value = serde_json::to_value(record).expect("record");
                    for field in [
                        "source",
                        "last_seen",
                        "last_success",
                        "failures",
                        "tried",
                        "new_buckets",
                    ] {
                        assert_eq!(value[field], entry[field], "{address} {field}");
                    }
                    assert_eq!(record.last_attempt, 0);
                    assert_eq!(record.last_count_attempt, 0);
                }
                assert_eq!(
                    manager
                        .stored
                        .records
                        .iter()
                        .map(|entry| entry.new_buckets.len())
                        .max(),
                    Some(8)
                );
                assert_indexes(&manager);
            }
            let backup = source.with_extension(format!(
                "v7-{}.bak",
                Sha256::digest(bytes)[..].to_lower_hex_string()
            ));
            assert_eq!(fs::read(&backup).expect("backup"), bytes);
            assert_eq!(fs::read(&source).expect("source before publish"), bytes);
            book.save();
            if !scoped {
                assert_eq!(fs::read(&source).expect("legacy source retained"), bytes);
            }
            let migrated = stored_value(&path);
            assert_eq!(migrated["version"], 8);
            let restored = AddressBook::open(
                Some(base),
                [1; 4],
                false,
                configured.then_some(map.as_path()),
            );
            assert_eq!(
                serde_json::to_value(&restored.state.lock().stored).expect("second reopen"),
                migrated
            );
            restored.set_services(target(), 0);
            restored.save();
            assert!(
                !restored.ordinary_services_eligible(target(), u64::MAX),
                "the next actual observation resolves historical ambiguity without Good"
            );
        }
    }
}

#[test]
fn v7_migration_failure_and_invalid_map_preserve_original_observation_bytes() {
    let directory = tempfile::tempdir().expect("directory");
    let base = directory.path().join("peers.dat");
    let path = network_path(&base, [1; 4]);
    let map = directory.path().join("map.raw");
    fs::write(&path, V7_SERVICES_ASMAP).expect("v7");
    fs::write(&map, b"invalid map").expect("invalid map");
    let readonly = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
    assert!(!readonly.state.lock().writable);
    readonly.set_services(target(), 0);
    readonly.save();
    assert_eq!(fs::read(&path).expect("preserved"), V7_SERVICES_ASMAP);
    assert_eq!(
        fs::read_dir(directory.path()).expect("directory").count(),
        2,
        "invalid map produces no backup or publication"
    );
    fs::write(&map, SERVICE_MAP).expect("restored map");
    let backup = path.with_extension(format!(
        "v7-{}.bak",
        Sha256::digest(V7_SERVICES_ASMAP)[..].to_lower_hex_string()
    ));
    fs::create_dir(&backup).expect("backup obstruction");
    let blocked = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
    assert!(!blocked.state.lock().writable);
    blocked.set_services(target(), 0);
    blocked.save();
    assert_eq!(fs::read(&path).expect("still preserved"), V7_SERVICES_ASMAP);
    fs::remove_dir(backup).expect("remove obstruction");
    let restored = AddressBook::open(Some(base), [1; 4], false, Some(&map));
    assert!(restored.state.lock().writable);
    assert_eq!(
        restored
            .state
            .lock()
            .stored
            .records
            .iter()
            .map(|entry| entry.new_buckets.len())
            .max(),
        Some(8)
    );
    restored.save();
    assert_eq!(stored_value(&path)["version"], 8);
}
