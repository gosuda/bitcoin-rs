use super::*;

fn rejected_backup(path: &Path, bytes: &[u8]) -> PathBuf {
    path.with_extension(format!(
        "pre-release-{}.bak",
        Sha256::digest(bytes)[..].to_lower_hex_string()
    ))
}

#[test]
fn pre_release_version_is_frozen_and_the_format_marker_is_required() {
    // #1688: edit the canonical v1 directly until the first official release.
    assert_eq!(SCHEMA_VERSION, 1);
    let value = serde_json::to_value(&book().state.lock().stored).expect("schema");
    assert_eq!(value["format"], "bitcoin-rs-addrman");
    assert_eq!(value["version"], 1);
    assert_eq!(value["magic"], serde_json::json!([1, 1, 1, 1]));
    assert_eq!(value["records"], serde_json::json!([]));
    assert_eq!(value["anchors"], serde_json::json!([]));
    assert!(value["asmap_id"].is_null());
}

#[test]
fn canonical_fixture_pins_endpoint_source_anchor_and_netgroup_semantics() {
    // Shared adoption fixture for #1684/#1687; no historical reader is needed.
    let payload = include_str!("persistence/canonical-v1.json");
    let expected: serde_json::Value = serde_json::from_str(payload).expect("canonical fixture");
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
        serde_json::to_value(&book.state.lock().stored).expect("state"),
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
    publish_book(&path, &book.state.lock().stored, &mut installed).expect("canonical write");
    let restored = AddressBook::open(Some(base), [1; 4], false, None);
    assert_eq!(
        serde_json::to_value(&restored.state.lock().stored).expect("round trip"),
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
            // Only the old envelope matters. In particular, the divergent v9
            // record/source/netgroup layouts never pass through a decoder.
            let bytes = fixture_bytes(&serde_json::json!({
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
            // A restart before the first fresh save must reuse the backup.
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
    let mut value = serde_json::to_value(&known.state.lock().stored).expect("schema");
    value.as_object_mut().expect("object").remove("format");
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
        let bytes = fixture_bytes(&serde_json::json!({"version": 9, "magic": [1, 1, 1, 1]}));
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
    orphan_anchor["anchors"] = serde_json::json!([
        {"addr": "8.8.8.8:8333", "confirmed_at": EPOCH}
    ]);
    cases.push(fixture_bytes(&orphan_anchor));
    let mut invalid_record = current;
    invalid_record["records"] = serde_json::json!([{"broken": true}]);
    cases.push(fixture_bytes(&invalid_record));
    cases.push(fixture_bytes(
        &serde_json::json!({"version": 8, "magic": [2, 2, 2, 2]}),
    ));
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
fn invalid_configured_map_preserves_current_and_pre_release_files_until_repaired() {
    for stale in [false, true] {
        let dir = tempfile::tempdir().expect("directory");
        let base = dir.path().join("peers.dat");
        let path = network_path(&base, [1; 4]);
        let map = dir.path().join("map.raw");
        let current = book();
        current.learn_dns("seed", &[target()], EPOCH);
        let mut value = serde_json::to_value(&current.state.lock().stored).expect("schema");
        if stale {
            value.as_object_mut().expect("object").remove("format");
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
