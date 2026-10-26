use super::*;

#[test]
fn overlay_endpoints_sources_and_anchors_survive_restart_and_addrv2_gossip() {
    let directory = tempfile::tempdir().expect("directory");
    let base = directory.path().join("peers.dat");
    let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    let onion = PeerEndpoint::new(crate::PeerAddress::Onion([1; 32]), 8333);
    let i2p = PeerEndpoint::new(crate::PeerAddress::I2p([2; 32]), 8333);
    book.learn_peer(
        onion.address(),
        &[(onion, 9, EPOCH), (i2p, 9, EPOCH)],
        EPOCH,
    );
    book.succeeded(onion, 9, EPOCH + 1);
    book.succeeded(i2p, 9, EPOCH + 1);
    book.remember_anchors(&[onion, i2p], EPOCH + 2);
    let before = serde_json::to_value(&book.state.lock().stored).expect("state");
    let rows = book.gossip(EPOCH + 3);
    assert!(rows.iter().any(
        |row| matches!(row.addr, bitcoin::p2p::address::AddrV2::TorV3(key) if key == [1; 32])
    ));
    assert!(
        rows.iter().any(
            |row| matches!(row.addr, bitcoin::p2p::address::AddrV2::I2p(key) if key == [2; 32])
        )
    );
    book.save();
    let restored = AddressBook::open(Some(base), [1; 4], false, None);
    assert_eq!(
        serde_json::to_value(&restored.state.lock().stored).expect("restored"),
        before
    );
    assert_ne!(
        restored.netgroup(onion.address()),
        restored.netgroup(i2p.address())
    );
    assert_eq!(
        restored.select(&[onion], &[], EPOCH + 10, u64::MAX, |_| true),
        Some(i2p)
    );
    let count = restored.len();
    restored.learn_peer(
        crate::PeerAddress::AnonymousTor(7),
        &[(addr(99), 9, EPOCH)],
        EPOCH,
    );
    assert_eq!(
        restored.len(),
        count,
        "anonymous circuits are not durable learning sources"
    );
}

#[test]
fn original_v8_writer_migrates_with_exact_backup_and_no_ip_membership_changes() {
    let bytes = include_bytes!("../../../tests/data/addrman-historical-v8-endpoints.dat");
    let directory = tempfile::tempdir().expect("directory");
    let base = directory.path().join("peers.dat");
    let path = network_path(&base, [1; 4]);
    fs::write(&path, bytes).expect("original writer bytes");
    let original: serde_json::Value =
        serde_json::from_slice(&bytes[..bytes.len() - 32]).expect("v8 JSON");
    assert_eq!(original["version"], 8);
    let mut expected = original;
    expected["version"] = VERSION.into();
    let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    assert!(book.state.lock().writable);
    assert_eq!(
        serde_json::to_value(&book.state.lock().stored).expect("migrated"),
        expected
    );
    assert_eq!(fs::read(&path).expect("source before save"), bytes);
    let backup = path.with_extension(format!(
        "v8-{}.bak",
        Sha256::digest(bytes)[..].to_lower_hex_string()
    ));
    assert_eq!(fs::read(&backup).expect("backup before publication"), bytes);
    book.save();
    let restored = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    assert_eq!(
        serde_json::to_value(&restored.state.lock().stored).expect("reopened"),
        expected
    );
    // A conflicting backup must preserve the old file and make writes unavailable.
    fs::write(&path, bytes).expect("restore v8 fixture");
    fs::write(&backup, b"damaged backup").expect("conflict");
    let blocked = AddressBook::open(Some(base), [1; 4], false, None);
    assert!(!blocked.state.lock().writable);
    blocked.save();
    assert_eq!(fs::read(path).expect("preserved v8 source"), bytes);
}
