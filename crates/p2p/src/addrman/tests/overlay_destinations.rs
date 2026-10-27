use super::*;

#[test]
fn ip_source_disguised_as_overlay_is_rejected_without_rewriting_the_book() {
    let directory = tempfile::tempdir().expect("directory");
    let base = directory.path().join("peers.dat");
    let path = network_path(&base, [1; 4]);
    let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    book.learn_peer(addr(2).address(), &[(addr(1), 9, EPOCH)], EPOCH);
    book.save();
    let original = fs::read(&path).expect("valid book");
    let mut value = serde_json::to_value(&book.state.lock().stored).expect("state");
    // This alias has the same source group as the valid IP source, so only
    // the source representation invariant rejects the otherwise valid file.
    value["records"][0]["source"] = serde_json::json!({"overlay": addr(2).address().to_string()});
    let mut bytes = serde_json::to_vec(&value).expect("invalid source payload");
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    fs::write(&path, &bytes).expect("write alias");
    let rejected = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    assert!(!rejected.state.lock().writable);
    rejected.save();
    assert_eq!(fs::read(&path).expect("preserved bytes"), bytes);
    fs::write(&path, original).expect("restore valid book");
    let restored = AddressBook::open(Some(base), [1; 4], false, None);
    assert!(restored.state.lock().writable);
    assert_eq!(restored.len(), 1);
}

#[test]
fn overlay_self_announcements_keep_the_advertised_time() {
    for address in [
        crate::PeerAddress::Onion([3; 32]),
        crate::PeerAddress::I2p([4; 32]),
    ] {
        let book = AddressBook::open(None, [1; 4], false, None);
        let own = PeerEndpoint::new(address, 8333);
        let other = PeerEndpoint::new(crate::PeerAddress::Onion([5; 32]), 8333);
        book.learn_peer(address, &[(own, 9, EPOCH), (other, 9, EPOCH)], EPOCH);
        let state = book.state.lock();
        let seen = |endpoint| {
            state
                .stored
                .records
                .iter()
                .find(|entry| entry.addr == endpoint)
                .expect("learned endpoint")
                .last_seen
        };
        assert_eq!(seen(own), EPOCH);
        assert_eq!(seen(other), EPOCH - 2 * 60 * 60);
    }
}

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
}
