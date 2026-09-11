use super::*;

#[test]
fn invalid_nbits_headers_disconnect_source_and_rotate_getheaders()
-> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    } = header_sync_with_genesis()?;
    let invalid_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let other_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let (invalid_tx, invalid_rx) = unbounded::<Message>();
    let (other_tx, other_rx) = unbounded::<Message>();

    // Seed only the invalid peer so the first tick routes a GetHeaders to
    // it and arms the pending gate against its address.
    let invalid_lease = bitcoin_rs_p2p::PeerLease::new(invalid_tx);
    peers.register(invalid_peer, invalid_lease.clone());
    peers.publish_info(
        invalid_peer,
        &invalid_lease,
        synthetic_peer(invalid_peer, 9),
    );

    sync.tick();
    assert!(
        matches!(invalid_rx.try_recv()?, Message::GetHeaders(_)),
        "the first getheaders must target the invalid peer"
    );
    assert!(
        sync.pending_getheaders
            .lock()
            .is_some_and(|request| request.peer_addr == invalid_peer),
        "a pending getheaders must name the invalid peer before its batch arrives"
    );

    // Deliver the attributed invalid batch while the gate is still armed
    // against the invalid peer. No other selectable peer remains, so this
    // tick cannot re-arm the gate against a different address: the only way
    // `pending_getheaders` ends up clear is the peer-fault cleanup.
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![nbits_mismatch_header(genesis.compute_hash(), 1)],
        source: Some(current_source(&peers, invalid_peer)),
    })?;
    sync.tick();

    assert!(
        sync.pending_getheaders.lock().is_none(),
        "an attributed invalid-header fault must release the pending getheaders gate"
    );
    assert!(
        !peers.is_connected(invalid_peer),
        "invalid header source must be removed from peer selection"
    );
    assert!(
        !peers.is_connected(invalid_peer),
        "invalid header source must lose its outbound lease"
    );

    // Re-introduce a healthy peer; the next getheaders must rotate to it.
    let other_lease = bitcoin_rs_p2p::PeerLease::new(other_tx);
    peers.register(other_peer, other_lease.clone());
    peers.publish_info(other_peer, &other_lease, synthetic_peer(other_peer, 8));
    sync.tick();
    assert!(
        peers.is_connected(other_peer),
        "healthy peer must remain eligible for rotation"
    );
    assert!(
        peers.is_connected(other_peer),
        "healthy peer must retain its outbound lease"
    );
    assert!(
        invalid_rx.try_recv().is_err(),
        "the invalid peer must not receive another getheaders"
    );
    assert!(
        matches!(other_rx.try_recv()?, Message::GetHeaders(_)),
        "the next getheaders must rotate to the remaining peer"
    );
    Ok(())
}
