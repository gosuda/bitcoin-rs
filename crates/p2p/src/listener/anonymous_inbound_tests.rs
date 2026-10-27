use super::*;

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let client = TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
    (client, listener.accept().expect("accept").0)
}

#[test]
fn anonymous_admission_uses_capacity_without_learning_or_loopback_privilege() {
    let table = Arc::new(crate::PeerTable::new());
    let mut shared = test_shared(
        Arc::clone(&table),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    );
    shared.overlay = Arc::new(crate::overlay::OverlayTransport::new(Arc::new(
        crate::OverlayConfig {
            onion_proxy: Some("127.0.0.1:9050".parse().expect("proxy")),
            ..crate::OverlayConfig::default()
        },
    )));
    shared.max_inbound = 2;
    let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), false, None);
    shared.address_book = Some(Arc::clone(&book));
    let (first_client, first) = pair();
    let (second_client, second) = pair();
    let (third_client, third) = pair();
    admit_anonymous_tor(first, &shared);
    admit_anonymous_tor(second, &shared);
    let sessions = table.sessions();
    assert_eq!(sessions.len(), 2);
    assert_ne!(sessions[0].addr, sessions[1].addr);
    for session in &sessions {
        assert_eq!(session.addr.endpoint(), None);
        assert_eq!(session.addr.network(), crate::PeerNetwork::Onion);
        assert!(!session.lease.is_no_ban());
        assert_eq!(
            session
                .addr
                .to_string()
                .parse::<crate::PeerRemote>()
                .expect("RPC handle"),
            session.addr
        );
    }
    // All two slots are protected by the existing eviction policy at this size.
    admit_anonymous_tor(third, &shared);
    assert_eq!(table.live_inbound_count(), 2);
    let first = &sessions[0];
    let mut allowance = 32;
    let mut refill = crate::addrman::now();
    learn_addresses(
        &shared,
        &first.lease,
        first.addr,
        &[("8.8.8.8:8333".parse().expect("destination"), 9, refill)],
        &mut allowance,
        &mut refill,
    );
    assert_eq!(book.len(), 0);
    shared.note_misbehavior(
        first.addr,
        &first.lease,
        &crate::PeerError::Protocol("invalid peer message"),
    );
    assert!(
        !shared
            .banned
            .is_discouraged(std::net::IpAddr::from([127, 0, 0, 1]))
    );
    table.cancel_all();
    drop((first_client, second_client, third_client));
    let deadline = Instant::now() + Duration::from_secs(3);
    while !table.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(table.len(), 0);
}
