use super::*;

#[test]
fn overlay_destinations_have_canonical_checked_encodings() {
    let onion = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion:8333";
    let endpoint = onion.parse::<PeerEndpoint>().expect("Tor v3 vector");
    assert_eq!(endpoint.address(), PeerAddress::Onion([0; 32]));
    assert_eq!(endpoint.to_string(), onion);
    assert_eq!(
        onion
            .to_ascii_uppercase()
            .parse::<PeerEndpoint>()
            .expect("case"),
        endpoint
    );
    assert!(endpoint.socket_addr().is_none());
    assert!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion:8333"
            .parse::<PeerEndpoint>()
            .is_err()
    );
    assert!(
        "expyuzz4wqqyqhjn.onion:8333"
            .parse::<PeerEndpoint>()
            .is_err()
    );
    let i2p = PeerEndpoint::new(PeerAddress::I2p([255; 32]), 18444);
    assert_eq!(i2p.to_string().parse::<PeerEndpoint>().expect("I2P"), i2p);
    assert!(i2p.socket_addr().is_none());
    let json = sonic_rs::to_string(&i2p).expect("encoding");
    assert_eq!(
        sonic_rs::from_str::<PeerEndpoint>(&json).expect("decoding"),
        i2p
    );
}

#[test]
fn ip_sockets_keep_scope_and_anonymous_circuits_are_not_durable_destinations() {
    let socket = SocketAddr::V6(std::net::SocketAddrV6::new(
        "fe80::1".parse().expect("IP"),
        18444,
        123,
        7,
    ));
    let endpoint = PeerEndpoint::from(socket);
    assert_eq!(endpoint.socket_addr(), Some(socket));
    assert_eq!(endpoint.to_canonical(), endpoint);
    assert!("tor-inbound-7:0".parse::<PeerEndpoint>().is_err());
    assert!("tor-inbound-7".parse::<PeerAddress>().is_err());
    assert!(sonic_rs::from_str::<PeerEndpoint>("\"tor-inbound-7:0\"").is_err());
}
