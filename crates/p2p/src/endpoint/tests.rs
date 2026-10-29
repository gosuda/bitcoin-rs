use super::*;
use bitcoin_rs_primitives::endpoint::tor_v3_payload;
use std::net::{IpAddr, Ipv4Addr};

fn tor_endpoint() -> PeerEndpoint {
    PeerEndpoint::TorV3 {
        key: [3u8; 32],
        port: 8333,
    }
}

#[test]
fn parse_format_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    for endpoint in [
        PeerEndpoint::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333)),
        PeerEndpoint::Ip("[::1]:8333".parse::<SocketAddr>()?),
        tor_endpoint(),
        PeerEndpoint::I2p {
            hash: [5u8; 32],
            port: 7656,
        },
    ] {
        let text = format_endpoint(endpoint);
        assert_eq!(parse_endpoint(&text), Some(endpoint), "{text}");
    }
    Ok(())
}

#[test]
fn parse_rejects_bad_tor_checksum_and_payload() {
    let mut payload = tor_v3_payload(&[3u8; 32]);
    payload[32] ^= 1;
    let bad = format!(
        "{}.onion:8333",
        bitcoin_rs_primitives::endpoint::base32_encode(&payload)
    );
    assert_eq!(parse_endpoint(&bad), None);
    assert_eq!(parse_endpoint("abc.onion:8333"), None);
    let good = format_endpoint(tor_endpoint());
    assert_eq!(parse_endpoint(&good.replace("8333", "0")), None);
    assert_eq!(parse_endpoint(&good.to_uppercase()), None);
    assert_eq!(
        parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(51))),
        None
    );
    assert_eq!(
        parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(53))),
        None
    );
    assert_eq!(
        parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(52))),
        Some(PeerEndpoint::I2p {
            hash: [0u8; 32],
            port: 8333
        })
    );
}

#[test]
fn classification_matrix_valid_cases() {
    let good_tor = format_endpoint(tor_endpoint());
    let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

    assert!(matches!(
        classify_endpoint(&good_tor),
        ClassifiedEndpoint::Valid(PeerEndpoint::TorV3 { port: 8333, .. })
    ));
    assert_eq!(
        classify_endpoint(&good_i2p),
        ClassifiedEndpoint::Valid(PeerEndpoint::I2p {
            hash: [0u8; 32],
            port: 8333
        })
    );
    assert_eq!(
        classify_endpoint("127.0.0.1:8333"),
        ClassifiedEndpoint::Valid(PeerEndpoint::Ip(SocketAddr::from(([127, 0, 0, 1], 8333))))
    );
}

#[test]
fn classification_matrix_invalid_overlay_cases() {
    let good_tor = format_endpoint(tor_endpoint());
    let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

    let mut bad_payload = tor_v3_payload(&[3u8; 32]);
    bad_payload[32] ^= 1;
    let bad_checksum_onion = format!(
        "{}.onion:8333",
        bitcoin_rs_primitives::endpoint::base32_encode(&bad_payload)
    );

    let wrong_len_i2p_51 = format!("{}.b32.i2p:8333", "a".repeat(51));
    let wrong_len_i2p_53 = format!("{}.b32.i2p:8333", "a".repeat(53));
    let missing_port_onion = format!(
        "{}.onion",
        bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
    );
    let missing_port_i2p = format!("{}.b32.i2p", "a".repeat(52));
    let malformed_port_onion = format!(
        "{}.onion:notaport",
        bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
    );
    let zero_port_onion = good_tor.replace("8333", "0");
    let overflow_port_onion = format!(
        "{}.onion:99999",
        bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
    );

    let uppercase_onion = good_tor.to_uppercase();
    let mixedcase_onion = format!(
        "{}.ONION:8333",
        bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
    );
    let uppercase_i2p = good_i2p.to_uppercase();
    let mixedcase_i2p = format!("{}.B32.I2P:8333", "a".repeat(52));
    let trailing_dot_onion = format!(
        "{}.onion.:8333",
        bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
    );
    let trailing_dot_no_port = format!(
        "{}.onion.",
        bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
    );
    let trailing_dot_i2p = format!("{}.b32.i2p.:8333", "a".repeat(52));
    let trailing_dot_i2p_no_port = format!("{}.b32.i2p.", "a".repeat(52));

    let invalid_targets = [
        bad_checksum_onion.as_str(),
        "abc.onion:8333",
        wrong_len_i2p_51.as_str(),
        wrong_len_i2p_53.as_str(),
        missing_port_onion.as_str(),
        missing_port_i2p.as_str(),
        malformed_port_onion.as_str(),
        zero_port_onion.as_str(),
        overflow_port_onion.as_str(),
        uppercase_onion.as_str(),
        mixedcase_onion.as_str(),
        uppercase_i2p.as_str(),
        mixedcase_i2p.as_str(),
        trailing_dot_onion.as_str(),
        trailing_dot_no_port.as_str(),
        trailing_dot_i2p.as_str(),
        trailing_dot_i2p_no_port.as_str(),
        "foo.i2p:8333",
        "foo.i2p",
        "FOO.I2P:8333",
        "foo.i2p.:8333",
        "foo.i2p.",
        "b32.i2p:8333",
        "b32.i2p",
        "B32.I2P:8333",
        "b32.i2p.:8333",
        "onion.:8333",
        "onion.",
        "ONION.:8333",
        "i2p.:8333",
        "i2p.",
        "I2P.:8333",
    ];

    for rejected in invalid_targets {
        assert_eq!(
            classify_endpoint(rejected),
            ClassifiedEndpoint::InvalidOverlay,
            "invalid overlay target must classify as InvalidOverlay: {rejected}"
        );
        assert_eq!(parse_endpoint(rejected), None);
    }
}

#[test]
fn classification_matrix_ordinary_hostnames() {
    for ordinary in [
        "seed.bitcoin.sipa.be:8333",
        "node.example.com:8333",
        "onion.com:8333",
        "fakeb32.i2p.org:8333",
        "onion:8333",
        "onion",
        "i2p:8333",
        "i2p",
    ] {
        assert_eq!(
            classify_endpoint(ordinary),
            ClassifiedEndpoint::NonOverlay,
            "ordinary hostname must classify as NonOverlay: {ordinary}"
        );
        assert_eq!(parse_endpoint(ordinary), None);
    }
}

#[test]
fn i2p_port_zero_is_valid_but_tor_and_ip_are_not() {
    let i2p_zero = format!("{}.b32.i2p:0", "a".repeat(52));
    assert_eq!(
        classify_endpoint(&i2p_zero),
        ClassifiedEndpoint::Valid(PeerEndpoint::I2p {
            hash: [0u8; 32],
            port: 0
        })
    );
    assert_eq!(
        parse_endpoint(&i2p_zero),
        Some(PeerEndpoint::I2p {
            hash: [0u8; 32],
            port: 0
        })
    );

    let tor_zero = format_endpoint(tor_endpoint()).replace("8333", "0");
    assert_eq!(
        classify_endpoint(&tor_zero),
        ClassifiedEndpoint::InvalidOverlay
    );
    assert_eq!(parse_endpoint(&tor_zero), None);
    assert_eq!(parse_endpoint("127.0.0.1:0"), None);
}

#[test]
fn addrv2_accepts_i2p_port_zero_only() {
    let i2p_zero = AddrV2Message {
        time: 1,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::I2p([7u8; 32]),
        port: 0,
    };
    assert_eq!(
        endpoint_from_addrv2(&i2p_zero),
        Some(PeerEndpoint::I2p {
            hash: [7u8; 32],
            port: 0
        })
    );
    for addr in [AddrV2::Ipv4(Ipv4Addr::LOCALHOST), AddrV2::TorV3([3u8; 32])] {
        assert_eq!(
            endpoint_from_addrv2(&AddrV2Message {
                time: 1,
                services: ServiceFlags::NETWORK,
                addr,
                port: 0,
            }),
            None
        );
    }
}

#[test]
fn addrv2_round_trip_and_rejections() {
    for endpoint in [
        PeerEndpoint::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333)),
        tor_endpoint(),
        PeerEndpoint::I2p {
            hash: [5u8; 32],
            port: 7656,
        },
    ] {
        let row = endpoint_to_addrv2(endpoint, 1, ServiceFlags::NETWORK);
        assert_eq!(endpoint_from_addrv2(&row), Some(endpoint));
    }
    let torv2 = AddrV2Message {
        time: 1,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::TorV2([0u8; 10]),
        port: 8333,
    };
    assert_eq!(endpoint_from_addrv2(&torv2), None);
    let unknown = AddrV2Message {
        time: 1,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Unknown(99, vec![1, 2, 3]),
        port: 8333,
    };
    assert_eq!(endpoint_from_addrv2(&unknown), None);
}

#[test]
fn overlay_dial_is_unavailable_without_fallback() {
    for endpoint in [
        tor_endpoint(),
        PeerEndpoint::I2p {
            hash: [1u8; 32],
            port: 8333,
        },
    ] {
        let Err(error) =
            connect_peer_stream(endpoint, &DialRoutes::default(), Duration::from_millis(10))
        else {
            panic!("overlay must not dial");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(!error.counts_as_peer_failure());
    }
}

#[test]
fn dead_onion_proxy_is_transport_not_peer_failure() -> Result<(), Box<dyn std::error::Error>> {
    let routes = DialRoutes {
        onion: Some("127.0.0.1:1".parse()?),
        ..DialRoutes::default()
    };
    let Err(error) = connect_peer_stream(tor_endpoint(), &routes, Duration::from_secs(2)) else {
        panic!("dead proxy must fail the dial");
    };
    assert!(matches!(error, DialFailure::Transport(_)));
    assert!(!error.counts_as_peer_failure());
    Ok(())
}

#[test]
fn onlynet_refusal_is_transport_not_peer_failure() {
    let routes = DialRoutes {
        onlynet: vec![NetworkLabel::Ipv4],
        ..DialRoutes::default()
    };
    let Err(error) = connect_peer_stream(tor_endpoint(), &routes, Duration::from_millis(10)) else {
        panic!("onlynet must refuse the dial");
    };
    assert!(matches!(error, DialFailure::Transport(_)));
    assert!(!error.counts_as_peer_failure());
}

#[test]
fn route_table_denial_prefilters_unroutable_endpoints() {
    let ip = PeerEndpoint::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333));
    let i2p = PeerEndpoint::I2p {
        hash: [7u8; 32],
        port: 8333,
    };
    let open = RouteTable::default();
    assert_eq!(open.denial(&ip), None);
    assert_eq!(
        open.denial(&tor_endpoint()),
        Some(RouteDenial::NoOnionRoute)
    );
    assert_eq!(open.denial(&i2p), Some(RouteDenial::NoI2pRoute));
    let onion_only = RouteTable {
        onlynet: vec![NetworkLabel::Onion],
        ..RouteTable::default()
    };
    assert_eq!(onion_only.denial(&ip), Some(RouteDenial::NotInOnlynet));
}

#[test]
fn direct_tcp_classifies_only_refusal_as_peer_unreachable() -> Result<(), Box<dyn std::error::Error>>
{
    let unused_port: SocketAddr = "127.0.0.1:1".parse()?;
    let Err(error) = connect_peer_stream(
        PeerEndpoint::Ip(unused_port),
        &DialRoutes::default(),
        Duration::from_millis(200),
    ) else {
        panic!("refused dial must fail");
    };
    match &error {
        DialFailure::PeerUnreachable(io_err) => {
            assert_eq!(io_err.kind(), io::ErrorKind::ConnectionRefused);
            assert!(
                error.counts_as_peer_failure(),
                "ConnectionRefused must count as peer failure"
            );
        }
        DialFailure::Transport(_) => {
            assert_ne!(error.kind(), io::ErrorKind::ConnectionRefused);
            assert!(
                !error.counts_as_peer_failure(),
                "Non-refusal must not count as peer failure"
            );
        }
    }

    let blackhole: SocketAddr = "192.0.2.1:8333".parse()?;
    let Err(error) = connect_peer_stream(
        PeerEndpoint::Ip(blackhole),
        &DialRoutes::default(),
        Duration::from_millis(1),
    ) else {
        panic!("timed out dial must fail");
    };
    match &error {
        DialFailure::Transport(_) => {
            assert_ne!(error.kind(), io::ErrorKind::ConnectionRefused);
            assert!(
                !error.counts_as_peer_failure(),
                "Timeout or network error must remain Transport failure"
            );
        }
        DialFailure::PeerUnreachable(io_err) => {
            assert_eq!(io_err.kind(), io::ErrorKind::ConnectionRefused);
            assert!(
                error.counts_as_peer_failure(),
                "ConnectionRefused must count as peer failure"
            );
        }
    }
    Ok(())
}

#[test]
fn overlay_netgroup_vectors() {
    assert_eq!(
        overlay_netgroup(EndpointHost::TorV3 { key: [0x21u8; 32] }),
        Some(vec![4, 0x2f])
    );
    assert_eq!(
        overlay_netgroup(EndpointHost::I2p { hash: [0x30u8; 32] }),
        Some(vec![5, 0x3f])
    );
    assert_eq!(
        overlay_netgroup(EndpointHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))),
        None
    );
}
