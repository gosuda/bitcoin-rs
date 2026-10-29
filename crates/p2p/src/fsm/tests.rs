use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::message_network::VersionMessage;

use super::*;
use crate::feature::FeatureId;
use crate::packages::{PKG_RELAY_ANC, PKG_RELAY_PKGTXNS};

fn fresh_peer() -> Peer<Cursor<Vec<u8>>> {
    Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN)
}

fn peer_awaiting_verack(version: u32) -> Result<Peer<Cursor<Vec<u8>>>, PeerError> {
    let mut peer = fresh_peer();
    step(
        &mut peer,
        &Message::Version(VersionMessage {
            version,
            ..version_message()
        }),
    )?;
    Ok(peer)
}

fn feature_message(id: &[u8], data: &[u8]) -> Message {
    Message::Feature(FeatureAnnouncement::new(
        FeatureId::from_raw_unchecked(id.to_vec()),
        data.to_vec(),
    ))
}

fn version_message() -> VersionMessage {
    let socket = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let address = Address::new(&socket, ServiceFlags::NETWORK);
    VersionMessage {
        version: 70_016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: address.clone(),
        sender: address,
        nonce: 1,
        user_agent: "/test:0.1/".to_owned(),
        start_height: 0,
        relay: true,
    }
}

const fn sendcmpct_message(send_compact: bool, version: u64) -> Message {
    Message::SendCmpct(SendCmpct {
        send_compact,
        version,
    })
}

#[test]
fn valid_handshake_reaches_a_usable_peer() -> Result<(), PeerError> {
    let mut peer = fresh_peer();

    assert!(step(&mut peer, &Message::Ping(1)).is_err());

    step(&mut peer, &Message::Version(version_message()))?;
    assert!(step(&mut peer, &Message::Ping(1)).is_err());

    step(&mut peer, &Message::Verack)?;

    step(&mut peer, &Message::Ping(1))?;
    Ok(())
}

#[test]
fn duplicate_version_after_handshake_is_rejected() -> Result<(), PeerError> {
    let mut peer = fresh_peer();
    step(&mut peer, &Message::Version(version_message()))?;
    step(&mut peer, &Message::Verack)?;

    assert!(step(&mut peer, &Message::Version(version_message())).is_err());
    Ok(())
}

#[test]
fn verack_before_version_is_rejected() {
    let mut peer = fresh_peer();
    assert!(step(&mut peer, &Message::Verack).is_err());
}

#[test]
fn feature_negotiation_is_rejected_before_handshake() {
    let mut peer = fresh_peer();
    assert!(step(&mut peer, &sendcmpct_message(true, 2)).is_err());
}

#[test]
fn feature_before_version_is_rejected() {
    let mut peer = fresh_peer();
    assert!(matches!(
        step(&mut peer, &feature_message(b"BIP332", &[1])),
        Err(PeerError::Misbehavior(_))
    ));
    assert!(peer.remote_features.is_empty());
}

#[test]
fn feature_from_a_peer_below_the_feature_version_is_rejected() -> Result<(), PeerError> {
    let mut peer = peer_awaiting_verack(FEATURE_VERSION - 1)?;
    assert!(matches!(
        step(&mut peer, &feature_message(b"BIP332", &[1])),
        Err(PeerError::Misbehavior(_))
    ));
    assert_eq!(peer.remote_feature(b"BIP332"), None);
    Ok(())
}

#[test]
fn feature_after_verack_is_rejected() -> Result<(), PeerError> {
    let mut peer = peer_awaiting_verack(FEATURE_VERSION)?;
    step(&mut peer, &Message::Verack)?;
    assert_eq!(peer.state, PeerState::Ready);
    assert!(matches!(
        step(&mut peer, &feature_message(b"BIP332", &[1])),
        Err(PeerError::Misbehavior(_))
    ));
    assert_eq!(peer.remote_feature(b"BIP332"), None);
    Ok(())
}

#[test]
fn feature_is_accepted_while_the_inbound_handshake_holds_version_exchange() -> Result<(), PeerError>
{
    let mut peer = peer_awaiting_verack(FEATURE_VERSION)?;
    peer.state = PeerState::VersionExchange;
    step(&mut peer, &feature_message(b"BIP332", &[0]))?;
    assert_eq!(peer.remote_feature(b"BIP332"), Some([0].as_slice()));

    step(&mut peer, &Message::Verack)?;
    assert!(matches!(
        step(&mut peer, &feature_message(b"BIP332", &[1])),
        Err(PeerError::Misbehavior(_))
    ));
    assert_eq!(peer.remote_feature(b"BIP332"), Some([0].as_slice()));
    Ok(())
}

#[test]
fn feature_between_version_and_verack_is_retained_and_handshake_completes() -> Result<(), PeerError>
{
    let mut peer = peer_awaiting_verack(FEATURE_VERSION)?;
    step(&mut peer, &feature_message(b"BIP332", &[1]))?;
    assert_eq!(peer.state, PeerState::Verack);

    step(&mut peer, &Message::Verack)?;
    assert_eq!(peer.state, PeerState::Ready);
    assert_eq!(peer.remote_feature(b"BIP332"), Some([1].as_slice()));
    Ok(())
}

#[test]
fn unknown_well_formed_features_are_ignored_without_retention() -> Result<(), PeerError> {
    let mut peer = peer_awaiting_verack(FEATURE_VERSION)?;
    let unknown_ids: [&[u8]; 5] = [
        b"BIP999",
        b"bip332",
        &[0x00, 0x01, 0x02, 0x03],
        &[0xff; 80],
        b"    ",
    ];
    for id in unknown_ids {
        step(&mut peer, &feature_message(id, &[1]))?;
    }
    for index in 0_u32..1_000 {
        let id = format!("unknown-feature-{index}");
        step(&mut peer, &feature_message(id.as_bytes(), &[0; 64]))?;
    }

    assert!(peer.remote_features.is_empty());
    assert_eq!(peer.state, PeerState::Verack);
    Ok(())
}

#[test]
fn first_valid_bip332_wins_and_invalid_payloads_are_ignored() -> Result<(), PeerError> {
    let mut peer = peer_awaiting_verack(FEATURE_VERSION)?;
    let invalid_payloads: [&[u8]; 5] = [&[], &[2], &[0xff], &[0, 1], &[0; 512]];
    for invalid in invalid_payloads {
        step(&mut peer, &feature_message(b"BIP332", invalid))?;
    }
    assert_eq!(
        peer.remote_feature(b"BIP332"),
        None,
        "invalid payloads never reserve the identifier"
    );

    step(&mut peer, &feature_message(b"BIP332", &[1]))?;
    step(&mut peer, &feature_message(b"BIP332", &[0]))?;
    step(&mut peer, &feature_message(b"BIP332", &[]))?;

    assert_eq!(peer.remote_feature(b"BIP332"), Some([1].as_slice()));
    assert_eq!(peer.remote_features.len(), 1);
    Ok(())
}

const BOTH: u64 = PKG_RELAY_PKGTXNS | PKG_RELAY_ANC;

fn send_packages(versions: u64) -> Message {
    Message::SendPackages(SendPackages { versions })
}

fn completed_handshake(
    ours: u64,
    relay: bool,
    negotiation: &[Message],
) -> Result<Peer<Cursor<Vec<u8>>>, PeerError> {
    let mut peer = fresh_peer();
    peer.offer_package_relay(ours);
    step(
        &mut peer,
        &Message::Version(VersionMessage {
            relay,
            ..version_message()
        }),
    )?;
    if let Some(versions) = peer.package_relay.unsent_offer() {
        peer.package_relay.record_advertised(versions);
    }
    for message in negotiation {
        step(&mut peer, message)?;
    }
    step(&mut peer, &Message::Verack)?;
    assert_eq!(peer.state, PeerState::Ready);
    Ok(peer)
}

fn package_negotiation(versions: u64) -> [Message; 2] {
    [Message::WtxidRelay, send_packages(versions)]
}

#[test]
fn package_relay_is_the_intersection_of_known_bits_both_sides_sent() -> Result<(), PeerError> {
    for (ours, theirs, expected) in [
        (BOTH, BOTH, BOTH),
        (PKG_RELAY_PKGTXNS, BOTH, PKG_RELAY_PKGTXNS),
        (BOTH, PKG_RELAY_ANC, PKG_RELAY_ANC),
        (PKG_RELAY_ANC, PKG_RELAY_PKGTXNS, 0),
        (BOTH, 0, 0),
        (BOTH, 1 << 40, 0),
        (BOTH, (1 << 40) | PKG_RELAY_ANC, PKG_RELAY_ANC),
        (BOTH, u64::MAX, BOTH),
        (0, BOTH, 0),
        (1 << 40, BOTH, 0),
    ] {
        let peer = completed_handshake(ours, true, &package_negotiation(theirs))?;
        assert_eq!(
            peer.package_relay_versions(),
            expected,
            "ours {ours:#x}, theirs {theirs:#x}"
        );
    }
    Ok(())
}

#[test]
fn package_relay_needs_every_handshake_precondition() -> Result<(), PeerError> {
    assert_eq!(
        completed_handshake(BOTH, true, &[Message::WtxidRelay])?.package_relay_versions(),
        0,
        "the peer never sent sendpackages"
    );
    assert_eq!(
        completed_handshake(BOTH, true, &[send_packages(BOTH)])?.package_relay_versions(),
        0,
        "the peer never sent wtxidrelay"
    );
    assert_eq!(
        completed_handshake(BOTH, false, &package_negotiation(BOTH))?.package_relay_versions(),
        0,
        "the peer's version cleared fRelay"
    );
    assert_eq!(
        completed_handshake(BOTH, true, &package_negotiation(BOTH))?.package_relay_versions(),
        BOTH
    );
    Ok(())
}

#[test]
fn package_relay_is_off_until_both_veracks_completed_the_handshake() -> Result<(), PeerError> {
    let mut peer = peer_awaiting_verack(FEATURE_VERSION)?;
    peer.offer_package_relay(BOTH);
    peer.package_relay.record_advertised(BOTH);
    step(&mut peer, &Message::WtxidRelay)?;
    step(&mut peer, &send_packages(BOTH))?;
    assert_eq!(peer.package_relay_versions(), 0);

    step(&mut peer, &Message::Verack)?;
    assert_eq!(peer.package_relay_versions(), BOTH);
    Ok(())
}

#[test]
fn package_relay_offer_keeps_only_known_bits_and_is_sent_once() {
    let mut peer = fresh_peer();
    assert_eq!(peer.package_relay.unsent_offer(), None, "off by default");

    peer.offer_package_relay(u64::MAX);
    assert_eq!(peer.package_relay.unsent_offer(), Some(BOTH));

    peer.package_relay.record_advertised(BOTH);
    assert_eq!(peer.package_relay.unsent_offer(), None);

    peer.offer_package_relay(1 << 40);
    assert_eq!(peer.package_relay.unsent_offer(), None);
}

#[test]
fn sendpackages_before_version_is_rejected() {
    let mut peer = fresh_peer();
    assert!(matches!(
        step(&mut peer, &send_packages(BOTH)),
        Err(PeerError::Misbehavior(_))
    ));
    assert_eq!(
        peer.package_relay,
        crate::peer::PackageRelayNegotiation::default()
    );
}

#[test]
fn sendpackages_after_verack_is_rejected_and_changes_nothing() -> Result<(), PeerError> {
    let mut peer = completed_handshake(BOTH, true, &package_negotiation(PKG_RELAY_ANC))?;
    assert!(matches!(
        step(&mut peer, &send_packages(BOTH)),
        Err(PeerError::Misbehavior(_))
    ));
    assert_eq!(peer.package_relay_versions(), PKG_RELAY_ANC);
    Ok(())
}

#[test]
fn first_sendpackages_wins_even_when_it_offers_nothing() -> Result<(), PeerError> {
    let mut peer = peer_awaiting_verack(FEATURE_VERSION)?;
    peer.offer_package_relay(BOTH);
    peer.package_relay.record_advertised(BOTH);
    step(&mut peer, &Message::WtxidRelay)?;
    step(&mut peer, &send_packages(1 << 40))?;
    step(&mut peer, &send_packages(BOTH))?;
    step(&mut peer, &Message::Verack)?;

    assert_eq!(peer.package_relay_versions(), 0);
    Ok(())
}

#[test]
fn sendpackages_is_not_a_bip434_feature() -> Result<(), PeerError> {
    let mut peer = peer_awaiting_verack(FEATURE_VERSION)?;
    step(&mut peer, &send_packages(BOTH))?;
    assert!(peer.remote_features.is_empty());

    let before = peer.package_relay;
    step(&mut peer, &feature_message(b"BIP331", &[3]))?;
    assert!(peer.remote_features.is_empty());
    assert_eq!(peer.package_relay, before);
    Ok(())
}

#[test]
fn feature_negotiation_is_accepted_during_and_after_handshake() -> Result<(), PeerError> {
    let mut peer = fresh_peer();
    step(&mut peer, &Message::Version(version_message()))?;
    step(&mut peer, &sendcmpct_message(true, 2))?;

    step(&mut peer, &Message::Verack)?;
    step(&mut peer, &sendcmpct_message(false, 1))?;
    assert_eq!(
        peer.compact_blocks.remote_preference(),
        Some(SendCmpct {
            send_compact: true,
            version: 2,
        })
    );
    Ok(())
}
