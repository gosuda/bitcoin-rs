use std::io::{self, Cursor};

use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};

use super::{
    COMPACT_BLOCK_VERSION, Message, Peer, PeerError, PeerRole, PeerState, announceable_to,
    feature_messages, negotiated_features, post_verack_messages, run_inbound_handshake, start,
    version_message,
};
use crate::feature::{FEATURE_VERSION, FeatureAnnouncement, FeatureId};
use crate::packages::{PKG_RELAY_ANC, PKG_RELAY_PKGTXNS, SendPackages};
use crate::wire::{PROTOCOL_VERSION, read_message, write_message};

struct ScriptedStream {
    inbound: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl ScriptedStream {
    fn new(inbound: Vec<u8>) -> Self {
        Self {
            inbound: Cursor::new(inbound),
            written: Vec::new(),
        }
    }
}

impl io::Read for ScriptedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inbound.read(buffer)
    }
}

impl io::Write for ScriptedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn services() -> ServiceFlags {
    ServiceFlags::NETWORK | ServiceFlags::WITNESS
}

fn remote_version(version: u32) -> Message {
    Message::Version(VersionMessage {
        version,
        ..version_message(99, 0, PeerRole::FullRelay, services())
    })
}

fn remote_feature(id: &[u8], data: &[u8]) -> Message {
    Message::Feature(FeatureAnnouncement::new(
        FeatureId::from_raw_unchecked(id.to_vec()),
        data.to_vec(),
    ))
}

fn inbound_handshake_over(
    remote: &[Message],
) -> Result<(Peer<ScriptedStream>, Result<(), PeerError>), PeerError> {
    inbound_handshake_offering(0, remote)
}

fn inbound_handshake_offering(
    offer: u64,
    remote: &[Message],
) -> Result<(Peer<ScriptedStream>, Result<(), PeerError>), PeerError> {
    inbound_handshake_with(|peer| peer.offer_package_relay(offer), remote)
}

fn inbound_handshake_with(
    configure: impl FnOnce(&mut Peer<ScriptedStream>),
    remote: &[Message],
) -> Result<(Peer<ScriptedStream>, Result<(), PeerError>), PeerError> {
    let magic = Magic::BITCOIN;
    let mut inbound = Vec::new();
    for message in remote {
        write_message(&mut inbound, magic, message)?;
    }
    let mut peer = Peer::new(ScriptedStream::new(inbound), magic);
    configure(&mut peer);
    let (lease_tx, _lease_rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new_inbound(lease_tx);
    let outcome = run_inbound_handshake(
        &mut peer,
        1,
        0,
        services(),
        &lease,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    );
    Ok((peer, outcome))
}

fn sent_messages(written: &[u8]) -> Result<Vec<Message>, PeerError> {
    let mut outbound = Cursor::new(written);
    let mut sent = Vec::new();
    while usize::try_from(outbound.position()).unwrap_or(usize::MAX) < written.len() {
        sent.push(read_message(&mut outbound, Magic::BITCOIN)?.0);
    }
    Ok(sent)
}

fn send_packages(versions: u64) -> Message {
    Message::SendPackages(SendPackages { versions })
}

#[test]
fn inbound_handshake_sends_one_sendpackages_before_verack_and_activates_the_common_bits()
-> Result<(), PeerError> {
    let both = PKG_RELAY_PKGTXNS | PKG_RELAY_ANC;
    let (peer, outcome) = inbound_handshake_offering(
        both,
        &[
            remote_version(PROTOCOL_VERSION),
            Message::WtxidRelay,
            send_packages(PKG_RELAY_ANC | (1 << 40)),
            Message::Verack,
        ],
    )?;
    outcome?;

    let mut expected = vec![Message::Version(version_message(
        1,
        0,
        PeerRole::FullRelay,
        services(),
    ))];
    expected.extend(feature_messages());
    expected.extend(
        negotiated_features(&peer, PROTOCOL_VERSION)
            .into_iter()
            .map(Message::Feature),
    );
    expected.push(send_packages(both));
    expected.push(Message::Verack);
    expected.extend(post_verack_messages());
    assert_eq!(sent_messages(&peer.stream.written)?, expected);
    assert_eq!(peer.package_relay_versions(), PKG_RELAY_ANC);
    assert!(
        peer.remote_features.is_empty(),
        "sendpackages is not mapped onto BIP434"
    );
    Ok(())
}

#[test]
fn inbound_handshake_offers_nothing_by_default_and_never_activates() -> Result<(), PeerError> {
    let (peer, outcome) = inbound_handshake_over(&[
        remote_version(PROTOCOL_VERSION),
        Message::WtxidRelay,
        send_packages(PKG_RELAY_PKGTXNS | PKG_RELAY_ANC),
        Message::Verack,
    ])?;
    outcome?;

    assert!(
        !sent_messages(&peer.stream.written)?
            .iter()
            .any(|message| matches!(message, Message::SendPackages(_)))
    );
    assert_eq!(peer.package_relay_versions(), 0);
    Ok(())
}

#[test]
fn inbound_handshake_rejects_sendpackages_before_version() -> Result<(), PeerError> {
    let (peer, outcome) = inbound_handshake_offering(
        PKG_RELAY_ANC,
        &[send_packages(PKG_RELAY_ANC), Message::Verack],
    )?;

    assert!(matches!(outcome, Err(PeerError::Misbehavior(_))));
    assert_eq!(peer.package_relay_versions(), 0);
    Ok(())
}

#[test]
fn outbound_start_offers_package_relay_only_on_relaying_roles() {
    for (role, offered) in [
        (PeerRole::FullRelay, Some(PKG_RELAY_ANC)),
        (PeerRole::BlockRelayOnly, None),
    ] {
        let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
        peer.offer_package_relay(PKG_RELAY_ANC);

        start(&mut peer, 7, 0, role, services());

        assert_eq!(peer.package_relay.unsent_offer(), offered, "{role:?}");
    }
}

#[test]
fn announcements_go_only_to_peers_at_the_feature_version() {
    let local = vec![
        FeatureAnnouncement::new(FeatureId::from_raw_unchecked(b"BIP332".to_vec()), vec![0]),
        FeatureAnnouncement::new(
            FeatureId::from_raw_unchecked(b"BIP999".to_vec()),
            vec![1, 2],
        ),
    ];
    assert_eq!(announceable_to(FEATURE_VERSION - 1, local.clone()), []);
    assert_eq!(announceable_to(FEATURE_VERSION, local.clone()), local);
    assert_eq!(announceable_to(u32::MAX, local.clone()), local);
    let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
    assert_eq!(negotiated_features(&peer, FEATURE_VERSION), []);

    peer.offer_stale_tip_relay(true);
    assert_eq!(
        negotiated_features(&peer, FEATURE_VERSION),
        vec![FeatureAnnouncement::bip332(true)]
    );
    assert_eq!(negotiated_features(&peer, FEATURE_VERSION - 1), []);
}

#[test]
fn inbound_handshake_announces_an_offered_bip332_between_feature_messages_and_verack()
-> Result<(), PeerError> {
    for prefers_blocks in [false, true] {
        let (peer, outcome) = inbound_handshake_with(
            |peer| peer.offer_stale_tip_relay(prefers_blocks),
            &[remote_version(PROTOCOL_VERSION), Message::Verack],
        )?;
        outcome?;

        let mut expected = vec![Message::Version(version_message(
            1,
            0,
            PeerRole::FullRelay,
            services(),
        ))];
        expected.extend(feature_messages());
        expected.push(Message::Feature(FeatureAnnouncement::bip332(
            prefers_blocks,
        )));
        expected.push(Message::Verack);
        expected.extend(post_verack_messages());
        assert_eq!(sent_messages(&peer.stream.written)?, expected);
    }
    Ok(())
}

#[test]
fn inbound_handshake_never_announces_bip332_to_a_pre_bip434_peer() -> Result<(), PeerError> {
    let (peer, outcome) = inbound_handshake_with(
        |peer| peer.offer_stale_tip_relay(true),
        &[remote_version(FEATURE_VERSION - 1), Message::Verack],
    )?;
    outcome?;

    assert!(
        !sent_messages(&peer.stream.written)?
            .iter()
            .any(|message| matches!(message, Message::Feature(_)))
    );
    Ok(())
}

#[test]
fn inbound_handshake_to_a_pre_bip434_peer_is_unchanged() -> Result<(), PeerError> {
    let (peer, outcome) =
        inbound_handshake_over(&[remote_version(FEATURE_VERSION - 1), Message::Verack])?;
    outcome?;

    let sent = sent_messages(&peer.stream.written)?;
    let mut expected = vec![Message::Version(version_message(
        1,
        0,
        PeerRole::FullRelay,
        services(),
    ))];
    expected.extend(feature_messages());
    expected.push(Message::Verack);
    expected.extend(post_verack_messages());
    assert_eq!(sent, expected, "no `feature` frame reaches the old peer");
    assert!(peer.remote_features.is_empty());
    Ok(())
}

#[test]
fn inbound_handshake_sends_negotiated_features_between_feature_messages_and_verack()
-> Result<(), PeerError> {
    let (peer, outcome) =
        inbound_handshake_over(&[remote_version(PROTOCOL_VERSION), Message::Verack])?;
    outcome?;

    let mut expected = vec![Message::Version(version_message(
        1,
        0,
        PeerRole::FullRelay,
        services(),
    ))];
    expected.extend(feature_messages());
    expected.extend(
        negotiated_features(&peer, PROTOCOL_VERSION)
            .into_iter()
            .map(Message::Feature),
    );
    expected.push(Message::Verack);
    expected.extend(post_verack_messages());
    assert_eq!(sent_messages(&peer.stream.written)?, expected);
    Ok(())
}

#[test]
fn inbound_handshake_retains_only_valid_recognised_remote_features() -> Result<(), PeerError> {
    let (peer, outcome) = inbound_handshake_over(&[
        remote_version(PROTOCOL_VERSION),
        remote_feature(&[0x00, 0x01, 0x02, 0xff], &[1]),
        remote_feature(b"BIP332", &[7]),
        remote_feature(b"BIP332", &[1]),
        remote_feature(b"BIP332", &[0]),
        remote_feature(b"unknown-feature", b"opaque"),
        Message::Verack,
    ])?;
    outcome?;

    assert_eq!(peer.state, PeerState::Ready);
    assert_eq!(peer.remote_feature(b"BIP332"), Some([1].as_slice()));
    assert_eq!(peer.remote_features.len(), 1);
    Ok(())
}

#[test]
fn inbound_handshake_rejects_a_feature_from_a_pre_bip434_peer() -> Result<(), PeerError> {
    let (peer, outcome) = inbound_handshake_over(&[
        remote_version(FEATURE_VERSION - 1),
        remote_feature(b"BIP332", &[1]),
        Message::Verack,
    ])?;

    assert!(matches!(outcome, Err(PeerError::Misbehavior(_))));
    assert_ne!(peer.state, PeerState::Ready);
    assert!(peer.remote_features.is_empty());
    Ok(())
}

#[test]
fn inbound_handshake_rejects_a_feature_before_version() -> Result<(), PeerError> {
    let (peer, outcome) =
        inbound_handshake_over(&[remote_feature(b"BIP332", &[1]), Message::Verack])?;

    assert!(matches!(outcome, Err(PeerError::Misbehavior(_))));
    assert!(peer.remote_version.is_none());
    assert!(peer.remote_features.is_empty());
    Ok(())
}

#[test]
fn inbound_handshake_reaches_ready_after_remote_version_and_verack() -> Result<(), PeerError> {
    let magic = Magic::BITCOIN;
    let mut remote_outbound = Vec::new();
    write_message(
        &mut remote_outbound,
        magic,
        &Message::Version(version_message(
            99,
            0,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        )),
    )?;
    write_message(&mut remote_outbound, magic, &Message::Verack)?;

    let stream = ScriptedStream::new(remote_outbound);
    let mut peer = Peer::new(stream, magic);

    let (lease_tx, _lease_rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new_inbound(lease_tx);

    run_inbound_handshake(
        &mut peer,
        1,
        0,
        ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        &lease,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )?;

    assert_eq!(peer.state, PeerState::Ready, "inbound peer reaches Ready");
    assert!(
        peer.received_verack,
        "verack flag is set after remote Verack"
    );
    assert!(peer.remote_version.is_some(), "remote Version is recorded");
    assert!(
        !peer.stream.written.is_empty(),
        "wire responses are written"
    );

    let announced = negotiated_features(&peer, PROTOCOL_VERSION);
    let mut outbound = Cursor::new(peer.stream.written);
    let (outbound_version, _) = read_message(&mut outbound, magic)?;
    assert!(matches!(outbound_version, Message::Version(_)));

    for expected in feature_messages() {
        let (actual, _) = read_message(&mut outbound, magic)?;
        assert_eq!(actual, expected);
    }
    for expected in announced {
        let (actual, _) = read_message(&mut outbound, magic)?;
        assert_eq!(actual, Message::Feature(expected));
    }

    let (outbound_verack, _) = read_message(&mut outbound, magic)?;
    assert_eq!(outbound_verack, Message::Verack);
    for expected in post_verack_messages() {
        let (actual, _) = read_message(&mut outbound, magic)?;
        assert_eq!(actual, expected, "post-verack preference follows verack");
    }
    assert_eq!(
        usize::try_from(outbound.position()).unwrap_or(usize::MAX),
        outbound.get_ref().len(),
        "handshake writes each frame once",
    );

    assert_eq!(
        peer.compact_blocks.local_version(),
        Some(COMPACT_BLOCK_VERSION),
        "post-verack advertisement is recorded on the negotiation state",
    );

    Ok(())
}

#[test]
fn inbound_handshake_resumes_frames_split_by_poll_timeouts() -> Result<(), PeerError> {
    use crate::test_support::{Inbound, StallingStream};

    let magic = Magic::BITCOIN;
    let mut version = Vec::new();
    write_message(
        &mut version,
        magic,
        &Message::Version(version_message(
            99,
            0,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        )),
    )?;
    let mut verack = Vec::new();
    write_message(&mut verack, magic, &Message::Verack)?;
    let stream = StallingStream::new([
        Inbound::Bytes(version[..30].to_vec()),
        Inbound::Stall(io::ErrorKind::TimedOut),
        Inbound::Bytes(version[30..].to_vec()),
        Inbound::Bytes(verack[..5].to_vec()),
        Inbound::Stall(io::ErrorKind::WouldBlock),
        Inbound::Bytes(verack[5..].to_vec()),
    ]);
    let mut peer = Peer::new(stream, magic);

    let (lease_tx, _lease_rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new_inbound(lease_tx);
    run_inbound_handshake(
        &mut peer,
        1,
        0,
        ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        &lease,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )?;

    assert_eq!(peer.state, PeerState::Ready);
    Ok(())
}

#[test]
fn version_message_advertises_relay_only_for_full_relay() {
    assert!(
        version_message(1, 0, PeerRole::FullRelay, ServiceFlags::NETWORK).relay,
        "a full-relay handshake asks for transaction relay"
    );
    assert!(
        !version_message(1, 0, PeerRole::BlockRelayOnly, ServiceFlags::NETWORK).relay,
        "a block-relay-only handshake asks for none"
    );
}

#[test]
fn outbound_handshake_start_carries_the_connection_role() {
    let stream: std::io::Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut peer = Peer::new(stream, Magic::BITCOIN);
    let messages = start(
        &mut peer,
        7,
        42,
        PeerRole::BlockRelayOnly,
        ServiceFlags::NETWORK | ServiceFlags::WITNESS,
    );
    assert_eq!(
        messages.len(),
        4,
        "one version plus the three feature messages"
    );
    assert!(
        matches!(&messages[0], Message::Version(version)
                if !version.relay && version.start_height == 42 && version.nonce == 7),
        "the first message is the version the role advertises"
    );
    assert_eq!(peer.state, PeerState::VersionExchange);
}
