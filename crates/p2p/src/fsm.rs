use crate::feature::{FEATURE_VERSION, FeatureAnnouncement};
use crate::packages::SendPackages;
use crate::peer::{Peer, PeerState};
use crate::wire::{Message, PeerError};

/// Advance a peer by one inbound message.
pub(crate) fn step<S>(peer: &mut Peer<S>, message: &Message) -> Result<(), PeerError> {
    match message {
        Message::Version(version) => receive_version(peer, version.clone()),
        Message::Verack => receive_verack(peer),
        Message::Feature(announcement) => receive_feature(peer, announcement),
        Message::SendPackages(send_packages) => receive_send_packages(peer, *send_packages),
        Message::SendHeaders => {
            ensure_negotiating_or_ready(peer)?;
            peer.capabilities.send_headers = true;
            Ok(())
        }
        Message::SendAddrV2 => {
            ensure_negotiating_or_ready(peer)?;
            peer.capabilities.addr_v2 = true;
            Ok(())
        }
        Message::WtxidRelay => {
            ensure_negotiating_or_ready(peer)?;
            // BIP339 requires negotiation before verack. Once Ready, keep
            // the published per-connection relay preference unchanged.
            if peer.state == PeerState::Ready {
                return Ok(());
            }
            peer.wtxid_relay.mark_peer_supported();
            Ok(())
        }
        Message::SendCmpct(send_cmpct) => {
            ensure_negotiating_or_ready(peer)?;
            peer.compact_blocks.record_remote_preference(send_cmpct);
            Ok(())
        }
        _ => {
            if peer.state == PeerState::Ready {
                Ok(())
            } else {
                Err(PeerError::Misbehavior(
                    "message received before handshake completed",
                ))
            }
        }
    }
}

fn receive_version<S>(
    peer: &mut Peer<S>,
    version: bitcoin::p2p::message_network::VersionMessage,
) -> Result<(), PeerError> {
    if peer.remote_version.is_some() {
        return Err(PeerError::Misbehavior("duplicate version message"));
    }
    match peer.state {
        PeerState::Disconnected | PeerState::VersionExchange | PeerState::Verack => {
            peer.remote_version = Some(version);
            if peer.received_verack {
                peer.state = PeerState::Ready;
            } else {
                peer.state = PeerState::Verack;
            }
            Ok(())
        }
        PeerState::Ready | PeerState::Disconnecting => {
            Err(PeerError::Misbehavior("duplicate version message"))
        }
    }
}

/// Record one BIP434 `feature` announcement.
///
/// PRE: `announcement` decoded within the codec bounds.
/// POST: the peer sent it after its `version`, at protocol version
///   [`FEATURE_VERSION`] or above, and before its `verack`; otherwise the
///   result is a protocol violation and the peer is unchanged. Unknown
///   identifiers (printable or not) and invalid payloads for a recognised
///   identifier are ignored, not punished. The first valid payload of a
///   recognised identifier is retained and later ones are ignored.
/// INVARIANT: `Peer::remote_features` only ever holds
///   [`FeatureAnnouncement::is_supported`] announcements, one per identifier.
fn receive_feature<S>(
    peer: &mut Peer<S>,
    announcement: &FeatureAnnouncement,
) -> Result<(), PeerError> {
    if ensure_version_to_verack_window(peer)? < FEATURE_VERSION {
        return Err(PeerError::Misbehavior(
            "feature received from a peer below the feature protocol version",
        ));
    }
    if announcement.is_supported() {
        peer.remote_features
            .entry(announcement.id.clone())
            .or_insert_with(|| announcement.data.clone());
    }
    Ok(())
}

/// Record one BIP331 `sendpackages`.
///
/// PRE: `send_packages` decoded; any `versions` value is well formed.
/// POST: the peer sent it after its `version` and before its `verack`;
///   otherwise the result is a protocol violation and the peer is unchanged.
///   Only the known `PKG_RELAY_*` bits of the first message are kept: `0`,
///   unknown bits and later messages are ignored, not punished. BIP331 has no
///   protocol-version floor and no BIP434 mapping.
/// INVARIANT: this records the peer's offer only. [`Peer::package_relay_versions`]
///   is the one place that combines it with `verack`, `wtxidrelay`, `fRelay`
///   and our own `sendpackages`.
fn receive_send_packages<S>(
    peer: &mut Peer<S>,
    send_packages: SendPackages,
) -> Result<(), PeerError> {
    ensure_version_to_verack_window(peer)?;
    peer.package_relay.record_remote(send_packages.versions);
    Ok(())
}

/// The peer's protocol version, when it is inside its own pre-`verack`
/// negotiation window: after its `version`, before its `verack`.
///
/// The window is the peer's `verack`, not our [`PeerState`]: the inbound
/// handshake resets the state to `VersionExchange` after accepting `version`.
fn ensure_version_to_verack_window<S>(peer: &Peer<S>) -> Result<u32, PeerError> {
    let Some(remote_version) = peer.remote_version.as_ref() else {
        return Err(PeerError::Misbehavior(
            "negotiation message received before version",
        ));
    };
    if peer.received_verack || !matches!(peer.state, PeerState::VersionExchange | PeerState::Verack)
    {
        return Err(PeerError::Misbehavior(
            "negotiation message received outside the version-to-verack window",
        ));
    }
    Ok(remote_version.version)
}

const fn receive_verack<S>(peer: &mut Peer<S>) -> Result<(), PeerError> {
    if peer.remote_version.is_none() {
        return Err(PeerError::Misbehavior("verack received before version"));
    }
    peer.received_verack = true;
    peer.refresh_ready_state();
    Ok(())
}

const fn ensure_negotiating_or_ready<S>(peer: &Peer<S>) -> Result<(), PeerError> {
    match peer.state {
        PeerState::VersionExchange | PeerState::Verack | PeerState::Ready => Ok(()),
        PeerState::Disconnected | PeerState::Disconnecting => Err(PeerError::Misbehavior(
            "feature negotiation outside handshake",
        )),
    }
}

#[cfg(test)]
mod tests {
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

    /// A peer that has sent `version` at `version` and owes its `verack`.
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

    /// A `feature` message as decoded from any wire bytes: the identifier
    /// need not be printable.
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
    fn feature_is_accepted_while_the_inbound_handshake_holds_version_exchange()
    -> Result<(), PeerError> {
        let mut peer = peer_awaiting_verack(FEATURE_VERSION)?;
        // `run_inbound_handshake` resets the state after accepting `version`.
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
    fn feature_between_version_and_verack_is_retained_and_handshake_completes()
    -> Result<(), PeerError> {
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
        // A peer cannot grow the map with distinct unknown identifiers.
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

    /// A peer that offered `ours` in its version reply, then received the
    /// remote's `version` (its `fRelay` is `relay`), the pre-`verack`
    /// messages in `negotiation`, and finally its `verack`.
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
        // The version reply sends our `sendpackages`, then `verack`.
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

    /// The remote's usual full-relay package negotiation: `wtxidrelay`, then
    /// `sendpackages` for `versions`.
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
            // Zero and unknown bits are ignored on both sides.
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

        // A BIP434 announcement does not stand in for `sendpackages` either.
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
}
