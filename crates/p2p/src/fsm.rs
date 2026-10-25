use crate::feature::{FEATURE_VERSION, FeatureAnnouncement};
use crate::peer::{Peer, PeerState};
use crate::wire::{Message, PeerError};

/// Advance a peer by one inbound message.
pub(crate) fn step<S>(peer: &mut Peer<S>, message: &Message) -> Result<(), PeerError> {
    match message {
        Message::Version(version) => receive_version(peer, version.clone()),
        Message::Verack => receive_verack(peer),
        Message::Feature(announcement) => receive_feature(peer, announcement),
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
    let Some(remote_version) = peer.remote_version.as_ref() else {
        return Err(PeerError::Misbehavior("feature received before version"));
    };
    if remote_version.version < FEATURE_VERSION {
        return Err(PeerError::Misbehavior(
            "feature received from a peer below the feature protocol version",
        ));
    }
    // The window is the peer's own `verack`, not our `PeerState`: the inbound
    // handshake resets the state to `VersionExchange` after accepting `version`.
    if peer.received_verack || !matches!(peer.state, PeerState::VersionExchange | PeerState::Verack)
    {
        return Err(PeerError::Misbehavior(
            "feature received outside the version-to-verack window",
        ));
    }
    if announcement.is_supported() {
        peer.remote_features
            .entry(announcement.id.clone())
            .or_insert_with(|| announcement.data.clone());
    }
    Ok(())
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
