use crate::peer::{Peer, PeerState};
use crate::wire::{Message, PeerError};

/// Advance a peer by one inbound message.
pub fn step<S>(peer: &mut Peer<S>, message: &Message) -> Result<(), PeerError> {
    match message {
        Message::Version(version) => receive_version(peer, version.clone()),
        Message::Verack => receive_verack(peer),
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
                Err(PeerError::Protocol(
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
            Err(PeerError::Protocol("duplicate version message"))
        }
    }
}

const fn receive_verack<S>(peer: &mut Peer<S>) -> Result<(), PeerError> {
    if peer.remote_version.is_none() {
        return Err(PeerError::Protocol("verack received before version"));
    }
    peer.received_verack = true;
    peer.refresh_ready_state();
    Ok(())
}

const fn ensure_negotiating_or_ready<S>(peer: &Peer<S>) -> Result<(), PeerError> {
    match peer.state {
        PeerState::VersionExchange | PeerState::Verack | PeerState::Ready => Ok(()),
        PeerState::Disconnected | PeerState::Disconnecting => {
            Err(PeerError::Protocol("feature negotiation outside handshake"))
        }
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

    fn fresh_peer() -> Peer<Cursor<Vec<u8>>> {
        Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN)
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

    /// A complete version/verack handshake makes a peer usable: ordinary
    /// application traffic is accepted only once the handshake is done.
    #[test]
    fn valid_handshake_reaches_a_usable_peer() -> Result<(), PeerError> {
        let mut peer = fresh_peer();

        // Before the handshake, application traffic is refused.
        assert!(step(&mut peer, &Message::Ping(1)).is_err());

        step(&mut peer, &Message::Version(version_message()))?;
        // Version received but verack outstanding: still not usable.
        assert!(step(&mut peer, &Message::Ping(1)).is_err());

        step(&mut peer, &Message::Verack)?;

        // Handshake complete: ordinary application traffic is now accepted.
        step(&mut peer, &Message::Ping(1))?;
        Ok(())
    }

    /// A second version after a completed handshake is a protocol violation.
    #[test]
    fn duplicate_version_after_handshake_is_rejected() -> Result<(), PeerError> {
        let mut peer = fresh_peer();
        step(&mut peer, &Message::Version(version_message()))?;
        step(&mut peer, &Message::Verack)?;

        assert!(step(&mut peer, &Message::Version(version_message())).is_err());
        Ok(())
    }

    /// Verack before version is an ordering violation.
    #[test]
    fn verack_before_version_is_rejected() {
        let mut peer = fresh_peer();
        assert!(step(&mut peer, &Message::Verack).is_err());
    }

    /// Feature negotiation is legal during and after the handshake, but
    /// illegal before negotiation has started.
    #[test]
    fn feature_negotiation_is_rejected_before_handshake() {
        let mut peer = fresh_peer();
        assert!(step(&mut peer, &sendcmpct_message(true, 2)).is_err());
    }

    #[test]
    fn feature_negotiation_is_accepted_during_and_after_handshake() -> Result<(), PeerError> {
        let mut peer = fresh_peer();
        // During negotiation (version received, verack outstanding).
        step(&mut peer, &Message::Version(version_message()))?;
        step(&mut peer, &sendcmpct_message(true, 2))?;

        // After the handshake completes.
        step(&mut peer, &Message::Verack)?;
        step(&mut peer, &sendcmpct_message(false, 1))?;
        Ok(())
    }
}
