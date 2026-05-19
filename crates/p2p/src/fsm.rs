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
            peer.wtxid_relay.mark_peer_supported();
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

fn receive_verack<S>(peer: &mut Peer<S>) -> Result<(), PeerError> {
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
