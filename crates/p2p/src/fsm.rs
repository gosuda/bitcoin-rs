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

    use bitcoin::p2p::Magic;
    use bitcoin::p2p::message_compact_blocks::SendCmpct;

    use super::*;

    #[test]
    fn sendcmpct_while_ready_updates_compact_block_state() -> Result<(), PeerError> {
        let mut peer = peer_in_state(PeerState::Ready);
        let message = sendcmpct_message(true, 2);

        step(&mut peer, &message)?;

        assert_eq!(peer.compact_blocks.remote_send_compact, Some(true));
        assert_eq!(peer.compact_blocks.remote_version, Some(2));
        assert_eq!(peer.state, PeerState::Ready);
        Ok(())
    }

    #[test]
    fn sendcmpct_during_negotiation_updates_compact_block_state() -> Result<(), PeerError> {
        let mut peer = peer_in_state(PeerState::VersionExchange);
        let message = sendcmpct_message(false, 1);

        step(&mut peer, &message)?;

        assert_eq!(peer.compact_blocks.remote_send_compact, Some(false));
        assert_eq!(peer.compact_blocks.remote_version, Some(1));
        assert_eq!(peer.state, PeerState::VersionExchange);
        Ok(())
    }

    #[test]
    fn sendcmpct_while_disconnected_is_rejected_without_state_mutation() {
        let mut peer = peer_in_state(PeerState::Disconnected);
        let before = peer.compact_blocks;
        let message = sendcmpct_message(true, 2);

        let result = step(&mut peer, &message);

        assert!(matches!(
            result,
            Err(PeerError::Protocol("feature negotiation outside handshake"))
        ));
        assert_eq!(peer.compact_blocks, before);
        assert_eq!(peer.state, PeerState::Disconnected);
    }

    fn peer_in_state(state: PeerState) -> Peer<Cursor<Vec<u8>>> {
        let mut peer = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
        peer.state = state;
        peer
    }

    const fn sendcmpct_message(send_compact: bool, version: u64) -> Message {
        Message::SendCmpct(SendCmpct {
            send_compact,
            version,
        })
    }
}
