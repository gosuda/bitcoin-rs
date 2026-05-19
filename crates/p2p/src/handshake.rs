use std::io::{Cursor, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message_network::VersionMessage;

use crate::dispatch::dispatch_inbound;
use crate::peer::{Peer, PeerState};
use crate::wire::{Message, PROTOCOL_VERSION, PeerError};

/// Build a local version message for handshake initiation.
pub fn version_message(nonce: u64, start_height: i32) -> VersionMessage {
    let socket = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let mut services = ServiceFlags::NETWORK;
    services.add(ServiceFlags::WITNESS);
    let address = Address::new(&socket, services);
    VersionMessage {
        version: PROTOCOL_VERSION,
        services,
        timestamp: 0,
        receiver: address.clone(),
        sender: address,
        nonce,
        user_agent: "/bitcoin-rs:0.1.0/".to_owned(),
        start_height,
        relay: true,
    }
}

/// Messages sent during feature negotiation after `version` and before readiness.
pub const fn feature_messages() -> [Message; 3] {
    [
        Message::WtxidRelay,
        Message::SendAddrV2,
        Message::SendHeaders,
    ]
}

/// Start an outbound handshake and return messages to send to the remote peer.
pub fn start<S>(peer: &mut Peer<S>, nonce: u64, start_height: i32) -> Vec<Message> {
    peer.state = PeerState::VersionExchange;
    let mut messages = Vec::with_capacity(4);
    messages.push(Message::Version(version_message(nonce, start_height)));
    messages.extend(feature_messages());
    messages
}

/// Exercise a complete version/verack handshake between two cursor-backed peers.
pub fn handshake_cursors(
    left: &mut Peer<Cursor<Vec<u8>>>,
    right: &mut Peer<Cursor<Vec<u8>>>,
) -> Result<(), PeerError> {
    let left_messages = start(left, 1, 0);
    exchange(left, right, left_messages)?;
    let right_messages = start(right, 2, 0);
    exchange(right, left, right_messages)?;
    exchange(left, right, vec![Message::Verack])?;
    exchange(right, left, vec![Message::Verack])?;
    Ok(())
}

fn exchange<A, B>(
    from: &mut Peer<A>,
    to: &mut Peer<B>,
    messages: Vec<Message>,
) -> Result<(), PeerError>
where
    A: Read + Write,
    B: Read + Write,
{
    for message in messages {
        from.send(&message)?;
        let responses = dispatch_inbound(to, &message)?;
        for response in responses {
            to.send(&response)?;
        }
    }
    Ok(())
}
