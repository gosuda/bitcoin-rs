use std::io::{Cursor, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message_network::VersionMessage;

use crate::dispatch::dispatch_inbound;
use crate::peer::{Peer, PeerState};
use crate::wire::{Message, PROTOCOL_VERSION, PeerError, read_message};

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
        user_agent: "/bitcoin-rs:0.3.0/".to_owned(),
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
/// Drive a Bitcoin v1 handshake from the inbound listener side.
///
/// The caller has already accepted the TCP connection and constructed a
/// `Peer<S>` whose `magic` matches the network. This reads the remote
/// `Version`, sends our `Version` followed by feature-negotiation messages and
/// `Verack`, then dispatches inbound messages until the peer is ready.
///
/// # Errors
///
/// Returns [`PeerError`] if reading or writing the wire stream fails, or if the
/// finite-state machine rejects any inbound message.
pub fn run_inbound_handshake<S: Read + Write>(
    peer: &mut Peer<S>,
    our_nonce: u64,
    our_start_height: i32,
) -> Result<(), PeerError> {
    let (remote_version, _) = read_message(&mut peer.stream, peer.magic)?;
    let responses = dispatch_inbound(peer, &remote_version)?;

    peer.state = PeerState::VersionExchange;
    peer.send(&Message::Version(version_message(
        our_nonce,
        our_start_height,
    )))?;
    for response in responses {
        peer.send(&response)?;
    }

    while peer.state != PeerState::Ready {
        let (inbound, _) = read_message(&mut peer.stream, peer.magic)?;
        let responses = dispatch_inbound(peer, &inbound)?;
        for response in responses {
            peer.send(&response)?;
        }
    }

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

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use bitcoin::p2p::Magic;

    use super::{Peer, PeerError, PeerState, run_inbound_handshake, version_message};
    use crate::handshake::feature_messages;
    use crate::wire::{Message, write_message};

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

    #[test]
    fn inbound_handshake_reaches_ready_after_remote_version_and_verack() -> Result<(), PeerError> {
        let magic = Magic::BITCOIN;
        let mut remote_outbound = Vec::new();
        write_message(
            &mut remote_outbound,
            magic,
            &Message::Version(version_message(99, 0)),
        )?;
        write_message(&mut remote_outbound, magic, &Message::Verack)?;

        let stream = ScriptedStream::new(remote_outbound);
        let mut peer = Peer::new(stream, magic);

        run_inbound_handshake(&mut peer, 1, 0)?;

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

        let outbound_version = peer
            .receiver
            .try_recv()
            .map_err(|_| PeerError::Protocol("missing outbound version"))?;
        assert!(matches!(outbound_version, Message::Version(_)));

        for expected in feature_messages() {
            let actual = peer
                .receiver
                .try_recv()
                .map_err(|_| PeerError::Protocol("missing outbound feature message"))?;
            assert_eq!(actual, expected);
        }

        let outbound_verack = peer
            .receiver
            .try_recv()
            .map_err(|_| PeerError::Protocol("missing outbound verack"))?;
        assert_eq!(outbound_verack, Message::Verack);

        Ok(())
    }
}
