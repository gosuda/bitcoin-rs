use std::io::{Cursor, Read, Write};

use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin_rs_p2p::CompactBlockNegotiation;
use bitcoin_rs_p2p::compact_blocks::COMPACT_BLOCK_VERSION;
use bitcoin_rs_p2p::dispatch::dispatch_inbound;
use bitcoin_rs_p2p::handshake::start;
use bitcoin_rs_p2p::wire::PROTOCOL_VERSION;
use bitcoin_rs_p2p::{Message, Peer, PeerError, PeerRole, PeerState};

fn handshake_cursors(
    left: &mut Peer<Cursor<Vec<u8>>>,
    right: &mut Peer<Cursor<Vec<u8>>>,
) -> Result<(), PeerError> {
    let unpruned = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    let left_messages = start(left, 1, 0, PeerRole::FullRelay, unpruned);
    exchange(left, right, left_messages)?;
    let right_messages = start(right, 2, 0, PeerRole::FullRelay, unpruned);
    exchange(right, left, right_messages)?;
    exchange(left, right, vec![Message::Verack])?;
    exchange(right, left, vec![Message::Verack])?;
    let send_cmpct = Message::SendCmpct(SendCmpct {
        send_compact: false,
        version: COMPACT_BLOCK_VERSION,
    });
    exchange(left, right, vec![send_cmpct.clone()])?;
    exchange(right, left, vec![send_cmpct])?;
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
        for response in dispatch_inbound(to, &message)? {
            to.send(&response)?;
        }
    }
    Ok(())
}

#[test]
fn cursor_peers_reach_ready_after_version_verack_exchange() -> Result<(), Box<dyn std::error::Error>>
{
    let mut left = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
    let mut right = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);

    handshake_cursors(&mut left, &mut right)?;

    assert_eq!(left.state, PeerState::Ready);
    assert_eq!(right.state, PeerState::Ready);
    assert!(left.capabilities.addr_v2);
    assert!(right.capabilities.addr_v2);
    assert!(left.wtxid_relay.peer_supported());
    assert!(right.wtxid_relay.peer_supported());
    Ok(())
}

#[test]
fn cursor_handshake_advertises_the_pinned_wire_protocol_version() {
    let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
    let messages = start(
        &mut peer,
        1,
        0,
        PeerRole::FullRelay,
        ServiceFlags::NETWORK | ServiceFlags::WITNESS,
    );

    let [Message::Version(version), ..] = messages.as_slice() else {
        panic!("the first message is the version announcement");
    };
    assert_eq!(version.version, PROTOCOL_VERSION);
    assert_eq!(
        peer.compact_blocks,
        CompactBlockNegotiation::default(),
        "the local advertisement is recorded only after verack"
    );
}

#[test]
fn cursor_handshake_records_the_remote_compact_block_advertisement()
-> Result<(), Box<dyn std::error::Error>> {
    let mut left = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
    let mut right = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);

    handshake_cursors(&mut left, &mut right)?;

    assert_eq!(
        left.compact_blocks.remote_version,
        Some(COMPACT_BLOCK_VERSION)
    );
    assert_eq!(
        right.compact_blocks.remote_version,
        Some(COMPACT_BLOCK_VERSION)
    );
    assert_eq!(left.compact_blocks.remote_send_compact, Some(false));
    assert_eq!(right.compact_blocks.remote_send_compact, Some(false));
    Ok(())
}
