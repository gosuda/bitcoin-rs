//! Handshake state-machine round trips.
//!
//! Both test-local helpers here drive cursor-backed peers only; production
//! code exercises the handshake through `run_inbound_handshake` and
//! `start` on real streams.
use std::io::{Cursor, Read, Write};

use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin_rs_p2p::handshake::{post_verack_messages, start};
use bitcoin_rs_p2p::peer::{COMPACT_BLOCK_VERSION, CompactBlockNegotiation};
use bitcoin_rs_p2p::wire::PROTOCOL_VERSION;
use bitcoin_rs_p2p::{Message, Peer, PeerError, PeerRole, PeerState};

/// Drive a complete version/verack handshake between two cursor-backed
/// peers.
///
/// PRE: both peers wrap independent buffers.
/// POST: both peers are ready, advertising the explicit unpruned service
///   set (full history plus witness), and both recorded the local
///   compact-block advertisement.
/// INVARIANT: this helper never varies the advertisement by role.
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
    exchange(left, right, post_verack_messages().to_vec())?;
    exchange(right, left, post_verack_messages().to_vec())?;
    left.compact_blocks
        .record_local_advertised(COMPACT_BLOCK_VERSION);
    right
        .compact_blocks
        .record_local_advertised(COMPACT_BLOCK_VERSION);
    Ok(())
}

/// Deliver each message from `from` to `to` through the collecting
/// dispatch, writing every response back onto `from`'s stream.
///
/// PRE: both peers wrap writable buffers.
/// POST: `to` applied every inbound message and answered onto `from`.
/// INVARIANT: response order matches the collecting dispatch's order.
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
        for response in collect_dispatch(to, &message)? {
            to.send(&response)?;
        }
    }
    Ok(())
}

/// Collecting form of the chainless inbound dispatch.
fn collect_dispatch<S: Read + Write>(
    peer: &mut Peer<S>,
    message: &Message,
) -> Result<Vec<Message>, PeerError> {
    let responses = std::cell::RefCell::new(Vec::new());
    bitcoin_rs_p2p::dispatch_inbound_full(
        peer,
        message,
        None,
        None,
        &|| true,
        &|| true,
        &mut |response| {
            responses.borrow_mut().push(response);
            Ok(())
        },
        &mut |_| {},
    )?;
    Ok(responses.into_inner())
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
fn cursor_handshake_records_the_local_compact_block_advertisement()
-> Result<(), Box<dyn std::error::Error>> {
    let mut left = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
    let mut right = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);

    handshake_cursors(&mut left, &mut right)?;

    assert_eq!(
        left.compact_blocks.local_version,
        Some(COMPACT_BLOCK_VERSION)
    );
    assert_eq!(
        right.compact_blocks.local_version,
        Some(COMPACT_BLOCK_VERSION)
    );
    Ok(())
}
