//! Handshake state-machine round trips.
use std::io::Cursor;

use bitcoin::p2p::Magic;
use bitcoin_rs_p2p::handshake::handshake_cursors;
use bitcoin_rs_p2p::{Peer, PeerState};

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
