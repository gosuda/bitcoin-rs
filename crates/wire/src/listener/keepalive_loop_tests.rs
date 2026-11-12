#![expect(
    clippy::expect_used,
    reason = "fixture setup and frame reads must fail loudly"
)]

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::p2p::Magic;

use super::{run_connected_session, test_shared};
use crate::peer::PeerState;
use crate::test_support::synthetic_peer;
use crate::{Message, Peer, PeerEndpoint, PeerRemote};

#[test]
fn a_silent_outbound_peer_gets_the_keepalive_ping_and_is_expired() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let client = TcpStream::connect(address).expect("client connect");
    let (server, _accepted_addr) = listener.accept().expect("accept");

    let table = Arc::new(crate::PeerTable::new());
    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
    let shared = Arc::new(test_shared(Arc::clone(&table), headers_tx, blocks_tx));
    let _ = shared
        .test_keepalive_intervals
        .set((Duration::from_millis(100), Duration::from_millis(2_500)));

    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(outbound_tx);
    let source = PeerEndpoint::from(address);
    table.register(source, lease.clone());

    let counters = Arc::new(crate::PeerCounters::default());
    let stream = crate::CountingStream::from_connected(server, counters).expect("counting stream");
    let negotiated = crate::transport::Negotiated::v1(shared.magic);
    let mut peer = Peer::with_transport(stream, shared.magic, negotiated);
    peer.state = PeerState::Ready;

    let info = synthetic_peer(PeerRemote::Endpoint(source), 0);
    let session_shared = Arc::clone(&shared);
    let session = std::thread::spawn(move || {
        run_connected_session(&mut peer, source, &session_shared, lease, outbound_rx, info)
    });

    let started = Instant::now();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("client read timeout");
    let ping = read_ping(&client, shared.magic);
    drop(ping);
    assert!(
        started.elapsed() <= Duration::from_secs(3),
        "the keepalive ping must arrive at the first poll after the ping interval"
    );

    let exit = session.join().expect("session thread");
    assert!(
        exit.is_ok(),
        "expiry closes the session without a transport error: {exit:?}"
    );
    assert!(
        started.elapsed() <= Duration::from_secs(6),
        "a silent peer is expired after the timeout interval, not held forever"
    );
}

fn read_ping(client: &TcpStream, magic: Magic) -> Message {
    loop {
        let (message, _raw) =
            crate::wire::read_message(&mut &*client, magic).expect("client reads session frames");
        if matches!(message, Message::Ping(_)) {
            return message;
        }
    }
}
