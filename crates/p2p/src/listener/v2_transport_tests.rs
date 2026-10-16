//! BIP324 negotiation over real loopback sockets: inbound v1/v2 detection,
//! outbound v2 with Core's single v1 retry, and the handshake deadline.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::secp256k1::rand::SeedableRng as _;
use bitcoin::secp256k1::rand::rngs::StdRng;

use super::configure_peer_stream;
use super::{
    ConnectionShared, bind_listener, run_outbound_handshake, serve,
    spawn_pinned_outbound_connection, test_shared,
};
use crate::bip324::Handshake;
use crate::transport::{Negotiated, TransportProtocol, establish};
use crate::{Message, Peer, PeerError, PeerLease, PeerRole, PeerTable};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAGIC: Magic = Magic::BITCOIN;

fn shared(v2_transport: bool) -> (ConnectionShared, Arc<PeerTable>) {
    let table = Arc::new(PeerTable::new());
    let mut shared = test_shared(
        Arc::clone(&table),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    );
    shared.v2_transport = v2_transport;
    if v2_transport {
        shared.local_services |= ServiceFlags::P2P_V2;
    }
    (shared, table)
}

fn lease() -> PeerLease {
    PeerLease::new(crossbeam_channel::unbounded().0)
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

/// A serving listener: its address, the flag that stops it, and its thread.
type Listening = (SocketAddr, Arc<AtomicBool>, std::thread::JoinHandle<()>);

/// A listener serving `shared` until the returned flag is raised.
fn listen(shared: ConnectionShared) -> Result<Listening, Box<dyn std::error::Error>> {
    let listener = bind_listener(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        let _ = serve(listener, flag, shared);
    });
    Ok((addr, shutdown, handle))
}

fn connect(addr: SocketAddr) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(addr)?;
    configure_peer_stream(&stream)?;
    Ok(stream)
}

/// Reads until `wanted` arrives, skipping other messages and poll timeouts.
fn read_until(
    peer: &mut Peer<TcpStream>,
    wanted: &Message,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = deadline();
    while Instant::now() < deadline {
        match peer.read_message() {
            Ok((message, _)) if &message == wanted => return Ok(()),
            Ok(_) => {}
            Err(PeerError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(format!("{wanted:?} never arrived").into())
}

/// Completes the version handshake as an outbound peer of `addr` over
/// `negotiated`, then proves the remote message loop answers over it.
fn handshake_and_ping(addr: SocketAddr, stream: TcpStream, negotiated: Negotiated) -> TestResult {
    let (client, _) = shared(false);
    let lease = lease();
    let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
    run_outbound_handshake(&mut peer, 7, 0, &lease, deadline(), addr, &client)?;
    peer.send(&Message::Ping(41))?;
    read_until(&mut peer, &Message::Pong(41))
}

#[test]
fn a_v2_listener_negotiates_bip324_with_a_v2_initiator() -> TestResult {
    let (listener_shared, _) = shared(true);
    let (addr, shutdown, handle) = listen(listener_shared)?;

    let mut stream = connect(addr)?;
    let mut handshake = Handshake::initiator(MAGIC, &mut StdRng::seed_from_u64(1));
    let negotiated = establish(&mut stream, &mut handshake, MAGIC, &lease(), deadline())?;
    assert!(matches!(negotiated.protocol, TransportProtocol::V2 { .. }));
    // The listener's writer thread answers the ping over the session.
    handshake_and_ping(addr, stream, negotiated)?;

    shutdown.store(true, Ordering::Relaxed);
    handle.join().map_err(|_| "listener panicked")?;
    Ok(())
}

#[test]
fn a_v2_listener_still_serves_a_v1_peer() -> TestResult {
    let (listener_shared, _) = shared(true);
    let (addr, shutdown, handle) = listen(listener_shared)?;

    handshake_and_ping(addr, connect(addr)?, Negotiated::v1(MAGIC))?;

    shutdown.store(true, Ordering::Relaxed);
    handle.join().map_err(|_| "listener panicked")?;
    Ok(())
}

#[test]
fn an_outbound_v2_dial_negotiates_bip324() -> TestResult {
    let server = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = server.local_addr()?;
    let responder = std::thread::spawn(move || -> Result<TransportProtocol, String> {
        let (stream, _) = server.accept().map_err(|error| error.to_string())?;
        configure_peer_stream(&stream).map_err(|error| error.to_string())?;
        let mut stream = stream;
        let lease = lease();
        let mut handshake = Handshake::responder(MAGIC, &mut StdRng::seed_from_u64(2));
        let negotiated = establish(&mut stream, &mut handshake, MAGIC, &lease, deadline())
            .map_err(|error| error.to_string())?;
        let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
        crate::handshake::run_inbound_handshake(
            &mut peer,
            9,
            0,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            &lease,
            deadline(),
        )
        .map_err(|error| error.to_string())?;
        // The dialer's writer thread answers the ping over the session.
        peer.send(&Message::Ping(42))
            .map_err(|error| error.to_string())?;
        read_until(&mut peer, &Message::Pong(42)).map_err(|error| error.to_string())?;
        Ok(peer.transport())
    });

    let (dialer, dialer_table) = shared(true);
    let dial = spawn_pinned_outbound_connection(addr, dialer, PeerRole::FullRelay);
    let protocol = responder.join().map_err(|_| "responder panicked")??;
    assert!(matches!(protocol, TransportProtocol::V2 { .. }));

    dialer_table.cancel_all();
    let _ = dial.join().map_err(|_| "dialer panicked")?;
    Ok(())
}

#[test]
fn both_ends_publish_the_negotiated_v2_session() -> TestResult {
    let (listener_shared, listener_table) = shared(true);
    let (addr, shutdown, handle) = listen(listener_shared)?;

    let (dialer, dialer_table) = shared(true);
    let dial = spawn_pinned_outbound_connection(addr, dialer, PeerRole::FullRelay);
    let deadline = deadline();
    let published = loop {
        if let (Some(outbound), Some(inbound)) = (
            dialer_table.infos().into_iter().next(),
            listener_table.infos().into_iter().next(),
        ) {
            break Some((outbound, inbound));
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    dialer_table.cancel_all();
    let _ = dial.join().map_err(|_| "dialer panicked")?;
    shutdown.store(true, Ordering::Relaxed);
    handle.join().map_err(|_| "listener panicked")?;

    let (outbound, inbound) = published.ok_or("the v2 connection never published both ends")?;
    let TransportProtocol::V2 { session_id } = outbound.transport else {
        return Err(format!("the dialer published {:?}", outbound.transport).into());
    };
    assert_eq!(
        inbound.transport,
        TransportProtocol::V2 { session_id },
        "both ends derive the same session id"
    );
    Ok(())
}

#[test]
fn an_unanswered_v2_dial_retries_once_over_v1() -> TestResult {
    // A v1-only listener reads the v2 key as a v1 header for another network
    // and closes without answering.
    let (listener_shared, listener_table) = shared(false);
    let (addr, shutdown, handle) = listen(listener_shared)?;

    let (dialer, dialer_table) = shared(true);
    let dial = spawn_pinned_outbound_connection(addr, dialer, PeerRole::FullRelay);
    let deadline = deadline();
    let dialed = loop {
        let dialed = dialer_table.infos();
        if !dialed.is_empty() && !listener_table.infos().is_empty() {
            break Some(dialed);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let accepted = listener_table.len();

    dialer_table.cancel_all();
    let _ = dial.join().map_err(|_| "dialer panicked")?;
    shutdown.store(true, Ordering::Relaxed);
    handle.join().map_err(|_| "listener panicked")?;

    let dialed = dialed.ok_or("the v1 retry never completed its handshake")?;
    assert_eq!(accepted, 1, "only the v1 retry stayed connected");
    assert!(
        dialed
            .iter()
            .all(|info| info.transport == TransportProtocol::V1),
        "the retry publishes v1"
    );
    Ok(())
}

#[test]
fn a_silent_responder_ends_at_the_handshake_deadline() -> TestResult {
    let server = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = server.local_addr()?;
    let mut stream = connect(addr)?;
    let (_held, _) = server.accept()?;
    let mut handshake = Handshake::initiator(MAGIC, &mut StdRng::seed_from_u64(3));
    let started = Instant::now();
    let result = establish(
        &mut stream,
        &mut handshake,
        MAGIC,
        &lease(),
        started + Duration::from_millis(1500),
    );
    assert!(
        matches!(&result, Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut),
        "{result:?}"
    );
    assert!(!handshake.received_any(), "a silent peer allows a v1 retry");
    assert!(started.elapsed() < Duration::from_secs(10));
    Ok(())
}
