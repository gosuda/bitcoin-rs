use bitcoin_rs_primitives::PeerEndpoint;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::secp256k1::rand::SeedableRng as _;
use bitcoin::secp256k1::rand::rngs::StdRng;

use super::configure_peer_stream;
use super::{
    ConnectionShared, bind_listener, run_message_loop, run_outbound_handshake, serve,
    spawn_pinned_outbound_connection, test_shared,
};
use crate::bip324::{Handshake, msg_type};
use crate::connection::QueuedFrame;
use crate::transport::{Negotiated, SendTransport, TransportProtocol, establish};
use crate::{Message, Peer, PeerError, PeerLease, PeerRole, PeerTable, wire};

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

fn lease_with_replies() -> (PeerLease, crossbeam_channel::Receiver<QueuedFrame>) {
    let (outbound, replies) = crossbeam_channel::unbounded();
    (PeerLease::new(outbound), replies)
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

type Listening = (PeerEndpoint, Arc<AtomicBool>, std::thread::JoinHandle<()>);

fn listen(shared: ConnectionShared) -> Result<Listening, Box<dyn std::error::Error>> {
    let listener = bind_listener(
        PeerEndpoint::from(([127, 0, 0, 1], 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    let addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        let _ = serve(listener, flag, shared);
    });
    Ok((addr.into(), shutdown, handle))
}

fn connect(addr: PeerEndpoint) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(
        addr.socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    configure_peer_stream(&stream)?;
    Ok(stream)
}

fn read_until(
    peer: &mut Peer<TcpStream>,
    wanted: &Message,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = deadline();
    while Instant::now() < deadline {
        match peer.read_message() {
            Ok(Some((message, _))) if &message == wanted => return Ok(()),
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

fn handshake_and_ping(addr: PeerEndpoint, stream: TcpStream, negotiated: Negotiated) -> TestResult {
    let (client, _) = shared(false);
    let lease = lease();
    let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
    run_outbound_handshake(&mut peer, 7, 0, &lease, deadline(), addr, &client)?;
    peer.send(&Message::Ping(41))?;
    read_until(&mut peer, &Message::Pong(41))
}

#[test]
fn bip434_windows_preserve_bip332_and_package_negotiation_on_v1_and_v2() -> TestResult {
    use crate::feature::{FEATURE_VERSION, FeatureAnnouncement};
    use crate::packages::{PKG_RELAY_ANC, PKG_RELAY_PKGTXNS, SendPackages};
    for v2 in [false, true] {
        for version in [FEATURE_VERSION - 1, FEATURE_VERSION] {
            let (mut listener_shared, table) = shared(v2);
            listener_shared.relay_offers = super::RelayOffers {
                package_relay: true,
                stale_tip_relay: true,
                stale_tip_prefers_blocks: true,
            };
            let (addr, shutdown, handle) = listen(listener_shared)?;
            let result = (|| -> TestResult {
                let mut stream = connect(addr)?;
                let negotiated = if v2 {
                    let mut handshake =
                        Handshake::initiator(MAGIC, &mut StdRng::seed_from_u64(434));
                    establish(&mut stream, &mut handshake, MAGIC, &lease(), deadline())?
                } else {
                    Negotiated::v1(MAGIC)
                };
                let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
                let mut announcement = crate::handshake::version_message(
                    434,
                    0,
                    PeerRole::FullRelay,
                    ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                );
                announcement.version = version;
                peer.send(&Message::Version(announcement))?;
                let until = deadline();
                let mut commands = Vec::new();
                loop {
                    if Instant::now() >= until {
                        return Err("server handshake timed out".into());
                    }
                    match peer.read_message() {
                        Ok(Some((message, _))) => {
                            commands.push(message.command().to_string());
                            crate::fsm::step(&mut peer, &message)?;
                            if message == Message::Verack {
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(PeerError::Io(error)) if crate::recv::is_poll_timeout(&error) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                let mut expected = vec!["version", "wtxidrelay", "sendaddrv2", "sendheaders"];
                if version >= FEATURE_VERSION {
                    expected.push("feature");
                }
                expected.extend(["sendpackages", "verack"]);
                assert_eq!(commands, expected);
                assert_eq!(
                    peer.remote_feature(b"BIP332"),
                    (version >= FEATURE_VERSION).then_some([1].as_slice())
                );
                if version >= FEATURE_VERSION {
                    peer.send(&Message::Feature(FeatureAnnouncement::bip332(true)))?;
                }
                peer.send(&Message::WtxidRelay)?;
                peer.send(&Message::SendPackages(SendPackages {
                    versions: PKG_RELAY_PKGTXNS | PKG_RELAY_ANC,
                }))?;
                peer.send(&Message::Verack)?;
                assert!(matches!(
                    peer.send(&Message::Feature(FeatureAnnouncement::bip332(true))),
                    Err(PeerError::Protocol(_))
                ));
                peer.send(&Message::Ping(434))?;
                read_until(&mut peer, &Message::Pong(434))?;
                Ok(())
            })();
            table.cancel_all();
            shutdown.store(true, Ordering::Relaxed);
            handle.join().map_err(|_| "listener panicked")?;
            result?;
        }
    }
    Ok(())
}

#[test]
fn a_v2_listener_negotiates_bip324_with_a_v2_initiator() -> TestResult {
    let (listener_shared, _) = shared(true);
    let (addr, shutdown, handle) = listen(listener_shared)?;

    let mut stream = connect(addr)?;
    let mut handshake = Handshake::initiator(MAGIC, &mut StdRng::seed_from_u64(1));
    let negotiated = establish(&mut stream, &mut handshake, MAGIC, &lease(), deadline())?;
    assert!(matches!(negotiated.protocol, TransportProtocol::V2 { .. }));
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
    let server = TcpListener::bind(
        PeerEndpoint::from(([127, 0, 0, 1], 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
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
        peer.send(&Message::Ping(42))
            .map_err(|error| error.to_string())?;
        read_until(&mut peer, &Message::Pong(42)).map_err(|error| error.to_string())?;
        Ok(peer.transport())
    });

    let (dialer, dialer_table) = shared(true);
    let dial = spawn_pinned_outbound_connection(addr.into(), dialer, PeerRole::FullRelay);
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
    let server = TcpListener::bind(
        PeerEndpoint::from(([127, 0, 0, 1], 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    let addr = server.local_addr()?;
    let mut stream = connect(addr.into())?;
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

fn wait_for_writer_done(done_wait: &crossbeam_channel::Receiver<()>) {
    let started = Instant::now();
    loop {
        match done_wait.recv_timeout(Duration::from_millis(200)) {
            Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the decoy writer never finished after the stop"
        );
    }
}

fn spawn_decoy_then_ping_writer(
    server: TcpListener,
    stop: Arc<AtomicBool>,
    writer_lease: PeerLease,
    done: crossbeam_channel::Sender<()>,
) -> std::thread::JoinHandle<Result<(), String>> {
    std::thread::spawn(move || -> Result<(), String> {
        let (stream, _) = loop {
            match server.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if stop.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.to_string()),
            }
        };
        configure_peer_stream(&stream).map_err(|error| error.to_string())?;
        let mut stream = stream;
        let mut handshake = Handshake::initiator(MAGIC, &mut StdRng::seed_from_u64(4));
        let negotiated = establish(
            &mut stream,
            &mut handshake,
            MAGIC,
            &writer_lease,
            deadline(),
        )
        .map_err(|error| error.to_string())?;
        if !matches!(negotiated.protocol, TransportProtocol::V2 { .. }) {
            return Err("expected a v2 transport".into());
        }
        let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
        crate::handshake::run_inbound_handshake(
            &mut peer,
            9,
            0,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            &writer_lease,
            deadline(),
        )
        .map_err(|error| error.to_string())?;
        let mut cipher = match peer.take_send_transport() {
            Some(SendTransport::V2(cipher)) => cipher,
            _ => return Err("expected a v2 send transport".into()),
        };
        for _ in 0..2 {
            let decoy = cipher
                .seal(&[0; 16], &[], true)
                .map_err(|error| error.to_string())?;
            std::io::Write::write_all(&mut peer.stream, &decoy)
                .map_err(|error| error.to_string())?;
        }
        let payload =
            wire::encode_payload(&Message::Ping(41)).map_err(|error| error.to_string())?;
        let contents = msg_type::encode(&Message::Ping(41).command(), &payload);
        let ping = cipher
            .seal(&contents, &[], false)
            .map_err(|error| error.to_string())?;
        std::io::Write::write_all(&mut peer.stream, &ping).map_err(|error| error.to_string())?;

        while !stop.load(Ordering::Relaxed) {
            let decoy = cipher
                .seal(&[0; 16], &[], true)
                .map_err(|error| error.to_string())?;
            match std::io::Write::write_all(&mut peer.stream, &decoy) {
                Ok(()) => {}
                Err(_) if stop.load(Ordering::Relaxed) => break,
                Err(error) => return Err(error.to_string()),
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = done.send(());
        Ok(())
    })
}

#[test]
fn a_decoy_only_peer_yields_and_lease_cancel_ends_the_loop() -> TestResult {
    let server = TcpListener::bind(
        PeerEndpoint::from(([127, 0, 0, 1], 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    let addr = server.local_addr()?;
    server.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let (writer_lease, _) = lease_with_replies();
    let (done, done_wait) = crossbeam_channel::bounded(0);
    let writer =
        spawn_decoy_then_ping_writer(server, Arc::clone(&stop), writer_lease.clone(), done);

    let result = (|| -> Result<(Result<(), PeerError>, Duration), Box<dyn std::error::Error>> {
        let mut stream = connect(addr.into())?;
        let mut handshake = Handshake::responder(MAGIC, &mut StdRng::seed_from_u64(5));
        let negotiated = establish(&mut stream, &mut handshake, MAGIC, &lease(), deadline())?;
        if !matches!(negotiated.protocol, TransportProtocol::V2 { .. }) {
            return Err("expected a v2 transport".into());
        }

        let (client, _) = shared(false);
        let (lease, replies) = lease_with_replies();
        let cancel_handle = lease.clone();
        let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
        run_outbound_handshake(&mut peer, 7, 0, &lease, deadline(), addr.into(), &client)?;
        let loop_handle =
            std::thread::spawn(move || run_message_loop(&mut peer, addr, &lease, &client, None));
        let arrived = Instant::now();
        let pong = loop {
            match replies.recv_timeout(Duration::from_millis(200)) {
                Ok(frame) => break frame.into_message(),
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    return Err("the loop dropped the reply queue".into());
                }
            }
            if arrived.elapsed() >= Duration::from_secs(10) {
                return Err("the loop never dispatched the peer's ping past the decoy run".into());
            }
        };
        if pong != Message::Pong(41) {
            return Err("the decoy run must precede exactly one real message".into());
        }
        if replies.try_recv().is_ok() {
            return Err("the peer sent more than one real message".into());
        }
        let started = Instant::now();
        cancel_handle.cancel();
        let outcome = loop_handle
            .join()
            .map_err(|_| -> Box<dyn std::error::Error> { "loop panicked".into() })?;
        if started.elapsed() >= Duration::from_secs(2) {
            return Err("lease cancel must end a decoy-only session promptly".into());
        }
        Ok((outcome, started.elapsed()))
    })();
    stop.store(true, Ordering::Relaxed);
    writer_lease.cancel();
    wait_for_writer_done(&done_wait);
    let writer_failure = writer
        .join()
        .map_err(|_| -> Box<dyn std::error::Error> { "decoy writer panicked".into() });
    let (outcome, elapsed) = result?;
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(
        elapsed < Duration::from_secs(2),
        "lease cancel must end a decoy-only session promptly"
    );
    writer_failure?.map_err(|error| format!("decoy writer failed: {error}"))?;
    Ok(())
}
