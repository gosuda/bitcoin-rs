use bitcoin_rs_consensus::primitives::{PeerEndpoint, USER_AGENT};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_wire::PeerRole;
use bitcoin_rs_wire::handshake::version_message;
use bitcoin_rs_wire::listener::{
    ConnectionShared, bind_listener, serve, spawn_outbound_connection,
};
use bitcoin_rs_wire::wire::{Message, read_message, write_message};
use bitcoin_rs_wire::{
    BannedSubnet, IpSubnet, ListenerExtras, NetworkActivity, PeerError, PeerTable,
};
use parking_lot::RwLock;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Peer(#[from] PeerError),
    #[error(transparent)]
    Listener(#[from] bitcoin_rs_wire::listener::ListenerError),
    #[error(transparent)]
    SubnetParse(#[from] bitcoin_rs_wire::SubnetParseError),
}

#[test]
fn outbound_ban_short_circuits_before_connect_with_typed_error() -> Result<(), TestError> {
    let helper = TcpListener::bind(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    helper.set_nonblocking(true)?;
    let addr = helper.local_addr()?;
    let accept_helper = helper.try_clone()?;
    accept_helper.set_nonblocking(true)?;
    let helper_shutdown = Arc::new(AtomicBool::new(false));
    let accept_shutdown = Arc::clone(&helper_shutdown);
    let accept_handle =
        thread::spawn(move || accept_one_connection(&accept_helper, &accept_shutdown));
    let shared = wiring(
        Arc::new(PeerTable::new()),
        Arc::new(RwLock::new(vec![ban(IpSubnet::from_ip(addr.ip()))])),
        Arc::new(AtomicBool::new(true)),
        bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
    );

    let handle = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);
    let result = match handle.join() {
        Ok(result) => result,
        Err(error) => std::panic::resume_unwind(error),
    };
    helper_shutdown.store(true, Ordering::Relaxed);
    let accepted = join_accept(accept_handle)?;
    assert!(
        !accepted,
        "outbound ban should reject before opening a TCP connection"
    );

    match result {
        Err(PeerError::BannedDestination(ip)) => assert_eq!(ip.ip(), Some(addr.ip())),
        other => {
            return Err(io::Error::other(format!(
                "expected banned destination error, got {other:?}"
            ))
            .into());
        }
    }

    Ok(())
}

#[test]
fn inbound_ban_drops_connection_pre_handshake() -> Result<(), TestError> {
    let listener = bind_listener(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    let addr = listener.local_addr()?;

    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    let peer_table = Arc::new(PeerTable::new());
    let banned = Arc::new(RwLock::new(vec![ban(IpSubnet::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
    )?)]));
    let shared = wiring(
        Arc::clone(&peer_table),
        banned,
        Arc::new(AtomicBool::new(true)),
        bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
    );

    let listener_shutdown = shutdown.reader();
    let handle = thread::spawn(move || serve(listener, listener_shutdown, shared));

    let mut client = match connect_with_retry(addr.into(), Duration::from_secs(1)) {
        Ok(client) => client,
        Err(error) => {
            shutdown.trigger();
            join_listener(handle)?;
            return Err(error.into());
        }
    };

    wait_for_disconnect(&mut client, Duration::from_secs(1))?;
    assert!(peer_table.is_empty());

    shutdown.trigger();
    join_listener(handle)?;

    Ok(())
}

#[test]
fn network_inactive_drops_inbound_pre_handshake() -> Result<(), TestError> {
    let listener = bind_listener(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    let addr = listener.local_addr()?;

    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    let peer_table = Arc::new(PeerTable::new());
    let shared = wiring(
        Arc::clone(&peer_table),
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(AtomicBool::new(false)),
        bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
    );

    let listener_shutdown = shutdown.reader();
    let handle = thread::spawn(move || serve(listener, listener_shutdown, shared));

    let mut client = connect_with_retry(addr.into(), Duration::from_secs(1))?;
    wait_for_disconnect(&mut client, Duration::from_secs(1))?;
    assert!(peer_table.is_empty());

    shutdown.trigger();
    join_listener(handle)?;
    Ok(())
}

#[test]
fn network_active_blocks_outbound_until_reenabled() -> Result<(), TestError> {
    let helper = TcpListener::bind(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    helper.set_nonblocking(true)?;
    let addr = helper.local_addr()?;
    let accept_helper = helper.try_clone()?;
    accept_helper.set_nonblocking(true)?;
    let accept_shutdown = Arc::new(AtomicBool::new(false));
    let accept_handle = thread::spawn({
        let accept_shutdown = Arc::clone(&accept_shutdown);
        move || accept_one_connection(&accept_helper, &accept_shutdown)
    });

    let network_active = Arc::new(AtomicBool::new(false));
    let shared = wiring(
        Arc::new(PeerTable::new()),
        Arc::new(RwLock::new(Vec::new())),
        Arc::clone(&network_active),
        bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
    );

    let inactive = spawn_outbound_connection(addr.into(), shared.clone(), PeerRole::FullRelay);
    let inactive = inactive
        .join()
        .map_err(|_| io::Error::other("inactive outbound thread panicked"))?;
    assert!(
        matches!(inactive, Err(PeerError::Protocol("network inactive"))),
        "inactive outbound attempt must exit before TCP connect, got {inactive:?}"
    );
    thread::sleep(Duration::from_millis(100));
    assert!(
        !accept_handle.is_finished(),
        "inactive outbound attempt opened a TCP connection"
    );

    network_active.store(true, Ordering::Release);
    let active = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);
    assert!(join_accept(accept_handle)?);
    let _ = active
        .join()
        .map_err(|_| io::Error::other("active outbound thread panicked"))?;
    accept_shutdown.store(true, Ordering::Relaxed);
    Ok(())
}

#[test]
fn cancelled_start_refuses_outbound_before_connect() -> Result<(), TestError> {
    let helper = TcpListener::bind(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    helper.set_nonblocking(true)?;
    let addr = helper.local_addr()?;
    let accept_helper = helper.try_clone()?;
    accept_helper.set_nonblocking(true)?;
    let accept_shutdown = Arc::new(AtomicBool::new(false));
    let accept_handle = thread::spawn({
        let accept_shutdown = Arc::clone(&accept_shutdown);
        move || accept_one_connection(&accept_helper, &accept_shutdown)
    });

    let peer_table = Arc::new(PeerTable::new());
    let cancelled = bitcoin_rs_consensus::latch::LatchWriter::new();
    cancelled.trigger();
    let shared = wiring(
        Arc::clone(&peer_table),
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(AtomicBool::new(true)),
        cancelled.reader(),
    );

    let refused = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay)
        .join()
        .map_err(|_| io::Error::other("cancelled outbound thread panicked"))?;
    assert!(
        matches!(refused, Err(PeerError::Protocol("p2p startup cancelled"))),
        "a cancelled start must refuse the dial, got {refused:?}"
    );
    thread::sleep(Duration::from_millis(100));
    accept_shutdown.store(true, Ordering::Relaxed);
    assert!(
        !join_accept(accept_handle)?,
        "a cancelled start must not open a TCP connection"
    );
    assert!(peer_table.is_empty());
    Ok(())
}

#[test]
fn live_handshake_traffic_reaches_the_aggregate_ledger() -> Result<(), TestError> {
    let listener = TcpListener::bind(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    let addr = listener.local_addr()?;

    let peer_table = Arc::new(PeerTable::new());
    let shared = wiring(
        Arc::clone(&peer_table),
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(AtomicBool::new(true)),
        bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
    );
    let outbound_handle = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);

    let (mut server, _) = listener.accept()?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    server.set_write_timeout(Some(Duration::from_secs(5)))?;
    let Ok((Message::Version(_), _)) = read_message(&mut server, Magic::BITCOIN) else {
        return Err(io::Error::other("the dial opens with a version message").into());
    };
    write_message(
        &mut server,
        Magic::BITCOIN,
        &Message::Version(version_message(
            1,
            0,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            USER_AGENT,
        )),
    )?;
    write_message(&mut server, Magic::BITCOIN, &Message::Verack)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (received, sent) = peer_table.traffic_totals();
        if received > 0 && sent > 0 {
            break;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "handshake traffic never reached the aggregate ledger \
                 (received={received}, sent={sent})"
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert_ne!(peer_table.len(), 0);

    drop(server);
    if outbound_handle.join().is_err() {
        return Err(io::Error::other("outbound thread panicked during teardown").into());
    }
    Ok(())
}

#[test]
fn self_dial_is_refused_by_its_own_in_flight_nonce() -> Result<(), TestError> {
    let listener = bind_listener(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    let addr = listener.local_addr()?;

    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    let session_cancel = Arc::new(bitcoin_rs_consensus::latch::LatchWriter::new());
    let peer_table = Arc::new(PeerTable::new());
    let shared = wiring(
        Arc::clone(&peer_table),
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(AtomicBool::new(true)),
        session_cancel.reader(),
    );

    let listener_shutdown = shutdown.reader();
    let serve_shared = shared.clone();
    let serve_handle = thread::spawn(move || serve(listener, listener_shutdown, serve_shared));
    let outbound_handle = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);

    let deadline = Instant::now() + Duration::from_secs(5);
    while !outbound_handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    let finished = outbound_handle.is_finished();

    session_cancel.trigger();
    peer_table.cancel_all();
    shutdown.trigger();
    join_listener(serve_handle)?;
    let joined = outbound_handle.join();
    assert!(
        finished,
        "a dial to our own listener must not stay connected"
    );
    match joined {
        Ok(Err(_)) => {}
        Ok(Ok(())) => {
            return Err(io::Error::other("a dial to our own listener completed").into());
        }
        Err(_) => return Err(io::Error::other("outbound thread panicked").into()),
    }
    assert!(
        peer_table.live_sessions().is_empty(),
        "a refused self-connection leaves no live session"
    );
    Ok(())
}

fn wiring(
    peer_table: Arc<PeerTable>,
    banned: Arc<RwLock<Vec<BannedSubnet>>>,
    network_active: Arc<AtomicBool>,
    session_cancel: bitcoin_rs_consensus::latch::LatchReader,
) -> ConnectionShared {
    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
    ConnectionShared::new(
        peer_table,
        banned,
        Arc::new(NetworkActivity::from_shared(network_active)),
        session_cancel,
        None,
        Magic::BITCOIN,
        headers_tx,
        blocks_tx,
        None,
        None,
        ListenerExtras::default(),
    )
}

fn ban(subnet: IpSubnet) -> BannedSubnet {
    BannedSubnet {
        subnet,
        banned_until: None,
        ban_created: SystemTime::now(),
        reason: String::from("test ban"),
    }
}

fn connect_with_retry(addr: PeerEndpoint, timeout: Duration) -> io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(
            addr.socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        ) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(error);
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_disconnect(stream: &mut TcpStream, timeout: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(20)))?;
    let deadline = Instant::now() + timeout;
    let mut byte = [0_u8; 1];

    loop {
        match stream.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(io::Error::other("banned inbound connection sent data")),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Ok(()),
        }

        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "banned inbound connection stayed open",
            ));
        }
    }
}

fn accept_one_connection(listener: &TcpListener, shutdown: &Arc<AtomicBool>) -> io::Result<bool> {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer_addr)) => {
                drop(stream);
                return Ok(true);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

fn join_accept(handle: thread::JoinHandle<io::Result<bool>>) -> Result<bool, TestError> {
    match handle.join() {
        Ok(Ok(accepted)) => Ok(accepted),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(io::Error::other("helper accept thread panicked").into()),
    }
}

fn join_listener(
    handle: thread::JoinHandle<Result<(), bitcoin_rs_wire::listener::ListenerError>>,
) -> Result<(), TestError> {
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(io::Error::other("listener thread panicked").into()),
    }
}
