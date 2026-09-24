//! P2P listener manual-ban and network-control enforcement coverage.
use std::error::Error;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use bitcoin::p2p::Magic;
use bitcoin_rs_p2p::listener::{ConnectionShared, bind_listener, serve, spawn_outbound_connection};
use bitcoin_rs_p2p::{BannedSubnet, IpSubnet, NetworkActivity, PeerError, PeerRole, PeerTable};
use parking_lot::RwLock;

#[test]
fn outbound_ban_short_circuits_before_connect_with_typed_error() -> Result<(), Box<dyn Error>> {
    let helper = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    helper.set_nonblocking(true)?;
    let addr = helper.local_addr()?;
    let accept_helper = helper.try_clone()?;
    let helper_shutdown = Arc::new(AtomicBool::new(false));
    let accept_shutdown = Arc::clone(&helper_shutdown);
    let accept_handle =
        thread::spawn(move || accept_one_connection(&accept_helper, &accept_shutdown));

    let shared = wiring(
        Arc::new(PeerTable::new()),
        Arc::new(RwLock::new(vec![ban(IpSubnet::from_ip(addr.ip()))])),
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicBool::new(false)),
    );

    let handle = spawn_outbound_connection(addr, shared, PeerRole::FullRelay);
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
        Err(PeerError::BannedDestination(ip)) => assert_eq!(ip, addr.ip()),
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
fn inbound_ban_drops_connection_pre_handshake() -> Result<(), Box<dyn Error>> {
    let listener = bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = listener.local_addr()?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let peer_table = Arc::new(PeerTable::new());
    let banned = Arc::new(RwLock::new(vec![ban(IpSubnet::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
    )?)]));
    let shared = wiring(
        Arc::clone(&peer_table),
        banned,
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicBool::new(false)),
    );

    let listener_shutdown = Arc::clone(&shutdown);
    let handle = thread::spawn(move || serve(listener, listener_shutdown, shared));

    let mut client = match connect_with_retry(addr, Duration::from_secs(1)) {
        Ok(client) => client,
        Err(error) => {
            shutdown.store(true, Ordering::Relaxed);
            join_listener(handle)?;
            return Err(error.into());
        }
    };

    wait_for_disconnect(&mut client, Duration::from_secs(1))?;
    assert!(peer_table.is_empty());

    shutdown.store(true, Ordering::Relaxed);
    join_listener(handle)?;

    Ok(())
}

#[test]
fn network_inactive_drops_inbound_pre_handshake() -> Result<(), Box<dyn Error>> {
    let listener = bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = listener.local_addr()?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let peer_table = Arc::new(PeerTable::new());
    let shared = wiring(
        Arc::clone(&peer_table),
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );

    let listener_shutdown = Arc::clone(&shutdown);
    let handle = thread::spawn(move || serve(listener, listener_shutdown, shared));

    let mut client = connect_with_retry(addr, Duration::from_secs(1))?;
    wait_for_disconnect(&mut client, Duration::from_secs(1))?;
    assert!(peer_table.is_empty());

    shutdown.store(true, Ordering::Relaxed);
    join_listener(handle)?;
    Ok(())
}

#[test]
fn network_active_blocks_outbound_until_reenabled() -> Result<(), Box<dyn Error>> {
    let helper = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    helper.set_nonblocking(true)?;
    let addr = helper.local_addr()?;
    let accept_helper = helper.try_clone()?;
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
        Arc::new(AtomicBool::new(false)),
    );

    let inactive = spawn_outbound_connection(addr, shared.clone(), PeerRole::FullRelay);
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
    let active = spawn_outbound_connection(addr, shared, PeerRole::FullRelay);
    assert!(join_accept(accept_handle)?);
    let _ = active
        .join()
        .map_err(|_| io::Error::other("active outbound thread panicked"))?;
    accept_shutdown.store(true, Ordering::Relaxed);
    Ok(())
}

#[test]
fn cancelled_start_refuses_outbound_before_connect() -> Result<(), Box<dyn Error>> {
    let helper = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    helper.set_nonblocking(true)?;
    let addr = helper.local_addr()?;
    let accept_helper = helper.try_clone()?;
    let accept_shutdown = Arc::new(AtomicBool::new(false));
    let accept_handle = thread::spawn({
        let accept_shutdown = Arc::clone(&accept_shutdown);
        move || accept_one_connection(&accept_helper, &accept_shutdown)
    });

    let peer_table = Arc::new(PeerTable::new());
    let shared = wiring(
        Arc::clone(&peer_table),
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicBool::new(true)),
    );

    let refused = spawn_outbound_connection(addr, shared, PeerRole::FullRelay)
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

/// Wiring for one test start epoch with no ready callback.
fn wiring(
    peer_table: Arc<PeerTable>,
    banned: Arc<RwLock<Vec<BannedSubnet>>>,
    network_active: Arc<AtomicBool>,
    session_cancel: Arc<AtomicBool>,
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

fn connect_with_retry(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr) {
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

fn join_accept(handle: thread::JoinHandle<io::Result<bool>>) -> Result<bool, Box<dyn Error>> {
    match handle.join() {
        Ok(Ok(accepted)) => Ok(accepted),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(io::Error::other("helper accept thread panicked").into()),
    }
}

fn join_listener(
    handle: thread::JoinHandle<Result<(), bitcoin_rs_p2p::listener::ListenerError>>,
) -> Result<(), Box<dyn Error>> {
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(io::Error::other("listener thread panicked").into()),
    }
}
