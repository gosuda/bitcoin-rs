//! P2P listener manual ban enforcement coverage.
use std::error::Error;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use bitcoin::p2p::Magic;
use bitcoin_rs_p2p::listener::{serve_with_shutdown, spawn_outbound_connection};
use bitcoin_rs_p2p::{BannedSubnet, IpSubnet, PeerError};
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

    let registry = Arc::new(RwLock::new(Vec::new()));
    let outbound = Arc::new(RwLock::new(hashbrown::HashMap::new()));
    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
    let banned = Arc::new(RwLock::new(vec![ban(IpSubnet::from_ip(addr.ip()))]));

    let handle = spawn_outbound_connection(
        addr,
        Magic::BITCOIN,
        registry,
        outbound,
        headers_tx,
        blocks_tx,
        banned,
    );
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
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let helper = TcpListener::bind(bind_addr)?;
    let addr = helper.local_addr()?;
    drop(helper);

    let shutdown = Arc::new(AtomicBool::new(false));
    let listener_shutdown = Arc::clone(&shutdown);
    let registry = Arc::new(RwLock::new(Vec::new()));
    let listener_registry = Arc::clone(&registry);
    let outbound = Arc::new(RwLock::new(hashbrown::HashMap::new()));
    let listener_outbound = Arc::clone(&outbound);
    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
    let banned = Arc::new(RwLock::new(vec![ban(IpSubnet::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
    )?)]));
    let listener_banned = Arc::clone(&banned);

    let handle = thread::spawn(move || {
        serve_with_shutdown(
            addr,
            listener_shutdown,
            Magic::BITCOIN,
            listener_registry,
            listener_outbound,
            headers_tx,
            blocks_tx,
            listener_banned,
        )
    });

    let mut client = match connect_with_retry(addr, Duration::from_secs(1)) {
        Ok(client) => client,
        Err(error) => {
            shutdown.store(true, Ordering::Relaxed);
            join_listener(handle)?;
            return Err(error.into());
        }
    };

    wait_for_disconnect(&mut client, Duration::from_secs(1))?;
    assert!(registry.read().is_empty());

    shutdown.store(true, Ordering::Relaxed);
    join_listener(handle)?;

    Ok(())
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
