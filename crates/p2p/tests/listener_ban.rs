//! P2P listener manual-ban and network-control enforcement coverage.
use std::error::Error;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use bitcoin::p2p::Magic;
use bitcoin_rs_p2p::listener::{
    serve_with_controls, serve_with_shutdown, spawn_outbound_connection,
    spawn_outbound_connection_with_controls,
};
use bitcoin_rs_p2p::{BannedSubnet, IpSubnet, NetworkControls, PeerError};
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

type LoopbackPeer = (
    Arc<NetworkControls>,
    SocketAddr,
    thread::JoinHandle<Result<(), bitcoin_rs_p2p::listener::ListenerError>>,
);
/// Spawns a controls-driven listener and dials it with a controls-driven
/// outbound connection; both sides register into the same shared state.
fn loopback_peer_pair(shutdown: &Arc<AtomicBool>) -> Result<LoopbackPeer, Box<dyn Error>> {
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let helper = TcpListener::bind(bind_addr)?;
    let addr = helper.local_addr()?;
    drop(helper);

    let registry = Arc::new(RwLock::new(Vec::new()));
    let outbound = Arc::new(RwLock::new(hashbrown::HashMap::new()));
    let banned = Arc::new(RwLock::new(Vec::new()));
    let controls = Arc::new(NetworkControls::new(
        Arc::clone(&registry),
        Arc::clone(&outbound),
        Arc::clone(&banned),
        8_333,
    ));

    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
    let listener_shutdown = Arc::clone(shutdown);
    let listener_controls = Arc::clone(&controls);
    let listener = thread::spawn(move || {
        serve_with_controls(
            addr,
            listener_shutdown,
            Magic::BITCOIN,
            listener_controls,
            headers_tx,
            blocks_tx,
            None,
            None,
            None,
        )
    });

    // Retry outbound dials until the controls map shows the outbound lease, or
    // a finished attempt fails for a reason other than ConnectionRefused.
    // Joining each refused attempt avoids silently losing a race against the
    // asynchronously started listener.
    let dial_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let (dial_headers_tx, _dial_headers_rx) = crossbeam_channel::unbounded();
        let (dial_blocks_tx, _dial_blocks_rx) = crossbeam_channel::unbounded();
        let dial_controls = Arc::clone(&controls);
        let dial = spawn_outbound_connection_with_controls(
            addr,
            Magic::BITCOIN,
            dial_controls,
            dial_headers_tx,
            dial_blocks_tx,
            None,
            None,
            None,
        );

        while !dial.is_finished() {
            if controls.peer_outbound().read().contains_key(&addr) {
                // Successful dial stays attached to shared state; detach the
                // handle the same way as before so tests join only the listener.
                drop(dial);
                return Ok((controls, addr, listener));
            }
            thread::sleep(Duration::from_millis(10));
        }

        let result = match dial.join() {
            Ok(result) => result,
            Err(error) => std::panic::resume_unwind(error),
        };
        match result {
            Ok(()) => {
                if controls.peer_outbound().read().contains_key(&addr) {
                    return Ok((controls, addr, listener));
                }
                shutdown.store(true, Ordering::Relaxed);
                let _ = join_listener(listener);
                return Err("outbound dial finished without registering a lease".into());
            }
            Err(PeerError::Io(error))
                if error.kind() == io::ErrorKind::ConnectionRefused
                    && Instant::now() < dial_deadline => {}
            Err(error) => {
                shutdown.store(true, Ordering::Relaxed);
                let _ = join_listener(listener);
                return Err(error.into());
            }
        }
    }
}

fn wait_until(deadline: Duration, predicate: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + deadline;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    predicate()
}

fn unix_micros_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
        })
}

#[test]
fn controls_see_both_connection_directions_and_handshake_registry() -> Result<(), Box<dyn Error>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (controls, addr, listener) = loopback_peer_pair(&shutdown)?;

    let handshake_done = wait_until(Duration::from_secs(5), || {
        controls
            .peer_registry()
            .read()
            .iter()
            .any(|p| p.addr == addr)
    });
    shutdown.store(true, Ordering::Relaxed);
    join_listener(listener)?;

    assert!(handshake_done, "inbound handshake must publish peer info");
    let counts = controls.connection_counts();
    assert_eq!(counts.total(), 2, "one inbound and one outbound connection");
    assert_eq!(counts.inbound, 1);
    assert_eq!(counts.outbound, 1);

    let peers = controls.connected_peers();
    assert_eq!(peers.len(), 2);
    assert!(peers.iter().all(|peer| peer.info.is_some()));
    assert!(peers.iter().any(|peer| peer.inbound && peer.node_id > 0));
    Ok(())
}

#[test]
fn ping_round_trip_measures_duration_on_both_sides() -> Result<(), Box<dyn Error>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (controls, addr, listener) = loopback_peer_pair(&shutdown)?;

    let handshake_done = wait_until(Duration::from_secs(5), || {
        controls
            .peer_registry()
            .read()
            .iter()
            .any(|p| p.addr == addr)
    });
    assert!(handshake_done, "handshake must complete before pinging");
    assert_eq!(controls.send_pings(unix_micros_now()), 2);

    let measured = wait_until(Duration::from_secs(5), || {
        controls
            .connected_peers()
            .iter()
            .all(|peer| peer.stats.ping_time().is_some())
    });
    shutdown.store(true, Ordering::Relaxed);
    join_listener(listener)?;

    assert!(
        measured,
        "both peers must answer their ping with a measured round trip"
    );
    Ok(())
}

#[test]
fn traffic_totals_accumulate_from_live_connections() -> Result<(), Box<dyn Error>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (controls, addr, listener) = loopback_peer_pair(&shutdown)?;

    let traffic_flowed = wait_until(Duration::from_secs(5), || {
        controls
            .peer_registry()
            .read()
            .iter()
            .any(|p| p.addr == addr)
            && controls.totals().total_bytes_recv() > 0
            && controls.totals().total_bytes_sent() > 0
    });
    shutdown.store(true, Ordering::Relaxed);
    join_listener(listener)?;

    assert!(traffic_flowed, "handshake traffic must reach the totals");
    assert_eq!(
        controls.connection_counts().total(),
        2,
        "both connection directions stay live until shutdown"
    );
    Ok(())
}

#[test]
fn setnetworkactive_refuses_new_outbound_activity() -> Result<(), Box<dyn Error>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (controls, addr, listener) = loopback_peer_pair(&shutdown)?;
    let handshake_done = wait_until(Duration::from_secs(5), || {
        controls
            .peer_registry()
            .read()
            .iter()
            .any(|p| p.addr == addr)
    });
    assert!(handshake_done);
    assert!(!controls.set_network_active(false));
    assert!(!controls.network_active());

    // A further dial while inactive must fail without opening activity.
    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
    let dial_controls = Arc::clone(&controls);
    let refused = spawn_outbound_connection_with_controls(
        addr,
        Magic::BITCOIN,
        dial_controls,
        headers_tx,
        blocks_tx,
        None,
        None,
        None,
    );
    let refused_result = match refused.join() {
        Ok(result) => result,
        Err(error) => std::panic::resume_unwind(error),
    };
    shutdown.store(true, Ordering::Relaxed);
    join_listener(listener)?;

    assert!(
        matches!(refused_result, Err(PeerError::Protocol("network inactive"))),
        "inactive networking must refuse the dial, got {refused_result:?}"
    );

    assert!(controls.set_network_active(true));
    assert!(controls.network_active());
    Ok(())
}

#[test]
fn controls_disconnect_node_promptly_removes_the_lease() -> Result<(), Box<dyn Error>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (controls, addr, listener) = loopback_peer_pair(&shutdown)?;
    let handshake_done = wait_until(Duration::from_secs(5), || {
        controls
            .peer_registry()
            .read()
            .iter()
            .any(|p| p.addr == addr)
    });
    assert!(handshake_done);
    assert!(controls.disconnect_node(&addr));

    let outbound_gone = wait_until(Duration::from_secs(5), || {
        !controls.peer_outbound().read().contains_key(&addr)
            || !controls
                .peer_registry()
                .read()
                .iter()
                .any(|peer| peer.addr == addr)
    });
    shutdown.store(true, Ordering::Relaxed);
    join_listener(listener)?;

    assert!(
        outbound_gone,
        "disconnect_node must remove the lease and its registry entry"
    );
    assert!(!controls.disconnect_node(&addr));
    Ok(())
}
