//! P2P listener shutdown integration coverage.
use bitcoin::p2p::Magic;
use bitcoin_rs_p2p::listener::{ConnectionShared, bind_listener, serve};
use bitcoin_rs_p2p::{NetworkActivity, PeerTable};
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn serve_exits_when_flag_set() -> Result<(), Box<dyn Error>> {
    let listener = bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = listener.local_addr()?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let listener_shutdown = Arc::clone(&shutdown);
    let (tx, rx) = mpsc::channel();
    let peer_table = Arc::new(PeerTable::new());
    let shared = wiring(Arc::clone(&peer_table));

    let handle = thread::spawn(move || {
        let result = serve(listener, listener_shutdown, shared);
        let _ = tx.send(result);
    });

    // The listener is already bound, so the connect completes at once. The
    // accept loop proves it is running when it registers the connection;
    // the deadline is a hang failsafe.
    let client = TcpStream::connect(addr)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while peer_table.is_empty() {
        match rx.try_recv() {
            Ok(listener_result) => {
                listener_result?;
                return Err(io::Error::other("listener exited before shutdown").into());
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(io::Error::other("listener thread exited early").into());
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("listener never accepted the connection").into());
        }
        thread::sleep(Duration::from_millis(5));
    }

    shutdown.store(true, Ordering::Relaxed);
    // Drop the accepted stream so the orphan handshake thread exits on a
    // read error instead of holding the connection open.
    drop(client);

    let result = rx.recv_timeout(Duration::from_secs(5))?;

    match handle.join() {
        Ok(()) => {}
        Err(_) => return Err(io::Error::other("listener thread panicked").into()),
    }

    result?;
    // Connection threads outlive the listener. The orphan handshake thread
    // removes its own registration once it reads EOF.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !peer_table.is_empty() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(peer_table.is_empty());
    Ok(())
}

#[test]
fn serve_returns_without_accepting_when_flag_preset() -> Result<(), Box<dyn Error>> {
    let listener = bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;

    // The flag is set before the listener thread spawns; the serve call must
    // observe it before accepting and return without registering peers.
    let shutdown = Arc::new(AtomicBool::new(true));
    let listener_shutdown = Arc::clone(&shutdown);
    let (tx, rx) = mpsc::channel();
    let peer_table = Arc::new(PeerTable::new());
    let shared = wiring(Arc::clone(&peer_table));

    let handle = thread::spawn(move || {
        let result = serve(listener, listener_shutdown, shared);
        let _ = tx.send(result);
    });

    let result = rx.recv_timeout(Duration::from_secs(5))?;
    match handle.join() {
        Ok(()) => {}
        Err(_) => return Err(io::Error::other("listener thread panicked").into()),
    }

    result?;
    assert!(peer_table.is_empty());
    Ok(())
}

/// Wiring with an active network, no bans, and a start token that stays
/// `false`.
fn wiring(peer_table: Arc<PeerTable>) -> ConnectionShared {
    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
    ConnectionShared::new(
        peer_table,
        Arc::new(parking_lot::RwLock::new(Vec::new())),
        Arc::new(NetworkActivity::from_shared(Arc::new(AtomicBool::new(
            true,
        )))),
        Arc::new(AtomicBool::new(false)),
        None,
        Magic::BITCOIN,
        headers_tx,
        blocks_tx,
    )
}
