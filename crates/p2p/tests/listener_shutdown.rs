//! P2P listener shutdown integration coverage.
use bitcoin::p2p::Magic;
use bitcoin_rs_p2p::PeerTable;
use bitcoin_rs_p2p::listener::serve_with_shutdown;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn serve_with_shutdown_exits_when_flag_set() -> Result<(), Box<dyn Error>> {
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let helper = TcpListener::bind(bind_addr)?;
    let addr = helper.local_addr()?;
    drop(helper);

    let shutdown = Arc::new(AtomicBool::new(false));
    let listener_shutdown = Arc::clone(&shutdown);
    let network_active = Arc::new(AtomicBool::new(true));
    let (tx, rx) = mpsc::channel();
    let peer_table = Arc::new(PeerTable::new());
    let listener_peer_table = Arc::clone(&peer_table);
    let (inbound_headers_tx, _inbound_headers_rx) =
        crossbeam_channel::unbounded::<bitcoin_rs_p2p::InboundHeaders>();
    let (inbound_blocks_tx, _inbound_blocks_rx) =
        crossbeam_channel::unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let banned = Arc::new(parking_lot::RwLock::new(Vec::new()));

    let listener_banned = Arc::clone(&banned);
    let listener_network_active = Arc::clone(&network_active);
    let handle = thread::spawn(move || {
        let result = serve_with_shutdown(
            addr,
            listener_shutdown,
            listener_network_active,
            Magic::BITCOIN,
            listener_peer_table,
            inbound_headers_tx,
            inbound_blocks_tx,
            listener_banned,
        );
        let _ = tx.send(result);
    });

    // Wait until the listener accepts. The deadline is a hang failsafe;
    // yielding lets the listener thread run after an immediate refusal.
    let deadline = Instant::now() + Duration::from_secs(5);
    let accepted = loop {
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
        match TcpStream::connect(addr) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() >= deadline => return Err(error.into()),
            Err(_) => thread::yield_now(),
        }
    };

    shutdown.store(true, Ordering::Relaxed);
    // Drop the accepted stream so the orphan handshake thread exits on a
    // read error instead of holding the connection open.
    drop(accepted);

    let result = rx.recv_timeout(Duration::from_secs(5))?;

    match handle.join() {
        Ok(()) => {}
        Err(_) => return Err(io::Error::other("listener thread panicked").into()),
    }

    result?;
    assert!(peer_table.is_empty());
    Ok(())
}

#[test]
fn serve_with_shutdown_returns_without_accepting_when_flag_preset() -> Result<(), Box<dyn Error>> {
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let helper = TcpListener::bind(bind_addr)?;
    let addr = helper.local_addr()?;
    drop(helper);

    // The flag is set before the listener thread spawns; the serve call must
    // observe it before accepting and return without registering peers.
    let shutdown = Arc::new(AtomicBool::new(true));
    let listener_shutdown = Arc::clone(&shutdown);
    let network_active = Arc::new(AtomicBool::new(true));
    let (tx, rx) = mpsc::channel();
    let peer_table = Arc::new(PeerTable::new());
    let listener_peer_table = Arc::clone(&peer_table);
    let (inbound_headers_tx, _inbound_headers_rx) =
        crossbeam_channel::unbounded::<bitcoin_rs_p2p::InboundHeaders>();
    let (inbound_blocks_tx, _inbound_blocks_rx) =
        crossbeam_channel::unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let banned = Arc::new(parking_lot::RwLock::new(Vec::new()));

    let handle = thread::spawn(move || {
        let result = serve_with_shutdown(
            addr,
            listener_shutdown,
            network_active,
            Magic::BITCOIN,
            listener_peer_table,
            inbound_headers_tx,
            inbound_blocks_tx,
            banned,
        );
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
