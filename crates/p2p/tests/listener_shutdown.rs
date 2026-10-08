//! P2P listener shutdown integration coverage.
use bitcoin::p2p::Magic;
use bitcoin_rs_p2p::listener::{ConnectionShared, bind_listener, serve};
use bitcoin_rs_p2p::{ListenerExtras, NetworkActivity, PeerTable};
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Stops the serve thread on every exit path: Drop stores the shutdown
/// flag and joins the thread, so an early return never leaks an accepting
/// listener thread.
struct ServeGuard {
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ServeGuard {
    fn new(shutdown: &Arc<AtomicBool>, handle: thread::JoinHandle<()>) -> Self {
        Self {
            shutdown: Arc::clone(shutdown),
            handle: Some(handle),
        }
    }

    fn join(mut self) -> Result<(), Box<dyn Error>> {
        self.shutdown.store(true, Ordering::Relaxed);
        match self.handle.take() {
            Some(handle) => handle
                .join()
                .map_err(|_| io::Error::other("listener thread panicked").into()),
            None => Ok(()),
        }
    }
}

impl Drop for ServeGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

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
    let guard = ServeGuard::new(&shutdown, handle);

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

    drop(client);

    shutdown.store(true, Ordering::Relaxed);
    let result = rx.recv_timeout(Duration::from_secs(5))?;
    guard.join()?;

    result?;
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

    let shutdown = Arc::new(AtomicBool::new(true));
    let listener_shutdown = Arc::clone(&shutdown);
    let (tx, rx) = mpsc::channel();
    let peer_table = Arc::new(PeerTable::new());
    let shared = wiring(Arc::clone(&peer_table));

    let handle = thread::spawn(move || {
        let result = serve(listener, listener_shutdown, shared);
        let _ = tx.send(result);
    });
    let guard = ServeGuard::new(&shutdown, handle);

    let result = rx.recv_timeout(Duration::from_secs(5))?;
    guard.join()?;

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
        None,
        None,
        ListenerExtras::default(),
    )
}
