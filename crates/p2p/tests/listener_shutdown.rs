use bitcoin::p2p::Magic;
use bitcoin_rs_p2p::listener::{ConnectionShared, ListenerError, bind_listener, serve};
use bitcoin_rs_p2p::{ListenerExtras, NetworkActivity, PeerTable};
use bitcoin_rs_primitives::PeerEndpoint;
use std::io;
use std::net::{Ipv4Addr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Listener(#[from] ListenerError),
    #[error(transparent)]
    RecvTimeout(#[from] mpsc::RecvTimeoutError),
}

struct ServeGuard {
    shutdown: Arc<bitcoin_rs_chain::LatchWriter>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ServeGuard {
    fn new(shutdown: &Arc<bitcoin_rs_chain::LatchWriter>, handle: thread::JoinHandle<()>) -> Self {
        Self {
            shutdown: Arc::clone(shutdown),
            handle: Some(handle),
        }
    }

    fn join(mut self) -> Result<(), TestError> {
        self.shutdown.trigger();
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
        self.shutdown.trigger();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn serve_exits_when_flag_set() -> Result<(), TestError> {
    let listener = bind_listener(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    let addr = listener.local_addr()?;

    let shutdown = Arc::new(bitcoin_rs_chain::LatchWriter::new());
    let listener_shutdown = shutdown.reader();
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

    shutdown.trigger();
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
fn serve_returns_without_accepting_when_flag_preset() -> Result<(), TestError> {
    let listener = bind_listener(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;

    let shutdown = Arc::new(bitcoin_rs_chain::LatchWriter::new());
    shutdown.trigger();
    let listener_shutdown = shutdown.reader();
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

#[test]
fn serve_unblocks_promptly_on_latch_trigger() -> Result<(), TestError> {
    let listener = bind_listener(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )?;
    let latch = bitcoin_rs_chain::LatchWriter::new();
    let reader = latch.reader();
    let peer_table = Arc::new(PeerTable::new());
    let shared = wiring(Arc::clone(&peer_table));
    let (tx, rx) = crossbeam_channel::bounded(1);
    let handle = thread::spawn(move || {
        let result = serve(listener, reader, shared);
        let _ = tx.send(result);
    });
    thread::sleep(Duration::from_millis(20));
    latch.trigger();
    let result = rx
        .recv_timeout(Duration::from_millis(50))
        .map_err(|_| io::Error::other("serve did not unblock promptly upon latch trigger"))?;
    result?;
    handle
        .join()
        .map_err(|_| io::Error::other("serve thread panicked"))?;
    Ok(())
}

fn wiring(peer_table: Arc<PeerTable>) -> ConnectionShared {
    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
    ConnectionShared::new(
        peer_table,
        Arc::new(parking_lot::RwLock::new(Vec::new())),
        Arc::new(NetworkActivity::from_shared(Arc::new(AtomicBool::new(
            true,
        )))),
        bitcoin_rs_chain::LatchWriter::new().reader(),
        None,
        Magic::BITCOIN,
        headers_tx,
        blocks_tx,
        None,
        None,
        ListenerExtras::default(),
    )
}
