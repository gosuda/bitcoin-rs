use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use bitcoin::p2p::Magic;
use crossbeam_channel::Sender;
use parking_lot::RwLock;

use thiserror::Error;

use crate::handshake::run_inbound_handshake;
use crate::peer::Peer;

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_mins(1);
type ChainQueryHandle = Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>;

/// Errors returned by the P2P listener accept loop.
#[derive(Debug, Error)]
pub enum ListenerError {
    /// Failed to bind the TCP listener.
    #[error("bind {addr}: {source}")]
    Bind {
        /// Address the listener attempted to bind.
        addr: SocketAddr,
        /// Underlying bind or listener setup failure.
        source: io::Error,
    },
    /// Accept loop returned a fatal I/O error.
    #[error("accept: {0}")]
    Accept(#[from] io::Error),
}

/// Binds `addr` and runs an accept loop until `shutdown` is set.
///
/// On each accepted connection, spawns a thread that runs the inbound
/// handshake followed by a message-dispatch loop. The handshake uses
/// `HANDSHAKE_READ_TIMEOUT` (60s); after handshake, the message loop polls
/// inbound reads every second while enforcing a 60s inbound idle timeout.
/// The thread terminates on:
///   - successful handshake then idle (60s of no inbound messages)
///   - wire / FSM error
///   - explicit FSM disconnect transition
///
/// Per-connection threads are NOT joined by the outer shutdown — they
/// outlive the listener by up to the timeout. On exit (clean or error),
/// the peer is removed from `peer_registry` via address-match retain.
///
/// Successful inbound handshakes append their public metadata to
/// `peer_registry`. The peer is removed from `peer_registry` when the
/// per-connection thread exits.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_shutdown(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_headers_tx: Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: Sender<bitcoin::Block>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
) -> Result<(), ListenerError> {
    serve_with_shutdown_with_chain(
        addr,
        shutdown,
        magic,
        peer_registry,
        peer_outbound,
        inbound_headers_tx,
        inbound_blocks_tx,
        banned,
        None,
    )
}

/// Binds `addr` and runs an accept loop with an optional active-chain responder.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_shutdown_with_chain(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_headers_tx: Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: Sender<bitcoin::Block>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
) -> Result<(), ListenerError> {
    let listener =
        TcpListener::bind(addr).map_err(|source| ListenerError::Bind { addr, source })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| ListenerError::Bind { addr, source })?;
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                if crate::subnet::is_banned(&banned.read(), peer_addr.ip(), SystemTime::now()) {
                    drop(stream);
                    tracing::debug!(peer_addr = %peer_addr, "p2p inbound rejected: banned");
                    continue;
                }
                spawn_handshake_thread(
                    stream,
                    peer_addr,
                    magic,
                    Arc::clone(&peer_registry),
                    Arc::clone(&peer_outbound),
                    inbound_headers_tx.clone(),
                    inbound_blocks_tx.clone(),
                    chain_query.clone(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(ListenerError::Accept(error)),
        }
    }
    Ok(())
}

/// Spawns an outbound TCP connection to `addr`, performs the outbound P2P
/// handshake, and enters the same message loop the inbound path uses.
///
/// Returns a `JoinHandle` for the spawned thread. Errors during connect or
/// handshake bubble up via the `JoinHandle`'s `Result`.
#[allow(clippy::needless_pass_by_value)]
pub fn spawn_outbound_connection(
    addr: SocketAddr,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_headers_tx: Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: Sender<bitcoin::Block>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_outbound_connection_with_chain(
        addr,
        magic,
        peer_registry,
        peer_outbound,
        inbound_headers_tx,
        inbound_blocks_tx,
        banned,
        None,
    )
}

/// Spawns an outbound connection with an optional active-chain responder.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn spawn_outbound_connection_with_chain(
    addr: SocketAddr,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_headers_tx: Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: Sender<bitcoin::Block>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let thread_name = format!("bitcoin-rs-p2p-outbound-{addr}");
    let result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            run_outbound_connection(
                addr,
                magic,
                &peer_registry,
                &peer_outbound,
                &inbound_headers_tx,
                &inbound_blocks_tx,
                &banned,
                &chain_query,
            )
        });

    match result {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(
                addr = %addr,
                %error,
                "p2p outbound spawn failed",
            );
            std::thread::spawn(move || Err(crate::wire::PeerError::Io(error)))
        }
    }
}

fn run_outbound_connection(
    addr: SocketAddr,
    magic: Magic,
    peer_registry: &RwLock<Vec<crate::PeerInfo>>,
    peer_outbound: &RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>,
    inbound_headers_tx: &Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: &Sender<bitcoin::Block>,
    banned: &RwLock<Vec<crate::BannedSubnet>>,
    chain_query: &ChainQueryHandle,
) -> Result<(), crate::wire::PeerError> {
    if crate::subnet::is_banned(&banned.read(), addr.ip(), SystemTime::now()) {
        return Err(crate::wire::PeerError::BannedDestination(addr.ip()));
    }

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_read_timeout(Some(HANDSHAKE_READ_TIMEOUT))
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_write_timeout(Some(HANDSHAKE_READ_TIMEOUT))
        .map_err(crate::wire::PeerError::Io)?;

    let nonce = generate_nonce(addr);
    let mut peer = Peer::new(stream, magic);
    run_outbound_handshake(&mut peer, nonce, 0)?;

    let Some(remote_version) = peer.remote_version.as_ref() else {
        return Err(crate::wire::PeerError::Protocol(
            "missing remote version after outbound handshake",
        ));
    };
    let conn_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let info = crate::PeerInfo::outbound_from_version(addr, remote_version, conn_time);
    peer_registry.write().push(info);

    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::Message>();
    peer_outbound.write().insert(addr, outbound_tx);

    tracing::info!(
        peer_addr = %addr,
        "p2p outbound handshake complete; entering message loop",
    );

    let loop_result = (|| {
        peer.stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(crate::wire::PeerError::Io)?;
        run_message_loop(
            &mut peer,
            addr,
            &outbound_rx,
            inbound_headers_tx,
            inbound_blocks_tx,
            chain_query.as_deref(),
        )
    })();

    peer_outbound.write().remove(&addr);
    peer_registry.write().retain(|p| p.addr != addr);
    if let Err(error) = &loop_result {
        tracing::warn!(peer_addr = %addr, %error, "p2p outbound peer disconnected with error");
    } else {
        tracing::debug!(peer_addr = %addr, "p2p outbound peer disconnected cleanly");
    }
    loop_result
}

fn run_outbound_handshake<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    nonce: u64,
    start_height: i32,
) -> Result<(), crate::wire::PeerError> {
    let outbound_messages = crate::handshake::start(peer, nonce, start_height);
    for message in outbound_messages {
        peer.send(&message)?;
    }

    while peer.state != crate::peer::PeerState::Ready {
        let inbound = crate::wire::read_message(&mut peer.stream, peer.magic)?;
        let responses = crate::dispatch::dispatch_inbound(peer, &inbound)?;
        for response in responses {
            peer.send(&response)?;
        }
    }

    Ok(())
}

fn spawn_handshake_thread(
    stream: TcpStream,
    peer_addr: SocketAddr,
    magic: Magic,
    registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_headers_tx: Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: Sender<bitcoin::Block>,
    chain_query: ChainQueryHandle,
) {
    let thread_name = format!("bitcoin-rs-p2p-handshake-{peer_addr}");
    let spawn_result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            if let Err(error) = run_handshake(
                stream,
                peer_addr,
                magic,
                &registry,
                &peer_outbound,
                &inbound_headers_tx,
                &inbound_blocks_tx,
                &chain_query,
            ) {
                tracing::warn!(
                    peer_addr = %peer_addr,
                    %error,
                    "p2p inbound handshake failed",
                );
            }
        });

    if let Err(error) = spawn_result {
        tracing::warn!(
            peer_addr = %peer_addr,
            %error,
            "failed to spawn p2p inbound handshake thread",
        );
    }
    // The handle is intentionally dropped: per-connection threads outlive
    // this listener thread by up to HANDSHAKE_READ_TIMEOUT.
}

fn run_handshake(
    stream: TcpStream,
    peer_addr: SocketAddr,
    magic: Magic,
    registry: &RwLock<Vec<crate::PeerInfo>>,
    peer_outbound: &RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>,
    inbound_headers_tx: &Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: &Sender<bitcoin::Block>,
    chain_query: &ChainQueryHandle,
) -> Result<(), crate::wire::PeerError> {
    stream
        .set_nonblocking(false)
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_read_timeout(Some(HANDSHAKE_READ_TIMEOUT))
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_write_timeout(Some(HANDSHAKE_READ_TIMEOUT))
        .map_err(crate::wire::PeerError::Io)?;

    let nonce = generate_nonce(peer_addr);
    let mut peer = Peer::new(stream, magic);
    run_inbound_handshake(&mut peer, nonce, 0)?;

    let Some(remote_version) = peer.remote_version.as_ref() else {
        return Err(crate::wire::PeerError::Protocol(
            "missing remote version after successful handshake",
        ));
    };
    let conn_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let info = crate::PeerInfo::inbound_from_version(peer_addr, remote_version, conn_time);
    registry.write().push(info);

    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::Message>();
    peer_outbound.write().insert(peer_addr, outbound_tx);

    tracing::info!(
        peer_addr = %peer_addr,
        "p2p inbound handshake complete; entering message loop",
    );

    let loop_result = (|| {
        peer.stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(crate::wire::PeerError::Io)?;
        run_message_loop(
            &mut peer,
            peer_addr,
            &outbound_rx,
            inbound_headers_tx,
            inbound_blocks_tx,
            chain_query.as_deref(),
        )
    })();

    peer_outbound.write().remove(&peer_addr);
    registry.write().retain(|p| p.addr != peer_addr);
    if let Err(error) = &loop_result {
        tracing::warn!(peer_addr = %peer_addr, %error, "p2p peer disconnected with error");
    } else {
        tracing::debug!(peer_addr = %peer_addr, "p2p peer disconnected cleanly");
    }
    loop_result
}

fn run_message_loop<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    peer_addr: SocketAddr,
    outbound_rx: &crossbeam_channel::Receiver<crate::Message>,
    inbound_headers_tx: &Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: &Sender<bitcoin::Block>,
    chain_query: Option<&dyn crate::dispatch::ChainQuery>,
) -> Result<(), crate::wire::PeerError> {
    use crate::peer::PeerState;
    use std::time::Instant;

    const IDLE_DISCONNECT: Duration = Duration::from_mins(1);

    let mut last_inbound = Instant::now();

    loop {
        if peer.state == PeerState::Disconnecting {
            return Ok(());
        }

        while let Ok(message) = outbound_rx.try_recv() {
            peer.send(&message)?;
        }

        if last_inbound.elapsed() >= IDLE_DISCONNECT {
            tracing::debug!(peer_addr = %peer_addr, "p2p peer idle 60s; closing");
            return Ok(());
        }

        match crate::wire::read_message(&mut peer.stream, peer.magic) {
            Ok(message) => {
                last_inbound = Instant::now();
                tracing::trace!(
                    peer_addr = %peer_addr,
                    command = ?std::mem::discriminant(&message),
                    "p2p message received",
                );
                let responses =
                    crate::dispatch::dispatch_inbound_with_chain(peer, &message, chain_query)?;
                match message {
                    bitcoin::p2p::message::NetworkMessage::Headers(headers) => {
                        if let Err(error) = inbound_headers_tx.send(headers) {
                            tracing::warn!(
                                peer_addr = %peer_addr,
                                %error,
                                "p2p inbound headers channel disconnected",
                            );
                        }
                    }
                    bitcoin::p2p::message::NetworkMessage::Block(block) => {
                        if let Err(error) = inbound_blocks_tx.send(block) {
                            tracing::warn!(
                                peer_addr = %peer_addr,
                                %error,
                                "p2p inbound blocks channel disconnected",
                            );
                        }
                    }
                    _ => {}
                }
                for response in responses {
                    peer.send(&response)?;
                }
            }
            Err(crate::wire::PeerError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
}

fn generate_nonce(peer_addr: SocketAddr) -> u64 {
    use std::hash::{BuildHasher, Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let random_state = std::collections::hash_map::RandomState::new();
    let mut hasher = random_state.build_hasher();
    peer_addr.hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
        duration.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod outbound_tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;

    use bitcoin::p2p::Magic;
    use parking_lot::RwLock;

    use super::spawn_outbound_connection;

    #[test]
    fn spawn_outbound_connection_to_closed_port_fails_quickly()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        drop(listener);

        let registry = Arc::new(RwLock::new(Vec::new()));
        let outbound = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let banned = Arc::new(RwLock::new(Vec::new()));

        let handle = spawn_outbound_connection(
            addr,
            Magic::BITCOIN,
            registry,
            outbound,
            headers_tx,
            blocks_tx,
            banned,
        );
        let inner = match handle.join() {
            Ok(inner) => inner,
            Err(error) => std::panic::resume_unwind(error),
        };

        assert!(
            inner.is_err(),
            "expected connection failure to unlistened port"
        );

        Ok(())
    }
}
