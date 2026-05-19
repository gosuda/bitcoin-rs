use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bitcoin::p2p::Magic;

use thiserror::Error;

use crate::handshake::run_inbound_handshake;
use crate::peer::Peer;

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(60);

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
/// handshake. The thread has a [`HANDSHAKE_READ_TIMEOUT`] (60s) read and
/// write timeout; it terminates on success, on failure, or when the
/// timeout expires. Per-connection threads are NOT joined by the outer
/// shutdown — they outlive the listener by up to the timeout.
///
/// Peer-management integration (tracking accepted peers, dispatching
/// inv/getdata/headers, etc.) lands in a follow-up.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_with_shutdown(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    magic: Magic,
) -> Result<(), ListenerError> {
    let listener =
        TcpListener::bind(addr).map_err(|source| ListenerError::Bind { addr, source })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| ListenerError::Bind { addr, source })?;
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                spawn_handshake_thread(stream, peer_addr, magic);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(ListenerError::Accept(error)),
        }
    }
    Ok(())
}

fn spawn_handshake_thread(stream: TcpStream, peer_addr: SocketAddr, magic: Magic) {
    let thread_name = format!("bitcoin-rs-p2p-handshake-{peer_addr}");
    let spawn_result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            if let Err(error) = run_handshake(stream, peer_addr, magic) {
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
    // this listener thread by up to HANDSHAKE_READ_TIMEOUT. Tracking them
    // lands when peer-management is wired.
}

fn run_handshake(
    stream: TcpStream,
    peer_addr: SocketAddr,
    magic: Magic,
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
    tracing::debug!(peer_addr = %peer_addr, "p2p inbound handshake complete");
    Ok(())
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
