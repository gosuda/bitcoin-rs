use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use thiserror::Error;

const POLL_INTERVAL: Duration = Duration::from_millis(100);

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
/// Skeleton implementation: every accepted connection is immediately
/// dropped after a debug-level log line. Real handshake / FSM wiring
/// (see `crates/p2p/src/handshake.rs`, `crates/p2p/src/fsm.rs`) lands
/// in a follow-up.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_with_shutdown(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
) -> Result<(), ListenerError> {
    let listener =
        TcpListener::bind(addr).map_err(|source| ListenerError::Bind { addr, source })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| ListenerError::Bind { addr, source })?;
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                tracing::debug!(
                    peer_addr = %peer_addr,
                    "p2p accept (skeleton — closing immediately, handshake wiring deferred)"
                );
                drop(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(ListenerError::Accept(error)),
        }
    }
    Ok(())
}
