//! Production TCP options for one Bitcoin peer connection.
//!
//! Inbound accept and outbound connect both pass through
//! [`configure_peer_stream`]. Address equality is not identity; this module
//! only owns the socket flags, not lease or handshake state.

use std::io;
use std::net::TcpStream;
use std::time::Duration;

/// Handshake and idle-write ceiling. Matches Bitcoin Core's 60s inactivity
/// window for a peer that never completes version/verack.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_mins(1);
/// Read timeout used while polling handshake and message reads.
pub(crate) const STREAM_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Applies the peer-socket policy: `TCP_NODELAY`, blocking I/O, and the
/// handshake/poll timeouts.
///
/// `TCP_NODELAY` is required so the vectored header+payload write in
/// [`crate::wire::write_message`] is not delayed by Nagle after a short
/// first segment. Timeouts are the same on inbound and outbound so a stalled
/// peer cannot park a connection thread past the handshake ceiling.
pub fn configure_peer_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(STREAM_POLL_INTERVAL))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

    use super::configure_peer_stream;

    fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server)
    }

    /// Contract `P2P-03` requires the peer socket policy on both directions.
    #[test]
    fn configure_peer_stream_disables_nagle_on_both_halves() {
        let (client, server) = loopback_pair();
        configure_peer_stream(&client).expect("configure client");
        configure_peer_stream(&server).expect("configure server");
        assert!(client.nodelay().expect("client nodelay"));
        assert!(server.nodelay().expect("server nodelay"));
    }
}
