//! Public peer metadata published after a successful handshake.

use std::net::SocketAddr;

use bitcoin::p2p::message_network::VersionMessage;

/// Information collected during a successful Bitcoin v1 handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Protocol version advertised by the remote.
    pub version: u32,
    /// Service flags advertised by the remote (`ServiceFlags::to_u64`).
    pub services: u64,
    /// User-agent string advertised by the remote.
    pub user_agent: String,
    /// Best-chain height the remote reports.
    pub start_height: i32,
    /// Unix-epoch seconds of handshake completion.
    pub conn_time: u64,
    /// Whether this connection was inbound (`true` for listener-accepted peers).
    pub inbound: bool,
}

impl PeerInfo {
    /// Constructs a `PeerInfo` for an inbound peer from the captured remote `VersionMessage`.
    #[must_use]
    pub fn inbound_from_version(
        addr: SocketAddr,
        version: &VersionMessage,
        conn_time: u64,
    ) -> Self {
        Self {
            addr,
            version: version.version,
            services: version.services.to_u64(),
            user_agent: version.user_agent.clone(),
            start_height: version.start_height,
            conn_time,
            inbound: true,
        }
    }
}
