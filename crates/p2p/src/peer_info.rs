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

    /// Constructs a `PeerInfo` for an outbound peer from the captured remote `VersionMessage`.
    #[must_use]
    pub fn outbound_from_version(
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
            inbound: false,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bitcoin::p2p::ServiceFlags;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;

    fn fake_version() -> VersionMessage {
        VersionMessage {
            version: 70_016,
            services: ServiceFlags::NETWORK,
            timestamp: 0,
            receiver: Address::new(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333),
                ServiceFlags::NONE,
            ),
            sender: Address::new(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 8333),
                ServiceFlags::NETWORK,
            ),
            nonce: 0,
            user_agent: "/test:0.1/".to_owned(),
            start_height: 7,
            relay: true,
        }
    }

    #[test]
    fn outbound_from_version_sets_inbound_false() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let version = fake_version();
        let info = PeerInfo::outbound_from_version(addr, &version, 100);
        assert!(!info.inbound);
        assert_eq!(info.start_height, 7);
        assert_eq!(info.conn_time, 100);
    }

    #[test]
    fn inbound_from_version_sets_inbound_true() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let version = fake_version();
        let info = PeerInfo::inbound_from_version(addr, &version, 100);
        assert!(info.inbound);
    }
}
