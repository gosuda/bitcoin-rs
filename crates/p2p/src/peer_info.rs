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

    /// Returns Bitcoin Core service-flag names decoded from `self.services`.
    ///
    /// Order follows Bitcoin Core's bit assignment. Unrecognized bits are dropped.
    #[must_use]
    pub fn services_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = Vec::new();

        if self.services & 1_u64 != 0 {
            names.push("NETWORK");
        }
        if self.services & (1_u64 << 1) != 0 {
            names.push("GETUTXO");
        }
        if self.services & (1_u64 << 2) != 0 {
            names.push("BLOOM");
        }
        if self.services & (1_u64 << 3) != 0 {
            names.push("WITNESS");
        }
        if self.services & (1_u64 << 6) != 0 {
            names.push("COMPACT_FILTERS");
        }
        if self.services & (1_u64 << 10) != 0 {
            names.push("NETWORK_LIMITED");
        }
        if self.services & (1_u64 << 11) != 0 {
            names.push("P2P_V2");
        }

        names
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

    #[test]
    fn services_names_decodes_inbound_peer_with_network_witness() {
        let mut version = fake_version();
        version.services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let info = PeerInfo::inbound_from_version(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333),
            &version,
            0,
        );
        assert_eq!(info.services_names(), vec!["NETWORK", "WITNESS"]);
    }

    #[test]
    fn services_names_empty_for_no_flags() {
        let mut version = fake_version();
        version.services = ServiceFlags::NONE;
        let info = PeerInfo::inbound_from_version(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333),
            &version,
            0,
        );
        assert!(info.services_names().is_empty());
    }
}
