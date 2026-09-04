//! Public peer metadata published after a successful handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use bitcoin::p2p::message_network::VersionMessage;

use crate::counters::PeerCounters;

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
    /// Local socket address this connection is bound to.
    ///
    /// Bitcoin Core reports it as `addrbind`, and it is the node's own address
    /// on this connection -- not the peer's. Reporting the peer's address
    /// twice, as this used to, tells an operator listening on several
    /// interfaces nothing about which one carried the connection.
    pub addr_bind: SocketAddr,
    /// Seconds the peer's clock is ahead of this node's, from its version.
    ///
    /// Bitcoin Core's `timeoffset`, measured once at handshake as the peer's
    /// declared time minus local time.
    pub time_offset: i64,
    /// Live traffic counters for the connection.
    pub counters: Arc<PeerCounters>,
}

impl PeerInfo {
    fn time_offset(version: &VersionMessage, version_received_time: u64) -> i64 {
        version
            .timestamp
            .saturating_sub(i64::try_from(version_received_time).unwrap_or(i64::MAX))
    }

    /// Constructs a `PeerInfo` for an inbound peer from the captured remote `VersionMessage`.
    #[must_use]
    pub fn inbound_from_version(
        addr: SocketAddr,
        addr_bind: SocketAddr,
        version: &VersionMessage,
        conn_time: u64,
        version_received_time: u64,
        counters: Arc<PeerCounters>,
    ) -> Self {
        Self {
            addr,
            version: version.version,
            services: version.services.to_u64(),
            user_agent: version.user_agent.clone(),
            start_height: version.start_height,
            conn_time,
            inbound: true,
            addr_bind,
            // The peer states its own clock in the version message. Core takes
            // the difference against local time at that moment and never
            // revisits it, so a long-lived connection reports the offset as it
            // was at handshake.
            time_offset: Self::time_offset(version, version_received_time),
            counters,
        }
    }

    /// Constructs a `PeerInfo` for an outbound peer from the captured remote `VersionMessage`.
    #[must_use]
    pub fn outbound_from_version(
        addr: SocketAddr,
        addr_bind: SocketAddr,
        version: &VersionMessage,
        conn_time: u64,
        version_received_time: u64,
        counters: Arc<PeerCounters>,
    ) -> Self {
        Self {
            addr,
            version: version.version,
            services: version.services.to_u64(),
            user_agent: version.user_agent.clone(),
            start_height: version.start_height,
            conn_time,
            inbound: false,
            addr_bind,
            // The peer states its own clock in the version message. Core takes
            // the difference against local time at that moment and never
            // revisits it, so a long-lived connection reports the offset as it
            // was at handshake.
            time_offset: Self::time_offset(version, version_received_time),
            counters,
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

    fn peer_info_with_services(services: u64) -> PeerInfo {
        PeerInfo {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333),
            version: 70_016,
            services,
            user_agent: String::new(),
            start_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333),
            time_offset: 0,
            counters: counters(),
        }
    }

    fn counters() -> Arc<PeerCounters> {
        Arc::new(PeerCounters::default())
    }

    /// The offset is what the peer claimed, against the clock we read it at.
    ///
    /// A peer two minutes ahead must read as `+120`, not as an absolute time
    /// and not as zero -- the placeholder this replaced.
    #[test]
    fn time_offset_is_the_peers_clock_against_ours() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let mut version = fake_version();
        version.timestamp = 1_700_000_120;
        let info = PeerInfo::inbound_from_version(
            addr,
            addr,
            &version,
            1_700_000_000,
            1_700_000_000,
            counters(),
        );
        assert_eq!(info.time_offset, 120);

        version.timestamp = 1_699_999_940;
        let behind = PeerInfo::inbound_from_version(
            addr,
            addr,
            &version,
            1_700_000_000,
            1_700_000_000,
            counters(),
        );
        assert_eq!(behind.time_offset, -60);
    }

    /// The bind address is the node's own end of the connection.
    #[test]
    fn addr_bind_is_kept_apart_from_the_peer_address() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 51_234);
        let info = PeerInfo::inbound_from_version(peer, local, &fake_version(), 0, 0, counters());
        assert_eq!(info.addr, peer);
        assert_eq!(info.addr_bind, local);
    }

    #[test]
    fn outbound_from_version_sets_inbound_false() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let version = fake_version();
        let info = PeerInfo::outbound_from_version(addr, addr, &version, 100, 0, counters());
        assert!(!info.inbound);
        assert_eq!(info.start_height, 7);
        assert_eq!(info.conn_time, 100);
    }

    #[test]
    fn inbound_from_version_sets_inbound_true() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let version = fake_version();
        let info = PeerInfo::inbound_from_version(addr, addr, &version, 100, 0, counters());
        assert!(info.inbound);
    }

    #[test]
    fn services_names_decodes_inbound_peer_with_network_witness() {
        let mut version = fake_version();
        version.services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let info = PeerInfo::inbound_from_version(addr, addr, &version, 0, 0, counters());
        assert_eq!(info.services_names(), vec!["NETWORK", "WITNESS"]);
    }

    #[test]
    fn services_names_empty_for_no_flags() {
        let mut version = fake_version();
        version.services = ServiceFlags::NONE;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let info = PeerInfo::inbound_from_version(addr, addr, &version, 0, 0, counters());
        assert!(info.services_names().is_empty());
    }

    /// `services_names` is Bitcoin Core-compatible `getpeerinfo` output: the
    /// recognized service bits decode to Core's canonical names in bit order,
    /// and unrecognized bits are dropped. This pins the external RPC contract,
    /// not the helper's internal representation.
    #[test]
    fn services_names_match_bitcoin_core_service_flag_names() {
        let all_known = (1_u64 << 0)  // NETWORK
            | (1_u64 << 1)            // GETUTXO
            | (1_u64 << 2)            // BLOOM
            | (1_u64 << 3)            // WITNESS
            | (1_u64 << 6)            // COMPACT_FILTERS
            | (1_u64 << 10)           // NETWORK_LIMITED
            | (1_u64 << 11); // P2P_V2

        assert_eq!(
            peer_info_with_services(all_known).services_names(),
            vec![
                "NETWORK",
                "GETUTXO",
                "BLOOM",
                "WITNESS",
                "COMPACT_FILTERS",
                "NETWORK_LIMITED",
                "P2P_V2",
            ]
        );

        // No recognized bits -> no names (Core reports an empty array).
        assert!(peer_info_with_services(0).services_names().is_empty());

        // Unrecognized bits (e.g. bit 63) contribute no names.
        assert!(
            peer_info_with_services(1_u64 << 63)
                .services_names()
                .is_empty()
        );
    }
}
