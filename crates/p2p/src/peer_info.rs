//! Public peer metadata published after a successful handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use bitcoin::p2p::message_network::VersionMessage;

use crate::counters::PeerCounters;

/// What one connection relays.
///
/// PRE: assigned once, by the code that creates the connection.
/// POST: `FullRelay` carries transactions, addresses, blocks, and
///   announcements; `BlockRelayOnly` carries blocks and headers alone.
/// INVARIANT: a connection's role never changes after assignment; a
///   same-address replacement is a new connection and gets a fresh role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRole {
    /// Full relay: transactions, addresses, blocks, and announcements.
    ///
    /// Core: an inbound or `OUTBOUND_FULL_RELAY` connection.
    FullRelay,
    /// Block relay only: blocks and headers, never a transaction or address
    /// message in either direction.
    ///
    /// Core: a `BLOCK_RELAY` connection
    /// (`MAX_BLOCK_RELAY_ONLY_CONNECTIONS`, `net.h:73`).
    BlockRelayOnly,
}

impl PeerRole {
    /// Whether this role may carry transaction and address relay.
    ///
    /// PRE: none.
    /// POST: `true` only for `FullRelay`.
    /// INVARIANT: block and header relay is never restricted by role.
    #[must_use]
    pub const fn relays_transactions(&self) -> bool {
        matches!(self, Self::FullRelay)
    }
}

/// Information collected during a successful Bitcoin v1 handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Protocol version advertised by the remote.
    pub version: u32,
    /// Whether this connection requested BIP339 witness-id announcements.
    /// Published with the completed handshake; never inherited by a replacement.
    pub wtxid_relay: bool,
    /// Whether this connection announced BIP152 compact-block relay (sent a
    /// `sendcmpct` with a known version). Published `false` at handshake and
    /// raised by the listener when the peer's post-verack announcement
    /// arrives; compact-fetch eligibility reads this, never a stale guess.
    /// The high-bandwidth push preference is a separate per-peer decision and
    /// does not gate eligibility.
    pub compact_block_relay: bool,
    /// Service flags advertised by the remote (`ServiceFlags::to_u64`).
    pub services: u64,
    /// User-agent string advertised by the remote.
    pub user_agent: String,
    /// Best-chain height the remote reports at handshake.
    pub start_height: i32,
    /// Highest chain height this peer has demonstrated while connected:
    /// starts at the handshake `start_height` and is raised monotonically as
    /// the peer hands us accepted headers. Sync request eligibility and
    /// per-request truncation read this, not the handshake snapshot, so a
    /// long-lived connection at the tip can still serve newly announced
    /// blocks (the `pindexBestKnownBlock` role, headers-fed).
    pub best_known_height: i32,
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
            inbound: true,
            ..Self::outbound_from_version(
                addr,
                addr_bind,
                version,
                conn_time,
                version_received_time,
                counters,
            )
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
            wtxid_relay: false,
            compact_block_relay: false,
            services: version.services.to_u64(),
            user_agent: version.user_agent.clone(),
            start_height: version.start_height,
            best_known_height: version.start_height,
            conn_time,
            inbound: false,
            addr_bind,
            // Freeze the offset at version receipt, not handshake completion.
            time_offset: version
                .timestamp
                .saturating_sub(i64::try_from(version_received_time).unwrap_or(i64::MAX)),
            counters,
        }
    }

    /// Returns Bitcoin Core service-flag names decoded from `self.services`.
    ///
    /// Order follows Bitcoin Core's bit assignment. Unrecognized bits are dropped.
    #[must_use]
    pub fn services_names(&self) -> Vec<&'static str> {
        service_flag_names(self.services)
    }
}

/// Decodes a Bitcoin service-flags bitmask into its name strings.
///
/// One table for every surface that renders service bits (P2P `getpeerinfo`
/// and RPC `getnetworkinfo`), so the two cannot disagree about a bit. Order
/// follows Bitcoin Core's bit assignment (`GetServiceNames`); unrecognized
/// bits are dropped.
///
/// PRE: `flags` is a `MSG_...`-free service bitmask as sent on the wire.
/// POST: the recognized names in bit order, empty when no bit is recognized.
/// INVARIANT: the name for a bit is a compile-time constant; no allocation
///   beyond the returned vector occurs.
#[must_use]
pub fn service_flag_names(flags: u64) -> Vec<&'static str> {
    [
        (0, "NETWORK"),
        (1, "GETUTXO"),
        (2, "BLOOM"),
        (3, "WITNESS"),
        (6, "COMPACT_FILTERS"),
        (10, "NETWORK_LIMITED"),
        (11, "P2P_V2"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (flags & (1_u64 << bit) != 0).then_some(name))
    .collect()
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
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        PeerInfo {
            services,
            ..PeerInfo::outbound_from_version(addr, addr, &fake_version(), 0, 0, counters())
        }
    }

    /// A `version` message whose remote peer advertises `services`. The
    /// advertised set is resolved once by the node's service policy, so no
    /// test restates a local advertisement inline.
    fn version_with_services(services: ServiceFlags) -> VersionMessage {
        VersionMessage {
            services,
            ..fake_version()
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
    fn constructors_preserve_direction_and_handshake_metadata() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let version = fake_version();
        let counters = counters();
        let inbound =
            PeerInfo::inbound_from_version(addr, addr, &version, 100, 50, Arc::clone(&counters));
        let outbound = PeerInfo::outbound_from_version(addr, addr, &version, 100, 50, counters);
        assert!(inbound.inbound);
        assert!(!outbound.inbound);
        assert_eq!(outbound.start_height, 7);
        assert_eq!(outbound.best_known_height, 7);
        assert_eq!(outbound.conn_time, 100);
        assert_eq!(outbound.time_offset, -50);
        assert!(!outbound.wtxid_relay);
        assert!(!outbound.compact_block_relay);
        assert_eq!(
            PeerInfo {
                inbound: false,
                ..inbound
            },
            outbound
        );
    }

    #[test]
    fn services_names_decodes_inbound_peer_with_network_witness() {
        let version = version_with_services(ServiceFlags::NETWORK | ServiceFlags::WITNESS);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let info = PeerInfo::inbound_from_version(addr, addr, &version, 0, 0, counters());
        assert_eq!(info.services_names(), vec!["NETWORK", "WITNESS"]);
    }

    #[test]
    fn services_names_empty_for_no_flags() {
        let version = version_with_services(ServiceFlags::NONE);
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
