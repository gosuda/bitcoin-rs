use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::p2p::Magic;
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::message_network::VersionMessage;

use crate::wire::{Message, PeerError, write_message};
use crate::wtxid::WtxidRelayState;

/// Peer connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// No version negotiation has started.
    Disconnected,
    /// Version negotiation is in progress.
    VersionExchange,
    /// Version was exchanged and verack is outstanding.
    Verack,
    /// Peer may exchange ordinary P2P messages.
    Ready,
    /// Peer is being disconnected.
    Disconnecting,
}

/// Negotiated peer capability flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerCapabilities {
    /// Peer requested header announcements per BIP130.
    pub send_headers: bool,
    /// Peer supports BIP155 addrv2 messages.
    pub addr_v2: bool,
}

/// BIP152 compact-block protocol version this node speaks and advertises.
///
/// v2 identifies transactions by wtxid and carries witness data; we send it
/// in the handshake so peers serving us compact blocks use the witness
/// profile. See `docs/policies/p2p-compatibility.md` §4/§5.
pub const COMPACT_BLOCK_VERSION: u64 = 2;

/// Remote BIP152 compact-block negotiation preference.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompactBlockNegotiation {
    /// Whether the peer requested compact-block announcements.
    pub remote_send_compact: Option<bool>,
    /// Compact-block protocol version requested by the peer.
    pub remote_version: Option<u64>,
    /// Compact-block version this node advertised in its handshake `sendcmpct`.
    pub local_version: Option<u64>,
}

impl CompactBlockNegotiation {
    /// Record the latest remote `sendcmpct` preference.
    pub const fn record_remote_preference(&mut self, preference: &SendCmpct) {
        self.remote_send_compact = Some(preference.send_compact);
        self.remote_version = Some(preference.version);
    }

    /// Record the version this node sent in its handshake `sendcmpct`.
    pub const fn record_local_advertised(&mut self, version: u64) {
        self.local_version = Some(version);
    }

    /// The transaction-identity profile valid for this peer's compact blocks.
    ///
    /// v1 identifies transactions by txid with witness-stripped prefills;
    /// v2 identifies them by wtxid and carries witness data. A peer that
    /// never sent `sendcmpct`, or announced an unknown version, falls back to
    /// the base v1 profile: short IDs are hints, so a wrong guess only costs
    /// round trips, never a wrong block.
    #[must_use]
    pub const fn negotiated_version(&self) -> u64 {
        match self.remote_version {
            Some(2) => 2,
            _ => 1,
        }
    }

    /// The version to serve this peer's `MSG_CMPCT_BLOCK` requests at, or
    /// `None` while the peer never announced BIP152 support. The identity
    /// profile is the peer's recorded `sendcmpct` version; short IDs are
    /// hints, so an unknown recorded version degrades to the v1 profile.
    #[must_use]
    pub const fn servable_version(&self) -> Option<u64> {
        match self.remote_send_compact {
            Some(_) => Some(self.negotiated_version()),
            None => None,
        }
    }
}

/// One peer connection and its negotiated protocol state.
#[derive(Debug)]
pub struct Peer<S> {
    /// Underlying byte stream.
    pub stream: S,
    /// Current protocol state.
    pub state: PeerState,
    /// Expected network magic.
    pub magic: Magic,
    /// Last remote version message.
    pub remote_version: Option<VersionMessage>,
    /// Local Unix timestamp when the remote Version message was received.
    pub version_received_time: Option<u64>,
    /// Whether a remote verack has been received.
    pub received_verack: bool,
    /// Local view of negotiated feature flags.
    pub capabilities: PeerCapabilities,
    /// BIP152 compact-block negotiation state for the peer.
    pub compact_blocks: CompactBlockNegotiation,
    /// BIP339 state for the peer.
    pub wtxid_relay: WtxidRelayState,
}

impl<S> Peer<S> {
    /// Create a peer over `stream`.
    pub fn new(stream: S, magic: Magic) -> Self {
        Self {
            stream,
            state: PeerState::Disconnected,
            magic,
            remote_version: None,
            version_received_time: None,
            received_verack: false,
            capabilities: PeerCapabilities::default(),
            compact_blocks: CompactBlockNegotiation::default(),
            wtxid_relay: WtxidRelayState::default(),
        }
    }

    /// Mark the peer ready once both version and verack have arrived.
    pub const fn refresh_ready_state(&mut self) {
        if self.remote_version.is_some() && self.received_verack {
            self.state = PeerState::Ready;
        }
    }
}

impl<S: Read + Write> Peer<S> {
    /// Write one outbound message.
    ///
    /// Returns the framed wire length so handshake accounting can charge the
    /// same bytes `write_message` emitted, without encoding the payload twice.
    pub fn send(&mut self, message: &Message) -> Result<usize, PeerError> {
        write_message(&mut self.stream, self.magic, message)
    }
}

/// DNS resolver injection point for peer discovery.
pub trait DnsResolver: Send + Sync {
    /// Resolve a DNS seed name into socket addresses.
    fn resolve(&self, seed: &str) -> Result<Vec<SocketAddr>, PeerError>;
}

/// Peer manager skeleton with injectable DNS resolution.
pub struct PeerManager {
    dns_resolver: Box<dyn DnsResolver>,
    seeds: Vec<String>,
}

impl PeerManager {
    /// Create a peer manager from a resolver implementation.
    pub fn new(dns_resolver: Box<dyn DnsResolver>) -> Self {
        Self {
            dns_resolver,
            seeds: Vec::new(),
        }
    }

    /// Add a DNS seed name.
    pub fn add_seed(&mut self, seed: impl Into<String>) {
        self.seeds.push(seed.into());
    }

    /// Resolve every configured seed.
    pub fn bootstrap_addresses(&self) -> Result<Vec<SocketAddr>, PeerError> {
        let mut addresses = Vec::new();
        for seed in &self.seeds {
            addresses.extend(self.dns_resolver.resolve(seed)?);
        }
        Ok(addresses)
    }
}

/// DNS resolver backed by the operating system resolver.
#[derive(Debug, Clone, Copy)]
pub struct SystemDnsResolver {
    port: u16,
}

impl SystemDnsResolver {
    /// Create a DNS resolver that attaches `port` to each resolved seed host.
    #[must_use]
    pub const fn new(port: u16) -> Self {
        Self { port }
    }
}

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, seed: &str) -> Result<Vec<SocketAddr>, PeerError> {
        let seed = seed.trim_end_matches('.');
        (seed, self.port)
            .to_socket_addrs()
            .map(std::iter::Iterator::collect)
            .map_err(PeerError::Io)
    }
}

/// Authoritative p2p activity switch behind `setnetworkactive`.
///
/// Mirrors Core's `CConnman::fNetworkActive`: flipping the flag never
/// disconnects existing peers; it only stops new inbound accepts and new
/// outbound dials while inactive.
#[derive(Debug, Clone)]
pub struct NetworkActivity {
    active: Arc<AtomicBool>,
}

impl NetworkActivity {
    /// Shares the node-owned activity flag.
    /// PRE: `active` is the flag the RPC `setnetworkactive` handler stores.
    /// POST: Return a switch reading exactly that flag.
    /// INVARIANT: Flag changes happen only through
    /// [`crate::apply_network_active`]; this type never writes the flag.
    #[must_use]
    pub const fn from_shared(active: Arc<AtomicBool>) -> Self {
        Self { active }
    }

    /// Returns whether p2p network activity is enabled.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

/// Consensus maximum serialized block size in bytes, in `usize` form for
/// wire-buffer arithmetic. `peer` is the single p2p authority for this limit.
pub const MAX_BLOCK_SERIALIZED_SIZE_USIZE: usize = 4_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_manager_resolves_configured_seeds() -> Result<(), PeerError> {
        struct StaticResolver;

        impl DnsResolver for StaticResolver {
            fn resolve(&self, seed: &str) -> Result<Vec<SocketAddr>, PeerError> {
                let port = match seed {
                    "seed-one.example" => 8333,
                    "seed-two.example" => 18333,
                    _ => return Err(PeerError::Protocol("unexpected test seed")),
                };
                Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
            }
        }

        let mut manager = PeerManager::new(Box::new(StaticResolver));
        manager.add_seed("seed-one.example");
        manager.add_seed("seed-two.example");

        assert_eq!(
            manager.bootstrap_addresses()?,
            vec![
                SocketAddr::from(([127, 0, 0, 1], 8333)),
                SocketAddr::from(([127, 0, 0, 1], 18333)),
            ]
        );
        Ok(())
    }

    #[test]
    fn system_dns_resolver_uses_configured_port_for_literal_hosts() -> Result<(), PeerError> {
        let resolver = SystemDnsResolver::new(8333);

        assert!(
            resolver
                .resolve("127.0.0.1.")?
                .contains(&SocketAddr::from(([127, 0, 0, 1], 8333)))
        );
        Ok(())
    }
}
