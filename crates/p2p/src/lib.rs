#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Persistent, bounded peer discovery and automatic address selection.
pub(crate) mod addrman;
/// BIP324 v2 transport cryptography: key schedule and packet ciphers.
pub(crate) mod bip324;
/// Outbound block announcements: headers-first, high-bandwidth compact, inv fallback.
pub mod block_announce;
/// Out-of-order inbound block staging bounded by the download window budget.
pub(crate) mod block_stager;
/// Active-chain `getheaders` / `getdata` serving.
pub(crate) mod chain_query;
/// BIP152 compact-block reconstruction: bounded per-peer pending state.
pub mod compact_blocks;
/// Bitcoin Core P2P compatibility inventory: pinned reference and command set.
pub mod compat;
/// Per-connection identity and cancellation.
pub(crate) mod connection;
/// Per-connection traffic counters.
pub(crate) mod counters;
/// Inbound message dispatcher.
pub mod dispatch;
/// Block download window, peer-assignment, stall, and scheduling policy.
pub mod download_window;
/// Typed endpoint parsing, BIP155 conversion, and the single transport dial.
pub mod endpoint;
/// Inbound eviction selection when the inbound slots are full.
pub(crate) mod eviction;
/// BIP434 feature negotiation messages and codec.
pub mod feature;
/// Peer finite-state machine.
pub(crate) mod fsm;
/// Version/verack negotiation helpers.
pub mod handshake;
/// Inbound block payloads with preserved wire bytes.
pub(crate) mod inbound;
/// Inventory relay helpers.
pub mod inv;
/// Inbound accept loop, outbound dial, and their shared start-epoch wiring.
pub mod listener;
pub(crate) mod netgroup;

/// Bitcoin Core `net:*` tracepoint payload mapping.
mod net_trace;

/// Peer state and DNS resolution types.
pub(crate) mod peer;
/// Peer metadata published after a successful handshake.
pub(crate) mod peer_info;
/// Single owner of live peer sessions: leases and their handshake metadata.
pub(crate) mod peer_table;
/// Buffered reads that survive a peer socket's poll interval.
pub(crate) mod recv;
/// I2P SAM v3 client for typed I2P transports.
pub(crate) mod sam;
/// Runtime owner for P2P control state and workers.
pub(crate) mod service;
/// SOCKS5 client for proxied IP and onion transports.
pub(crate) mod socks;
/// Manual IP subnet banning primitives.
pub mod subnet;
/// Block-download executor driving the applied-chain [`sync::SyncChain`] seam.
pub mod sync;
/// External Tor control-port client for the onion hidden service.
pub(crate) mod tor_control;
/// A connection's v1 or BIP324 v2 transport and its negotiation.
pub(crate) mod transport;
/// Connection-bound transaction request and relay policy.
pub(crate) mod tx_policy;
/// Bounded transaction announcements and their peer relay worker.
pub(crate) mod tx_relay;
/// Bitcoin P2P wire codec.
pub mod wire;

#[cfg(test)]
mod test_support;

pub use bitcoin_rs_primitives::{EndpointHost, NetworkLabel, PeerEndpoint};
pub use block_announce::{
    BlockAnnounceConfig, BlockAnnounceQueue, BlockAnnounceReceiver, BlockAnnouncer,
    MAX_BLOCKS_TO_ANNOUNCE, MAX_HIGH_BANDWIDTH_PEERS, spawn_block_announce_worker,
};
pub(crate) use block_stager::BlockStager;
pub use chain_query::{ActiveChainQuery, RecentBlockSlot};
pub use compact_blocks::{CompactBlockHints, Reconstruction};
pub use compat::{COMMANDS, CORE_UNTYPED_COMMANDS, PINNED_CORE_VERSION};
pub use connection::{ConnectionId, OutboundRefusal, PeerLease, PeerSource, QueuedFrame};
pub use counters::{CountingStream, PeerCounters};
pub use dispatch::{ChainQuery, FilterRequest, FilterServing, InventoryServing, TxInventory};
pub use endpoint::{
    DialFailure, DialRoutes, OverlayConfig, TransportRemote, accepted_ip_identity,
    addrv2_gossip_enabled, connect_peer_stream, dialed_ip_identity, endpoint_from_addrv2,
    endpoint_to_addrv2, format_endpoint, parse_endpoint,
};
pub use feature::{
    FEATURE_COMMAND, FEATURE_V2_SHORT_ID, FEATURE_VERSION, FeatureAnnouncement, FeatureError,
    FeatureId,
};
pub use inbound::{InboundBlock, InboundHeaders, InboundTx};
pub use inv::request_missing_parents;
pub use listener::ListenerExtras;
pub use peer::{
    CompactBlockNegotiation, NetworkActivity, Peer, PeerCapabilities, PeerState, WtxidRelayState,
};
pub use peer_info::{PeerInfo, PeerRole, service_flag_names};
pub use peer_table::{PeerSession, PeerTable};
pub use service::{
    BannedReader, OutboundDial, P2pControlError, P2pJoinError, P2pService, P2pServiceConfig,
    P2pServiceError,
};
pub use subnet::{BannedSubnet, IpSubnet, SubnetParseError};
pub use tor_control::TorControlTarget;
pub use transport::{TransportFailure, TransportProtocol};
pub use tx_relay::{
    DEFAULT_TX_RELAY_QUEUE_CAPACITY, LocalTxRelayObserver, PeerRelaySink, RelayOutcome,
    RelayRequest, RelaySink, TxRelayQueue, spawn_tx_relay_worker,
};
pub use wire::{Message, PeerError};

pub use download_window::default_sync_budget;

/// Bounded automatic reconnect avoidance; manual bans retain their owner.
pub mod discouragement;
