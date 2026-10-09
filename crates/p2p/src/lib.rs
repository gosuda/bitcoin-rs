#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

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

/// Bitcoin Core `net:*` tracepoint payload mapping.
mod net_trace;

/// Peer state and DNS resolution types.
pub(crate) mod peer;
/// Peer metadata published after a successful handshake.
pub(crate) mod peer_info;
/// Single owner of live peer sessions: leases and their handshake metadata.
pub(crate) mod peer_table;
/// Runtime owner for P2P control state and workers.
pub(crate) mod service;
/// Peer TCP socket options: `TCP_NODELAY`, blocking I/O, poll timeouts.
pub(crate) mod socket;
/// Manual IP subnet banning primitives.
pub mod subnet;
/// Block-download executor driving the applied-chain [`sync::SyncChain`] seam.
pub mod sync;
/// Bounded transaction announcements and their peer relay worker.
pub(crate) mod tx_relay;
/// Bitcoin P2P wire codec.
pub mod wire;
/// BIP339 wtxid-relay state.
pub(crate) mod wtxid;

#[cfg(test)]
mod test_support;

pub use block_announce::{
    BlockAnnounceConfig, BlockAnnounceEvent, BlockAnnounceQueue, BlockAnnouncer,
    DEFAULT_BLOCK_ANNOUNCE_QUEUE_CAPACITY, MAX_BLOCKS_TO_ANNOUNCE, MAX_HIGH_BANDWIDTH_PEERS,
    PeerAnnounceTracker, spawn_block_announce_worker,
};
pub(crate) use block_stager::BlockStager;
pub use chain_query::ActiveChainQuery;
pub use compact_blocks::{CompactBlockHints, Reconstruction};
pub use compat::{COMMANDS, CORE_UNTYPED_COMMANDS, PINNED_CORE_VERSION};
pub use connection::{ConnectionId, PeerLease, PeerSource};
pub use counters::{CountingStream, PeerCounters};
pub use dispatch::{ChainQuery, InventoryServing, TxInventory};
pub use inbound::{InboundBlock, InboundHeaders, InboundTx};
pub use inv::request_missing_parents;
pub use listener::ListenerExtras;
pub use peer::{CompactBlockNegotiation, NetworkActivity, Peer, PeerCapabilities, PeerState};
pub use peer_info::{PeerInfo, PeerRole, service_flag_names};
pub use peer_table::{PeerSession, PeerTable};
pub use service::{
    BannedReader, OutboundDial, P2pControlError, P2pJoinError, P2pService, P2pServiceConfig,
    P2pServiceError,
};
pub use subnet::{BannedSubnet, IpSubnet, SubnetParseError};
pub use tx_relay::{
    DEFAULT_TX_RELAY_QUEUE_CAPACITY, LocalTxRelayObserver, PeerRelaySink, RelayOutcome,
    RelayRequest, RelaySink, TxRelayQueue, spawn_tx_relay_worker,
};
pub use wire::{Message, PeerError};
pub use wtxid::WtxidRelayState;

pub use download_window::default_sync_budget;
