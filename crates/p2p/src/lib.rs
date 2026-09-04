#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// BIP155 addrv2 address helpers.
pub mod addrv2;
/// Peer banning and persistence.
pub mod banlist;
/// Active-chain `getheaders` / `getdata` serving.
pub mod chain_query;
/// Bitcoin Core P2P compatibility inventory: pinned reference and command set.
pub mod compat;
/// Per-connection identity and cancellation.
pub mod connection;
/// Per-connection traffic counters.
pub mod counters;
/// Inbound message dispatcher.
pub mod dispatch;
/// Block download window, peer-assignment, stall, and scheduling policy.
pub mod download_window;
/// Peer finite-state machine.
pub mod fsm;
/// Version/verack negotiation helpers.
pub mod handshake;
/// Inbound block payloads with preserved wire bytes.
pub mod inbound;
/// Inventory relay helpers.
pub mod inv;
/// TCP listener skeleton with graceful shutdown.
pub mod listener;
/// Peer state and peer manager types.
pub mod peer;
/// Peer metadata published after a successful handshake.
pub mod peer_info;
/// Single owner of live peer sessions: leases and their handshake metadata.
pub mod peer_table;
/// Runtime owner for P2P control state and workers.
pub mod service;
/// Peer TCP socket options: `TCP_NODELAY`, blocking I/O, poll timeouts.
pub mod socket;
/// Manual IP subnet banning primitives.
pub mod subnet;
/// Bitcoin P2P wire codec.
pub mod wire;
/// BIP339 wtxid-relay state.
pub mod wtxid;

pub use chain_query::ActiveChainQuery;
pub use compat::{COMMANDS, CORE_UNTYPED_COMMANDS, Command, CommandStatus, PINNED_CORE_VERSION};
pub use connection::{ConnectionId, PeerLease, PeerLifecycle, PeerSource, PeerStats, ReadyPeer};
pub use counters::{CountingStream, PeerCounters};
pub use dispatch::{ChainQuery, InventoryServing, TxInventory};
pub use inbound::{InboundBlock, InboundHeaders, InboundTx};
pub use listener::{ListenerExtras, spawn_outbound_connection};
pub use peer::{
    AddNodeError, AddedNodeInfo, BanError, ConnectedPeer, ConnectionCounts, DnsResolver,
    MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE_USIZE, NetworkActivity, NetworkControls,
    NodeAddress, Peer, PeerManager, PeerState, SystemDnsResolver, TrafficTotals,
    UPLOAD_TIMEFRAME_SECS, UploadTarget,
};
pub use peer_info::PeerInfo;
pub use peer_table::{PeerSession, PeerTable};
pub use service::{
    P2pControlError, P2pJoinError, P2pService, P2pServiceConfig, P2pServiceError,
    apply_network_active,
};
pub use socket::configure_peer_stream;
pub use subnet::{BannedSubnet, IpSubnet, SubnetParseError};
pub use wire::{Message, PeerError};

pub use download_window::{
    DownloadWindow, FanoutCandidate, SyncBudget, SyncPeer, SyncPeerSelection,
    configure_request_mode, default_sync_budget, statically_fanout_eligible,
};
