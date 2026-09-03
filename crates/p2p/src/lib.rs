#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Block download window, peer-assignment, stall, and scheduling policy.
#[allow(missing_docs)]
pub mod download;
/// BIP155 addrv2 address helpers.
pub mod addrv2;
/// Peer banning and persistence.
pub mod banlist;
/// Per-connection identity and cancellation.
pub mod connection;
/// Inbound message dispatcher.
pub mod dispatch;
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
/// Runtime owner for P2P control state and workers.
pub mod service;
/// Manual IP subnet banning primitives.
pub mod subnet;
/// Bitcoin P2P wire codec.
pub mod wire;
/// BIP339 wtxid-relay state.
pub mod wtxid;

pub use connection::{ConnectionId, PeerLease, PeerLifecycle, PeerSource, PeerStats, ReadyPeer};
pub use dispatch::{ChainQuery, InventoryServing, TxInventory};
pub use inbound::{InboundBlock, InboundHeaders, InboundTx};
pub use peer::{
    AddNodeError, AddedNodeInfo, BanError, ConnectedPeer, ConnectionCounts, DnsResolver,
    MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE_USIZE, NetworkActivity, NetworkControls,
    NodeAddress, Peer, PeerManager, PeerState, SystemDnsResolver, TrafficTotals,
    UPLOAD_TIMEFRAME_SECS, UploadTarget,
};
pub use download::{
    DownloadWindow, PeerRequest, SyncBudget, SyncPeer, SyncPeerSelection, select_download_peers,
    statically_fanout_eligible,
};
pub use peer_info::PeerInfo;
pub use service::{P2pControlError, P2pService, P2pServiceConfig, P2pServiceError};
pub use subnet::{BannedSubnet, IpSubnet, SubnetParseError};
pub use wire::{Message, PeerError};
