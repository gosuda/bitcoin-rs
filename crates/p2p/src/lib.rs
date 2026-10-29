#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

pub(crate) mod addrman;
/// BIP324 v2 transport cryptography: key schedule and packet ciphers.
pub(crate) mod bip324;
pub mod block_announce;
pub(crate) mod block_stager;
pub(crate) mod chain_query;
/// BIP152 compact-block reconstruction: bounded per-peer pending state.
pub mod compact_blocks;
pub mod compat;
pub(crate) mod connection;
pub(crate) mod counters;
pub mod dispatch;
pub mod download_window;
/// Typed endpoint parsing, BIP155 conversion, and the single transport dial.
pub mod endpoint;
pub(crate) mod eviction;
/// BIP434 feature negotiation messages and codec.
pub mod feature;
pub(crate) mod fsm;
pub mod handshake;
pub(crate) mod inbound;
pub mod inv;
pub mod listener;
pub(crate) mod netgroup;
pub mod overlay;
pub use overlay::OverlayNetworkState;

mod net_trace;

/// BIP331 ancestor package relay codec and combined package hash.
pub mod packages;

pub(crate) mod peer;
pub(crate) mod peer_info;
pub(crate) mod peer_table;
pub(crate) mod recv;
pub(crate) mod sam;
pub(crate) mod service;
pub(crate) mod socks;
/// BIP332 `staletip` message codec.
pub mod staletip;
pub mod subnet;
pub mod sync;
/// A connection's v1 or BIP324 v2 transport and its negotiation.
pub(crate) mod transport;
pub(crate) mod tx_policy;
pub(crate) mod tx_relay;
pub mod wire;

#[cfg(test)]
mod test_support;

pub use bitcoin_rs_primitives::{
    EndpointHost, NetworkLabel, PeerAddress, PeerEndpoint, PeerNetwork,
};
pub use block_announce::{
    BlockAnnounceConfig, BlockAnnounceQueue, BlockAnnounceReceiver, BlockAnnouncer,
    MAX_BLOCKS_TO_ANNOUNCE, MAX_HIGH_BANDWIDTH_PEERS, spawn_block_announce_worker,
};
pub(crate) use block_stager::BlockStager;
pub use chain_query::{ActiveChainQuery, RecentBlockSlot};
pub use compact_blocks::{CompactBlockHints, Reconstruction};
pub use compat::{COMMANDS, CORE_UNTYPED_COMMANDS, PINNED_CORE_VERSION};
pub use connection::{
    ConnectionId, OutboundRefusal, PeerLease, PeerRemote, PeerSource, QueuedFrame,
};
pub use counters::{CountingStream, PeerCounters};
pub use dispatch::{
    ChainQuery, FilterRequest, FilterServing, InventoryServing, StaleTipHeaders, TxInventory,
};
pub use endpoint::{
    DialFailure, DialRoutes, RouteDenial, RouteTable, TransportRemote, accepted_ip_identity,
    addrv2_gossip_enabled, connect_peer_stream, dialed_ip_identity, endpoint_from_addrv2,
    endpoint_to_addrv2, format_endpoint, parse_endpoint,
};
pub use feature::{
    FEATURE_COMMAND, FEATURE_V2_SHORT_ID, FEATURE_VERSION, FeatureAnnouncement, FeatureError,
    FeatureId,
};
pub use inbound::{InboundBlock, InboundHeaders, InboundTx};
pub use inv::request_missing_parents;
pub use listener::{ListenerExtras, RelayOffers};
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
pub use transport::{TransportFailure, TransportProtocol};
pub use tx_policy::{
    InboundBody, InboundPackage, MAX_DECODED_PACKAGES_PER_PEER, OpenedPackage, PackageCapacity,
    PackageCharge, PackageOpening, PackagePlan, PackageRefusal, PackageRejection, PackageTeardown,
    PackageToken, plan_package_charge,
};
pub use tx_relay::{
    DEFAULT_TX_RELAY_QUEUE_CAPACITY, LocalTxRelayObserver, PeerRelaySink, RelayOutcome,
    RelayRequest, RelaySink, TxRelayQueue, spawn_tx_relay_worker,
};
pub use wire::{Message, PeerError};

pub use download_window::default_sync_budget;
pub use sync::StaleTipRetainer;

pub mod discouragement;
