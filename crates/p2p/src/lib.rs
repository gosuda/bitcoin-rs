#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "fuzzing")]
pub mod addrman;
#[cfg(not(feature = "fuzzing"))]
pub(crate) mod addrman;
#[cfg(feature = "fuzzing")]
pub mod bip324;
#[cfg(not(feature = "fuzzing"))]
pub(crate) mod bip324;
pub mod compact_blocks;
pub mod compat;
pub mod connection;
pub mod counters;
pub mod dispatch;
pub mod endpoint;
pub mod eviction;
pub mod feature;
pub mod fsm;
pub mod handshake;
pub mod inbound;
pub use inbound::block_memory;
pub mod inv;
pub mod listener;
pub mod netgroup;
pub mod overlay;
pub use overlay::OverlayNetworkState;

mod net_trace;

pub mod packages;

pub mod peer;
pub mod peer_info;
pub mod peer_table;
pub mod recv;
#[cfg(feature = "fuzzing")]
pub mod sam;
#[cfg(not(feature = "fuzzing"))]
pub(crate) mod sam;
pub mod service;
#[cfg(feature = "fuzzing")]
pub mod socks;
#[cfg(not(feature = "fuzzing"))]
pub(crate) mod socks;
pub mod staletip;
pub mod subnet;
pub mod transport;
pub mod wire;

#[cfg(any(test, verification))]
pub(crate) mod lease_model;

#[cfg(any(test, feature = "test-seam"))]
pub mod test_support;

pub use bitcoin_rs_consensus::primitives::{
    EndpointHost, NetworkLabel, PeerAddress, PeerEndpoint, PeerNetwork,
};

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

pub use wire::{Message, PeerError};

pub mod discouragement;
