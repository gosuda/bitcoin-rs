#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// BIP155 addrv2 address helpers.
pub mod addrv2;
/// Peer banning and persistence.
pub mod banlist;
/// BIP152 compact-block relay state.
pub mod compactblocks;
/// Inbound message dispatcher.
pub mod dispatch;
/// Peer finite-state machine.
pub mod fsm;
/// Version/verack negotiation helpers.
pub mod handshake;
/// Inventory relay helpers.
pub mod inv;
/// TCP listener skeleton with graceful shutdown.
pub mod listener;
/// Peer state and peer manager types.
pub mod peer;
/// Peer metadata published after a successful handshake.
pub mod peer_info;
/// Manual IP subnet banning primitives.
pub mod subnet;
/// Bitcoin P2P wire codec.
pub mod wire;
/// BIP339 wtxid-relay state.
pub mod wtxid;

pub use listener::spawn_outbound_connection;
pub use peer::{DnsResolver, Peer, PeerManager, PeerState};
pub use peer_info::PeerInfo;
pub use subnet::{BannedSubnet, IpSubnet, SubnetParseError};
pub use wire::{Message, PeerError};
