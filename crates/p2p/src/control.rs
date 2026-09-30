//! The two narrow capabilities the P2P runtime owner hands to RPC.
//!
//! ARCH-07 mutation boundary: `P2pService` is the single mutation authority
//! for P2P control state — the manual ban list, the persistent added-node
//! list, the network-active latch, the outbound dial queue, and peer
//! disconnects. [`P2pControl`] grants its control verbs while [`P2pQuery`]
//! answers read-only snapshots of that same state. `P2pService` implements
//! both, so query access stays narrow and separate from control access and no
//! writable P2P handle reaches a consumer.

use std::net::SocketAddr;

/// Read-only facts about one handshake-complete peer.
///
/// This deliberately copies the metadata, traffic measurements, and lease
/// properties RPC renders. It returns neither the live [`crate::PeerCounters`]
/// nor a [`crate::PeerLease`], either of which would grant mutation authority
/// through the query capability.
#[derive(Clone, Debug)]
pub struct PeerSnapshot {
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Protocol version advertised by the remote.
    pub version: u32,
    /// Service flags advertised by the remote.
    pub services: u64,
    /// User-agent string advertised by the remote.
    pub user_agent: String,
    /// Unix-epoch seconds of handshake completion.
    pub conn_time: u64,
    /// Whether the remote opened this connection.
    pub inbound: bool,
    /// Local socket address this connection is bound to.
    pub addr_bind: SocketAddr,
    /// Seconds the peer's clock is ahead of this node's.
    pub time_offset: i64,
    /// Total bytes written to the peer when this snapshot was taken.
    pub bytes_sent: u64,
    /// Total bytes read from the peer when this snapshot was taken.
    pub bytes_received: u64,
    /// Unix seconds of the latest write when this snapshot was taken.
    pub last_send: u64,
    /// Unix seconds of the latest read when this snapshot was taken.
    pub last_received: u64,
    /// Whether the operator explicitly requested this connection.
    pub manual: bool,
    /// Relay role assigned to this connection.
    pub role: crate::PeerRole,
}

/// Read-only projections of P2P control state.
///
/// Every answer is a snapshot or a plain value; nothing returned here is a
/// mutation handle.
pub trait P2pQuery: Send + Sync {
    /// Whether the node accepts or starts P2P connections.
    #[must_use]
    fn network_active(&self) -> bool;

    /// The service flags this node advertises in every `version`.
    #[must_use]
    fn local_services(&self) -> u64;

    /// A snapshot of the manual ban list.
    #[must_use]
    fn banned(&self) -> Vec<crate::BannedSubnet>;

    /// A snapshot of the configured `addnode add` addresses.
    #[must_use]
    fn added_nodes(&self) -> Vec<SocketAddr>;

    /// Read-only facts about every handshake-complete connection.
    #[must_use]
    fn peers(&self) -> Vec<PeerSnapshot>;

    /// Number of registered connections, including handshakes in progress.
    #[must_use]
    fn connection_count(&self) -> usize;

    /// Traffic the node can account for as `(received, sent)` bytes.
    #[must_use]
    fn traffic_totals(&self) -> (u64, u64);
}

/// Mutation authority for P2P control state.
///
/// `P2pService` implements this with the same verbs its own control API
/// exposes; a consumer holding this capability cannot reach workers or
/// lifecycle.
pub trait P2pControl: Send + Sync {
    /// Enables or disables network activity. Disabling cancels current peers.
    fn set_network_active(&self, active: bool);

    /// Adds or replaces one manual ban entry.
    fn set_ban(&self, entry: crate::BannedSubnet);

    /// Removes one manual ban entry.
    fn remove_ban(&self, subnet: crate::IpSubnet);

    /// Clears all manual bans.
    fn clear_banned(&self);

    /// Applies Core-like addnode state and requests a connection.
    /// While networking is inactive (including after shutdown), retains a
    /// persistent request without dialing and returns success unless banned.
    ///
    /// # Errors
    ///
    /// [`crate::P2pControlError`] when the destination is banned, or while
    /// networking is active, the dial queue is full or closed for a one-shot
    /// request.
    fn add_node(&self, addr: SocketAddr, persist: bool) -> Result<(), crate::P2pControlError>;

    /// Removes one configured addnode add address.
    fn remove_node(&self, addr: SocketAddr);

    /// Disconnects the peer named the way RPC `disconnectnode` names it:
    /// by address, optionally disambiguated with the `getpeerinfo` index.
    fn disconnect(&self, addr: SocketAddr, nodeid: Option<usize>) -> bool;
}
