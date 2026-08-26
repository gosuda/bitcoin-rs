use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use bitcoin::p2p::Magic;
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::message_network::VersionMessage;
use crossbeam_channel::{Receiver, Sender, unbounded};
use parking_lot::RwLock;
use thiserror::Error;

use crate::connection::PeerStats;
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

/// Remote BIP152 compact-block negotiation preference.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompactBlockNegotiation {
    /// Whether the peer requested compact-block announcements.
    pub remote_send_compact: Option<bool>,
    /// Compact-block protocol version requested by the peer.
    pub remote_version: Option<u64>,
}

impl CompactBlockNegotiation {
    /// Record the latest remote `sendcmpct` preference.
    pub const fn record_remote_preference(&mut self, preference: &SendCmpct) {
        self.remote_send_compact = Some(preference.send_compact);
        self.remote_version = Some(preference.version);
    }
}

/// One peer connection and its negotiated protocol state.
#[derive(Debug)]
pub struct Peer<S> {
    /// Underlying byte stream.
    pub stream: S,
    /// Current protocol state.
    pub state: PeerState,
    /// Outbound message sender for event-loop integration.
    pub sender: Sender<Message>,
    /// Receiver paired with `sender` for tests and simple loops.
    pub receiver: Receiver<Message>,
    /// Expected network magic.
    pub magic: Magic,
    /// Last remote version message.
    pub remote_version: Option<VersionMessage>,
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
    /// Create a peer using an in-process outbound queue.
    pub fn new(stream: S, magic: Magic) -> Self {
        let (sender, receiver) = unbounded();
        Self {
            stream,
            state: PeerState::Disconnected,
            sender,
            receiver,
            magic,
            remote_version: None,
            received_verack: false,
            capabilities: PeerCapabilities::default(),
            compact_blocks: CompactBlockNegotiation::default(),
            wtxid_relay: WtxidRelayState::default(),
        }
    }

    /// Create a peer using an externally managed outbound sender.
    pub fn with_sender(stream: S, magic: Magic, sender: Sender<Message>) -> Self {
        let (_unused_sender, receiver) = unbounded();
        Self {
            stream,
            state: PeerState::Disconnected,
            sender,
            receiver,
            magic,
            remote_version: None,
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
    /// Queue and write one outbound message.
    pub fn send(&mut self, message: &Message) -> Result<(), PeerError> {
        self.sender
            .send(message.clone())
            .map_err(|_| PeerError::Protocol("outbound peer queue disconnected"))?;
        write_message(&mut self.stream, self.magic, message).map(|_| ())
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
#[derive(Debug)]
pub struct NetworkActivity {
    active: AtomicBool,
}

impl NetworkActivity {
    /// Creates a switch that is active unless `active` is `false`.
    #[must_use]
    pub const fn new(active: bool) -> Self {
        Self {
            active: AtomicBool::new(active),
        }
    }

    /// Applies the requested state and returns the state now in effect.
    pub fn set_active(&self, active: bool) -> bool {
        self.active.store(active, Ordering::Release);
        active
    }

    /// Returns whether p2p network activity is enabled.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

/// Length of the upload-target measuring window in seconds
/// (Core `MAX_UPLOAD_TIMEFRAME`, one day).
pub const UPLOAD_TIMEFRAME_SECS: u64 = 86_400;
/// Consensus maximum serialized block size, the per-10-minute relay buffer
/// unit in Core's historical-block serving rule.
pub const MAX_BLOCK_SERIALIZED_SIZE: u64 = 4_000_000;

/// Aggregate traffic totals and upload-target accounting behind `getnettotals`.
///
/// Byte totals accumulate since construction; the upload-target cycle mirrors
/// Core `CConnman::RecordBytesSent`: a cycle resets when the last reset lies
/// more than [`UPLOAD_TIMEFRAME_SECS`] in the past, and a target of `0` means
/// unlimited (all derived fields then report Core's unlimited defaults).
#[derive(Debug)]
pub struct TrafficTotals {
    bytes_recv: AtomicU64,
    bytes_sent: AtomicU64,
    max_upload_bytes: u64,
    cycle_start_secs: AtomicI64,
    sent_in_cycle: AtomicU64,
}

impl TrafficTotals {
    /// Creates totals with an upload target in bytes; `0` means unlimited.
    #[must_use]
    pub const fn new(max_upload_bytes: u64) -> Self {
        Self {
            bytes_recv: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            max_upload_bytes,
            cycle_start_secs: AtomicI64::new(0),
            sent_in_cycle: AtomicU64::new(0),
        }
    }

    /// Accounts received bytes against the running total.
    pub fn record_recv(&self, bytes: u64) {
        self.bytes_recv.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Accounts sent bytes against the running total and the upload cycle.
    pub fn record_sent(&self, bytes: u64) {
        let now = unix_time_secs();
        self.record_sent_at(bytes, now);
    }

    /// Time-injectable core of [`Self::record_sent`].
    pub fn record_sent_at(&self, bytes: u64, now_secs: i64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        let cycle_start = self.cycle_start_secs.load(Ordering::Relaxed);
        if cycle_start + i64::try_from(UPLOAD_TIMEFRAME_SECS).unwrap_or(i64::MAX) < now_secs {
            self.cycle_start_secs.store(now_secs, Ordering::Relaxed);
            self.sent_in_cycle.store(0, Ordering::Relaxed);
        }
        self.sent_in_cycle.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Total bytes received since construction.
    #[must_use]
    pub fn total_bytes_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }

    /// Total bytes sent since construction.
    #[must_use]
    pub fn total_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Live upload-target projection at `now_secs` (Core `getnettotals`
    /// `uploadtarget` object).
    #[must_use]
    pub fn upload_target(&self, now_secs: i64) -> UploadTarget {
        let target = self.max_upload_bytes;
        if target == 0 {
            return UploadTarget {
                timeframe_secs: UPLOAD_TIMEFRAME_SECS,
                target_bytes: 0,
                target_reached: false,
                serve_historical_blocks: true,
                bytes_left_in_cycle: 0,
                time_left_in_cycle_secs: 0,
            };
        }

        let sent = self.sent_in_cycle.load(Ordering::Relaxed);
        let cycle_start = self.cycle_start_secs.load(Ordering::Relaxed);
        let cycle_end = cycle_start + i64::try_from(UPLOAD_TIMEFRAME_SECS).unwrap_or(i64::MAX);
        let time_left = if cycle_start == 0 {
            i64::try_from(UPLOAD_TIMEFRAME_SECS).unwrap_or(i64::MAX)
        } else {
            (cycle_end - now_secs).max(0)
        };

        let reached = sent >= target;
        // Core keeps a buffer large enough to relay each block once per
        // remaining ten-minute slice of the cycle before declaring the
        // historical-block budget reached.
        let buffer = u64::try_from(time_left).unwrap_or(0) / 600 * MAX_BLOCK_SERIALIZED_SIZE;
        let historical_reached = buffer >= target || sent >= target.saturating_sub(buffer);

        UploadTarget {
            timeframe_secs: UPLOAD_TIMEFRAME_SECS,
            target_bytes: target,
            target_reached: reached,
            serve_historical_blocks: !historical_reached,
            bytes_left_in_cycle: target.saturating_sub(sent),
            time_left_in_cycle_secs: u64::try_from(time_left).unwrap_or(0),
        }
    }
}

/// One `getnettotals` upload-target reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadTarget {
    /// Length of the measuring timeframe in seconds.
    pub timeframe_secs: u64,
    /// Upload target in bytes (`0` reports an unlimited configuration).
    pub target_bytes: u64,
    /// Whether the raw target has been reached.
    pub target_reached: bool,
    /// Whether historical blocks are still served.
    pub serve_historical_blocks: bool,
    /// Bytes left in the current time cycle.
    pub bytes_left_in_cycle: u64,
    /// Seconds left in the current time cycle.
    pub time_left_in_cycle_secs: u64,
}

/// Directional split of live connections.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionCounts {
    /// Live inbound connections.
    pub inbound: usize,
    /// Live outbound connections.
    pub outbound: usize,
}

impl ConnectionCounts {
    /// Total live connections in both directions.
    #[must_use]
    pub fn total(self) -> usize {
        self.inbound + self.outbound
    }
}

/// Failure modes of manual ban operations, mirroring Core `setban` semantics.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BanError {
    /// An active ban already covers the requested subnet.
    #[error("ip/subnet already banned")]
    AlreadyBanned,
    /// An absolute ban timestamp lies in the past.
    #[error("absolute timestamp is in the past")]
    AbsoluteTimestampInPast,
    /// No manual ban matches the requested subnet.
    #[error("address/subnet was not previously manually banned")]
    NotBanned,
}

/// Failure modes of added-node operations, mirroring Core `addnode` semantics.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AddNodeError {
    /// The node is already in the added-node list.
    #[error("node already added")]
    AlreadyAdded,
    /// The node is not in the added-node list.
    #[error("node could not be removed. it has not been added previously.")]
    NotAdded,
}

/// One added-node entry joined with its live connection state
/// (Core `getaddednodeinfo` record).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddedNodeInfo {
    /// The node string exactly as it was added.
    pub spec: String,
    /// Resolved socket address captured when the node was added, when it
    /// resolved.
    pub resolved: Option<SocketAddr>,
    /// Whether a live connection currently matches the resolved address.
    pub connected: bool,
}

/// One address-book entry returned by [`NetworkControls::node_addresses`]
/// (Core `getnodeaddresses` record).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAddress {
    /// UNIX epoch seconds when the address was last observed.
    pub time: u64,
    /// Advertised service flags bitmask (`0` when unknown).
    pub services: u64,
    /// Host portion only (no port).
    pub address: String,
    /// TCP port.
    pub port: u16,
    /// Network name: `ipv4`, `ipv6`, `onion`, `i2p`, or `cjdns`.
    pub network: String,
}

/// One durable observed-address book entry owned by [`NetworkControls`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedAddressEntry {
    addr: SocketAddr,
    services: u64,
    time: u64,
}

/// One live connection snapshot joined from the lease map and the handshake
/// registry, backing `getpeerinfo`/`getconnectioncount` projections.
#[derive(Clone, Debug)]
pub struct ConnectedPeer {
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Stable process-unique connection id (Core `nodeid`).
    pub node_id: u64,
    /// Whether the connection was accepted inbound.
    pub inbound: bool,
    /// Handshake metadata, `None` while the handshake is still in progress.
    pub info: Option<crate::PeerInfo>,
    /// Live traffic and ping telemetry.
    pub stats: Arc<PeerStats>,
}

/// One stored added-node entry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AddedNodeEntry {
    spec: String,
    resolved: Option<SocketAddr>,
}

/// Authoritative network control plane over the shared peer, lease, and ban
/// state owned by the P2P listener.
///
/// All operations act on the same `Arc` handles the live listener uses, so
/// control calls are immediately observable in the connection state and vice
/// versa. The kill switch and aggregate traffic totals are authoritative here;
/// dials requested by added-node operations are queued onto the optional dial
/// channel exactly like RPC-triggered outbound connections.
#[derive(Clone)]
pub struct NetworkControls {
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    activity: Arc<NetworkActivity>,
    totals: Arc<TrafficTotals>,
    added_nodes: Arc<RwLock<Vec<AddedNodeEntry>>>,
    /// Durable address-book distinct from the live peer map (Core addrman facts
    /// reachable through `getnodeaddresses`).
    observed_addresses: Arc<RwLock<hashbrown::HashMap<SocketAddr, ObservedAddressEntry>>>,
    dial_tx: Option<Sender<SocketAddr>>,
    default_port: u16,
}

impl NetworkControls {
    /// Builds the control plane over the listener's shared state.
    #[must_use]
    pub fn new(
        peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
        peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>>,
        banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
        default_port: u16,
    ) -> Self {
        Self {
            peer_registry,
            peer_outbound,
            banned,
            activity: Arc::new(NetworkActivity::new(true)),
            totals: Arc::new(TrafficTotals::new(0)),
            added_nodes: Arc::new(RwLock::new(Vec::new())),
            observed_addresses: Arc::new(RwLock::new(hashbrown::HashMap::new())),
            dial_tx: None,
            default_port,
        }
    }

    /// Returns `self` with a dial channel for added-node connection attempts.
    #[must_use]
    pub fn with_dial_sender(mut self, dial_tx: Sender<SocketAddr>) -> Self {
        self.dial_tx = Some(dial_tx);
        self
    }

    /// Returns `self` with an upload target in bytes (`0` keeps unlimited).
    #[must_use]
    pub fn with_max_upload(mut self, max_upload_bytes: u64) -> Self {
        self.totals = Arc::new(TrafficTotals::new(max_upload_bytes));
        self
    }

    /// Shared handshake registry, also published to RPC projections.
    #[must_use]
    pub fn peer_registry(&self) -> &Arc<RwLock<Vec<crate::PeerInfo>>> {
        &self.peer_registry
    }

    /// Shared live-connection lease map.
    #[must_use]
    pub fn peer_outbound(&self) -> &Arc<RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>> {
        &self.peer_outbound
    }

    /// Shared manual ban list, also enforced by the listener.
    #[must_use]
    pub fn banned(&self) -> &Arc<RwLock<Vec<crate::BannedSubnet>>> {
        &self.banned
    }

    /// The network activity switch.
    #[must_use]
    pub fn activity(&self) -> &Arc<NetworkActivity> {
        &self.activity
    }

    /// The aggregate traffic totals.
    #[must_use]
    pub fn totals(&self) -> &Arc<TrafficTotals> {
        &self.totals
    }

    /// Live connection count in both directions, including connections whose
    /// handshake has not completed (Core `GetNodeCount(Both)`).
    #[must_use]
    pub fn connection_counts(&self) -> ConnectionCounts {
        let outbound = self.peer_outbound.read();
        let mut counts = ConnectionCounts::default();
        for lease in outbound.values() {
            if lease.is_inbound() {
                counts.inbound += 1;
            } else {
                counts.outbound += 1;
            }
        }
        counts
    }

    /// Snapshot of every live connection joined with handshake metadata.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<ConnectedPeer> {
        let infos: hashbrown::HashMap<SocketAddr, crate::PeerInfo> = self
            .peer_registry
            .read()
            .iter()
            .map(|info| (info.addr, info.clone()))
            .collect();
        self.peer_outbound
            .read()
            .iter()
            .map(|(addr, lease)| ConnectedPeer {
                addr: *addr,
                node_id: lease.node_id(),
                inbound: lease.is_inbound(),
                info: infos.get(addr).cloned(),
                stats: lease.stats_handle(),
            })
            .collect()
    }

    /// Median remote clock offset in seconds across peers that completed a
    /// handshake, when any offset has been observed.
    #[must_use]
    pub fn time_offset(&self) -> Option<i64> {
        let mut offsets: Vec<i64> = self
            .peer_outbound
            .read()
            .values()
            .filter_map(|lease| lease.stats().time_offset())
            .collect();
        offsets.sort_unstable();
        offsets.get(offsets.len() / 2).copied()
    }

    /// Queues one ping toward every live connection and returns the number of
    /// pings successfully queued (Core `PeerManager::SendPings`).
    pub fn send_pings(&self, now_us: u64) -> usize {
        let mut scheduled = 0;
        for lease in self.peer_outbound.read().values() {
            let nonce = lease.stats().begin_ping(now_us);
            if lease.send(crate::Message::Ping(nonce)).is_ok() {
                scheduled += 1;
            }
        }
        scheduled
    }

    /// Applies the network activity switch; existing peers stay connected.
    pub fn set_network_active(&self, active: bool) -> bool {
        self.activity.set_active(active)
    }

    /// Reads back the effective network activity state.
    #[must_use]
    pub fn network_active(&self) -> bool {
        self.activity.is_active()
    }

    /// Adds a manual ban following Core `setban add` semantics and disconnects
    /// every live peer matching the subnet, returning the disconnected
    /// addresses.
    pub fn ban(
        &self,
        subnet: crate::IpSubnet,
        ban_time_secs: i64,
        absolute: bool,
        now: SystemTime,
        reason: &str,
    ) -> Result<Vec<SocketAddr>, BanError> {
        let now_secs = unix_time_secs_at(now);
        if self.banned.read().iter().any(|entry| {
            entry.subnet == subnet && entry.banned_until.is_none_or(|until| until > now)
        }) {
            return Err(BanError::AlreadyBanned);
        }
        if absolute && ban_time_secs < now_secs {
            return Err(BanError::AbsoluteTimestampInPast);
        }

        let offset_secs = if ban_time_secs <= 0 {
            DEFAULT_BAN_TIME_SECS
        } else {
            ban_time_secs
        };
        let until_epoch = (if absolute { 0 } else { now_secs }).saturating_add(offset_secs);
        self.banned.write().push(crate::BannedSubnet {
            subnet,
            banned_until: Some(
                SystemTime::UNIX_EPOCH
                    + Duration::from_secs(until_epoch.max(0).try_into().unwrap_or(u64::MAX)),
            ),
            ban_created: now,
            reason: reason.to_owned(),
        });

        let disconnected = self.disconnect_matching(|addr, _| subnet.contains(addr.ip()));
        if !disconnected.is_empty() {
            tracing::info!(
                subnet = %subnet,
                disconnected = disconnected.len(),
                "manual ban applied; matching peers disconnected"
            );
        }
        Ok(disconnected)
    }

    /// Removes the manual ban exactly matching `subnet`
    /// (Core `setban remove`).
    pub fn unban(&self, subnet: &crate::IpSubnet) -> Result<(), BanError> {
        let mut banned = self.banned.write();
        let before = banned.len();
        banned.retain(|entry| &entry.subnet != subnet);
        if banned.len() == before {
            return Err(BanError::NotBanned);
        }
        Ok(())
    }

    /// Active manual bans with expired entries swept first
    /// (Core `BanMan::GetBanned`).
    #[must_use]
    pub fn banned_list(&self, now: SystemTime) -> Vec<crate::BannedSubnet> {
        let mut banned = self.banned.write();
        banned.retain(|entry| entry.banned_until.is_none_or(|until| until > now));
        banned.clone()
    }

    /// Clears every manual ban (Core `clearbanned`).
    pub fn clear_banned(&self) {
        self.banned.write().clear();
    }

    /// Whether `ip` is covered by an active manual ban.
    #[must_use]
    pub fn is_banned(&self, ip: IpAddr, now: SystemTime) -> bool {
        crate::subnet::is_banned(&self.banned.read(), ip, now)
    }

    /// Records a persistent added node and queues a best-effort connection
    /// (Core `addnode add`).
    pub fn add_node(&self, spec: &str) -> Result<(), AddNodeError> {
        let resolved = resolve_node(spec, self.default_port);
        let mut added = self.added_nodes.write();
        for entry in added.iter() {
            if entry.spec == spec {
                return Err(AddNodeError::AlreadyAdded);
            }
            if let (Some(existing), Some(new)) = (entry.resolved, resolved) {
                if existing == new {
                    return Err(AddNodeError::AlreadyAdded);
                }
            }
        }
        added.push(AddedNodeEntry {
            spec: spec.to_owned(),
            resolved,
        });
        drop(added);
        if let Some(addr) = resolved {
            self.observe_address(addr, 0, SystemTime::now());
            self.dial(addr);
        }
        Ok(())
    }

    /// Removes a persistent added node by its exact spec string; the current
    /// connection, if any, is left running (Core `addnode remove`).
    pub fn remove_added_node(&self, spec: &str) -> Result<(), AddNodeError> {
        let mut added = self.added_nodes.write();
        let before = added.len();
        added.retain(|entry| entry.spec != spec);
        if added.len() == before {
            return Err(AddNodeError::NotAdded);
        }
        Ok(())
    }

    /// Queues a one-shot connection attempt without recording the node
    /// (Core `addnode onetry`).
    pub fn try_node_connection(&self, spec: &str) {
        if let Some(addr) = resolve_node(spec, self.default_port) {
            self.observe_address(addr, 0, SystemTime::now());
            self.dial(addr);
        }
    }

    /// Added-node entries joined with live connection state
    /// (Core `getaddednodeinfo`).
    #[must_use]
    pub fn added_node_infos(&self) -> Vec<AddedNodeInfo> {
        let entries = self.added_nodes.read().clone();
        let connected: hashbrown::HashSet<SocketAddr> =
            self.peer_outbound.read().keys().copied().collect();
        entries
            .into_iter()
            .map(|entry| {
                let connected_flag = entry.resolved.is_some_and(|addr| connected.contains(&addr));
                AddedNodeInfo {
                    spec: entry.spec,
                    resolved: entry.resolved,
                    connected: connected_flag,
                }
            })
            .collect()
    }

    /// Records an observed peer address into the durable address book
    /// (Core addrman-style fact used by `getnodeaddresses`).
    pub fn observe_address(&self, addr: SocketAddr, services: u64, now: SystemTime) {
        let time = u64::try_from(unix_time_secs_at(now).max(0)).unwrap_or(0);
        let mut book = self.observed_addresses.write();
        book.entry(addr)
            .and_modify(|entry| {
                entry.time = time;
                if services != 0 {
                    entry.services = services;
                }
            })
            .or_insert(ObservedAddressEntry {
                addr,
                services,
                time,
            });
    }

    /// Ingests connection and added-node facts already owned by this control
    /// plane into the durable address book without replacing prior entries.
    fn ingest_known_address_facts(&self, now: SystemTime) {
        let infos: hashbrown::HashMap<SocketAddr, u64> = self
            .peer_registry
            .read()
            .iter()
            .map(|info| (info.addr, info.services))
            .collect();
        for (addr, services) in &infos {
            self.observe_address(*addr, *services, now);
        }
        for addr in self.peer_outbound.read().keys().copied() {
            let services = infos.get(&addr).copied().unwrap_or(0);
            self.observe_address(addr, services, now);
        }
        for entry in self.added_nodes.read().iter() {
            if let Some(addr) = entry.resolved {
                let services = infos.get(&addr).copied().unwrap_or(0);
                self.observe_address(addr, services, now);
            }
        }
    }

    /// Returns up to `count` observed addresses, optionally filtered by
    /// network name (Core `getnodeaddresses`).
    ///
    /// `count == 0` returns every matching address. `network` of `None` or
    /// `"all"` disables the network filter. Addresses persist after the peer
    /// disconnects because the book is distinct from the live lease map.
    #[must_use]
    pub fn node_addresses(&self, count: usize, network: Option<&str>) -> Vec<NodeAddress> {
        let now = SystemTime::now();
        self.ingest_known_address_facts(now);
        let filter = network
            .map(str::trim)
            .filter(|name| !name.is_empty() && !name.eq_ignore_ascii_case("all"));
        let mut addresses: Vec<NodeAddress> = self
            .observed_addresses
            .read()
            .values()
            .filter(|entry| filter.is_none_or(|wanted| address_network_name(entry.addr) == wanted))
            .map(|entry| NodeAddress {
                time: entry.time,
                services: entry.services,
                address: entry.addr.ip().to_string(),
                port: entry.addr.port(),
                network: address_network_name(entry.addr).to_owned(),
            })
            .collect();
        addresses.sort_by(|left, right| {
            right
                .time
                .cmp(&left.time)
                .then_with(|| left.address.cmp(&right.address))
                .then_with(|| left.port.cmp(&right.port))
        });
        if count != 0 && count < addresses.len() {
            addresses.truncate(count);
        }
        addresses
    }

    /// Cancels and removes every live lease matching `predicate`, also
    /// dropping its handshake-registry entry; returns the disconnected
    /// addresses in registry order.
    fn disconnect_matching(
        &self,
        predicate: impl Fn(&SocketAddr, &crate::PeerLease) -> bool,
    ) -> Vec<SocketAddr> {
        let targets: Vec<SocketAddr> = {
            let outbound = self.peer_outbound.read();
            outbound
                .iter()
                .filter(|(addr, lease)| predicate(addr, lease))
                .map(|(addr, _)| *addr)
                .collect()
        };
        if targets.is_empty() {
            return Vec::new();
        }
        let mut outbound = self.peer_outbound.write();
        let mut registry = self.peer_registry.write();
        let mut disconnected = Vec::new();
        for addr in targets {
            if let Some(lease) = outbound.remove(&addr) {
                lease.cancel();
                registry.retain(|peer| peer.addr != addr);
                disconnected.push(addr);
            }
        }
        disconnected
    }

    /// Disconnects the live connection at `addr`, removing its registry entry;
    /// returns `false` when no live connection matches.
    pub fn disconnect_node(&self, addr: &SocketAddr) -> bool {
        !self
            .disconnect_matching(|lease_addr, _| lease_addr == addr)
            .is_empty()
    }

    /// Disconnects the live connection with stable id `node_id`.
    pub fn disconnect_node_by_id(&self, node_id: u64) -> bool {
        !self
            .disconnect_matching(|_, lease| lease.node_id() == node_id)
            .is_empty()
    }

    /// Queues one dial onto the shared outbound channel unless networking is
    /// switched off (Core `OpenNetworkConnection` early-returns when
    /// inactive).
    fn dial(&self, addr: SocketAddr) {
        // Dial targets are observed even when networking is inactive so the
        // address book still learns about attempted peers.
        self.observe_address(addr, 0, SystemTime::now());
        if !self.activity.is_active() {
            return;
        }
        if let Some(dial_tx) = &self.dial_tx {
            let _ = dial_tx.try_send(addr);
        }
    }
}

/// Core `-bantime` default: 24 hours.
const DEFAULT_BAN_TIME_SECS: i64 = 86_400;

/// Resolves one addnode-style destination: `host:port`, `host` (default
/// port), a bare IP, or a bracketed IPv6 literal.
fn resolve_node(spec: &str, default_port: u16) -> Option<SocketAddr> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    (spec, default_port).to_socket_addrs().ok()?.next()
}

fn address_network_name(addr: SocketAddr) -> &'static str {
    match addr.ip() {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

fn unix_time_secs() -> i64 {
    unix_time_secs_at(SystemTime::now())
}

fn unix_time_secs_at(now: SystemTime) -> i64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

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

    #[test]
    fn upload_target_defaults_match_core_unlimited_configuration() {
        let totals = TrafficTotals::new(0);
        totals.record_sent_at(123_456, 1_000);
        assert_eq!(
            totals.upload_target(2_000),
            UploadTarget {
                timeframe_secs: UPLOAD_TIMEFRAME_SECS,
                target_bytes: 0,
                target_reached: false,
                serve_historical_blocks: true,
                bytes_left_in_cycle: 0,
                time_left_in_cycle_secs: 0,
            }
        );
        assert_eq!(totals.total_bytes_sent(), 123_456);
    }

    #[test]
    fn network_activity_switch_flips() {
        let activity = NetworkActivity::new(true);
        assert!(activity.is_active());
        assert!(!activity.set_active(false));
        assert!(!activity.is_active());
        assert!(activity.set_active(true));
    }

    fn controls_with_no_peers() -> NetworkControls {
        NetworkControls::new(
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(hashbrown::HashMap::new())),
            Arc::new(RwLock::new(Vec::new())),
            8_333,
        )
    }

    fn lease_in_map(
        controls: &NetworkControls,
        addr: SocketAddr,
        inbound: bool,
    ) -> crate::PeerLease {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = if inbound {
            crate::PeerLease::new_inbound(tx)
        } else {
            crate::PeerLease::new(tx)
        };
        controls.peer_outbound().write().insert(addr, lease.clone());
        lease
    }

    #[test]
    fn connection_counts_split_by_direction() {
        let controls = controls_with_no_peers();
        let a = SocketAddr::from(([127, 0, 0, 1], 1));
        let b = SocketAddr::from(([127, 0, 0, 1], 2));
        lease_in_map(&controls, a, true);
        lease_in_map(&controls, b, false);
        let counts = controls.connection_counts();
        assert_eq!(counts.inbound, 1);
        assert_eq!(counts.outbound, 1);
        assert_eq!(counts.total(), 2);
    }

    #[test]
    fn disconnect_node_removes_lease_and_registry_entry() {
        let controls = controls_with_no_peers();
        let addr = SocketAddr::from(([127, 0, 0, 1], 3));
        let lease = lease_in_map(&controls, addr, false);
        controls.peer_registry().write().push(crate::PeerInfo {
            addr,
            version: 70_016,
            services: 0,
            user_agent: String::from("/test/"),
            start_height: 0,
            conn_time: 0,
            inbound: false,
        });
        assert!(controls.disconnect_node(&addr));
        assert!(lease.is_cancelled());
        assert!(controls.peer_outbound().read().is_empty());
        assert!(controls.peer_registry().read().is_empty());
        assert!(!controls.disconnect_node(&addr));
    }

    #[test]
    fn send_pings_queues_nonce_per_live_lease() {
        let controls = controls_with_no_peers();
        let addr = SocketAddr::from(([127, 0, 0, 1], 5));
        let (tx, rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_inbound(tx);
        controls.peer_outbound().write().insert(addr, lease.clone());
        assert_eq!(controls.send_pings(10_000), 1);
        assert!(matches!(rx.try_recv(), Ok(Message::Ping(_))));
        assert!(lease.stats().ping_wait(10_500).is_some());
    }

    #[test]
    fn add_node_records_and_dials() {
        let (dial_tx, dial_rx) = crossbeam_channel::unbounded();
        let controls = controls_with_no_peers().with_dial_sender(dial_tx);
        controls
            .add_node("127.0.0.1:8333")
            .unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(
            dial_rx.try_recv(),
            Ok(SocketAddr::from(([127, 0, 0, 1], 8333)))
        );
        assert_eq!(controls.added_node_infos().len(), 1);
        assert!(matches!(
            controls.add_node("127.0.0.1:8333"),
            Err(AddNodeError::AlreadyAdded)
        ));
    }

    #[test]
    fn dials_are_suppressed_while_network_inactive() {
        let (dial_tx, dial_rx) = crossbeam_channel::unbounded();
        let controls = controls_with_no_peers().with_dial_sender(dial_tx);
        controls.set_network_active(false);
        controls.try_node_connection("127.0.0.3:18444");
        assert!(dial_rx.try_recv().is_err());
        // Address book still observes the attempt.
        assert_eq!(controls.node_addresses(0, None).len(), 1);
    }

    #[test]
    fn node_addresses_persist_observed_peers_and_added_nodes() {
        let controls = controls_with_no_peers();
        let connected = SocketAddr::from(([198, 51, 100, 1], 8333));
        lease_in_map(&controls, connected, false);
        controls.peer_registry().write().push(crate::PeerInfo {
            addr: connected,
            version: 70_016,
            services: 9,
            user_agent: String::from("/test/"),
            start_height: 1,
            conn_time: 10,
            inbound: false,
        });
        controls
            .add_node("198.51.100.2:8333")
            .unwrap_or_else(|err| panic!("add_node failed: {err}"));

        let all = controls.node_addresses(0, None);
        assert_eq!(all.len(), 2);
        let first = all
            .iter()
            .find(|entry| entry.address == "198.51.100.1")
            .unwrap_or_else(|| panic!("missing connected observation"));
        assert_eq!(first.port, 8333);
        assert_eq!(first.services, 9);
        assert_eq!(first.network, "ipv4");

        assert!(controls.disconnect_node(&connected));
        let after = controls.node_addresses(0, Some("ipv4"));
        assert!(
            after.iter().any(|entry| entry.address == "198.51.100.1"),
            "observed address must survive disconnect: {after:?}"
        );
        assert!(
            after.iter().any(|entry| entry.address == "198.51.100.2"),
            "added-node observation missing: {after:?}"
        );
        assert_eq!(controls.node_addresses(1, Some("ipv4")).len(), 1);
        assert!(controls.node_addresses(0, Some("ipv6")).is_empty());
    }

    #[test]
    fn observe_address_updates_services_without_dropping_entry() {
        let controls = controls_with_no_peers();
        let addr = SocketAddr::from(([203, 0, 113, 9], 18444));
        controls.observe_address(addr, 0, SystemTime::UNIX_EPOCH);
        controls.observe_address(addr, 73, SystemTime::UNIX_EPOCH + Duration::from_secs(50));
        let entries = controls.node_addresses(0, None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].services, 73);
        assert_eq!(entries[0].time, 50);
    }
}
