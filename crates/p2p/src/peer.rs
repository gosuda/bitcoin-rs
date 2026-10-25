use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::p2p::Magic;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::message_network::VersionMessage;
use hashbrown::HashMap;

use crate::feature::FeatureId;
use crate::wire::{Message, PeerError};

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

/// BIP339 wtxid-relay negotiation state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WtxidRelayState {
    peer_advertised: bool,
}

impl WtxidRelayState {
    /// Mark that the remote peer sent `wtxidrelay`.
    pub(crate) const fn mark_peer_supported(&mut self) {
        self.peer_advertised = true;
    }

    /// Return true if the remote peer advertised BIP339 support.
    pub const fn peer_supported(self) -> bool {
        self.peer_advertised
    }
}

/// BIP152 compact-block protocol version this node speaks and advertises.
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
    /// Whether `version` is one this node advertises and can negotiate.
    #[must_use]
    const fn supports_version(version: u64) -> bool {
        version == COMPACT_BLOCK_VERSION
    }

    /// Record the latest supported remote `sendcmpct` preference. Messages
    /// for versions we did not advertise have no effect, as BIP152 requires.
    pub(crate) const fn record_remote_preference(&mut self, preference: &SendCmpct) {
        if !Self::supports_version(preference.version) {
            return;
        }
        self.remote_send_compact = Some(preference.send_compact);
        self.remote_version = Some(preference.version);
    }

    /// Record the version this node sent in its handshake `sendcmpct`.
    pub(crate) const fn record_local_advertised(&mut self, version: u64) {
        self.local_version = Some(version);
    }

    /// The compact-block version this node advertised to the peer.
    #[must_use]
    pub(crate) const fn local_version(&self) -> Option<u64> {
        self.local_version
    }

    /// The mutually supported remote preference selected for this connection.
    #[must_use]
    pub(crate) const fn remote_preference(&self) -> Option<SendCmpct> {
        match (self.remote_send_compact, self.remote_version) {
            (Some(send_compact), Some(version)) => Some(SendCmpct {
                send_compact,
                version,
            }),
            _ => None,
        }
    }

    /// The version to serve this peer's `MSG_CMPCT_BLOCK` requests at, or
    /// `None` while the peer has not announced a mutually supported BIP152
    /// version. Unsupported messages never change the negotiated profile.
    #[must_use]
    pub(crate) const fn servable_version(&self) -> Option<u64> {
        match self.remote_preference() {
            Some(preference) => Some(preference.version),
            _ => None,
        }
    }
}

/// Why a parked compact-filter request last made no progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FilterHalt {
    /// The filter index has not published the range yet, or the last pass
    /// was never refused by an outbound budget.
    Index,
    /// This connection's own outbound bounds refused the reservation.
    Local,
    /// The node's aggregate outbound budget refused the reservation.
    Shared,
}

impl FilterHalt {
    /// The halt a serving pass reports: the kind of its last refused
    /// reservation, or [`FilterHalt::Index`] when nothing was refused.
    pub(crate) const fn from_refusal(refusal: Option<crate::connection::Refusal>) -> Self {
        match refusal {
            Some(crate::connection::Refusal::Local) => Self::Local,
            Some(crate::connection::Refusal::Shared) => Self::Shared,
            None => Self::Index,
        }
    }
}

/// One compact-filter request waiting to resume, with its publication
/// deadline.
///
/// `pending` is the only cursor: the peer's request, or the narrowed
/// remainder after a prefix was sent. The allowance is the time the request
/// may wait for index publication or for this connection's own queue. Time
/// spent refused by the node aggregate is never charged to it. The aggregate
/// counts this connection's own queued bytes with everyone else's, with no
/// fairness quota.
#[derive(Debug)]
pub(crate) struct ParkedFilter {
    /// The request still to serve.
    pub(crate) pending: crate::dispatch::FilterRequest,
    /// Waiting time left before the request times out.
    pub(crate) allowance: std::time::Duration,
    /// Start of the interval the next pass charges.
    pub(crate) since: std::time::Instant,
    /// Why the last pass stopped; decides whether the interval is charged.
    pub(crate) last: FilterHalt,
}

impl ParkedFilter {
    /// Total waiting time one request is allowed outside shared refusals.
    pub(crate) const ALLOWANCE: std::time::Duration = std::time::Duration::from_secs(5);

    /// Parks `pending` at `now` with the full allowance.
    pub(crate) const fn new(
        pending: crate::dispatch::FilterRequest,
        now: std::time::Instant,
    ) -> Self {
        Self {
            pending,
            allowance: Self::ALLOWANCE,
            since: now,
            last: FilterHalt::Index,
        }
    }

    /// Charges the interval since the last pass at `now` and starts the next.
    ///
    /// POST: the allowance shrinks by the interval unless the last pass was
    /// refused by the node aggregate; `true` means the allowance is spent.
    pub(crate) fn charge(&mut self, now: std::time::Instant) -> bool {
        if self.last != FilterHalt::Shared {
            self.allowance = self
                .allowance
                .saturating_sub(now.saturating_duration_since(self.since));
        }
        self.since = now;
        self.allowance.is_zero()
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
    /// BIP434 feature announcements the peer sent between its `version` and
    /// `verack`, by identifier.
    ///
    /// This map is the sole owner of remote feature announcements and only
    /// the FSM's `receive_feature` inserts into it. It keeps the first valid
    /// payload of each recognised feature (see
    /// `FeatureAnnouncement::is_supported`); unknown identifiers and invalid
    /// payloads are never retained, so its size is bounded by the number of
    /// recognised features, not by what the peer sends. Readers use
    /// [`Peer::remote_feature`].
    pub(crate) remote_features: HashMap<FeatureId, Vec<u8>>,
    /// Whether this node announces BIP332 stale-tip relay to the peer, and
    /// its `prefers_blocks` byte; `None`, the default, announces nothing.
    pub(crate) stale_tip_offer: Option<bool>,
    /// One BIP157 request waiting for asynchronous index publication or for
    /// outbound room.
    pub(crate) pending_filter_request: Option<ParkedFilter>,
    /// One decoded request-scoped message whose reply could not be reserved
    /// yet (`ping`, `getheaders`, `getaddr`, a compact-block follow-up). It
    /// is dispatched once, after its reply is reserved; the session reads
    /// nothing from the peer while it is held, so the inbound side stays
    /// bounded at one decoded request.
    pub(crate) deferred_inbound: Option<Message>,
    /// The unserved remainder of one `getdata` that stopped at the outbound
    /// production gate, in request order; empty when nothing is parked.
    /// Always a suffix of one decoded request, so it never exceeds
    /// [`crate::inv::MAX_INV_PER_MSG`] items. The session loop reads nothing
    /// from the peer while it is non-empty.
    pub(crate) pending_getdata: Vec<Inventory>,
    /// Items of the parked `getdata` already found unservable. They are
    /// reported in one `notfound` ahead of the tail's own answers once the
    /// queue can take the message.
    pub(crate) pending_notfound: Vec<Inventory>,
    /// `net:*` probe context attached by live connection roots; `None` on
    /// probe-free constructions, which keeps the probes out of their binaries.
    pub(crate) net_trace: Option<crate::net_trace::NetTrace>,
    /// Receive half of the transport, with any partial frame or packet kept
    /// across poll timeouts.
    recv: crate::transport::RecvTransport,
    /// Send half of the transport, until the connection's writer thread takes it.
    send: Option<crate::transport::SendTransport>,
    /// The transport this connection negotiated.
    transport: crate::transport::TransportProtocol,
}

impl<S> Peer<S> {
    /// Create a v1 peer over `stream`.
    pub fn new(stream: S, magic: Magic) -> Self {
        Self::with_transport(stream, magic, crate::transport::Negotiated::v1(magic))
    }

    /// Create a peer over `stream` speaking the `negotiated` transport.
    pub(crate) fn with_transport(
        stream: S,
        magic: Magic,
        negotiated: crate::transport::Negotiated,
    ) -> Self {
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
            remote_features: HashMap::new(),
            stale_tip_offer: None,
            pending_filter_request: None,
            deferred_inbound: None,
            pending_getdata: Vec::new(),
            pending_notfound: Vec::new(),
            net_trace: None,
            recv: negotiated.recv,
            send: Some(negotiated.send),
            transport: negotiated.protocol,
        }
    }

    /// The transport this connection negotiated.
    pub const fn transport(&self) -> crate::TransportProtocol {
        self.transport
    }

    /// Hands the send half to the connection's writer thread. Later sends
    /// through this peer fail.
    pub(crate) fn take_send_transport(&mut self) -> Option<crate::transport::SendTransport> {
        self.send.take()
    }

    /// Announce BIP332 stale-tip relay to this peer, with `prefers_blocks` as
    /// the feature's single data byte.
    ///
    /// PRE: called before the handshake sends our `version` reply.
    /// POST: the BIP434 `feature` goes only to a peer at protocol version
    ///   70017 or above ([`crate::handshake`]); by default nothing is announced.
    ///   Whether the peer relays stale tips back is
    ///   [`Peer::remote_feature`]`(b"BIP332")`.
    pub fn offer_stale_tip_relay(&mut self, prefers_blocks: bool) {
        self.stale_tip_offer = Some(prefers_blocks);
    }

    /// The payload the peer announced for the recognised BIP434 feature `id`,
    /// or `None` when it announced no valid one before `verack`.
    ///
    /// POST: a returned payload already satisfies the feature's own validity
    /// rules; the first valid announcement wins.
    #[must_use]
    pub fn remote_feature(&self, id: &[u8]) -> Option<&[u8]> {
        self.remote_features.get(id).map(Vec::as_slice)
    }

    /// Whether a `getdata` is parked, tail or deferred `notfound`: the
    /// session owes the peer answers and must not read further requests.
    #[must_use]
    pub(crate) fn has_parked_getdata(&self) -> bool {
        !self.pending_getdata.is_empty() || !self.pending_notfound.is_empty()
    }

    /// Attaches the `net:*` probe context captured at the connection root.
    pub(crate) fn attach_net_trace(&mut self, net_trace: crate::net_trace::NetTrace) {
        self.net_trace = Some(net_trace);
    }

    /// Mark the peer ready once both version and verack have arrived.
    pub(crate) const fn refresh_ready_state(&mut self) {
        if self.remote_version.is_some() && self.received_verack {
            self.state = PeerState::Ready;
        }
    }
}

impl<S: Read + Write> Peer<S> {
    /// Write one outbound message through the connection's transport.
    ///
    /// Returns the v1 frame length, the budget a lease charges for the
    /// message whichever transport carries it.
    ///
    /// The message is encoded once, and `net:outbound_message` observes its
    /// payload before the write attempt, the way Core's `CSerializedNetMsg` is
    /// shared by its send path and the probe.
    pub fn send(&mut self, message: &Message) -> Result<usize, PeerError> {
        let transport = self.send.as_mut().ok_or(PeerError::Protocol(
            "send transport moved to the writer thread",
        ))?;
        let frame = transport.encode(message)?;
        crate::net_trace::outbound_message(self.net_trace.as_ref(), message, frame.payload());
        crate::wire::write_frame(&mut self.stream, &frame)
    }
}

impl<S: Read> Peer<S> {
    /// Read at most one message through the connection's transport.
    ///
    /// `Ok(None)` only from a v2 session: the packet was a BIP324 decoy or a
    /// message of an empty or undefined type, both dropped. A v1 frame always
    /// yields `Some`. A poll timeout part-way through a frame or packet keeps
    /// the bytes already read, so retrying after `TimedOut` or `WouldBlock`
    /// continues it.
    pub fn read_message(&mut self) -> Result<Option<(Message, bytes::Bytes)>, PeerError> {
        let net_trace = self.net_trace.as_ref();
        self.recv
            .read_message(&mut self.stream, self.magic, |command, payload| {
                crate::net_trace::inbound_message(net_trace, command, payload);
            })
            .map_err(PeerError::inbound)
    }
}

/// DNS resolver injection point for peer discovery.
pub(crate) trait DnsResolver: Send + Sync {
    /// Resolve a DNS seed name into socket addresses.
    fn resolve(&self, seed: &str) -> Result<Vec<SocketAddr>, PeerError>;
}

/// DNS resolver backed by the operating system resolver.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SystemDnsResolver {
    port: u16,
}

impl SystemDnsResolver {
    /// Create a DNS resolver that attaches `port` to each resolved seed host.
    #[must_use]
    pub(crate) const fn new(port: u16) -> Self {
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

/// Read-only view of the service activity switch behind `setnetworkactive`.
///
/// The service changes this flag through `PeerTable`, serialized with socket
/// admission. Disabling cancels admitted leases and prevents new registration;
/// connection owners tear down their sockets. Enabling permits fresh admission.
#[derive(Debug, Clone)]
pub struct NetworkActivity {
    active: Arc<AtomicBool>,
}

impl NetworkActivity {
    /// Shares the service-owned activity flag.
    /// PRE: `active` is the flag owned by [`crate::P2pService`].
    /// POST: Return a switch reading exactly that flag.
    /// INVARIANT: The service owns activity transitions; this type never
    /// writes the flag.
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
pub(crate) const MAX_BLOCK_SERIALIZED_SIZE_USIZE: usize = 4_000_000;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::write_message;

    fn filter_request() -> crate::dispatch::FilterRequest {
        crate::dispatch::FilterRequest::new(crate::Message::GetAddr)
    }

    /// The publication deadline is charged for waiting on the filter index or
    /// on the connection's own queue, never for time the node aggregate
    /// refused the request.
    #[test]
    fn filter_deadline_excludes_only_shared() {
        let t0 = std::time::Instant::now();
        let half = ParkedFilter::ALLOWANCE / 2;

        let mut shared = ParkedFilter::new(filter_request(), t0);
        shared.last = FilterHalt::Shared;
        assert!(
            !shared.charge(t0 + ParkedFilter::ALLOWANCE * 4),
            "an interval the aggregate refused is not charged"
        );
        assert_eq!(shared.allowance, ParkedFilter::ALLOWANCE);
        assert_eq!(shared.since, t0 + ParkedFilter::ALLOWANCE * 4);

        for halt in [FilterHalt::Index, FilterHalt::Local] {
            let mut parked = ParkedFilter::new(filter_request(), t0);
            parked.last = halt;
            assert!(!parked.charge(t0 + half), "{halt:?}: half the allowance");
            assert_eq!(parked.allowance, half, "{halt:?}: the interval is charged");
            assert!(
                parked.charge(t0 + half + ParkedFilter::ALLOWANCE),
                "{halt:?}: a spent allowance times the request out"
            );
        }
    }

    #[test]
    fn a_shared_interval_does_not_hide_a_genuine_one() {
        let t0 = std::time::Instant::now();
        let mut parked = ParkedFilter::new(filter_request(), t0);
        parked.last = FilterHalt::Shared;
        let after_stall = t0 + ParkedFilter::ALLOWANCE * 10;
        assert!(!parked.charge(after_stall));
        parked.last = FilterHalt::Index;
        assert!(
            parked.charge(after_stall + ParkedFilter::ALLOWANCE),
            "the next pass charges only its own interval, and that interval is spent"
        );
    }

    #[test]
    fn filter_halt_reports_the_kind_of_the_last_refusal() {
        use crate::connection::Refusal;
        assert_eq!(FilterHalt::from_refusal(None), FilterHalt::Index);
        assert_eq!(
            FilterHalt::from_refusal(Some(Refusal::Local)),
            FilterHalt::Local
        );
        assert_eq!(
            FilterHalt::from_refusal(Some(Refusal::Shared)),
            FilterHalt::Shared
        );
    }

    #[test]
    fn compact_negotiation_ignores_versions_we_do_not_advertise() {
        let mut negotiation = CompactBlockNegotiation::default();

        negotiation.record_remote_preference(&SendCmpct {
            send_compact: true,
            version: 1,
        });
        assert_eq!(negotiation.servable_version(), None);
        assert_eq!(negotiation.remote_preference(), None);

        negotiation.record_remote_preference(&SendCmpct {
            send_compact: true,
            version: COMPACT_BLOCK_VERSION,
        });
        assert_eq!(negotiation.servable_version(), Some(COMPACT_BLOCK_VERSION));
        assert_eq!(
            negotiation.remote_preference(),
            Some(SendCmpct {
                send_compact: true,
                version: COMPACT_BLOCK_VERSION,
            })
        );

        negotiation.record_remote_preference(&SendCmpct {
            send_compact: false,
            version: 1,
        });
        assert_eq!(negotiation.servable_version(), Some(COMPACT_BLOCK_VERSION));
        assert_eq!(
            negotiation.remote_preference(),
            Some(SendCmpct {
                send_compact: true,
                version: COMPACT_BLOCK_VERSION,
            })
        );
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
    fn traced_send_emits_a_parseable_frame_of_the_reported_length() -> Result<(), PeerError> {
        use std::io::Cursor;

        let mut peer = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
        peer.attach_net_trace(crate::net_trace::NetTrace::outbound(
            4,
            SocketAddr::from(([127, 0, 0, 1], 8333)),
            crate::peer_info::PeerRole::FullRelay,
            false,
        ));

        let written = peer.send(&Message::Ping(9))?;

        let mut buffer = peer.stream;
        buffer.set_position(0);
        assert_eq!(
            buffer.get_ref().len(),
            written,
            "returned length is the framed bytes that landed"
        );
        let (message, payload) = crate::wire::read_message(&mut buffer, Magic::BITCOIN)?;
        assert_eq!(message, Message::Ping(9));
        assert!(!payload.is_empty());
        Ok(())
    }

    #[test]
    fn traced_read_returns_the_checksum_validated_message() -> Result<(), PeerError> {
        use std::io::Cursor;

        let mut frame = Vec::new();
        write_message(&mut frame, Magic::BITCOIN, &Message::Pong(2))?;

        let mut peer = Peer::new(Cursor::new(frame), Magic::BITCOIN);
        peer.attach_net_trace(crate::net_trace::NetTrace::inbound(
            2,
            SocketAddr::from(([127, 0, 0, 1], 8333)),
        ));

        let (message, payload) = peer
            .read_message()?
            .ok_or_else(|| std::io::Error::other("a v1 frame is a message"))?;

        assert_eq!(message, Message::Pong(2));
        assert!(!payload.is_empty());
        Ok(())
    }

    #[test]
    fn socket_read_continues_a_frame_that_outlasts_the_poll_timeout() -> Result<(), PeerError> {
        use std::io::ErrorKind;
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let mut sender = TcpStream::connect(listener.local_addr()?)?;
        let (receiver, _) = listener.accept()?;
        receiver.set_read_timeout(Some(Duration::from_millis(20)))?;
        let mut frame = Vec::new();
        write_message(&mut frame, Magic::REGTEST, &Message::Ping(5))?;
        let (head, tail) = frame.split_at(10);
        let tail = tail.to_vec();
        sender.write_all(head)?;
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(120));
            sender.write_all(&tail)
        });

        let mut peer = Peer::new(receiver, Magic::REGTEST);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stalls = 0_usize;
        let message = loop {
            match peer.read_message() {
                Ok(Some((message, _))) => break message,
                Ok(None) => continue,
                Err(PeerError::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                        && Instant::now() < deadline =>
                {
                    stalls += 1;
                }
                Err(error) => return Err(error),
            }
        };
        late.join()
            .map_err(|_| PeerError::Protocol("late writer panicked"))??;

        assert_eq!(message, Message::Ping(5));
        assert!(stalls > 0, "the read timed out mid-frame at least once");
        Ok(())
    }
}
