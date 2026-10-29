use bitcoin_rs_primitives::PeerEndpoint;
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::p2p::Magic;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin_rs_primitives::Wtxid;
use hashbrown::HashMap;

use crate::feature::FeatureId;
use crate::packages::{PKG_RELAY_ANC, PKG_RELAY_PKGTXNS};
use crate::wire::{Message, PeerError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Disconnected,
    VersionExchange,
    Verack,
    Ready,
    Disconnecting,
}

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
    pub(crate) const fn mark_peer_supported(&mut self) {
        self.peer_advertised = true;
    }

    /// Return true if the remote peer advertised BIP339 support.
    pub const fn peer_supported(self) -> bool {
        self.peer_advertised
    }
}

/// BIP331 package-relay negotiation state.
/// (see [`Peer::package_relay_versions`]). Nothing here is a BIP434 feature:
/// BIP331 negotiates through its own pre-`verack` message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PackageRelayNegotiation {
    offered: u64,
    advertised: u64,
    remote: Option<u64>,
}

impl PackageRelayNegotiation {
    pub(crate) const KNOWN: u64 = PKG_RELAY_PKGTXNS | PKG_RELAY_ANC;

    pub(crate) const fn offer(&mut self, versions: u64) {
        self.offered = versions & Self::KNOWN;
    }

    pub(crate) const fn withdraw_offer(&mut self) {
        self.offered = 0;
    }

    pub(crate) const fn unsent_offer(&self) -> Option<u64> {
        if self.offered != 0 && self.advertised == 0 {
            Some(self.offered)
        } else {
            None
        }
    }

    pub(crate) const fn record_advertised(&mut self, versions: u64) {
        self.advertised = versions & Self::KNOWN;
    }

    pub(crate) const fn record_remote(&mut self, versions: u64) {
        if self.remote.is_none() {
            self.remote = Some(versions & Self::KNOWN);
        }
    }

    const fn common(&self) -> u64 {
        match self.remote {
            Some(remote) => remote & self.advertised,
            None => 0,
        }
    }
}

/// The one BIP331 download `dispatch` asks the request owner to start after
/// an `ancpkginfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageRequest {
    pub(crate) subject: Wtxid,
    pub(crate) wtxids: Vec<Wtxid>,
}

/// BIP152 compact-block protocol version this node speaks and advertises.
pub const COMPACT_BLOCK_VERSION: u64 = 2;

/// Remote BIP152 compact-block negotiation preference.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompactBlockNegotiation {
    pub remote_send_compact: Option<bool>,
    pub remote_version: Option<u64>,
    pub local_version: Option<u64>,
}

impl CompactBlockNegotiation {
    #[must_use]
    const fn supports_version(version: u64) -> bool {
        version == COMPACT_BLOCK_VERSION
    }

    /// for versions we did not advertise have no effect, as BIP152 requires.
    pub(crate) const fn record_remote_preference(&mut self, preference: &SendCmpct) {
        if !Self::supports_version(preference.version) {
            return;
        }
        self.remote_send_compact = Some(preference.send_compact);
        self.remote_version = Some(preference.version);
    }

    pub(crate) const fn record_local_advertised(&mut self, version: u64) {
        self.local_version = Some(version);
    }

    #[must_use]
    pub(crate) const fn local_version(&self) -> Option<u64> {
        self.local_version
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FilterHalt {
    Index,
    Local,
    Shared,
}

impl FilterHalt {
    pub(crate) const fn from_refusal(refusal: Option<crate::connection::Refusal>) -> Self {
        match refusal {
            Some(crate::connection::Refusal::Local) => Self::Local,
            Some(crate::connection::Refusal::Shared) => Self::Shared,
            None => Self::Index,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ParkedFilter {
    pub(crate) pending: crate::dispatch::FilterRequest,
    pub(crate) allowance: std::time::Duration,
    pub(crate) since: std::time::Instant,
    pub(crate) last: FilterHalt,
}

impl ParkedFilter {
    pub(crate) const ALLOWANCE: std::time::Duration = std::time::Duration::from_secs(5);

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

#[derive(Debug)]
pub struct Peer<S> {
    pub stream: S,
    pub state: PeerState,
    pub magic: Magic,
    pub remote_version: Option<VersionMessage>,
    pub version_received_time: Option<u64>,
    pub received_verack: bool,
    /// Whether our VERACK was successfully written; closes the BIP434 send window.
    sent_verack: bool,
    pub capabilities: PeerCapabilities,
    /// BIP152 compact-block negotiation state for the peer.
    pub compact_blocks: CompactBlockNegotiation,
    /// BIP339 state for the peer.
    pub wtxid_relay: WtxidRelayState,
    /// BIP434 feature announcements the peer sent between its `version` and
    /// `verack`, by identifier.
    pub(crate) remote_features: HashMap<FeatureId, Vec<u8>>,
    /// BIP331 `sendpackages` negotiation for the peer.
    pub(crate) package_relay: PackageRelayNegotiation,
    /// Whether this node announces BIP332 stale-tip relay to the peer, and
    /// its `prefers_blocks` byte; `None`, the default, announces nothing.
    pub(crate) stale_tip_offer: Option<bool>,
    pub(crate) pending_package_request: Option<PackageRequest>,
    /// One BIP157 request waiting for asynchronous index publication or for
    /// outbound room.
    pub(crate) pending_filter_request: Option<ParkedFilter>,
    pub(crate) deferred_inbound: Option<Message>,
    pub(crate) pending_getdata: Vec<Inventory>,
    pub(crate) pending_notfound: Vec<Inventory>,
    pub(crate) net_trace: Option<crate::net_trace::NetTrace>,
    recv: crate::transport::RecvTransport,
    send: Option<crate::transport::SendTransport>,
    transport: crate::transport::TransportProtocol,
}

impl<S> Peer<S> {
    pub fn new(stream: S, magic: Magic) -> Self {
        Self::with_transport(stream, magic, crate::transport::Negotiated::v1(magic))
    }

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
            sent_verack: false,
            capabilities: PeerCapabilities::default(),
            compact_blocks: CompactBlockNegotiation::default(),
            wtxid_relay: WtxidRelayState::default(),
            remote_features: HashMap::new(),
            package_relay: PackageRelayNegotiation::default(),
            stale_tip_offer: None,
            pending_package_request: None,
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

    pub const fn transport(&self) -> crate::TransportProtocol {
        self.transport
    }

    pub(crate) fn take_send_transport(&mut self) -> Option<crate::transport::SendTransport> {
        self.send.take()
    }

    /// Offer BIP331 package relay on this connection with `versions`, the
    /// `PKG_RELAY_*` bits to put in our `sendpackages`.
    pub fn offer_package_relay(&mut self, versions: u64) {
        self.package_relay.offer(versions);
    }

    /// Announce BIP332 stale-tip relay to this peer, with `prefers_blocks` as the
    /// feature's single data byte.
    ///
    /// POST: the BIP434 `feature` goes only to a peer at protocol version
    /// [`Peer::remote_feature`] reports for `b"BIP332"`.
    pub fn offer_stale_tip_relay(&mut self, prefers_blocks: bool) {
        self.stale_tip_offer = Some(prefers_blocks);
    }

    /// INVARIANT: this node sends `wtxidrelay` and `verack` in the same
    ///   `version` reply that carries `sendpackages`, and advertises `fRelay`
    ///   whenever it offers package relay, so the peer's side is the only
    ///   one left to check.
    #[must_use]
    pub fn package_relay_versions(&self) -> u64 {
        let Some(remote_version) = self.remote_version.as_ref() else {
            return 0;
        };
        if self.state == PeerState::Ready
            && self.received_verack
            && self.wtxid_relay.peer_supported()
            && remote_version.relay
        {
            self.package_relay.common()
        } else {
            0
        }
    }

    pub(crate) fn take_package_request(&mut self) -> Option<PackageRequest> {
        self.pending_package_request.take()
    }

    /// The payload the peer announced for the recognised BIP434 feature `id`,
    /// or `None` when it announced no valid one before `verack`.
    #[must_use]
    pub fn remote_feature(&self, id: &[u8]) -> Option<&[u8]> {
        self.remote_features.get(id).map(Vec::as_slice)
    }

    #[must_use]
    pub(crate) fn has_parked_getdata(&self) -> bool {
        !self.pending_getdata.is_empty() || !self.pending_notfound.is_empty()
    }

    pub(crate) fn attach_net_trace(&mut self, net_trace: crate::net_trace::NetTrace) {
        self.net_trace = Some(net_trace);
    }

    pub(crate) const fn refresh_ready_state(&mut self) {
        if self.remote_version.is_some() && self.received_verack {
            self.state = PeerState::Ready;
        }
    }
}

impl<S: Read + Write> Peer<S> {
    pub fn send(&mut self, message: &Message) -> Result<usize, PeerError> {
        if matches!(message, Message::Feature(_))
            && (self.sent_verack
                || self
                    .remote_version
                    .as_ref()
                    .is_none_or(|version| version.version < crate::feature::FEATURE_VERSION))
        {
            return Err(PeerError::Protocol(
                "feature outside negotiated send window",
            ));
        }
        let transport = self.send.as_mut().ok_or(PeerError::Protocol(
            "send transport moved to the writer thread",
        ))?;
        let frame = transport.encode(message)?;
        crate::net_trace::outbound_message(self.net_trace.as_ref(), message, frame.payload());
        let written = crate::wire::write_frame(&mut self.stream, &frame)?;
        if matches!(message, Message::Verack) {
            self.sent_verack = true;
        }
        Ok(written)
    }
}

impl<S: Read> Peer<S> {
    /// `Ok(None)` only from a v2 session: the packet was a BIP324 decoy or a message of
    /// an empty or undefined type, both dropped.
    ///
    /// A v1 frame always yields `Some`. A poll timeout part-way through a frame or
    /// packet keeps the bytes already read, so retrying after `TimedOut` or
    /// `WouldBlock` continues it.
    pub fn read_message(&mut self) -> Result<Option<(Message, bytes::Bytes)>, PeerError> {
        let net_trace = self.net_trace.as_ref();
        self.recv
            .read_message(&mut self.stream, self.magic, |command, payload| {
                crate::net_trace::inbound_message(net_trace, command, payload);
            })
            .map_err(PeerError::inbound)
    }
}

pub(crate) trait DnsResolver: Send + Sync {
    fn resolve(&self, seed: &str) -> Result<Vec<PeerEndpoint>, PeerError>;
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SystemDnsResolver {
    port: u16,
}

impl SystemDnsResolver {
    #[must_use]
    pub(crate) const fn new(port: u16) -> Self {
        Self { port }
    }
}

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, seed: &str) -> Result<Vec<PeerEndpoint>, PeerError> {
        let seed = seed.trim_end_matches('.');
        (seed, self.port)
            .to_socket_addrs()
            .map(|addresses| addresses.map(PeerEndpoint::from).collect())
            .map_err(PeerError::Io)
    }
}

#[derive(Debug, Clone)]
pub struct NetworkActivity {
    active: Arc<AtomicBool>,
}

impl NetworkActivity {
    /// INVARIANT: The service owns activity transitions; this type never
    /// writes the flag.
    #[must_use]
    pub const fn from_shared(active: Arc<AtomicBool>) -> Self {
        Self { active }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

pub(crate) const MAX_BLOCK_SERIALIZED_SIZE_USIZE: usize = 4_000_000;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::write_message;

    #[test]
    fn bip434_send_window_uses_remote_version_and_local_verack() -> Result<(), PeerError> {
        use std::io::Cursor;
        let mut peer = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
        let feature = Message::Feature(crate::feature::FeatureAnnouncement::bip332(true));
        assert!(matches!(peer.send(&feature), Err(PeerError::Protocol(_))));
        assert_eq!(peer.stream.get_ref().as_slice(), [0_u8; 0]);

        let mut version = crate::handshake::version_message(
            1,
            0,
            crate::PeerRole::FullRelay,
            bitcoin::p2p::ServiceFlags::NETWORK,
        );
        version.version = crate::feature::FEATURE_VERSION - 1;
        peer.remote_version = Some(version.clone());
        assert!(matches!(peer.send(&feature), Err(PeerError::Protocol(_))));
        assert_eq!(peer.stream.get_ref().as_slice(), [0_u8; 0]);

        version.version = crate::feature::FEATURE_VERSION;
        peer.remote_version = Some(version);
        peer.send(&feature)?;
        crate::fsm::step(&mut peer, &Message::Verack)?;
        peer.send(&feature)?;
        peer.send(&Message::Verack)?;
        let written = peer.stream.get_ref().len();
        assert!(matches!(peer.send(&feature), Err(PeerError::Protocol(_))));
        assert_eq!(peer.stream.get_ref().len(), written);
        Ok(())
    }

    #[test]
    fn bip434_send_window_closes_only_after_a_successful_verack_write() -> Result<(), PeerError> {
        struct FailOnce(bool);
        impl Read for FailOnce {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }
        impl Write for FailOnce {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if std::mem::take(&mut self.0) {
                    Err(std::io::Error::other("injected write failure"))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut peer = Peer::new(FailOnce(true), Magic::BITCOIN);
        peer.remote_version = Some(crate::handshake::version_message(
            1,
            0,
            crate::PeerRole::FullRelay,
            bitcoin::p2p::ServiceFlags::NETWORK,
        ));
        let feature = Message::Feature(crate::feature::FeatureAnnouncement::bip332(true));
        assert!(matches!(peer.send(&Message::Verack), Err(PeerError::Io(_))));
        peer.send(&feature)?;
        peer.send(&Message::Verack)?;
        assert!(matches!(peer.send(&feature), Err(PeerError::Protocol(_))));
        Ok(())
    }

    fn filter_request() -> crate::dispatch::FilterRequest {
        crate::dispatch::FilterRequest::new(crate::Message::GetAddr)
    }

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
                .contains(&PeerEndpoint::from(([127, 0, 0, 1], 8333)))
        );
        Ok(())
    }

    #[test]
    fn traced_send_emits_a_parseable_frame_of_the_reported_length() -> Result<(), PeerError> {
        use std::io::Cursor;

        let mut peer = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
        peer.attach_net_trace(crate::net_trace::NetTrace::outbound(
            4,
            crate::PeerRemote::Endpoint(PeerEndpoint::from(([127, 0, 0, 1], 8333))),
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
            crate::PeerRemote::Endpoint(PeerEndpoint::from(([127, 0, 0, 1], 8333))),
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

        let listener = TcpListener::bind(
            PeerEndpoint::from(([127, 0, 0, 1], 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
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
