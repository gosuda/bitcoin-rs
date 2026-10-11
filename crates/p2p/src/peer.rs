use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::p2p::Magic;
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::message_network::VersionMessage;

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
    /// `net:*` probe context attached by live connection roots; `None` on
    /// probe-free constructions, which keeps the probes out of their binaries.
    pub(crate) net_trace: Option<crate::net_trace::NetTrace>,
}

impl<S> Peer<S> {
    /// Create a peer over `stream`.
    pub fn new(stream: S, magic: Magic) -> Self {
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
            net_trace: None,
        }
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
    /// Write one outbound message.
    ///
    /// Returns the framed wire length so handshake accounting can charge the
    /// same bytes `write_message` emitted, without encoding the payload twice.
    ///
    /// With a `net:*` probe context attached, the frame is encoded once and
    /// `net:outbound_message` observes its payload before the write attempt,
    /// the way Core's `CSerializedNetMsg` is shared by its send path and the
    /// probe.
    pub fn send(&mut self, message: &Message) -> Result<usize, PeerError> {
        if self.net_trace.is_some() {
            let frame = crate::wire::encode_frame(self.magic, message)?;
            crate::net_trace::outbound_message(self.net_trace.as_ref(), message, frame.payload());
            return crate::wire::write_frame(&mut self.stream, &frame);
        }
        write_message(&mut self.stream, self.magic, message)
    }
}

impl<S: Read> Peer<S> {
    /// Read one framed message.
    pub fn read_message(&mut self) -> Result<(Message, bytes::Bytes), PeerError> {
        let net_trace = self.net_trace.as_ref();
        crate::wire::read_message_with(&mut self.stream, self.magic, |command, payload| {
            crate::net_trace::inbound_message(net_trace, command, payload);
        })
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

        let (message, payload) = peer.read_message()?;

        assert_eq!(message, Message::Pong(2));
        assert!(!payload.is_empty());
        Ok(())
    }
}
