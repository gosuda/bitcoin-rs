use std::io::{Read, Write};
use std::net::SocketAddr;

use bitcoin::p2p::Magic;
use bitcoin::p2p::message_network::VersionMessage;
use crossbeam_channel::{Receiver, Sender, unbounded};

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
        write_message(&mut self.stream, self.magic, message)
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
