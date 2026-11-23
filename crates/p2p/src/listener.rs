pub trait BlockSyncObserver: Send + Sync {
    fn announce_block(
        &self,
        source: crate::PeerSource,
        hash: bitcoin_rs_consensus::primitives::Hash256,
    );
    fn block_not_found(
        &self,
        source: crate::PeerSource,
        items: &[bitcoin::p2p::message_blockdata::Inventory],
    ) -> bool;
    fn note_header_response_received(&self, source: crate::PeerSource);
    fn owns_body_fetch(
        &self,
        source: crate::PeerSource,
        hash: bitcoin_rs_consensus::primitives::Hash256,
    ) -> bool;
    fn compact_reconstruction_admissible(
        &self,
        source: crate::PeerSource,
        header: &bitcoin_rs_consensus::primitives::Header,
    ) -> bool;
    fn enqueue_owned_body_fetch(
        &self,
        source: crate::PeerSource,
        hash: bitcoin_rs_consensus::primitives::Hash256,
        follow_up: &mut dyn FnMut() -> bool,
    ) -> bool;
    fn note_stale_tip_heard(
        &self,
        source: crate::PeerSource,
        tip_hash: bitcoin_rs_consensus::primitives::Hash256,
    );
    fn allow_extra_full_relay_dial(&self) -> bool;
    fn is_downloading_bodies(&self, source: crate::PeerSource) -> bool;
}

pub trait BlockAnnounceObserver: Send + Sync {
    fn on_peer_ready(&self);
    fn on_peer_disconnected(&self, source: crate::PeerSource);
    fn reconcile_high_bandwidth_peers(&self);
}

pub trait IbdState: Send + Sync {
    fn is_ibd(&self, now: u64, network: bitcoin_rs_consensus::primitives::Network) -> bool;
}

pub trait TxPolicyObserver: Send + Sync {
    fn transaction_serving_sequence(&self, _source: crate::PeerSource) -> Option<u64> {
        None
    }

    fn announce_transactions(
        &self,
        source: crate::PeerSource,
        items: &[bitcoin::p2p::message_blockdata::Inventory],
    );
    fn request_parent_transactions(
        &self,
        source: crate::PeerSource,
        items: &[bitcoin::p2p::message_blockdata::Inventory],
    ) -> bool;
    fn transaction_not_found(
        &self,
        source: crate::PeerSource,
        items: &[bitcoin::p2p::message_blockdata::Inventory],
        inventory: &dyn crate::dispatch::TxInventory,
    );
    fn poll_transaction_requests(&self, inventory: &dyn crate::dispatch::TxInventory);
    fn transaction_peer_disconnected(
        &self,
        source: crate::PeerSource,
        inventory: &dyn crate::dispatch::TxInventory,
    );
    fn note_transaction_inventory(
        &self,
        source: crate::PeerSource,
        items: &[bitcoin::p2p::message_blockdata::Inventory],
    );
    fn request_package_transactions(
        &self,
        source: crate::PeerSource,
        subject: bitcoin_rs_consensus::primitives::Wtxid,
        wtxids: Vec<bitcoin_rs_consensus::primitives::Wtxid>,
    );
    fn release_package_info(
        &self,
        source: crate::PeerSource,
        subject: bitcoin_rs_consensus::primitives::Wtxid,
        inventory: &dyn crate::dispatch::TxInventory,
    );
    fn receive_fee_filter(&self, source: crate::PeerSource, rate: i64);
}

pub trait TxIngressObserver: Send + Sync {
    fn on_inbound_tx(
        &self,
        source: crate::PeerSource,
        tx: bitcoin_rs_consensus::primitives::Tx,
        memory_credit: Option<crate::inbound::block_memory::BlockMemoryCredit>,
    );
    fn on_inbound_package(
        &self,
        source: crate::PeerSource,
        payload: bytes::Bytes,
    ) -> Result<(), crate::wire::PeerError>;
}

use bitcoin_rs_consensus::primitives::PeerEndpoint;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
#[cfg(test)]
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_consensus::primitives::{Network, unix_time_secs};
use crossbeam_channel::Sender;
use thiserror::Error;

use crate::handshake::run_inbound_handshake;
use crate::peer::Peer;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_mins(1);
const HANDSHAKE_READ_POLL: Duration = Duration::from_secs(1);

const BUDGET_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

const MESSAGE_LOOP_POLL: Duration = Duration::from_secs(1);

pub fn configure_peer_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(HANDSHAKE_READ_POLL))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    Ok(())
}

const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(100);

const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(10);

const PING_INTERVAL: Duration = Duration::from_mins(2);

const TIMEOUT_INTERVAL: Duration = Duration::from_mins(20);

const NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS: u64 = 144;

const POW_TARGET_SPACING_SECS: u64 = 600;

type ChainQueryHandle = Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>;

type TxInventoryHandle = Option<Arc<dyn crate::dispatch::TxInventory + 'static>>;

type CompactHintsHandle = Option<Arc<dyn crate::compact_blocks::CompactBlockHints + 'static>>;

type SyncWakeHandle = Option<Sender<()>>;

type PeerReadyHandle = Option<Arc<dyn Fn(crate::PeerSource) + Send + Sync>>;

#[derive(Clone, Default)]
pub struct ListenerExtras {
    pub tx_inventory: TxInventoryHandle,
    pub compact_hints: CompactHintsHandle,
    pub tx_ingress: Option<Arc<dyn TxIngressObserver>>,
    pub tx_policy: Option<Arc<dyn TxPolicyObserver>>,
    pub ibd: Option<(Arc<dyn IbdState>, Network)>,
    pub block_sync: Option<Arc<dyn BlockSyncObserver>>,
    pub block_announcer: Option<Arc<dyn BlockAnnounceObserver>>,
    pub block_memory: Option<Arc<crate::inbound::block_memory::BlockMemory>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayOffers {
    pub package_relay: bool,
    pub stale_tip_relay: bool,
    pub stale_tip_prefers_blocks: bool,
}

#[derive(Clone)]
pub struct ConnectionShared {
    pub peer_table: Arc<crate::PeerTable>,
    pub banned: crate::BannedReader,
    pub(crate) address_book: Option<Arc<crate::addrman::AddressBook>>,
    pub(crate) feeler: bool,
    pub activity: Arc<crate::NetworkActivity>,
    pub session_cancel: bitcoin_rs_consensus::latch::LatchReader,
    pub peer_ready: PeerReadyHandle,
    pub magic: Magic,
    pub headers_tx: Sender<crate::InboundHeaders>,
    pub blocks_tx: Sender<crate::InboundBlock>,
    pub chain_query: ChainQueryHandle,
    pub wake_tx: SyncWakeHandle,
    pub tx_inventory: TxInventoryHandle,
    pub compact_hints: CompactHintsHandle,
    pub tx_ingress: Option<Arc<dyn TxIngressObserver>>,
    pub tx_policy: Option<Arc<dyn TxPolicyObserver>>,
    pub ibd: Option<(Arc<dyn IbdState>, Network)>,
    pub block_sync: Option<Arc<dyn BlockSyncObserver>>,
    pub block_announcer: Option<Arc<dyn BlockAnnounceObserver>>,
    pub max_inbound: usize,
    pub local_services: ServiceFlags,
    /// The subversion this node advertises in its version handshake.
    pub user_agent: String,
    pub v2_transport: bool,
    pub relay_offers: RelayOffers,
    pub(crate) overlay: Arc<crate::overlay::OverlayTransport>,
    pub shared_outbound: Arc<crate::connection::SharedOutboundBudget>,
    block_memory: Arc<crate::inbound::block_memory::BlockMemory>,
    pub dial_routes: crate::DialRoutes,
    #[cfg(test)]
    pub(crate) test_keepalive_intervals: std::sync::OnceLock<(Duration, Duration)>,
    #[cfg(test)]
    pub(crate) fail_cancel_clone: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderKind {
    WireResponse,
    EmbeddedBlock,
}

impl ConnectionShared {
    fn advertised_services(&self) -> ServiceFlags {
        let services = ServiceFlags::from(
            self.local_services.to_u64() & !ServiceFlags::COMPACT_FILTERS.to_u64(),
        );
        if self
            .chain_query
            .as_deref()
            .is_some_and(crate::ChainQuery::compact_filters_ready)
        {
            services | ServiceFlags::COMPACT_FILTERS
        } else {
            services
        }
    }

    #[must_use]
    pub fn new(
        peer_table: Arc<crate::PeerTable>,
        banned: impl Into<crate::BannedReader>,
        activity: Arc<crate::NetworkActivity>,
        session_cancel: bitcoin_rs_consensus::latch::LatchReader,
        peer_ready: PeerReadyHandle,
        magic: Magic,
        headers_tx: Sender<crate::InboundHeaders>,
        blocks_tx: Sender<crate::InboundBlock>,
        chain_query: ChainQueryHandle,
        wake_tx: SyncWakeHandle,
        extras: ListenerExtras,
    ) -> Self {
        Self {
            peer_table,
            banned: banned.into(),
            address_book: None,
            feeler: false,
            activity,
            session_cancel,
            peer_ready,
            magic,
            headers_tx,
            blocks_tx,
            chain_query,
            wake_tx,
            tx_inventory: extras.tx_inventory,
            compact_hints: extras.compact_hints,
            tx_ingress: extras.tx_ingress,
            tx_policy: extras.tx_policy,
            ibd: extras.ibd,
            block_sync: extras.block_sync,
            block_announcer: extras.block_announcer,
            max_inbound: crate::service::P2pServiceConfig::default().max_inbound(),
            local_services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            user_agent: bitcoin_rs_consensus::primitives::USER_AGENT.to_owned(),
            v2_transport: false,
            relay_offers: RelayOffers::default(),
            overlay: Arc::new(crate::overlay::OverlayTransport::new(Arc::default())),
            shared_outbound: Arc::new(crate::connection::SharedOutboundBudget::new()),
            block_memory: extras.block_memory.unwrap_or_default(),
            dial_routes: crate::DialRoutes::default(),
            #[cfg(test)]
            test_keepalive_intervals: std::sync::OnceLock::new(),
            #[cfg(test)]
            fail_cancel_clone: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    fn cancel_clone(
        &self,
    ) -> impl Fn(&std::net::TcpStream) -> std::io::Result<std::net::TcpStream> + '_ {
        move |stream| {
            if self
                .fail_cancel_clone
                .swap(false, std::sync::atomic::Ordering::Relaxed)
            {
                Err(std::io::Error::other("test-injected cancel clone failure"))
            } else {
                stream.try_clone()
            }
        }
    }

    #[cfg(not(test))]
    fn cancel_clone(
        &self,
    ) -> impl Fn(&std::net::TcpStream) -> std::io::Result<std::net::TcpStream> {
        std::net::TcpStream::try_clone
    }

    fn offer_relay_capabilities<S>(&self, peer: &mut Peer<S>, role: crate::PeerRole) {
        if self.relay_offers.package_relay && role.relays_transactions() {
            peer.offer_package_relay(
                crate::packages::PKG_RELAY_PKGTXNS | crate::packages::PKG_RELAY_ANC,
            );
        }
        if self.relay_offers.stale_tip_relay {
            peer.offer_stale_tip_relay(self.relay_offers.stale_tip_prefers_blocks);
        }
    }

    fn note_peer_stale_tip_relay<S>(
        &self,
        peer: &Peer<S>,
        endpoint: Option<crate::PeerEndpoint>,
        lease: &crate::PeerLease,
    ) {
        if !self.relay_offers.stale_tip_relay {
            return;
        }
        if let Some(feature_data) = peer.remote_feature(crate::feature::BIP332_ID) {
            self.peer_table
                .note_stale_tip_relay(lease.source(endpoint), feature_data == [1]);
        }
    }

    fn remove_session(&self, endpoint: Option<crate::PeerEndpoint>, lease: &crate::PeerLease) {
        match endpoint {
            Some(endpoint) => {
                self.peer_table.remove_current(endpoint, lease);
            }
            None => {
                self.peer_table.remove_unidentified(lease);
            }
        }
    }

    #[must_use]
    pub(crate) fn with_shared_outbound(
        mut self,
        shared: &Arc<crate::connection::SharedOutboundBudget>,
    ) -> Self {
        self.shared_outbound = Arc::clone(shared);
        self
    }

    pub(crate) fn check_manual_destination(
        &self,
        addr: PeerEndpoint,
    ) -> Result<(), crate::PeerError> {
        if !self.overlay.config.allows(addr.address().network()) {
            return Err(crate::PeerError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination network disabled",
            )));
        }
        if self.banned.is_banned(addr.address(), SystemTime::now()) {
            return Err(crate::PeerError::BannedDestination(addr.address()));
        }
        Ok(())
    }

    pub(crate) fn check_automatic_destination(
        &self,
        addr: PeerEndpoint,
    ) -> Result<(), crate::PeerError> {
        self.check_manual_destination(addr)?;
        if self.banned.is_discouraged(addr.address()) {
            return Err(crate::PeerError::DiscouragedDestination(addr.address()));
        }
        Ok(())
    }

    fn note_misbehavior(
        &self,
        addr: impl Into<crate::PeerRemote>,
        lease: &crate::PeerLease,
        error: &crate::PeerError,
    ) {
        let addr = addr.into();
        if !error.is_misbehavior() || self.is_session_cancelled() || !self.activity.is_active() {
            return;
        }
        let protected = lease.is_protected();
        let address = addr.endpoint().map(PeerEndpoint::address);
        let local = address.is_some_and(crate::discouragement::is_local);
        let mut discouraged = false;
        let current = self
            .peer_table
            .with_current(lease.source(addr.endpoint()), || {
                if !protected
                    && !local
                    && let Some(address) = address
                {
                    discouraged = self.banned.discourage(address);
                }
            });
        if current {
            if lease.ignores_protocol_error(error) {
                tracing::debug!(peer_addr = %addr, node_id = lease.node_id(), %error, protected, local,
                    discouraged, "peer protocol violation");
            } else {
                tracing::warn!(peer_addr = %addr, node_id = lease.node_id(), %error, protected, local,
                    discouraged, "peer protocol violation");
            }
        }
    }

    fn announce_block(
        &self,
        source: crate::PeerSource,
        hash: bitcoin_rs_consensus::primitives::Hash256,
    ) {
        let Some(sync) = self.block_sync.as_ref() else {
            return;
        };
        sync.announce_block(source, hash);
        wake_sync(self.wake_tx.as_ref());
    }

    fn block_not_found(
        &self,
        source: crate::PeerSource,
        items: &[bitcoin::p2p::message_blockdata::Inventory],
    ) {
        let Some(sync) = self.block_sync.as_ref() else {
            return;
        };
        if sync.block_not_found(source, items) {
            wake_sync(self.wake_tx.as_ref());
        }
    }

    fn notify_peer_ready(&self, source: crate::PeerSource) {
        if let Some(peer_ready) = &self.peer_ready {
            peer_ready(source);
        }
    }

    fn publish_info_and_notify_ready_with_package(
        &self,
        peer_addr: impl Into<crate::PeerRemote>,
        lease: &crate::PeerLease,
        info: &crate::PeerInfo,
        package_relay: u64,
    ) -> bool {
        let peer_addr = peer_addr.into();
        let source = lease.source(peer_addr.endpoint());
        if self.peer_table.publish_info(peer_addr, lease, info.clone())
            && self.peer_table.is_current(source)
        {
            if package_relay != 0 {
                self.peer_table.note_package_relay(source, package_relay);
            }
            if let Some(announcer) = &self.block_announcer {
                announcer.on_peer_ready();
            }
            if !lease.is_inbound() {
                if let Some(book) = &self.address_book
                    && let Some(endpoint) = peer_addr.endpoint()
                {
                    book.succeeded(endpoint, info.services, crate::addrman::now());
                }
            }
            self.notify_peer_ready(source);
            true
        } else {
            false
        }
    }

    pub(crate) fn is_session_cancelled(&self) -> bool {
        self.session_cancel.is_triggered()
    }

    /// Retain the whole response under backpressure. Never wait while holding
    /// the peer-table, scheduler, or chain transition lock; a cancelled
    /// connection/session releases the wait at the next send timeout.
    pub fn send_headers_response(
        &self,
        lease: &crate::PeerLease,
        source: crate::PeerSource,
        headers: Vec<bitcoin_rs_consensus::primitives::Header>,
    ) {
        if self.is_session_cancelled() || lease.is_cancelled() {
            return;
        }
        if let Some(sync) = &self.block_sync {
            sync.note_header_response_received(source);
        }
        self.enqueue_headers(lease, source, headers, HeaderKind::WireResponse);
    }

    pub(crate) fn send_embedded_headers(
        &self,
        lease: &crate::PeerLease,
        source: crate::PeerSource,
        headers: Vec<bitcoin_rs_consensus::primitives::Header>,
    ) {
        if self.is_session_cancelled() || lease.is_cancelled() {
            return;
        }
        self.enqueue_headers(lease, source, headers, HeaderKind::EmbeddedBlock);
    }

    fn enqueue_headers(
        &self,
        lease: &crate::PeerLease,
        source: crate::PeerSource,
        headers: Vec<bitcoin_rs_consensus::primitives::Header>,
        kind: HeaderKind,
    ) {
        let inbound = crate::InboundHeaders {
            headers,
            source: Some(source),
            wire_response: matches!(kind, HeaderKind::WireResponse),
        };
        if self.is_session_cancelled() || lease.is_cancelled() {
            return;
        }
        let close_rx = lease.close_signal();
        crossbeam_channel::select! {
            send(self.headers_tx, inbound) -> res => {
                if res.is_ok() {
                    wake_sync(self.wake_tx.as_ref());
                } else {
                    tracing::warn!(peer_addr = ?source.endpoint, "p2p inbound headers channel disconnected");
                }
            }
            recv(self.session_cancel.closed()) -> _ => {}
            recv(close_rx) -> signal => {
                if signal.is_ok() {
                    lease.cancel();
                }
            }
        }
    }

    pub fn send_block(
        &self,
        lease: &crate::PeerLease,
        peer_addr: impl Into<crate::PeerRemote>,
        payload: bitcoin_rs_consensus::primitives::BlockImage,
        memory_credit: Option<crate::inbound::block_memory::BlockMemoryCredit>,
    ) {
        let (memory_credit, payload) = (memory_credit, payload);
        let peer_addr = peer_addr.into();
        let source = lease.source(peer_addr.endpoint());
        let hash = bitcoin_rs_consensus::primitives::Hash256::from(payload.block_hash());
        let requested = self
            .block_sync
            .as_ref()
            .is_some_and(|sync| sync.owns_body_fetch(source, hash));
        let Some(credit) = lease.admit_block_forward(source, hash, requested) else {
            metrics::counter!("node.sync.dropped_unsolicited_blocks").increment(1);
            return;
        };
        let header = payload.header();
        if self.forward_block(payload, source, Some(credit), memory_credit) {
            self.send_embedded_headers(lease, source, vec![header]);
        }
    }

    pub(crate) fn forward_block(
        &self,
        payload: bitcoin_rs_consensus::primitives::BlockImage,
        source: crate::PeerSource,
        forward_credit: Option<crate::connection::BlockForwardCredit>,
        memory_credit: Option<crate::inbound::block_memory::BlockMemoryCredit>,
    ) -> bool {
        let mut inbound = crate::InboundBlock::new(payload, Some(source), forward_credit);
        inbound.memory_credit = memory_credit;
        if self.is_session_cancelled() {
            tracing::debug!(
                peer_addr = ?source.endpoint,
                "dropping inbound block: session cancelled"
            );
            return false;
        }
        crossbeam_channel::select! {
            send(self.blocks_tx, inbound) -> res => {
                if res.is_ok() {
                    wake_sync(self.wake_tx.as_ref());
                    true
                } else {
                    tracing::warn!(
                        peer_addr = ?source.endpoint,
                        "p2p inbound blocks channel disconnected"
                    );
                    false
                }
            }
            recv(self.session_cancel.closed()) -> _ => {
                tracing::debug!(
                    peer_addr = ?source.endpoint,
                    "dropping inbound block: session cancelled"
                );
                false
            }
        }
    }

    fn update_transaction_requests(&self, source: crate::PeerSource, message: &crate::Message) {
        let Some(inventory) = &self.tx_inventory else {
            return;
        };
        match message {
            crate::Message::NotFound(items) => {
                if let Some(tp) = &self.tx_policy {
                    tp.transaction_not_found(source, items, inventory.as_ref());
                }
            }
            crate::Message::Inv(items)
                if items.iter().any(|item| {
                    matches!(
                        item,
                        bitcoin::p2p::message_blockdata::Inventory::Transaction(_)
                            | bitcoin::p2p::message_blockdata::Inventory::WitnessTransaction(_)
                            | bitcoin::p2p::message_blockdata::Inventory::WTx(_)
                    )
                }) =>
            {
                if let Some(tp) = &self.tx_policy {
                    tp.poll_transaction_requests(inventory.as_ref());
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("bind {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        source: io::Error,
    },
    #[error("accept: {0}")]
    Accept(#[from] io::Error),
}

pub fn bind_listener(addr: std::net::SocketAddr) -> Result<TcpListener, ListenerError> {
    let listener =
        TcpListener::bind(addr).map_err(|source| ListenerError::Bind { addr, source })?;
    Ok(listener)
}

pub fn serve(
    listener: TcpListener,
    shutdown: impl Into<bitcoin_rs_consensus::latch::LatchReader>,
    shared: ConnectionShared,
) -> Result<(), ListenerError> {
    let shutdown = shutdown.into();
    let addr = listener.local_addr()?;
    accept_connections(addr, &listener, &shutdown, &shared);
    Ok(())
}

fn loopback_addr(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    match addr {
        std::net::SocketAddr::V4(v4) if v4.ip().is_unspecified() => std::net::SocketAddr::V4(
            std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, v4.port()),
        ),
        std::net::SocketAddr::V6(v6) if v6.ip().is_unspecified() => std::net::SocketAddr::V6(
            std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, v6.port(), 0, 0),
        ),
        other => other,
    }
}

fn accept_connections(
    addr: std::net::SocketAddr,
    listener: &TcpListener,
    shutdown: &bitcoin_rs_consensus::latch::LatchReader,
    shared: &ConnectionShared,
) {
    let mut accept_backoff = ACCEPT_BACKOFF_INITIAL;
    while !shutdown.is_triggered() && !shared.is_session_cancelled() {
        #[cfg(test)]
        if ACCEPT_ERROR_INJECT.swap(false, Ordering::Relaxed) {
            tracing::warn!(addr = %addr, "test-injected accept error; backing off");
            let _ = shutdown.closed().recv_timeout(ACCEPT_BACKOFF_INITIAL);
            continue;
        }
        let connect_addr = loopback_addr(addr);
        let guard_shutdown = shutdown.on_cancel(move || {
            let _ = std::net::TcpStream::connect(connect_addr);
        });
        let guard_session = shared.session_cancel.on_cancel(move || {
            let _ = std::net::TcpStream::connect(connect_addr);
        });
        let accepted = listener.accept();
        drop(guard_shutdown);
        drop(guard_session);
        if shutdown.is_triggered() || shared.is_session_cancelled() {
            if let Ok((stream, _)) = accepted {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            break;
        }
        match accepted {
            Ok((stream, peer_addr)) => {
                let peer_addr = PeerEndpoint::from(peer_addr);
                accept_backoff = ACCEPT_BACKOFF_INITIAL;
                admit_inbound(stream, peer_addr, shared);
            }
            Err(error) => {
                tracing::warn!(
                    addr = %addr,
                    %error,
                    backoff_ms = accept_backoff.as_millis(),
                    "p2p accept error; backing off and continuing",
                );
                let _ = shutdown.closed().recv_timeout(accept_backoff);
                accept_backoff = std::cmp::min(accept_backoff * 2, ACCEPT_BACKOFF_MAX);
            }
        }
    }
}

pub(crate) fn admit_inbound(stream: TcpStream, peer_addr: PeerEndpoint, shared: &ConnectionShared) {
    admit_inbound_with_epoch(stream, peer_addr, shared, None);
}
pub(crate) fn admit_inbound_with_epoch(
    stream: TcpStream,
    peer_addr: PeerEndpoint,
    shared: &ConnectionShared,
    alive: Option<Arc<AtomicBool>>,
) {
    admit_inbound_remote(stream, Some(peer_addr), shared, alive);
}

pub(crate) fn admit_anonymous_tor(stream: TcpStream, shared: &ConnectionShared) {
    admit_inbound_remote(stream, None, shared, None);
}

fn admit_inbound_remote(
    stream: TcpStream,
    endpoint: Option<PeerEndpoint>,
    shared: &ConnectionShared,
    alive: Option<Arc<AtomicBool>>,
) {
    if endpoint.map_or_else(
        || !shared.overlay.config.allows(crate::PeerNetwork::Onion),
        |endpoint| shared.check_automatic_destination(endpoint).is_err(),
    ) {
        drop(stream);
        tracing::debug!(?endpoint, "p2p inbound rejected by address policy");
        return;
    }
    if !shared.activity.is_active() {
        drop(stream);
        tracing::debug!(?endpoint, "p2p inbound rejected: network inactive");
        return;
    }
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::QueuedFrame>();
    let lease = crate::PeerLease::new_inbound(outbound_tx)
        .with_shared_budget(&shared.shared_outbound)
        .with_no_ban(endpoint.is_some_and(|endpoint| shared.banned.is_noban(endpoint.address())))
        .with_transport_alive(alive);
    let peer_addr = endpoint.map_or_else(
        || crate::PeerRemote::AnonymousTor(lease.connection_id()),
        crate::PeerRemote::Endpoint,
    );
    let netgroup = endpoint.map_or_else(
        || vec![4],
        |endpoint| {
            shared.address_book.as_ref().map_or_else(
                || crate::netgroup::NetGroups::default().group(endpoint.address()),
                |book| book.netgroup(endpoint.address()),
            )
        },
    );
    let Some(lease) = shared.peer_table.try_register_inbound(
        peer_addr,
        lease,
        &netgroup,
        shared.max_inbound,
        approximate_best_block_depth(shared.chain_query.as_deref()),
        &shared.activity,
    ) else {
        drop(stream);
        tracing::debug!(peer_addr = %peer_addr, "p2p inbound rejected: inactive or at capacity");
        return;
    };
    spawn_handshake_thread(stream, peer_addr, shared.clone(), lease, outbound_rx);
}

#[must_use]
pub fn spawn_outbound_connection(
    addr: PeerEndpoint,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_dial(
        addr,
        shared,
        role,
        ConnectionOrigin::Automatic,
        FailureAccounting::Ignore,
    )
}

#[must_use]
pub(crate) fn spawn_pinned_outbound_connection(
    addr: PeerEndpoint,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_dial(
        addr,
        shared,
        role,
        ConnectionOrigin::Manual,
        FailureAccounting::Ignore,
    )
}

pub(crate) fn spawn_automatic_dial(
    addr: PeerEndpoint,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
    failure_accounting: FailureAccounting,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_dial(
        addr,
        shared,
        role,
        ConnectionOrigin::Automatic,
        failure_accounting,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionOrigin {
    Manual,
    Automatic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureAccounting {
    Count,
    Ignore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportChoice {
    PreferV2,
    ForceV1,
}

fn spawn_dial(
    addr: PeerEndpoint,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
    origin: ConnectionOrigin,
    failure_accounting: FailureAccounting,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let thread_name = format!("bitcoin-rs-p2p-outbound-{addr}");
    let result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || run_outbound_connection(addr, &shared, role, origin, failure_accounting));

    match result {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(
                addr = %addr,
                %error,
                "p2p outbound spawn failed",
            );
            std::thread::spawn(move || Err(crate::wire::PeerError::Io(error)))
        }
    }
}

fn run_outbound_connection(
    addr: PeerEndpoint,
    shared: &ConnectionShared,
    role: crate::peer_info::PeerRole,
    origin: ConnectionOrigin,
    failure_accounting: FailureAccounting,
) -> Result<(), crate::wire::PeerError> {
    match origin {
        ConnectionOrigin::Manual => shared.check_manual_destination(addr)?,
        ConnectionOrigin::Automatic => shared.check_automatic_destination(addr)?,
    }
    if !shared.activity.is_active() {
        return Err(crate::wire::PeerError::Protocol("network inactive"));
    }
    if shared.is_session_cancelled() {
        return Err(crate::wire::PeerError::Protocol("p2p startup cancelled"));
    }

    if origin == ConnectionOrigin::Automatic && !shared.feeler {
        let depth = approximate_best_block_depth(shared.chain_query.as_deref());
        if shared
            .address_book
            .as_ref()
            .is_some_and(|book| !book.ordinary_services_eligible(addr, depth))
        {
            return Err(crate::wire::PeerError::Protocol(
                "outbound peer lacks desirable services",
            ));
        }
    }
    let try_v2 = shared.v2_transport
        && (origin == ConnectionOrigin::Manual
            || shared
                .address_book
                .as_ref()
                .is_some_and(|book| book.advertises(addr, ServiceFlags::P2P_V2)));
    let transport_choice = if try_v2 {
        TransportChoice::PreferV2
    } else {
        TransportChoice::ForceV1
    };
    match dial(
        addr,
        shared,
        role,
        origin,
        failure_accounting,
        transport_choice,
    )? {
        Dialed::Done => Ok(()),
        Dialed::V1Retry => {
            tracing::debug!(
                peer_addr = %addr,
                "p2p v2 handshake unanswered; retrying with v1 transport protocol"
            );
            dial(
                addr,
                shared,
                role,
                origin,
                FailureAccounting::Ignore,
                TransportChoice::ForceV1,
            )
            .map(|_| ())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dialed {
    Done,
    V1Retry,
}

fn dial(
    addr: PeerEndpoint,
    shared: &ConnectionShared,
    role: crate::peer_info::PeerRole,
    origin: ConnectionOrigin,
    failure_accounting: FailureAccounting,
    transport_choice: TransportChoice,
) -> Result<Dialed, crate::wire::PeerError> {
    let connection = shared.overlay.connect(addr, &|| {
        shared.is_session_cancelled() || !shared.activity.is_active()
    });
    if let Some(book) = &shared.address_book {
        if addr.address().ip().is_some() && shared.overlay.config.proxy.is_none()
            || connection.is_ok()
            || connection
                .as_ref()
                .is_err_and(crate::overlay::remote_connect_failed)
        {
            if failure_accounting == FailureAccounting::Count
                && origin == ConnectionOrigin::Automatic
            {
                book.attempt_failed(addr, crate::addrman::now());
            } else {
                book.attempted(addr, crate::addrman::now());
            }
        }
    }
    let connected = connection.map_err(crate::wire::PeerError::Io)?;
    let stream = connected.stream;
    configure_peer_stream(&stream).map_err(crate::wire::PeerError::Io)?;
    match origin {
        ConnectionOrigin::Manual => shared.check_manual_destination(addr)?,
        ConnectionOrigin::Automatic => shared.check_automatic_destination(addr)?,
    }
    if shared.is_session_cancelled() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol("p2p startup cancelled"));
    }

    let counters = std::sync::Arc::new(crate::PeerCounters::default());
    let connection_cancel = shared.session_cancel.child();
    let stream = crate::CountingStream::from_connected(stream, counters)
        .map_err(crate::wire::PeerError::Io)?;

    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::QueuedFrame>();
    let lease = match (role, origin) {
        (crate::peer_info::PeerRole::FullRelay, ConnectionOrigin::Automatic) => {
            crate::PeerLease::new(outbound_tx)
        }
        (crate::peer_info::PeerRole::BlockRelayOnly, ConnectionOrigin::Automatic) => {
            crate::PeerLease::new_block_relay(outbound_tx)
        }
        (_, ConnectionOrigin::Manual) => crate::PeerLease::new_manual(outbound_tx, role),
    }
    .with_shared_budget(&shared.shared_outbound)
    .with_no_ban(shared.banned.is_noban(addr.address()))
    .with_transport_alive(connected.alive);
    let Some(lease) = shared
        .peer_table
        .try_register_outbound(addr, lease, &shared.activity)
    else {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol(
            "transport or network unavailable",
        ));
    };
    let stream = match stream
        .stop_reading_when(lease.clone())
        .recording_send_activity(lease.send_activity())
        .with_cancel(&connection_cancel.reader(), &shared.cancel_clone())
        .map_err(crate::wire::PeerError::Io)
    {
        Ok(stream) => stream,
        Err(error) => {
            shared.peer_table.remove_current(addr, &lease);
            return Err(error);
        }
    };
    let check = match origin {
        ConnectionOrigin::Manual => shared.check_manual_destination(addr),
        ConnectionOrigin::Automatic => shared.check_automatic_destination(addr),
    };
    if let Err(error) = check {
        shared.peer_table.remove_current(addr, &lease);
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(error);
    }
    if shared.is_session_cancelled() {
        shared.peer_table.remove_current(addr, &lease);
        lease.cancel();
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Ok(Dialed::Done);
    }

    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut stream = stream;
    let mut negotiated = if transport_choice == TransportChoice::PreferV2 {
        let mut handshake = crate::bip324::Handshake::initiator(
            shared.magic,
            &mut bitcoin::secp256k1::rand::thread_rng(),
        );
        handshake.bind_memory(&shared.block_memory)?;
        match crate::transport::establish(
            &mut stream,
            &mut handshake,
            shared.magic,
            &lease,
            handshake_deadline,
        ) {
            Ok(negotiated) => negotiated,
            Err(error) => {
                let revoked = lease.is_cancelled();
                shared.peer_table.remove_current(addr, &lease);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                if revoked {
                    tracing::debug!(peer_addr = %addr, "p2p outbound lease revoked during handshake");
                    return Ok(Dialed::Done);
                }
                if !handshake.received_any()
                    && shared.activity.is_active()
                    && !shared.is_session_cancelled()
                {
                    return Ok(Dialed::V1Retry);
                }
                return Err(error);
            }
        }
    } else {
        crate::transport::Negotiated::v1(shared.magic)
    };
    negotiated.recv.bind_memory(&shared.block_memory)?;

    let nonce = generate_nonce(addr);
    let nonce_guard = shared.peer_table.begin_outbound_handshake_nonce(nonce);

    let addr_bind = stream.local_addr().map_err(crate::wire::PeerError::Io)?;
    let counters = std::sync::Arc::clone(stream.counters());
    let mut peer = Peer::with_transport(stream, shared.magic, negotiated);
    peer.account_message_bytes(std::sync::Arc::clone(&counters));
    let trace = if origin == ConnectionOrigin::Manual {
        crate::net_trace::NetTrace::manual_outbound(lease.node_id(), addr.into())
    } else {
        crate::net_trace::NetTrace::outbound(lease.node_id(), addr.into(), role)
    };
    peer.attach_net_trace(trace);
    shared.offer_relay_capabilities(&mut peer, role);
    if let Err(error) = run_outbound_handshake(
        &mut peer,
        nonce,
        0,
        &lease,
        handshake_deadline,
        addr,
        shared,
    ) {
        let revoked = lease.is_cancelled();
        if !revoked {
            shared.note_misbehavior(addr, &lease, &error);
        }
        shared.peer_table.remove_current(addr, &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        if revoked {
            tracing::debug!(peer_addr = %addr, "p2p outbound lease revoked during handshake");
            return Ok(Dialed::Done);
        }
        return Err(error);
    }
    drop(nonce_guard);

    let Some(remote_version) = peer.remote_version.as_ref() else {
        shared.peer_table.remove_current(addr, &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol(
            "missing remote version after outbound handshake",
        ));
    };
    let conn_time = unix_time_secs();
    let info = crate::PeerInfo::outbound_from_version_endpoint(
        addr,
        addr_bind,
        remote_version,
        conn_time,
        peer.version_received_time.unwrap_or(conn_time),
        counters,
    );

    if shared.feeler {
        if shared.peer_table.is_current(lease.source(Some(addr)))
            && !lease.is_cancelled()
            && !shared.is_session_cancelled()
            && shared.activity.is_active()
        {
            if let Some(book) = &shared.address_book {
                book.succeeded(addr, info.services, unix_time_secs());
            }
        }
        shared.peer_table.remove_current(addr, &lease);
        lease.cancel();
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        return Ok(Dialed::Done);
    }
    run_connected_session(&mut peer, addr, shared, lease, outbound_rx, info).map(|()| Dialed::Done)
}

pub fn run_outbound_handshake<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    nonce: u64,
    start_height: i32,
    lease: &crate::PeerLease,
    deadline: Instant,
    addr: PeerEndpoint,
    shared: &ConnectionShared,
) -> Result<(), crate::wire::PeerError> {
    let endpoint = addr;
    let best_block_depth = approximate_best_block_depth(shared.chain_query.as_deref());
    let outbound_messages = crate::handshake::start(
        peer,
        nonce,
        start_height,
        lease.role(),
        shared.advertised_services(),
        &shared.user_agent,
    );
    for message in outbound_messages {
        peer.send(&message)?;
    }

    while peer.state != crate::peer::PeerState::Ready {
        let (accepted, responses) = crate::handshake::next_handshake_step(peer, lease, deadline)?;
        if !shared.feeler
            && matches!(accepted, crate::Message::Version(_))
            && let Some(version) = peer.remote_version.as_ref()
        {
            let _ = shared
                .peer_table
                .with_current(lease.source(Some(endpoint)), || {
                    if !shared.is_session_cancelled()
                        && shared.activity.is_active()
                        && let Some(book) = &shared.address_book
                    {
                        book.set_services(endpoint, version.services.to_u64());
                    }
                });
        }
        if shared.feeler && peer.remote_version.is_some() {
            return Ok(());
        }
        if peer.remote_version.as_ref().is_some_and(|version| {
            !has_all_desirable_service_flags(version.services, best_block_depth)
        }) {
            return Err(crate::wire::PeerError::Protocol(
                "outbound peer lacks desirable services",
            ));
        }
        for response in responses {
            peer.send(&response)?;
        }
    }
    crate::handshake::send_post_verack_messages(peer)?;
    Ok(())
}

pub(crate) fn approximate_best_block_depth(query: Option<&dyn crate::ChainQuery>) -> u64 {
    let Some(tip_time) = query.and_then(crate::ChainQuery::best_block_time) else {
        return u64::MAX;
    };
    unix_time_secs().saturating_sub(u64::from(tip_time)) / POW_TARGET_SPACING_SECS
}

#[must_use]
pub fn has_all_desirable_service_flags(
    remote_services: ServiceFlags,
    best_block_depth: u64,
) -> bool {
    let required = if remote_services.has(ServiceFlags::NETWORK_LIMITED)
        && best_block_depth < NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS
    {
        ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS
    } else {
        ServiceFlags::NETWORK | ServiceFlags::WITNESS
    };
    remote_services.has(required)
}

fn spawn_handshake_thread(
    stream: TcpStream,
    peer_addr: impl Into<crate::PeerRemote>,
    shared: ConnectionShared,
    lease: crate::PeerLease,
    outbound_rx: crossbeam_channel::Receiver<crate::QueuedFrame>,
) {
    let peer_addr = peer_addr.into();
    let thread_name = format!("bitcoin-rs-p2p-handshake-{peer_addr}");
    let reservation = lease.clone();
    let spawn_shared = shared.clone();
    let spawn_result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            if let Err(error) = run_handshake(stream, peer_addr, &shared, lease, outbound_rx) {
                tracing::warn!(
                    peer_addr = %peer_addr,
                    %error,
                    "p2p inbound handshake failed",
                );
            }
        });

    if let Err(error) = spawn_result {
        spawn_shared.remove_session(peer_addr.endpoint(), &reservation);
        reservation.cancel();
        tracing::warn!(
            peer_addr = %peer_addr,
            %error,
            "failed to spawn p2p inbound handshake thread",
        );
    }
}

fn negotiate_inbound(
    stream: &mut crate::CountingStream<TcpStream>,
    shared: &ConnectionShared,
    lease: &crate::PeerLease,
    deadline: Instant,
) -> Result<crate::transport::Negotiated, crate::wire::PeerError> {
    if !shared.v2_transport {
        let mut negotiated = crate::transport::Negotiated::v1(shared.magic);
        negotiated.recv.bind_memory(&shared.block_memory)?;
        return Ok(negotiated);
    }
    let mut handshake = crate::bip324::Handshake::responder(
        shared.magic,
        &mut bitcoin::secp256k1::rand::thread_rng(),
    );
    handshake.bind_memory(&shared.block_memory)?;
    crate::transport::establish(stream, &mut handshake, shared.magic, lease, deadline)
}

fn run_handshake(
    stream: TcpStream,
    peer_addr: impl Into<crate::PeerRemote>,
    shared: &ConnectionShared,
    lease: crate::PeerLease,
    outbound_rx: crossbeam_channel::Receiver<crate::QueuedFrame>,
) -> Result<(), crate::wire::PeerError> {
    let peer_addr = peer_addr.into();
    let endpoint = peer_addr.endpoint();
    if let Some(endpoint) = endpoint {
        let check = if lease.is_manual() {
            shared.check_manual_destination(endpoint)
        } else {
            shared.check_automatic_destination(endpoint)
        };
        if let Err(error) = check {
            shared.peer_table.remove_current(peer_addr, &lease);
            return Err(error);
        }
    }
    if let Err(error) = configure_peer_stream(&stream).map_err(crate::wire::PeerError::Io) {
        shared.remove_session(peer_addr.endpoint(), &lease);
        lease.cancel();
        return Err(error);
    }

    let counters = std::sync::Arc::new(crate::PeerCounters::default());
    let connection_cancel = shared.session_cancel.child();
    let stream = match crate::CountingStream::from_connected(stream, counters)
        .and_then(|stream| {
            stream
                .stop_reading_when(lease.clone())
                .recording_send_activity(lease.send_activity())
                .with_cancel(&connection_cancel.reader(), &std::net::TcpStream::try_clone)
        })
        .map_err(crate::wire::PeerError::Io)
    {
        Ok(stream) => stream,
        Err(error) => {
            shared.remove_session(peer_addr.endpoint(), &lease);
            lease.cancel();
            return Err(error);
        }
    };
    let addr_bind = match stream.local_addr().map_err(crate::wire::PeerError::Io) {
        Ok(addr) => addr,
        Err(error) => {
            shared.remove_session(peer_addr.endpoint(), &lease);
            lease.cancel();
            return Err(error);
        }
    };
    let counters = std::sync::Arc::clone(stream.counters());

    if shared.is_session_cancelled() {
        shared.remove_session(peer_addr.endpoint(), &lease);
        lease.cancel();
        return Ok(());
    }

    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut stream = stream;
    let negotiated = match negotiate_inbound(&mut stream, shared, &lease, handshake_deadline) {
        Ok(negotiated) => negotiated,
        Err(error) => {
            let revoked = lease.is_cancelled();
            if !revoked {
                shared.note_misbehavior(peer_addr, &lease, &error);
            }
            shared.remove_session(peer_addr.endpoint(), &lease);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            if revoked {
                return Ok(());
            }
            return Err(error);
        }
    };

    let nonce = generate_nonce(peer_addr);
    let mut peer = Peer::with_transport(stream, shared.magic, negotiated);
    peer.account_message_bytes(std::sync::Arc::clone(&counters));
    peer.attach_net_trace(crate::net_trace::NetTrace::inbound(
        lease.node_id(),
        peer_addr,
    ));
    peer.check_inbound_nonce_against(shared.peer_table.outbound_handshake_nonces());
    shared.offer_relay_capabilities(&mut peer, lease.role());
    if let Err(error) = run_inbound_handshake(
        &mut peer,
        nonce,
        0,
        shared.advertised_services(),
        &shared.user_agent,
        &lease,
        handshake_deadline,
    ) {
        let revoked = lease.is_cancelled();
        if !revoked {
            shared.note_misbehavior(peer_addr, &lease, &error);
        }
        shared.remove_session(peer_addr.endpoint(), &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        if revoked {
            tracing::debug!(peer_addr = %peer_addr, "p2p inbound lease revoked during handshake");
            return Ok(());
        }
        return Err(error);
    }

    let Some(remote_version) = peer.remote_version.as_ref() else {
        shared.remove_session(peer_addr.endpoint(), &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol(
            "missing remote version after successful handshake",
        ));
    };
    let conn_time = unix_time_secs();
    let mut info = crate::PeerInfo::inbound_from_version(
        peer_addr,
        addr_bind,
        remote_version,
        conn_time,
        peer.version_received_time.unwrap_or(conn_time),
        counters,
    );
    if let Some(identified) = endpoint {
        info.endpoint = Some(identified);
        info.network = identified.net();
    } else {
        info.endpoint = None;
        info.network = bitcoin_rs_consensus::primitives::NetworkLabel::Onion;
    }

    run_connected_session(&mut peer, peer_addr, shared, lease, outbound_rx, info)
}

fn publish_connected_peer(
    shared: &ConnectionShared,
    peer: &Peer<crate::CountingStream<TcpStream>>,
    endpoint: Option<crate::PeerEndpoint>,
    lease: &crate::PeerLease,
    info: &crate::PeerInfo,
) -> bool {
    let ready = shared.publish_info_and_notify_ready_with_package(
        crate::PeerRemote::from(lease.source(endpoint)),
        lease,
        info,
        peer.package_relay_versions(),
    );
    if ready {
        shared.note_peer_stale_tip_relay(peer, endpoint, lease);
    }
    ready
}

fn run_connected_session(
    peer: &mut Peer<crate::CountingStream<TcpStream>>,
    peer_addr: impl Into<crate::PeerRemote>,
    shared: &ConnectionShared,
    lease: crate::PeerLease,
    outbound_rx: crossbeam_channel::Receiver<crate::QueuedFrame>,
    mut info: crate::PeerInfo,
) -> Result<(), crate::wire::PeerError> {
    let peer_addr = peer_addr.into();
    let endpoint = peer_addr.endpoint();
    info.wtxid_relay = peer.wtxid_relay.peer_supported();
    info.send_headers = peer.capabilities.send_headers;
    info.transport = peer.transport();
    let setup_result: Result<std::thread::JoinHandle<()>, crate::wire::PeerError> = (|| {
        #[cfg(test)]
        if WRITER_SETUP_FAIL.swap(false, Ordering::Relaxed) {
            return Err(crate::wire::PeerError::Io(io::Error::other(
                "test-injected writer setup failure",
            )));
        }
        let writer_stream = peer
            .stream
            .try_clone()
            .map_err(crate::wire::PeerError::Io)?;
        let transport = peer
            .take_send_transport()
            .ok_or(crate::wire::PeerError::Protocol(
                "send transport already taken",
            ))?;
        spawn_connection_writer(
            writer_stream,
            transport,
            outbound_rx,
            lease.close_signal(),
            lease.budget_handle(),
            peer_addr,
            peer.net_trace,
        )
        .map_err(crate::wire::PeerError::Io)
    })();
    let writer = match setup_result {
        Ok(handle) => handle,
        Err(error) => {
            shared.remove_session(peer_addr.endpoint(), &lease);
            lease.cancel();
            let _ = peer.stream.shutdown(std::net::Shutdown::Both);
            drop(lease);
            return Err(error);
        }
    };
    let ready = publish_connected_peer(shared, peer, endpoint, &lease, &info);

    let inbound = lease.is_inbound();
    let transport = match info.transport {
        crate::TransportProtocol::V1 => "v1",
        crate::TransportProtocol::V2 { .. } => "v2",
    };
    tracing::info!(
        peer_addr = %peer_addr,
        inbound,
        transport,
        "p2p handshake complete; entering message loop",
    );

    let loop_result = match peer.stream.set_read_timeout(Some(MESSAGE_LOOP_POLL)) {
        Ok(()) => run_message_loop(peer, peer_addr, &lease, shared, shared.ibd.as_ref()),
        Err(error) => Err(crate::wire::PeerError::Io(error)),
    };

    let source = lease.source(peer_addr.endpoint());
    if let Err(error) = &loop_result {
        shared.note_misbehavior(peer_addr, &lease, error);
    }
    shared.remove_session(peer_addr.endpoint(), &lease);
    if let Some(inventory) = &shared.tx_inventory {
        if let Some(tp) = &shared.tx_policy {
            tp.transaction_peer_disconnected(source, inventory.as_ref());
        }
    }
    if let Some(announcer) = &shared.block_announcer {
        announcer.on_peer_disconnected(source);
    }
    if ready && !lease.is_inbound() && !lease.is_manual() && lease.role().relays_transactions() {
        if let Some(book) = &shared.address_book
            && let Some(endpoint) = peer_addr.endpoint()
        {
            book.connected(endpoint, crate::addrman::now());
        }
    }
    lease.cancel();
    let _ = peer.stream.shutdown(std::net::Shutdown::Both);
    drop(lease);
    let _ = writer.join();
    if let Err(error) = &loop_result {
        tracing::warn!(
            peer_addr = %peer_addr,
            inbound,
            %error,
            "p2p peer disconnected with error"
        );
    } else {
        tracing::debug!(peer_addr = %peer_addr, inbound, "p2p peer disconnected cleanly");
    }
    loop_result
}

fn enforce_relay_role(
    role: crate::peer_info::PeerRole,
    message: crate::Message,
) -> Result<Option<crate::Message>, crate::wire::PeerError> {
    use bitcoin::p2p::message_blockdata::Inventory;
    if role.relays_transactions() {
        return Ok(Some(message));
    }
    let is_transaction = |item: &Inventory| {
        matches!(
            item,
            Inventory::Transaction(_) | Inventory::WitnessTransaction(_) | Inventory::WTx(_)
        ) || matches!(
            item,
            Inventory::Unknown { inv_type, .. } if *inv_type == crate::packages::MSG_ANCPKGINFO
        )
    };
    if matches!(message, crate::Message::Tx(_)) {
        return Err(crate::wire::PeerError::Protocol(
            "transaction sent in violation of protocol",
        ));
    }
    if matches!(
        message,
        crate::Message::SendPackages(_)
            | crate::Message::AncPkgInfo(_)
            | crate::Message::GetPkgTxns(_)
            | crate::Message::PkgTxns(_)
            | crate::Message::PkgTxnsPayload(_)
    ) {
        return Err(crate::wire::PeerError::Protocol(
            "package message sent in violation of protocol",
        ));
    }
    if let crate::Message::Inv(items) = &message
        && items.iter().any(&is_transaction)
    {
        return Err(crate::wire::PeerError::Protocol(
            "transaction inv sent in violation of protocol",
        ));
    }
    if let crate::Message::GetData(mut items) = message {
        items.retain(|item| !is_transaction(item));
        if items.is_empty() {
            tracing::trace!("p2p dropping transaction getdata from block-relay-only peer");
            return Ok(None);
        }
        return Ok(Some(crate::Message::GetData(items)));
    }
    if matches!(message, crate::Message::Addr(_) | crate::Message::AddrV2(_)) {
        tracing::trace!("p2p dropping address message from block-relay-only peer");
        return Ok(None);
    }
    Ok(Some(message))
}

pub(crate) fn record_fee_filter(
    peer_table: &crate::PeerTable,
    tx_policy: Option<&Arc<dyn TxPolicyObserver>>,
    source: crate::PeerSource,
    rate: i64,
) {
    if let Ok(rate) = u64::try_from(rate) {
        if rate <= bitcoin_rs_consensus::primitives::Amount::MAX_MONEY.to_sat() {
            peer_table.note_fee_filter(source, rate);
        }
    }
    if let Some(policy) = tx_policy {
        policy.receive_fee_filter(source, rate);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum KeepaliveAction {
    Idle,
    Ping,
    Expired,
}

struct Keepalive {
    ping_interval: Duration,
    timeout_interval: Duration,
    last_recv: Instant,
    last_send: Instant,
    last_ping: Option<Instant>,
    stall: Option<Instant>,
    shared_refused: bool,
}

fn past_stall(last: Instant, since: Instant, now: Instant) -> Instant {
    last + now.saturating_duration_since(last.max(since))
}

impl Keepalive {
    fn starting(now: Instant) -> Self {
        Self::with_intervals(now, PING_INTERVAL, TIMEOUT_INTERVAL)
    }

    fn with_intervals(now: Instant, ping_interval: Duration, timeout_interval: Duration) -> Self {
        Self {
            ping_interval,
            timeout_interval,
            last_recv: now,
            last_send: now,
            last_ping: None,
            stall: None,
            shared_refused: false,
        }
    }

    fn note_refusal(&mut self, refusal: crate::connection::Refusal) {
        if refusal == crate::connection::Refusal::Shared {
            self.shared_refused = true;
        }
    }

    fn excluding_stall(&self, last: Instant, now: Instant) -> Instant {
        self.stall
            .map_or(last, |since| past_stall(last, since, now))
    }

    fn settle_pass(&mut self, now: Instant, parked_since: &mut Option<Instant>) {
        let blocked = std::mem::take(&mut self.shared_refused);
        match (self.stall, blocked) {
            (None, true) => self.stall = Some(now),
            (Some(since), false) => {
                self.stall = None;
                self.last_recv = past_stall(self.last_recv, since, now);
                self.last_send = past_stall(self.last_send, since, now);
                if let Some(parked) = parked_since {
                    *parked = past_stall(*parked, since, now);
                }
            }
            (None, false) | (Some(_), true) => {}
        }
    }

    fn record_recv(&mut self, now: Instant) {
        self.last_recv = now;
    }

    /// The message loop's ledger: the receive clock starts at loop entry
    /// (nothing has been received in this session yet), the send clock at
    /// the connection's last actual socket write, which the lease's
    /// send-activity feed carries (the handshake's final bytes), so a
    /// quiet handshake tail cannot mask send silence.
    fn starting_message_loop(now: Instant, last_send: Instant) -> Self {
        Self {
            last_recv: now,
            last_send,
            ..Self::starting(now)
        }
    }

    /// The writer's accounting feed: advances only, because the observed
    /// instant can predate a stall-shifted ledger.
    fn observe_send(&mut self, sent: Instant) {
        if sent > self.last_send {
            self.last_send = sent;
        }
    }

    /// One probe's admission: it owes its cadence (`last_ping`) but is not
    /// send activity — only actual socket writes feed the send-silence
    /// clock, so a queued-but-unwritten probe cannot mask a stalled writer.
    fn record_probe(&mut self, now: Instant) {
        self.last_ping = Some(now);
    }

    fn next_action(&self, now: Instant) -> KeepaliveAction {
        self.decide(now, true)
    }

    fn next_action_while_parked(&self, now: Instant) -> KeepaliveAction {
        self.decide(now, false)
    }

    fn decide(&self, now: Instant, receive_silence_expires: bool) -> KeepaliveAction {
        let last_recv = self.excluding_stall(self.last_recv, now);
        let last_send = self.excluding_stall(self.last_send, now);
        let receive_expired = receive_silence_expires
            && now.saturating_duration_since(last_recv) > self.timeout_interval;
        let send_expired = now.saturating_duration_since(last_send) > self.timeout_interval;
        if receive_expired || send_expired {
            return KeepaliveAction::Expired;
        }
        let idle = now.saturating_duration_since(last_recv) >= self.ping_interval
            || now.saturating_duration_since(last_send) >= self.ping_interval;
        let probe_owed = self
            .last_ping
            .is_none_or(|last| now.saturating_duration_since(last) >= self.ping_interval);
        // Core initializes a peer's `m_ping_start` to the clock epoch, so the
        // first `MaybeSendPing` pass after VERACK owes a probe without waiting
        // for silence (v31.1 net_processing.cpp); later probes stay idle-gated.
        if probe_owed && (self.last_ping.is_none() || idle) {
            KeepaliveAction::Ping
        } else {
            KeepaliveAction::Idle
        }
    }
}

#[cfg(test)]
mod keepalive_tests {
    use super::{Keepalive, KeepaliveAction, PING_INTERVAL, TIMEOUT_INTERVAL};
    use std::time::{Duration, Instant};

    #[test]
    fn first_probe_is_owed_immediately() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        assert_eq!(
            keepalive.next_action(t0),
            KeepaliveAction::Ping,
            "Core's m_ping_start initializes to the clock epoch, so the first pass after the handshake pings without waiting for silence"
        );
        keepalive.record_probe(t0);
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL / 2),
            KeepaliveAction::Idle,
            "after the first probe a busy-enough connection sends no keepalive"
        );
    }

    #[test]
    fn probes_owe_one_ping_per_idle_interval() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        keepalive.record_probe(t0);
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL / 2),
            KeepaliveAction::Idle,
            "a busy-enough connection sends no keepalive"
        );
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL),
            KeepaliveAction::Ping,
            "one silent direction for an interval owes a probe"
        );
        keepalive.record_probe(t0 + PING_INTERVAL);
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL + PING_INTERVAL / 2),
            KeepaliveAction::Idle
        );
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL * 2),
            KeepaliveAction::Ping
        );
    }

    #[test]
    fn receive_silence_expires_the_connection() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        keepalive.observe_send(t0 + TIMEOUT_INTERVAL);
        assert_eq!(
            keepalive.next_action(t0 + TIMEOUT_INTERVAL + Duration::from_secs(1)),
            KeepaliveAction::Expired
        );
    }

    #[test]
    fn send_silence_expires_the_connection() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        keepalive.record_recv(t0 + TIMEOUT_INTERVAL);
        assert_eq!(
            keepalive.next_action(t0 + TIMEOUT_INTERVAL + Duration::from_secs(1)),
            KeepaliveAction::Expired
        );
    }

    #[test]
    fn parked_loop_does_not_expire_on_receive_silence() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        keepalive.observe_send(t0 + TIMEOUT_INTERVAL);
        let now = t0 + TIMEOUT_INTERVAL + Duration::from_secs(1);
        assert_eq!(keepalive.next_action(now), KeepaliveAction::Expired);
        assert_ne!(
            keepalive.next_action_while_parked(now),
            KeepaliveAction::Expired,
            "the same ledger, parked, is not judged on receive silence"
        );
    }

    #[test]
    fn parked_loop_still_expires_on_send_silence() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        keepalive.record_recv(t0 + TIMEOUT_INTERVAL);
        assert_eq!(
            keepalive.next_action_while_parked(t0 + TIMEOUT_INTERVAL + Duration::from_secs(1)),
            KeepaliveAction::Expired
        );
    }

    #[test]
    fn parked_loop_orders_the_same_probe_as_an_unparked_one() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        keepalive.observe_send(t0);
        assert_eq!(
            keepalive.next_action_while_parked(t0 + PING_INTERVAL),
            KeepaliveAction::Ping
        );
    }

    #[test]
    fn fresh_activity_defers_the_timeout() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        let fresh = t0 + TIMEOUT_INTERVAL / 2;
        keepalive.record_recv(fresh);
        keepalive.observe_send(fresh);
        assert_eq!(
            keepalive.next_action(t0 + TIMEOUT_INTERVAL),
            KeepaliveAction::Ping
        );
        keepalive.record_probe(t0 + TIMEOUT_INTERVAL);
        assert_eq!(
            keepalive.next_action(t0 + TIMEOUT_INTERVAL + PING_INTERVAL / 2),
            KeepaliveAction::Idle
        );
    }

    #[test]
    fn an_admitted_probe_is_not_send_activity() {
        let t0 = Instant::now();
        let expired = t0 + TIMEOUT_INTERVAL + Duration::from_secs(1);
        let mut keepalive = Keepalive::starting_message_loop(t0, t0);
        // The probe is admitted to the queue minutes after the last actual
        // write; inbound traffic keeps the receive clock fresh the whole
        // time. Expiry is still judged from the last actual write.
        keepalive.record_probe(t0 + PING_INTERVAL);
        keepalive.record_recv(expired);
        assert_eq!(
            keepalive.next_action(expired),
            KeepaliveAction::Expired,
            "send silence runs from the last actual write, not probe admission"
        );
    }

    #[test]
    fn a_refused_probe_stays_owed_until_sent() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        keepalive.note_refusal(crate::connection::Refusal::Shared);
        keepalive.settle_pass(t0, &mut None);
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL),
            KeepaliveAction::Ping,
            "a refused probe is retryable, not silently lost"
        );
        keepalive.record_probe(t0 + PING_INTERVAL);
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL + PING_INTERVAL / 2),
            KeepaliveAction::Idle
        );
    }

    #[test]
    fn refusal_classification_keeps_the_silence_clock_honest() {
        let t0 = Instant::now();
        let expired = t0 + TIMEOUT_INTERVAL + Duration::from_secs(1);
        let mut locally_refused = Keepalive::starting(t0);
        locally_refused.note_refusal(crate::connection::Refusal::Local);
        locally_refused.settle_pass(expired, &mut None);
        assert_eq!(
            locally_refused.next_action(expired),
            KeepaliveAction::Expired,
            "connection-local control congestion is not a stall: a wire-silent peer whose queue is stuck full still expires"
        );
        let mut aggregate_refused = Keepalive::starting(t0);
        aggregate_refused.note_refusal(crate::connection::Refusal::Shared);
        aggregate_refused.settle_pass(t0 + Duration::from_secs(1), &mut None);
        assert_ne!(
            aggregate_refused.next_action(expired),
            KeepaliveAction::Expired,
            "aggregate backpressure is a stall, not keepalive silence"
        );
    }
}

pub struct ProductionSink<'a> {
    lease: &'a crate::PeerLease,
    production: std::cell::Cell<Option<crate::connection::OutboundCredit>>,
    reply: std::cell::Cell<Option<crate::connection::OutboundCredit>>,
    refused: std::cell::Cell<Option<crate::connection::Refusal>>,
}

impl<'a> ProductionSink<'a> {
    pub fn new(
        lease: &'a crate::PeerLease,
        reply: Option<crate::connection::OutboundCredit>,
    ) -> Self {
        Self {
            lease,
            production: std::cell::Cell::new(None),
            reply: std::cell::Cell::new(reply),
            refused: std::cell::Cell::new(None),
        }
    }

    fn headroom(&self) -> bool {
        if self.lease.is_cancelled() {
            return false;
        }
        let reserved = match self.production.take().or_else(|| self.reply.take()) {
            Some(held) => Ok(held),
            None => self.lease.try_reserve_production(),
        };
        match reserved {
            Ok(credit) => {
                self.production.set(Some(credit));
                true
            }
            Err(refusal) => {
                self.refused.set(Some(refusal));
                false
            }
        }
    }

    fn send(&self, message: crate::Message) -> Result<(), crate::wire::PeerError> {
        let Some(credit) = self.production.take().or_else(|| self.reply.take()) else {
            debug_assert!(false, "an outbound message was sent without a reservation");
            return Err(crate::wire::PeerError::Protocol(
                "unreserved outbound message",
            ));
        };
        self.lease
            .send_with(credit, message)
            .map_err(|_| closed_queue())
    }

    fn refusal(&self) -> Option<crate::connection::Refusal> {
        self.refused.take()
    }
}

const fn closed_queue() -> crate::wire::PeerError {
    crate::wire::PeerError::Protocol("outbound queue closed")
}

pub fn reply_bound(message: &crate::Message, getaddr_answerable: bool) -> Option<usize> {
    let payload = match message {
        crate::Message::Ping(_) => 8,
        crate::Message::GetHeaders(_) => 3 + crate::wire::MAX_HEADERS_MESSAGE_COUNT * 81,
        crate::Message::GetAddr if getaddr_answerable => {
            3 + crate::wire::MAX_ADDR_MESSAGE_COUNT * 33
        }
        crate::Message::CmpctBlock(cmpct) => {
            (32 + 9 + 5 * cmpct.compact_block.short_ids.len()).max(1 + 36)
        }
        crate::Message::BlockTxn(_) => 1 + 36,
        crate::Message::GetBlockTxn(_) => crate::peer::MAX_BLOCK_SERIALIZED_SIZE_USIZE,
        crate::Message::GetPkgTxns(_) => crate::wire::MAX_MESSAGE_PAYLOAD,
        _ => return None,
    };
    Some(crate::wire::HEADER_LEN + payload.min(crate::wire::MAX_MESSAGE_PAYLOAD))
}

fn reserves_production(message: &crate::Message) -> bool {
    matches!(
        message,
        crate::Message::GetBlockTxn(_) | crate::Message::GetPkgTxns(_)
    )
}

fn defers_on_local(message: &crate::Message) -> bool {
    matches!(
        message,
        crate::Message::CmpctBlock(_)
            | crate::Message::BlockTxn(_)
            | crate::Message::GetBlockTxn(_)
            | crate::Message::GetPkgTxns(_)
    )
}

fn getaddr_answerable(
    lease: &crate::PeerLease,
    shared: &ConnectionShared,
    answered_getaddr: bool,
) -> bool {
    lease.is_inbound()
        && !answered_getaddr
        && lease.role().relays_transactions()
        && shared.address_book.is_some()
}

enum DeferredStep {
    NoneHeld,
    Waiting,
    Ended,
    Ready(crate::Message, Option<crate::connection::OutboundCredit>),
}

fn retry_deferred_request<S>(
    peer: &mut Peer<S>,
    lease: &crate::PeerLease,
    keepalive: &mut Keepalive,
    parked_since: &mut Option<Instant>,
    getaddr_answerable: bool,
    now: Instant,
) -> DeferredStep {
    let Some(message) = peer.deferred_inbound.take() else {
        return DeferredStep::NoneHeld;
    };
    let since = *parked_since.get_or_insert(now);
    let budget = lease.budget_handle();
    if parked_tail_expired(keepalive.excluding_stall(since, now), now) || budget.writer_dead() {
        return DeferredStep::Ended;
    }
    let Some(bound) = reply_bound(&message, getaddr_answerable) else {
        *parked_since = None;
        return DeferredStep::Ready(message, None);
    };
    let bulk = reserves_production(&message);
    let reservation = if bulk {
        lease.try_reserve_production()
    } else {
        lease.try_reserve_reply(bound)
    };
    let may_reserve = || {
        if bulk {
            budget.may_reserve_production()
        } else {
            budget.may_charge(bound)
        }
    };
    match reservation {
        Ok(credit) => {
            *parked_since = None;
            DeferredStep::Ready(message, Some(credit))
        }
        Err(crate::connection::Refusal::Local) => {
            if defers_on_local(&message) && !budget.writer_dead() {
                peer.deferred_inbound = Some(message);
                budget.wait_for(BUDGET_DRAIN_TIMEOUT, may_reserve);
                DeferredStep::Waiting
            } else {
                lease.cancel();
                DeferredStep::Ended
            }
        }
        Err(refusal) => {
            keepalive.note_refusal(refusal);
            peer.deferred_inbound = Some(message);
            budget.wait_for(BUDGET_DRAIN_TIMEOUT, may_reserve);
            DeferredStep::Waiting
        }
    }
}

pub fn run_message_loop<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    peer_addr: impl Into<crate::PeerRemote>,
    lease: &crate::PeerLease,
    shared: &ConnectionShared,
    ibd: Option<&(Arc<dyn IbdState>, Network)>,
) -> Result<(), crate::wire::PeerError> {
    use crate::peer::PeerState;
    use std::time::Instant;
    let peer_addr = peer_addr.into();
    let endpoint = peer_addr.endpoint();

    let tx_relay_open =
        || ibd.is_none_or(|(latch, network)| !latch.is_ibd(unix_time_secs(), *network));

    let mut keepalive = Keepalive::starting_message_loop(Instant::now(), lease.last_send());
    #[cfg(test)]
    if let Some((ping_interval, timeout_interval)) = shared.test_keepalive_intervals.get() {
        keepalive.ping_interval = *ping_interval;
        keepalive.timeout_interval = *timeout_interval;
    }
    let budget = lease.budget_handle();
    let mut parked_since: Option<Instant> = None;
    let mut compact_reconstruction = crate::compact_blocks::Reconstruction::new();
    let mut address_budget = 32_u64;
    let mut last_address_refill = crate::addrman::now();
    let mut staletip_budget = 10_u32;
    let mut last_staletip_refill = Instant::now();
    let mut answered_getaddr = false;
    let mut getaddr_owed = !lease.is_inbound()
        && lease.role().relays_transactions()
        && shared
            .address_book
            .as_ref()
            .is_some_and(|book| book.len() < 1024);
    loop {
        if peer.state == PeerState::Disconnecting {
            return Ok(());
        }

        if lease.is_cancelled() {
            tracing::debug!(peer_addr = %peer_addr, "p2p peer lease revoked; closing");
            return Ok(());
        }

        keepalive.observe_send(lease.last_send());
        let paused =
            peer.has_parked_getdata() || parked_since.is_some() || peer.deferred_inbound.is_some();
        let action = if paused {
            keepalive.next_action_while_parked(Instant::now())
        } else {
            keepalive.next_action(Instant::now())
        };
        match action {
            KeepaliveAction::Idle => {}
            KeepaliveAction::Ping => {
                // The probe rides the bounded control lane so it stays prompt
                // without ever displacing a pending data response. The
                // budget owns the refusal classification: aggregate
                // (`Shared`) backpressure is a keepalive stall, while a full
                // lane or a dead writer is connection-local congestion that
                // defers the probe — it stays owed — without pausing the
                // silence clock.
                let probe = crate::Message::Ping(generate_nonce(peer_addr));
                let Ok(wire_len) = crate::wire::wire_len(&probe) else {
                    lease.cancel();
                    return Err(closed_queue());
                };
                match budget.try_charge_control(wire_len) {
                    Ok(credit) => {
                        lease
                            .send_with(credit, probe)
                            .map(|()| keepalive.record_probe(Instant::now()))
                            .map_err(|_| closed_queue())?;
                    }
                    Err(refusal @ crate::connection::Refusal::Shared) => {
                        keepalive.note_refusal(refusal);
                    }
                    Err(crate::connection::Refusal::Local) => {}
                }
            }
            KeepaliveAction::Expired => {
                tracing::debug!(
                    peer_addr = %peer_addr,
                    "p2p peer silent past the timeout interval; closing",
                );
                return Ok(());
            }
        }

        if getaddr_owed {
            match lease.send(crate::Message::GetAddr) {
                Err(crate::OutboundRefusal::Saturated(_)) => {}
                Ok(()) | Err(crate::OutboundRefusal::Closed(_)) => getaddr_owed = false,
            }
        }

        compact_reconstruction.prune(Instant::now());
        if compact_reconstruction.pending_len() == 0 {
            compact_reconstruction.memory_credit = None;
        }

        if let Some(chain) = shared.chain_query.as_deref()
            && let Some(mut parked) = peer.pending_filter_request.take()
        {
            if parked.charge(Instant::now()) {
                return Err(crate::wire::PeerError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "compact filter index publication timed out",
                )));
            }
            let sink = ProductionSink::new(lease, None);
            let serving = chain.serve_compact_filters(
                &parked.pending,
                &|| sink.headroom(),
                &mut |response| sink.send(response),
            )?;
            parked.last = crate::peer::FilterHalt::from_refusal(sink.refusal());
            if let crate::FilterServing::Pending(remainder) = serving {
                parked.pending = remainder;
                peer.pending_filter_request = Some(parked);
            }
        }

        let mut resumed = None;
        let step = match retry_deferred_request(
            peer,
            lease,
            &mut keepalive,
            &mut parked_since,
            getaddr_answerable(lease, shared, answered_getaddr),
            Instant::now(),
        ) {
            DeferredStep::NoneHeld => step_parked_getdata(
                peer,
                shared,
                lease,
                lease.source(endpoint),
                &mut keepalive,
                &mut parked_since,
            )?,
            DeferredStep::Waiting => ParkedStep::StillParked,
            DeferredStep::Ended => ParkedStep::Ended,
            DeferredStep::Ready(message, reply) => {
                resumed = Some((message, reply));
                ParkedStep::NotParked
            }
        };
        keepalive.settle_pass(Instant::now(), &mut parked_since);
        match step {
            ParkedStep::NotParked => {}
            ParkedStep::StillParked => continue,
            ParkedStep::Ended => {
                tracing::debug!(
                    peer_addr = %peer_addr,
                    "p2p parked request cannot be served; closing"
                );
                return Ok(());
            }
        }

        let (memory_credit, message, _raw, reply) = if let Some((message, reply)) = resumed {
            (None, message, bytes::Bytes::new(), reply)
        } else {
            let read_result = peer.read_message_bounded(&shared.block_memory, || {
                lease.is_cancelled() || shared.is_session_cancelled()
            });
            if shared.is_session_cancelled() {
                tracing::debug!(
                    peer_addr = %peer_addr,
                    "p2p session cancelled during read; closing"
                );
                return Ok(());
            }
            if lease.is_cancelled() {
                tracing::debug!(
                    peer_addr = %peer_addr,
                    "p2p peer lease revoked during read; closing"
                );
                return Ok(());
            }
            match read_result {
                Ok(None) => continue,
                Ok(Some(received)) => {
                    let (memory_credit, message, raw) = {
                        let (message, raw, memory_credit) = received;
                        (memory_credit, message, raw)
                    };
                    keepalive.record_recv(Instant::now());
                    let Some(message) = enforce_relay_role(lease.role(), message)? else {
                        continue;
                    };
                    let bound = reply_bound(
                        &message,
                        getaddr_answerable(lease, shared, answered_getaddr),
                    );
                    let reply = match bound.map(|bound| {
                        if reserves_production(&message) {
                            lease.try_reserve_production()
                        } else {
                            lease.try_reserve_reply(bound)
                        }
                    }) {
                        None => None,
                        Some(Ok(credit)) => Some(credit),
                        Some(Err(crate::connection::Refusal::Local)) => {
                            if defers_on_local(&message) && !budget.writer_dead() {
                                peer.deferred_inbound = Some(message);
                                parked_since.get_or_insert_with(Instant::now);
                                keepalive.settle_pass(Instant::now(), &mut parked_since);
                                continue;
                            }
                            lease.cancel();
                            return Err(closed_queue());
                        }
                        Some(Err(refusal)) => {
                            keepalive.note_refusal(refusal);
                            peer.deferred_inbound = Some(message);
                            parked_since.get_or_insert_with(Instant::now);
                            keepalive.settle_pass(Instant::now(), &mut parked_since);
                            continue;
                        }
                    };
                    (memory_credit, message, raw, reply)
                }
                Err(crate::wire::PeerError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) if lease.ignores_protocol_error(&error) => {
                    shared.note_misbehavior(peer_addr, lease, &error);
                    continue;
                }
                Err(error) => return Err(error),
            }
        };

        tracing::trace!(
            peer_addr = %peer_addr,
            command = ?std::mem::discriminant(&message),
            "p2p message received",
        );
        if let crate::Message::Inv(items) = &message {
            if let Some(tp) = &shared.tx_policy {
                tp.note_transaction_inventory(lease.source(peer_addr.endpoint()), items.as_slice());
            }
        }
        let sink = ProductionSink::new(lease, reply);
        let dispatched = crate::dispatch::dispatch_inbound_full(
            peer,
            &message,
            shared.chain_query.as_deref(),
            shared.tx_inventory.as_deref(),
            shared
                .tx_policy
                .as_ref()
                .and_then(|policy| policy.transaction_serving_sequence(lease.source(endpoint))),
            &tx_relay_open,
            &|| sink.headroom(),
            &mut |response| sink.send(response),
            &mut |hash| shared.announce_block(lease.source(peer_addr.endpoint()), hash),
            &mut |items| {
                if let Some(tp) = &shared.tx_policy {
                    tp.announce_transactions(lease.source(peer_addr.endpoint()), &items);
                }
            },
        );
        if let Err(error) = dispatched {
            if lease.ignores_protocol_error(&error) {
                shared.note_misbehavior(peer_addr, lease, &error);
                continue;
            }
            return Err(error);
        }
        if let Some(request) = peer.take_package_request() {
            if tx_relay_open() {
                if let Some(tp) = &shared.tx_policy {
                    tp.request_package_transactions(
                        lease.source(peer_addr.endpoint()),
                        request.subject,
                        request.wtxids,
                    );
                }
            } else if let Some(inventory) = shared.tx_inventory.as_deref() {
                if let Some(tp) = &shared.tx_policy {
                    tp.release_package_info(
                        lease.source(peer_addr.endpoint()),
                        request.subject,
                        inventory,
                    );
                }
            }
        } else if let crate::Message::AncPkgInfo(info) = &message
            && let (Some(subject), Some(inventory)) =
                (info.subject(), shared.tx_inventory.as_deref())
        {
            if let Some(tp) = &shared.tx_policy {
                tp.release_package_info(lease.source(peer_addr.endpoint()), subject, inventory);
            }
        }
        if matches!(
            message,
            crate::Message::GetCFilters(_)
                | crate::Message::GetCFHeaders(_)
                | crate::Message::GetCFCheckpt(_)
        ) && let Some(parked) = peer.pending_filter_request.as_mut()
        {
            parked.last = crate::peer::FilterHalt::from_refusal(sink.refusal());
        }
        if matches!(message, crate::Message::GetData(_))
            && !budget.may_charge(crate::wire::HEADER_LEN)
        {
            parked_since.get_or_insert_with(Instant::now);
        }
        match &message {
            crate::Message::FeeFilter(rate) => {
                record_fee_filter(
                    &shared.peer_table,
                    shared.tx_policy.as_ref(),
                    lease.source(peer_addr.endpoint()),
                    *rate,
                );
            }
            crate::Message::Tx(tx) => {
                use bitcoin::hashes::Hash as _;
                if let Some(tp) = &shared.tx_policy {
                    tp.note_transaction_inventory(
                        lease.source(peer_addr.endpoint()),
                        &[
                            bitcoin::p2p::message_blockdata::Inventory::Transaction(
                                bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()),
                            ),
                            bitcoin::p2p::message_blockdata::Inventory::WTx(
                                bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes()),
                            ),
                        ],
                    );
                }
            }
            _ => {}
        }
        if tx_relay_open() {
            shared.update_transaction_requests(lease.source(peer_addr.endpoint()), &message);
        }
        match message {
            crate::Message::Addr(addresses) => {
                let addresses: Vec<_> = addresses
                    .iter()
                    .filter_map(|(seen, addr)| {
                        addr.socket_addr().ok().map(|socket| {
                            (
                                PeerEndpoint::from(socket),
                                addr.services.to_u64(),
                                u64::from(*seen),
                            )
                        })
                    })
                    .collect();
                learn_addresses(
                    shared,
                    lease,
                    peer_addr,
                    &addresses,
                    &mut address_budget,
                    &mut last_address_refill,
                );
            }
            crate::Message::AddrV2(addresses) => {
                let addresses: Vec<_> = addresses
                    .iter()
                    .filter_map(|addr| {
                        let address = match addr.addr {
                            bitcoin::p2p::address::AddrV2::Ipv4(ip) => {
                                crate::PeerAddress::Ip(ip.into())
                            }
                            bitcoin::p2p::address::AddrV2::Ipv6(ip) => {
                                crate::PeerAddress::Ip(ip.into())
                            }
                            bitcoin::p2p::address::AddrV2::TorV3(key) => {
                                crate::PeerAddress::Onion(key)
                            }
                            bitcoin::p2p::address::AddrV2::I2p(hash) => {
                                crate::PeerAddress::I2p(hash)
                            }
                            _ => return None,
                        };
                        Some((
                            PeerEndpoint::new(address, addr.port),
                            addr.services.to_u64(),
                            u64::from(addr.time),
                        ))
                    })
                    .collect();
                learn_addresses(
                    shared,
                    lease,
                    peer_addr,
                    &addresses,
                    &mut address_budget,
                    &mut last_address_refill,
                );
            }
            crate::Message::GetAddr
                if lease.is_inbound()
                    && !answered_getaddr
                    && lease.role().relays_transactions() =>
            {
                answered_getaddr = true;
                if let Some(book) = &shared.address_book {
                    let reply = if peer.capabilities.addr_v2 {
                        crate::Message::AddrV2(book.gossip_addrv2(crate::addrman::now()))
                    } else {
                        crate::Message::Addr(addr_v1_rows(&book.gossip(crate::addrman::now())))
                    };
                    let _ = sink.send(reply);
                }
            }
            crate::Message::Headers(headers) => {
                shared.send_headers_response(lease, lease.source(peer_addr.endpoint()), headers);
            }
            crate::Message::NotFound(items) => {
                shared.block_not_found(lease.source(peer_addr.endpoint()), &items);
            }
            crate::Message::StaleTip(announcement) => {
                let negotiated = peer.remote_feature(crate::feature::BIP332_ID).is_some();
                let ibd_active =
                    ibd.is_some_and(|(latch, network)| latch.is_ibd(unix_time_secs(), *network));
                if shared.relay_offers.stale_tip_relay && negotiated && !ibd_active {
                    let now = Instant::now();
                    let elapsed = now.saturating_duration_since(last_staletip_refill);
                    let refill = u32::try_from(elapsed.as_secs() / 10).unwrap_or(u32::MAX);
                    if refill > 0 {
                        staletip_budget = staletip_budget.saturating_add(refill).min(10);
                        last_staletip_refill = now;
                    }
                    if staletip_budget > 0 {
                        staletip_budget -= 1;
                        let headers = announcement.reconstruct();
                        if let Some(tip_header) = headers.last() {
                            let tip_hash = bitcoin_rs_consensus::primitives::Hash256::from(
                                tip_header.compute_hash(),
                            );
                            let source = lease.source(peer_addr.endpoint());
                            if let Some(sync) = &shared.block_sync {
                                sync.note_stale_tip_heard(source, tip_hash);
                            }
                            shared.send_embedded_headers(lease, source, headers);
                        }
                    }
                }
            }
            crate::Message::Block(payload) => {
                shared.send_block(lease, peer_addr, payload, memory_credit);
            }
            crate::Message::Tx(tx) => {
                if tx_relay_open() {
                    if let Some(ingress) = &shared.tx_ingress {
                        ingress.on_inbound_tx(
                            lease.source(peer_addr.endpoint()),
                            tx,
                            memory_credit,
                        );
                    }
                } else {
                    tracing::debug!(peer_addr = %peer_addr, "tx dropped: initial block download");
                }
            }
            crate::Message::PkgTxnsPayload(payload) => {
                if peer.package_relay_versions() & crate::packages::PKG_RELAY_PKGTXNS == 0 {
                    return Err(crate::wire::PeerError::Protocol(
                        "pkgtxns without negotiated package relay",
                    ));
                }
                if tx_relay_open()
                    && let Some(ingress) = &shared.tx_ingress
                    && let Err(error) =
                        ingress.on_inbound_package(lease.source(peer_addr.endpoint()), payload)
                {
                    if lease.ignores_protocol_error(&error) {
                        shared.note_misbehavior(peer_addr, lease, &error);
                        continue;
                    }
                    return Err(error);
                }
            }
            crate::Message::SendHeaders => {
                shared.peer_table.note_send_headers(lease.source(endpoint));
            }
            crate::Message::SendCmpct(send_cmpct)
                if peer
                    .compact_blocks
                    .remote_preference()
                    .is_some_and(|preference| preference.version == send_cmpct.version) =>
            {
                shared.peer_table.note_compact_relay(lease.source(endpoint));
                shared.peer_table.note_compact_announcement(
                    lease.source(peer_addr.endpoint()),
                    &peer.compact_blocks,
                );
                if let Some(announcer) = &shared.block_announcer {
                    announcer.reconcile_high_bandwidth_peers();
                }
            }
            crate::Message::CmpctBlock(_) | crate::Message::BlockTxn(_) => {
                process_compact_wire_message(
                    &message,
                    &mut compact_reconstruction,
                    peer.compact_blocks.local_version(),
                    shared.compact_hints.as_deref(),
                    &sink,
                    peer_addr,
                    shared,
                );
            }
            _ => {}
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ParkedStep {
    NotParked,
    StillParked,
    Ended,
}

fn step_parked_getdata<S>(
    peer: &mut Peer<S>,
    shared: &ConnectionShared,
    lease: &crate::PeerLease,
    source: crate::PeerSource,
    keepalive: &mut Keepalive,
    parked_since: &mut Option<Instant>,
) -> Result<ParkedStep, crate::wire::PeerError> {
    let parked = peer.has_parked_getdata();
    if !parked && parked_since.is_none() {
        return Ok(ParkedStep::NotParked);
    }
    let now = Instant::now();
    let since = *parked_since.get_or_insert(now);
    let budget = lease.budget_handle();
    if parked_tail_expired(keepalive.excluding_stall(since, now), now) || budget.writer_dead() {
        return Ok(ParkedStep::Ended);
    }
    if !parked {
        return match budget.try_charge(crate::wire::HEADER_LEN) {
            Ok(probe) => {
                drop(probe);
                *parked_since = None;
                Ok(ParkedStep::NotParked)
            }
            Err(refusal) => {
                keepalive.note_refusal(refusal);
                budget.wait_for(BUDGET_DRAIN_TIMEOUT, || {
                    budget.may_charge(crate::wire::HEADER_LEN)
                });
                Ok(ParkedStep::StillParked)
            }
        };
    }
    match advance_parked_getdata(peer, shared, lease, source, keepalive, &budget) {
        Err(_) if lease.is_cancelled() => Ok(ParkedStep::Ended),
        advanced => advanced.map(|()| ParkedStep::StillParked),
    }
}

fn advance_parked_getdata<S>(
    peer: &mut Peer<S>,
    shared: &ConnectionShared,
    lease: &crate::PeerLease,
    source: crate::PeerSource,
    keepalive: &mut Keepalive,
    budget: &Arc<crate::connection::OutboundBudget>,
) -> Result<(), crate::wire::PeerError> {
    if !report_parked_misses(peer, lease, keepalive, budget)? {
        return Ok(());
    }
    resume_parked_getdata(peer, shared, lease, source, keepalive, budget)
}

fn notfound_wire_bound(items: usize) -> usize {
    let count = u64::try_from(items).unwrap_or(u64::MAX);
    crate::wire::HEADER_LEN
        + bitcoin_rs_consensus::primitives::varint::encode(count).len()
        + 36 * items
}

fn report_parked_misses<S>(
    peer: &mut Peer<S>,
    lease: &crate::PeerLease,
    keepalive: &mut Keepalive,
    budget: &Arc<crate::connection::OutboundBudget>,
) -> Result<bool, crate::wire::PeerError> {
    if peer.pending_notfound.is_empty() {
        return Ok(true);
    }
    let bound = notfound_wire_bound(peer.pending_notfound.len());
    let credit = match lease.try_reserve_reply(bound) {
        Ok(credit) => credit,
        Err(refusal) => {
            keepalive.note_refusal(refusal);
            budget.wait_for(BUDGET_DRAIN_TIMEOUT, || budget.may_charge(bound));
            return Ok(false);
        }
    };
    let misses = std::mem::take(&mut peer.pending_notfound);
    lease
        .send_with(credit, crate::Message::NotFound(misses))
        .map_err(|_| closed_queue())?;
    Ok(true)
}

fn parked_tail_expired(since: Instant, now: Instant) -> bool {
    now.saturating_duration_since(since) > TIMEOUT_INTERVAL
}

fn resume_parked_getdata<S>(
    peer: &mut Peer<S>,
    shared: &ConnectionShared,
    lease: &crate::PeerLease,
    source: crate::PeerSource,
    keepalive: &mut Keepalive,
    budget: &Arc<crate::connection::OutboundBudget>,
) -> Result<(), crate::wire::PeerError> {
    let sink = ProductionSink::new(lease, None);
    let mut send = |response: crate::Message| sink.send(response);
    let compact_version = peer.compact_blocks.servable_version();
    let mut not_found = Vec::new();
    let tail = crate::dispatch::serve_getdata(
        shared.chain_query.as_deref(),
        shared.tx_inventory.as_deref(),
        shared
            .tx_policy
            .as_ref()
            .and_then(|policy| policy.transaction_serving_sequence(source)),
        compact_version,
        &peer.pending_getdata,
        &mut not_found,
        &|| sink.headroom(),
        &mut send,
    )?;
    peer.pending_getdata = tail;
    peer.pending_notfound = not_found;
    if let Some(refusal) = sink.refusal() {
        keepalive.note_refusal(refusal);
        budget.wait_for(BUDGET_DRAIN_TIMEOUT, || budget.may_reserve_production());
    }
    Ok(())
}

fn addr_v1_rows(
    rows: &[bitcoin::p2p::address::AddrV2Message],
) -> Vec<(u32, bitcoin::p2p::address::Address)> {
    rows.iter()
        .filter_map(|row| {
            let ip: std::net::IpAddr = match row.addr {
                bitcoin::p2p::address::AddrV2::Ipv4(ip) => ip.into(),
                bitcoin::p2p::address::AddrV2::Ipv6(ip) => ip.into(),
                _ => return None,
            };
            Some((
                row.time,
                bitcoin::p2p::address::Address::new(
                    &std::net::SocketAddr::new(ip, row.port),
                    row.services,
                ),
            ))
        })
        .collect()
}
fn learn_addresses(
    shared: &ConnectionShared,
    lease: &crate::PeerLease,
    peer_addr: impl Into<crate::PeerRemote>,
    addresses: &[(PeerEndpoint, u64, u64)],
    budget: &mut u64,
    last_refill: &mut u64,
) {
    let peer_addr = peer_addr.into();
    if !lease.role().relays_transactions() {
        return;
    }
    let now = crate::addrman::now();
    let refill = now.saturating_sub(*last_refill) / 10;
    *budget = budget.saturating_add(refill).min(32);
    *last_refill = last_refill.saturating_add(refill.saturating_mul(10));
    let count = addresses.len().min(usize::try_from(*budget).unwrap_or(0));
    *budget = budget.saturating_sub(u64::try_from(count).unwrap_or(0));
    if let Some(book) = &shared.address_book {
        book.learn_peer(peer_addr, &addresses[..count], now);
    }
}

fn reserve_compact_materialization(
    reconstruction: &mut crate::compact_blocks::Reconstruction,
    message: &crate::Message,
    shared: &ConnectionShared,
    lease: &crate::PeerLease,
) -> Result<crate::inbound::block_memory::BlockMemoryCredit, crate::wire::PeerError> {
    reconstruction.prune(Instant::now());
    if reconstruction.pending_len() == 0 {
        reconstruction.memory_credit = None;
    }
    if shared.is_session_cancelled() || lease.is_cancelled() {
        return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
    }
    if reconstruction.memory_credit.is_none() {
        reconstruction.memory_credit = Some(
            shared
                .block_memory
                .try_reserve(crate::compact_blocks::MAX_PENDING_RETAINED_BYTES)?,
        );
    }
    let incoming_bytes = match message {
        crate::Message::CmpctBlock(compact) => compact
            .compact_block
            .prefilled_txs
            .iter()
            .map(|entry| entry.tx.total_size())
            .sum::<usize>(),
        crate::Message::BlockTxn(txns) => txns
            .transactions
            .transactions
            .iter()
            .map(bitcoin::Transaction::total_size)
            .sum::<usize>(),
        _ => 0,
    };
    let peak_bytes = bitcoin_rs_consensus::primitives::layout::decode_reservation(
        crate::compact_blocks::MAX_PENDING_RETAINED_BYTES.saturating_add(incoming_bytes),
    );
    let credit = shared.block_memory.try_reserve(peak_bytes);
    if credit.is_err() && reconstruction.pending_len() == 0 {
        reconstruction.memory_credit = None;
    }
    credit
}

/// The caller retains the source decoder credit until its message and raw bytes are disposed.
/// A completed image receives a separate credit that follows the forwarded image.
pub fn process_compact_wire_message(
    message: &crate::Message,
    compact_reconstruction: &mut crate::compact_blocks::Reconstruction,
    local_compact_version: Option<u64>,
    compact_hints: Option<&dyn crate::compact_blocks::CompactBlockHints>,
    sink: &ProductionSink<'_>,
    peer_addr: impl Into<crate::PeerRemote>,
    shared: &ConnectionShared,
) {
    let peer_addr = peer_addr.into();
    let lease = sink.lease;
    if let crate::Message::CmpctBlock(cmpct) = message
        && let Some(header) = crate::compact_blocks::native_header(&cmpct.compact_block.header)
        && !shared.block_sync.as_ref().is_some_and(|sync| {
            sync.compact_reconstruction_admissible(lease.source(peer_addr.endpoint()), &header)
        })
    {
        tracing::debug!(
            peer_addr = %peer_addr,
            hash = %header.compute_hash(),
            "p2p compact block header does not earn reconstruction"
        );
        shared.send_embedded_headers(lease, lease.source(peer_addr.endpoint()), vec![header]);
        return;
    }

    let mut materialization = match reserve_compact_materialization(
        compact_reconstruction,
        message,
        shared,
        lease,
    ) {
        Ok(credit) => credit,
        Err(error) => {
            tracing::debug!(peer_addr = %peer_addr, %error, "compact reconstruction admission refused");
            if let crate::Message::CmpctBlock(cmpct) = message
                && let Some(header) =
                    crate::compact_blocks::native_header(&cmpct.compact_block.header)
            {
                shared.send_embedded_headers(
                    lease,
                    lease.source(peer_addr.endpoint()),
                    vec![header],
                );
            }
            return;
        }
    };
    let identity_version = local_compact_version.unwrap_or(crate::peer::COMPACT_BLOCK_VERSION);
    let outcome = process_compact_message(
        compact_reconstruction,
        message,
        identity_version,
        compact_hints,
        Instant::now(),
    );
    if compact_reconstruction.pending_len() == 0 {
        compact_reconstruction.memory_credit = None;
    }
    let produced_credit = if let crate::compact_blocks::Outcome::Complete(image) = &outcome {
        if let Err(error) = materialization.retain(
            image
                .bytes()
                .len()
                .saturating_add(image.retained_heap_bytes()),
        ) {
            tracing::error!(peer_addr = %peer_addr, %error, "compact reconstruction exceeded ingress reservation");
            return;
        }
        Some(materialization)
    } else {
        None
    };
    let announced_header = if let crate::Message::CmpctBlock(cmpct) = message
        && !matches!(outcome, crate::compact_blocks::Outcome::Complete(_))
    {
        crate::compact_blocks::native_header(&cmpct.compact_block.header)
    } else {
        None
    };
    let source = lease.source(peer_addr.endpoint());
    if let Some((hash, follow_up)) =
        handle_compact_outcome(outcome, sink, peer_addr, shared, produced_credit)
        && let Some(sync) = shared.block_sync.as_ref()
    {
        sync.enqueue_owned_body_fetch(source, hash, &mut || sink.send(follow_up.clone()).is_ok());
    }
    if let Some(header) = announced_header {
        shared.send_embedded_headers(lease, source, vec![header]);
    }
}

fn handle_compact_outcome(
    outcome: crate::compact_blocks::Outcome,
    sink: &ProductionSink<'_>,
    peer_addr: impl Into<crate::PeerRemote>,
    shared: &ConnectionShared,
    memory_credit: Option<crate::inbound::block_memory::BlockMemoryCredit>,
) -> Option<(bitcoin_rs_consensus::primitives::Hash256, crate::Message)> {
    let peer_addr = peer_addr.into();
    let lease = sink.lease;
    match outcome {
        crate::compact_blocks::Outcome::Complete(image) => {
            tracing::info!(peer_addr = %peer_addr, hash = %image.block_hash(), "p2p compact block reconstructed");
            shared.send_block(lease, peer_addr, image, memory_credit);
            None
        }
        crate::compact_blocks::Outcome::RequestMissing(request) => {
            tracing::info!(peer_addr = %peer_addr, "p2p compact reconstruction missing");
            let hash = bitcoin_rs_consensus::primitives::Hash256::from(
                crate::inv::native_block_hash(request.txs_request.block_hash),
            );
            Some((hash, crate::Message::GetBlockTxn(request)))
        }
        crate::compact_blocks::Outcome::Fallback(hash) => {
            tracing::info!(peer_addr = %peer_addr, "p2p compact reconstruction fallback");
            Some((
                bitcoin_rs_consensus::primitives::Hash256::from(hash),
                crate::Message::GetData(vec![
                    bitcoin::p2p::message_blockdata::Inventory::WitnessBlock(
                        bitcoin::BlockHash::from_byte_array(*hash.as_bytes()),
                    ),
                ]),
            ))
        }
        crate::compact_blocks::Outcome::Idle => None,
    }
}

fn process_compact_message(
    reconstruction: &mut crate::compact_blocks::Reconstruction,
    message: &crate::Message,
    identity_version: u64,
    compact_hints: Option<&dyn crate::compact_blocks::CompactBlockHints>,
    now: std::time::Instant,
) -> crate::compact_blocks::Outcome {
    match message {
        crate::Message::CmpctBlock(cmpct) => match compact_hints {
            Some(hints) => reconstruction.receive_cmpctblock(cmpct, identity_version, hints, now),
            None => crate::compact_blocks::Outcome::Fallback(crate::inv::native_block_hash(
                cmpct.compact_block.header.block_hash(),
            )),
        },
        crate::Message::BlockTxn(txns) => reconstruction.receive_blocktxn(txns, now),
        _ => crate::compact_blocks::Outcome::Idle,
    }
}

fn spawn_connection_writer(
    mut stream: crate::CountingStream<TcpStream>,
    mut transport: crate::transport::SendTransport,
    outbound_rx: crossbeam_channel::Receiver<crate::QueuedFrame>,
    close_rx: crossbeam_channel::Receiver<()>,
    budget: Arc<crate::connection::OutboundBudget>,
    peer_addr: impl Into<crate::PeerRemote>,
    net_trace: Option<crate::net_trace::NetTrace>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let peer_addr = peer_addr.into();
    let counters = std::sync::Arc::clone(stream.counters());
    std::thread::Builder::new()
        .name(format!("bitcoin-rs-p2p-writer-{peer_addr}"))
        .spawn(move || {
            let _exit = WriterExit {
                budget: Arc::clone(&budget),
                outbound_rx: &outbound_rx,
            };
            run_writer_loop(
                &outbound_rx,
                close_rx,
                &mut stream,
                &mut transport,
                &counters,
                net_trace.as_ref(),
            );
            let _ = stream.shutdown(std::net::Shutdown::Both);
        })
}

struct WriterExit<'a> {
    budget: Arc<crate::connection::OutboundBudget>,
    outbound_rx: &'a crossbeam_channel::Receiver<crate::QueuedFrame>,
}

impl Drop for WriterExit<'_> {
    fn drop(&mut self) {
        self.budget.mark_writer_dead();
        while self.outbound_rx.try_recv().is_ok() {}
    }
}

fn collect_write_burst(
    first: crate::QueuedFrame,
    outbound_rx: &crossbeam_channel::Receiver<crate::QueuedFrame>,
) -> (Vec<crate::QueuedFrame>, Option<crate::QueuedFrame>) {
    if first.message().is_bulk_payload() {
        return (vec![first], None);
    }
    let mut burst = Vec::with_capacity(crate::wire::MAX_WRITE_BURST);
    burst.push(first);
    while burst.len() < crate::wire::MAX_WRITE_BURST {
        match outbound_rx.try_recv() {
            Ok(next) if next.message().is_bulk_payload() => return (burst, Some(next)),
            Ok(next) => burst.push(next),
            Err(_) => break,
        }
    }
    (burst, None)
}

fn write_ready_burst(
    first: crate::QueuedFrame,
    outbound_rx: &crossbeam_channel::Receiver<crate::QueuedFrame>,
    writer: &mut dyn std::io::Write,
    transport: &mut crate::transport::SendTransport,
    counters: &crate::PeerCounters,
    net_trace: Option<&crate::net_trace::NetTrace>,
) -> bool {
    let mut pending = Some(first);
    while let Some(head) = pending.take() {
        let (burst, leftover) = collect_write_burst(head, outbound_rx);
        let encoded: Result<Vec<_>, _> = burst
            .iter()
            .map(|queued| transport.encode(queued.message()))
            .collect();
        let frames = match encoded {
            Ok(frames) => frames,
            Err(error) => {
                tracing::debug!(%error, "p2p writer thread exiting");
                return false;
            }
        };
        for (queued, frame) in burst.iter().zip(&frames) {
            crate::net_trace::outbound_message(net_trace, queued.message(), frame.payload());
        }
        // Each frame is charged to its command once the writer accepts its
        // final byte, Core's flush semantics. A write error still tears the
        // connection down, but the frames the socket already accepted in
        // full keep their charges, so the per-message buckets track the
        // socket counter's accepted bytes; a frame the error cut short is
        // never charged.
        let written = crate::wire::write_frames(writer, &frames, &mut |index: usize| {
            let command = burst[index].message().command();
            counters.record_msg_sent(command.as_ref(), frames[index].wire_len());
        });
        drop(burst);
        match written {
            Ok(()) => pending = leftover,
            Err(error) => {
                tracing::debug!(%error, "p2p writer thread exiting");
                return false;
            }
        }
    }
    true
}

fn run_writer_loop(
    outbound_rx: &crossbeam_channel::Receiver<crate::QueuedFrame>,
    mut close_rx: crossbeam_channel::Receiver<()>,
    writer: &mut dyn std::io::Write,
    transport: &mut crate::transport::SendTransport,
    counters: &crate::PeerCounters,
    net_trace: Option<&crate::net_trace::NetTrace>,
) {
    loop {
        crossbeam_channel::select! {
            recv(outbound_rx) -> message => {
                let Ok(first) = message else { break };
                if !write_ready_burst(first, outbound_rx, writer, transport, counters, net_trace) {
                    break;
                }
            }
            recv(close_rx) -> signal => {
                if signal.is_ok() {
                    break;
                }
                close_rx = crossbeam_channel::never();
            }
        }
    }
}

fn wake_sync(sync_wake_tx: Option<&Sender<()>>) {
    if let Some(tx) = sync_wake_tx {
        let _ = tx.try_send(());
    }
}

fn generate_nonce(peer_addr: impl Into<crate::PeerRemote>) -> u64 {
    use std::hash::{BuildHasher, Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let peer_addr = peer_addr.into();

    let random_state = std::collections::hash_map::RandomState::new();
    let mut hasher = random_state.build_hasher();
    peer_addr.hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
        duration.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(any(test, feature = "test-seam"))]
pub fn test_shared(
    peer_table: Arc<crate::PeerTable>,
    headers_tx: Sender<crate::InboundHeaders>,
    blocks_tx: Sender<crate::InboundBlock>,
) -> ConnectionShared {
    ConnectionShared::new(
        peer_table,
        crate::BannedReader::fixture_empty(),
        Arc::new(crate::NetworkActivity::from_shared(Arc::new(
            AtomicBool::new(true),
        ))),
        bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
        None,
        Magic::BITCOIN,
        headers_tx,
        blocks_tx,
        None,
        None,
        ListenerExtras::default(),
    )
}

#[cfg(test)]
mod transaction_poll_tests {
    use super::*;
    use bitcoin_rs_consensus::primitives::USER_AGENT;
    use std::sync::atomic::AtomicUsize;

    struct InventoryReads(AtomicUsize);
    impl crate::TxInventory for InventoryReads {
        fn have_tx(&self, _: bitcoin_rs_consensus::primitives::Hash256, _: bool) -> bool {
            self.0.fetch_add(1, Ordering::Relaxed);
            false
        }
        fn get_tx(
            &self,
            _: bitcoin_rs_consensus::primitives::Txid,
            _last_inv_sequence: u64,
        ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
            None
        }
        fn get_tx_by_wtxid(
            &self,
            _: bitcoin_rs_consensus::primitives::Wtxid,
            _last_inv_sequence: u64,
        ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
            None
        }
        fn resident_ancestor_package(
            &self,
            _: bitcoin_rs_consensus::primitives::Wtxid,
            _last_inv_sequence: u64,
        ) -> Option<Vec<bitcoin_rs_consensus::primitives::Wtxid>> {
            None
        }
        fn resident_package(
            &self,
            _: &[bitcoin_rs_consensus::primitives::Wtxid],
        ) -> Option<Vec<Arc<bitcoin_rs_consensus::primitives::Tx>>> {
            None
        }

        fn package_for_relay(
            &self,
            wtxids: &[bitcoin_rs_consensus::primitives::Wtxid],
            _last_inv_sequence: u64,
        ) -> Option<Vec<Arc<bitcoin_rs_consensus::primitives::Tx>>> {
            self.resident_package(wtxids)
        }
    }
    #[derive(Default)]
    pub(super) struct MockTxPolicy {
        polls: AtomicUsize,
        serving_sequence: Option<u64>,
        pub(super) serving_reads: AtomicUsize,
    }
    impl MockTxPolicy {
        pub(super) fn with_serving_sequence(sequence: u64) -> Self {
            Self {
                polls: AtomicUsize::new(0),
                serving_sequence: Some(sequence),
                serving_reads: AtomicUsize::new(0),
            }
        }
    }

    impl crate::listener::TxPolicyObserver for MockTxPolicy {
        fn transaction_serving_sequence(&self, _: crate::PeerSource) -> Option<u64> {
            self.serving_reads.fetch_add(1, Ordering::Relaxed);
            self.serving_sequence
        }

        fn announce_transactions(
            &self,
            _: crate::PeerSource,
            _: &[bitcoin::p2p::message_blockdata::Inventory],
        ) {
        }
        fn request_parent_transactions(
            &self,
            _: crate::PeerSource,
            _: &[bitcoin::p2p::message_blockdata::Inventory],
        ) -> bool {
            false
        }
        fn transaction_not_found(
            &self,
            _: crate::PeerSource,
            _: &[bitcoin::p2p::message_blockdata::Inventory],
            _: &dyn crate::dispatch::TxInventory,
        ) {
        }
        fn poll_transaction_requests(&self, inventory: &dyn crate::TxInventory) {
            self.polls.fetch_add(1, Ordering::Relaxed);
            let _ = inventory.have_tx(bitcoin_rs_consensus::primitives::Hash256::default(), false);
        }
        fn transaction_peer_disconnected(
            &self,
            _: crate::PeerSource,
            _: &dyn crate::dispatch::TxInventory,
        ) {
        }
        fn note_transaction_inventory(
            &self,
            _: crate::PeerSource,
            _: &[bitcoin::p2p::message_blockdata::Inventory],
        ) {
        }
        fn request_package_transactions(
            &self,
            _: crate::PeerSource,
            _: bitcoin_rs_consensus::primitives::Wtxid,
            _: Vec<bitcoin_rs_consensus::primitives::Wtxid>,
        ) {
        }
        fn release_package_info(
            &self,
            _: crate::PeerSource,
            _: bitcoin_rs_consensus::primitives::Wtxid,
            _: &dyn crate::dispatch::TxInventory,
        ) {
        }
        fn receive_fee_filter(&self, _: crate::PeerSource, _: i64) {}
    }

    #[test]
    fn ping_and_nontransaction_messages_do_not_poll_gateway_inventory() {
        let table = Arc::new(crate::PeerTable::new());
        let (sender, _receiver) = crossbeam_channel::bounded(4);
        let lease = crate::PeerLease::new(sender);
        let addr: PeerEndpoint = ([127, 0, 0, 1], 8333).into();
        table.register(addr, lease.clone());
        let version = crate::handshake::version_message(
            1,
            0,
            crate::PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            USER_AGENT,
        );
        table.publish_info(
            addr,
            &lease,
            crate::PeerInfo::outbound_from_version(
                addr,
                addr.socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
                &version,
                0,
                0,
                Arc::new(crate::PeerCounters::default()),
            ),
        );
        let source = lease.source(Some(addr));
        let item = bitcoin::p2p::message_blockdata::Inventory::WTx(
            bitcoin::Wtxid::from_byte_array([1; 32]),
        );
        let mock_policy = Arc::new(MockTxPolicy::default());
        let (headers, _) = crossbeam_channel::bounded(1);
        let (blocks, _) = crossbeam_channel::bounded(1);
        let mut shared = test_shared(table, headers, blocks);
        let inventory = Arc::new(InventoryReads(AtomicUsize::new(0)));
        shared.tx_inventory = Some(inventory.clone());
        shared.tx_policy = Some(mock_policy.clone());
        for nonce in 0..1_000 {
            shared.update_transaction_requests(source, &crate::Message::Ping(nonce));
            shared.update_transaction_requests(source, &crate::Message::Headers(Vec::new()));
            shared.update_transaction_requests(
                source,
                &crate::Message::Inv(vec![bitcoin::p2p::message_blockdata::Inventory::Block(
                    bitcoin::BlockHash::from_byte_array([2; 32]),
                )]),
            );
        }
        assert_eq!(inventory.0.load(Ordering::Relaxed), 0);
        assert_eq!(mock_policy.polls.load(Ordering::Relaxed), 0);
        shared.update_transaction_requests(source, &crate::Message::Inv(vec![item]));
        assert_eq!(
            mock_policy.polls.load(Ordering::Relaxed),
            1,
            "inv message must poll transaction requests"
        );
        assert_eq!(
            inventory.0.load(Ordering::Relaxed),
            1,
            "polled transaction requests checks inventory"
        );
    }
    #[test]
    fn oversized_fee_filter_leaves_announced_filter_unchanged() {
        let table = Arc::new(crate::PeerTable::new());
        let (sender, _receiver) = crossbeam_channel::bounded(4);
        let lease = crate::PeerLease::new(sender);
        let addr: PeerEndpoint = ([127, 0, 0, 1], 8333).into();
        table.register(addr, lease.clone());
        let source = lease.source(Some(addr));
        record_fee_filter(&table, None, source, 1_000);
        record_fee_filter(&table, None, source, i64::MAX);
        assert_eq!(table.transaction_fee_filter(source), 1_000);
    }
}

#[cfg(test)]
mod outbound_tests {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::Arc;

    use super::{spawn_outbound_connection, spawn_pinned_outbound_connection, test_shared};
    use crate::PeerTable;
    use crate::peer_info::PeerRole;

    #[test]
    fn spawn_outbound_connection_to_closed_port_fails_quickly() -> std::io::Result<()> {
        let listener = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;
        drop(listener);

        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(PeerTable::new()), headers_tx, blocks_tx);

        let handle = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);
        let inner = match handle.join() {
            Ok(inner) => inner,
            Err(error) => std::panic::resume_unwind(error),
        };

        assert!(
            inner.is_err(),
            "expected connection failure to unlistened port"
        );

        Ok(())
    }

    type Dial = fn(
        PeerEndpoint,
        crate::listener::ConnectionShared,
        PeerRole,
    ) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>>;

    #[expect(
        clippy::expect_used,
        reason = "a helper that cannot build its fixture has nothing to report"
    )]
    fn registered_session(dial: Dial) -> crate::peer_table::PeerSession {
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )
        .expect("bind listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().expect("listener address");

        let table = Arc::new(PeerTable::new());
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::clone(&table), headers_tx, blocks_tx);
        let handle = dial(addr.into(), shared, PeerRole::FullRelay);

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut accepted = None;
        let session = loop {
            accepted = accepted.or_else(|| listener.accept().ok().map(|(stream, _)| stream));
            if let Some(session) = table.sessions().into_iter().find(|s| s.addr == addr.into()) {
                break session;
            }
            assert!(Instant::now() < deadline, "the dial never registered");
            std::thread::sleep(Duration::from_millis(5));
        };
        drop(accepted.take());
        let _ = handle.join();
        session
    }

    #[test]
    fn the_dial_origin_survives_to_the_lease() {
        let pinned = registered_session(spawn_pinned_outbound_connection);
        assert!(
            pinned.lease.is_manual(),
            "a dial the operator named must be marked manual"
        );
        assert_eq!(pinned.lease.role(), PeerRole::FullRelay);

        let automatic = registered_session(spawn_outbound_connection);
        assert!(
            !automatic.lease.is_manual(),
            "a dial the seed list produced is not the operator's"
        );
        assert_eq!(automatic.lease.role(), PeerRole::FullRelay);
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod relay_role_tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_blockdata::Inventory;

    use super::enforce_relay_role;
    use crate::peer_info::PeerRole;
    use crate::wire::{Message, PeerError};

    fn tx_inv() -> Message {
        Message::Inv(vec![Inventory::Transaction(
            bitcoin::Txid::from_byte_array([7; 32]),
        )])
    }

    #[test]
    fn relay_role_gate_splits_transaction_and_block_traffic() {
        let error = enforce_relay_role(PeerRole::BlockRelayOnly, tx_inv())
            .expect_err("a transaction announcement is a protocol violation");
        assert!(matches!(
            error,
            PeerError::Protocol("transaction inv sent in violation of protocol")
        ));

        let block_inv = Message::Inv(vec![Inventory::Block(bitcoin::BlockHash::from_byte_array(
            [8; 32],
        ))]);
        let kept = enforce_relay_role(PeerRole::BlockRelayOnly, block_inv)
            .expect("a block announcement is not a fault");
        assert!(kept.is_some(), "block traffic reaches the scheduler");

        let kept = enforce_relay_role(PeerRole::FullRelay, tx_inv())
            .expect("a full-relay connection is unrestricted");
        assert!(kept.is_some(), "transaction traffic is dispatched");

        let dropped = enforce_relay_role(PeerRole::BlockRelayOnly, Message::Addr(Vec::new()))
            .expect("address gossip is not a fault");
        assert!(
            dropped.is_none(),
            "address gossip is dropped unheard on a block-relay connection"
        );
    }
}

#[cfg(test)]
mod sync_wake_tests {
    use super::wake_sync;

    #[test]
    fn sync_wake_is_bounded_and_nonblocking() {
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);

        wake_sync(Some(&wake_tx));
        wake_sync(Some(&wake_tx));

        assert_eq!(wake_rx.try_iter().count(), 1);
    }
}

#[cfg(test)]
static ACCEPT_ERROR_INJECT: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
#[expect(clippy::expect_used)]
mod session_socket_tests {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    use super::{HANDSHAKE_READ_POLL, HANDSHAKE_TIMEOUT, configure_peer_stream};

    #[test]
    fn session_sockets_disable_nagle() {
        let listener = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )
        .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");

        configure_peer_stream(&client).expect("configure client");
        configure_peer_stream(&server).expect("configure server");

        assert!(client.nodelay().expect("client nodelay"));
        assert!(server.nodelay().expect("server nodelay"));
        assert_eq!(
            client.read_timeout().expect("client read timeout"),
            Some(HANDSHAKE_READ_POLL)
        );
        assert_eq!(
            server.write_timeout().expect("server write timeout"),
            Some(HANDSHAKE_TIMEOUT)
        );
    }
}

#[cfg(test)]
static WRITER_SETUP_FAIL: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
#[expect(clippy::expect_used)]
mod resilient_accept_tests {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::net::{Ipv4Addr, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use super::{ACCEPT_ERROR_INJECT, bind_listener, serve, test_shared};

    #[test]
    fn serve_survives_transient_accept_error() {
        let listener = bind_listener(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )
        .expect("bind listener");
        let addr = listener.local_addr().expect("local_addr");

        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);

        ACCEPT_ERROR_INJECT.store(true, Ordering::Relaxed);

        let thread_shutdown = shutdown.reader();
        let handle = std::thread::spawn(move || serve(listener, thread_shutdown, shared));

        std::thread::sleep(Duration::from_millis(300));

        let _client = TcpStream::connect(addr).expect("listener should still accept");

        shutdown.trigger();
        let result = handle.join().expect("listener thread panicked");
        assert!(
            result.is_ok(),
            "serve must return Ok after shutdown, got {result:?}"
        );
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod inbound_admission_tests {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::io::Read;
    use std::net::{Ipv4Addr, TcpStream};
    use std::sync::Arc;
    use std::time::Duration;

    use super::{bind_listener, serve, test_shared};
    use crate::PeerTable;

    #[test]
    fn inbound_admission_over_cap_drops_stream() -> crate::test_support::TestResult {
        let listener = bind_listener(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;
        let peer_table = Arc::new(PeerTable::new());
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let mut shared = test_shared(Arc::clone(&peer_table), headers_tx, blocks_tx);
        shared.max_inbound = 1;

        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let serve_shutdown = shutdown.reader();
        let handle = std::thread::spawn(move || serve(listener, serve_shutdown, shared));

        let _first = TcpStream::connect(addr)?;
        let mut second = TcpStream::connect(addr)?;
        let second_addr = second.local_addr()?;
        second.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut byte = [0u8; 1];
        let read = second.read(&mut byte)?;
        assert_eq!(
            read, 0,
            "the over-capacity socket must be closed by the listener"
        );
        assert_eq!(
            peer_table.live_inbound_count(),
            1,
            "the admitted socket keeps its reservation"
        );
        assert!(
            !peer_table.is_connected(crate::PeerEndpoint::Ip(second_addr)),
            "the refused socket registered no lease"
        );

        shutdown.trigger();
        handle.join().expect("listener thread panicked")?;
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod writer_setup_cleanup_tests {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use bitcoin::p2p::Magic;

    use super::{WRITER_SETUP_FAIL, run_connected_session, test_shared};
    use crate::peer::Peer;

    fn peer_info(addr: PeerEndpoint, conn_time: u64) -> crate::PeerInfo {
        crate::PeerInfo {
            endpoint: Some(addr),
            network: addr.net(),
            addr: addr.into(),
            version: 70_016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 0,
            user_agent: String::from("/test/"),
            start_height: 0,
            best_known_height: 0,
            conn_time,
            inbound: false,
            addr_bind: crate::TransportRemote::new(
                addr.socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            ),
            time_offset: 0,
            counters: Arc::new(crate::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
        }
    }

    #[test]
    fn writer_setup_failure_cleans_up_lease() {
        let listener = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )
        .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client = TcpStream::connect(addr).expect("connect");
        let (server_stream, peer_addr) = listener.accept().expect("accept");
        drop(server_stream);

        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);

        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let lease_probe = lease.clone();
        shared
            .peer_table
            .register(crate::PeerEndpoint::Ip(peer_addr), lease.clone());

        assert!(
            shared
                .peer_table
                .is_connected(crate::PeerEndpoint::Ip(peer_addr)),
            "lease must be registered before writer setup"
        );

        WRITER_SETUP_FAIL.store(true, Ordering::Relaxed);

        let counters = std::sync::Arc::new(crate::PeerCounters::default());
        let stream = crate::CountingStream::new(client, counters);
        let mut peer = Peer::new(stream, Magic::BITCOIN);
        let info = peer_info(peer_addr.into(), 0);
        let result = run_connected_session(&mut peer, peer_addr, &shared, lease, outbound_rx, info);

        assert!(result.is_err(), "writer setup failure must return Err");
        assert!(
            shared.peer_table.is_empty(),
            "peer_table must be cleaned up after writer setup failure"
        );
        assert!(
            lease_probe.is_cancelled(),
            "writer setup failure must cancel the registered lease"
        );
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod writer_shutdown_tests {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::cell::Cell;
    use std::io;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use bitcoin::p2p::Magic;

    use super::{
        collect_write_burst, run_connected_session, run_message_loop, run_writer_loop,
        spawn_connection_writer, test_shared, write_ready_burst,
    };
    use crate::connection::OutboundBudget;
    use crate::peer::{Peer, PeerState};

    const FAILSAFE: Duration = Duration::from_secs(5);

    #[test]
    fn inbound_handshake_failure_on_live_lease_returns_err() {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            headers_tx,
            crossbeam_channel::unbounded().0,
        );
        let (mut client, server, peer_addr) = loopback_pair();

        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33]);
        frame.extend_from_slice(b"version\0\0\0\0\0");
        frame.extend_from_slice(&0_u32.to_le_bytes());
        frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        io::Write::write_all(&mut client, &frame).expect("frame write");
        drop(client);

        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_inbound(outbound_tx);
        let lease = shared
            .peer_table
            .try_register_inbound(peer_addr, lease, &[], 1, 0, &shared.activity)
            .expect("the test lease reserves its inbound slot");
        let result = crate::listener::run_handshake(server, peer_addr, &shared, lease, outbound_rx);
        let Err(error) = result else {
            panic!("handshake failure on a live lease must not be masked as revoked");
        };
        assert!(
            error.to_string().contains("magic"),
            "unexpected handshake error: {error}"
        );
    }

    fn loopback_pair() -> (TcpStream, TcpStream, PeerEndpoint) {
        let listener = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )
        .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, peer_addr) = listener.accept().expect("accept");
        (client, server, peer_addr.into())
    }

    fn ping_len() -> usize {
        crate::wire::wire_len(&crate::Message::Ping(9)).expect("ping encodes")
    }

    #[test]
    fn unbacked_filter_service_bit_is_removed_from_handshake() {
        let mut shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        shared.local_services |= bitcoin::p2p::ServiceFlags::COMPACT_FILTERS;
        assert!(
            !shared
                .advertised_services()
                .has(bitcoin::p2p::ServiceFlags::COMPACT_FILTERS)
        );
    }

    fn peer_info(addr: PeerEndpoint, start_height: i32) -> crate::PeerInfo {
        crate::PeerInfo {
            endpoint: Some(addr),
            network: addr.net(),
            addr: addr.into(),
            version: 70_016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 1,
            user_agent: String::from("/test/"),
            start_height,
            conn_time: 0,
            best_known_height: start_height,
            inbound: false,
            addr_bind: crate::TransportRemote::new(
                addr.socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            ),
            time_offset: 0,
            counters: std::sync::Arc::new(crate::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
        }
    }

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        TryRecv(#[from] crossbeam_channel::TryRecvError),
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Primitives(#[from] bitcoin_rs_consensus::primitives::DecodeError),
    }

    #[test]
    fn sinks_stamp_exact_connection_source() -> Result<(), TestError> {
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_443));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_bytes = bitcoin::consensus::encode::serialize(&genesis);
        let serialized = bytes::Bytes::from(block_bytes);
        let payload = bitcoin_rs_consensus::primitives::BlockImage::from_raw(serialized.clone())?;
        let source = lease.source(Some(addr));

        shared.send_headers_response(&lease, source, Vec::new());
        shared.send_block(&lease, addr, payload, None);

        assert_eq!(headers_rx.try_recv()?.source, Some(source));
        let received = blocks_rx.try_recv()?;
        assert_eq!(received.source, Some(source));
        assert_eq!(received.payload().bytes(), &serialized);
        Ok(())
    }

    #[test]
    fn send_block_forwards_the_blocks_header() -> Result<(), TestError> {
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_449));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_bytes = bitcoin::consensus::encode::serialize(&genesis);
        let payload = bitcoin_rs_consensus::primitives::BlockImage::from_raw(bytes::Bytes::from(
            block_bytes,
        ))?;
        let header = payload.header();
        let source = lease.source(Some(addr));

        shared.send_block(&lease, addr, payload, None);

        let forwarded = headers_rx.try_recv()?;
        assert_eq!(forwarded.source, Some(source));
        assert_eq!(forwarded.headers, vec![header]);
        assert!(
            !forwarded.wire_response,
            "a body-carried header is not a getheaders response"
        );
        Ok(())
    }

    #[test]
    fn send_block_unblocks_when_session_is_cancelled() -> Result<(), TestError> {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(1);
        let mut shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
        let session_cancel = bitcoin_rs_consensus::latch::LatchWriter::new();
        shared.session_cancel = session_cancel.reader();
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_448));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let first_bytes = bitcoin::consensus::encode::serialize(&genesis);
        let first = bitcoin_rs_consensus::primitives::BlockImage::from_raw(bytes::Bytes::from(
            first_bytes,
        ))?;
        let second_bytes = first.bytes().clone();
        let second = bitcoin_rs_consensus::primitives::BlockImage::from_raw(second_bytes)?;
        shared.send_block(&lease, addr, first, None);

        let blocked = std::thread::spawn(move || {
            shared.send_block(&lease, addr, second, None);
        });
        let started = std::time::Instant::now();
        while !blocked.is_finished() && started.elapsed() < Duration::from_millis(250) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !blocked.is_finished(),
            "full inbound block channel must block until cancel"
        );
        session_cancel.trigger();
        blocked
            .join()
            .map_err(|_| std::io::Error::other("send_block thread panicked"))?;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cancelled send_block must not wait on the full queue"
        );
        drop(blocks_rx);
        Ok(())
    }

    #[test]
    fn message_loop_exits_before_read_when_cancelled() {
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_444));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        lease.cancel();
        let mut peer = Peer::new(
            ScriptedStream {
                script: io::Cursor::new(Vec::new()),
            },
            Magic::BITCOIN,
        );
        peer.state = PeerState::Ready;

        let shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_ok());
    }

    #[test]
    fn message_loop_exits_after_replacement_during_read() {
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_445));
        let table = Arc::new(crate::PeerTable::new());
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = crate::PeerLease::new(old_tx);
        table.register(addr, old.clone());
        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = crate::PeerLease::new(replacement_tx);
        table.register(addr, replacement.clone());

        let mut wire = Vec::new();
        crate::wire::write_message(
            &mut wire,
            Magic::BITCOIN,
            &crate::Message::Headers(Vec::new()),
        )
        .expect("headers encodes");
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(
            Arc::clone(&table),
            headers_tx,
            crossbeam_channel::unbounded().0,
        );
        let mut peer = Peer::new(
            ScriptedStream {
                script: io::Cursor::new(wire),
            },
            Magic::BITCOIN,
        );
        peer.state = PeerState::Ready;

        assert!(run_message_loop(&mut peer, addr, &old, &shared, None).is_ok());
        assert!(headers_rx.try_recv().is_err());
        assert!(old.is_cancelled());
        assert!(table.is_current(replacement.source(Some(addr))));
    }

    fn sendcmpct_scenario(send_compact: bool, version: u64, port: u16) -> bool {
        let mut wire = Vec::new();
        crate::wire::write_message(
            &mut wire,
            Magic::BITCOIN,
            &crate::Message::SendCmpct(bitcoin::p2p::message_compact_blocks::SendCmpct {
                send_compact,
                version,
            }),
        )
        .expect("sendcmpct encodes");
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, port));
        let table = Arc::new(crate::PeerTable::new());
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        table.register(addr, lease.clone());
        assert!(
            table.publish_info(
                addr,
                &lease,
                crate::PeerInfo {
                    endpoint: Some(addr),
                    network: addr.net(),
                    addr: addr.into(),
                    version: 70_016,
                    wtxid_relay: false,
                    relay_transactions: true,
                    compact_block_relay: false,
                    send_headers: false,
                    services: 0,
                    user_agent: String::from("/test/"),
                    start_height: 0,
                    best_known_height: 0,
                    conn_time: 0,
                    inbound: false,
                    addr_bind: crate::TransportRemote::new(
                        addr.socket_addr()
                            .unwrap_or_else(|| panic!("expected IP fixture")),
                    ),
                    time_offset: 0,
                    counters: std::sync::Arc::new(crate::PeerCounters::default()),
                    transport: crate::TransportProtocol::V1,
                },
            )
        );
        let mut peer = Peer::new(ScriptedEof(io::Cursor::new(wire)), Magic::BITCOIN);
        peer.state = PeerState::Ready;
        let shared = test_shared(
            Arc::clone(&table),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_err());
        table.compact_relay_of(addr)
    }

    #[test]
    fn sendcmpct_raises_published_compact_relay_preference() {
        assert!(sendcmpct_scenario(true, 2, 18_448));
        assert!(sendcmpct_scenario(false, 2, 18_449));
        assert!(!sendcmpct_scenario(false, 1, 18_450));
        assert!(!sendcmpct_scenario(false, 7, 18_451));
    }

    struct ScriptedEof(io::Cursor<Vec<u8>>);

    impl io::Read for ScriptedEof {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match io::Read::read(&mut self.0, buf)? {
                0 => Err(io::ErrorKind::UnexpectedEof.into()),
                read => Ok(read),
            }
        }
    }

    impl io::Write for ScriptedEof {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ContinuingStream(Arc<AtomicUsize>);

    impl io::Read for ContinuingStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            }
        }
    }

    impl io::Write for ContinuingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn message_loop_keeps_current_lease_running() {
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_446));
        let reads = Arc::new(AtomicUsize::new(0));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let mut peer = Peer::new(ContinuingStream(Arc::clone(&reads)), Magic::BITCOIN);
        peer.state = PeerState::Ready;
        let shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );

        assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_err());
        assert_eq!(reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn message_loop_probes_a_fresh_peer_immediately_then_stays_quiet() {
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let reads = Arc::new(AtomicUsize::new(0));
        let mut peer = Peer::new(ContinuingStream(Arc::clone(&reads)), Magic::BITCOIN);
        peer.state = PeerState::Ready;
        let shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_448));

        assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_err());
        assert!(
            matches!(
                outbound_rx.try_recv().map(|frame| frame.message().clone()),
                Ok(crate::Message::Ping(_))
            ),
            "the first pass after the handshake owes an immediate probe, like Core's epoch-initialized m_ping_start",
        );
        assert!(
            matches!(
                outbound_rx.try_recv(),
                Err(crossbeam_channel::TryRecvError::Empty)
            ),
            "a peer already probed owes no second probe inside one interval",
        );
    }

    #[test]
    fn registration_cancels_replaced_lease() {
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_447));
        let table = crate::PeerTable::new();
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = crate::PeerLease::new(old_tx);
        table.register(addr, old.clone());
        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = crate::PeerLease::new(replacement_tx);

        assert!(table.register(addr, replacement.clone()));
        table.publish_info(addr, &replacement, peer_info(addr, 2));
        assert!(old.is_cancelled());
        assert!(table.is_current(replacement.source(Some(addr))));
        assert_eq!(table.infos(), vec![peer_info(addr, 2)]);
    }

    #[test]
    fn stale_release_preserves_replacement_and_current_release_removes_it() {
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_448));
        let table = crate::PeerTable::new();
        let (stale_tx, _stale_rx) = crossbeam_channel::unbounded();
        let stale = crate::PeerLease::new(stale_tx);
        let (current_tx, _current_rx) = crossbeam_channel::unbounded();
        let current = crate::PeerLease::new(current_tx);
        table.register(addr, current.clone());
        table.publish_info(addr, &current, peer_info(addr, 2));

        assert!(!table.remove_current(addr, &stale));
        assert!(!current.is_cancelled());
        assert!(table.is_current(current.source(Some(addr))));
        assert!(table.remove_current(addr, &current));
        assert!(current.is_cancelled());
        assert!(table.is_empty());
    }

    struct BlockingTestWriter {
        remaining: Cell<usize>,
        unblock: crossbeam_channel::Receiver<()>,
        blocked: crossbeam_channel::Sender<()>,
    }

    impl io::Write for BlockingTestWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let remaining = self.remaining.get();
            if buf.len() <= remaining {
                self.remaining.set(remaining - buf.len());
                Ok(buf.len())
            } else {
                let _ = self.blocked.try_send(());
                let _ = self.unblock.recv();
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "test: unblocked",
                ))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct EventWriter {
        events: crossbeam_channel::Sender<()>,
    }

    impl io::Write for EventWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _ = self.events.send(());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ScriptedStream {
        script: io::Cursor<Vec<u8>>,
    }

    impl io::Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match io::Read::read(&mut self.script, buf)? {
                0 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                read => Ok(read),
            }
        }
    }

    impl io::Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn cancel_wakes_writer_blocked_on_empty_queue_with_live_senders() {
        let (_client, server, peer_addr) = loopback_pair();
        let writer_stream = crate::CountingStream::new(
            server.try_clone().expect("try_clone"),
            std::sync::Arc::new(crate::PeerCounters::default()),
        );
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let lease_probe = lease.clone();

        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let writer = spawn_connection_writer(
            writer_stream,
            crate::transport::SendTransport::V1(Magic::BITCOIN),
            outbound_rx,
            lease.close_signal(),
            lease.budget_handle(),
            peer_addr,
            None,
        )
        .expect("spawn writer");
        let waiter = std::thread::spawn(move || {
            writer.join().expect("writer join");
            let _ = done_tx.send(());
        });

        lease.cancel();
        done_rx
            .recv_timeout(FAILSAFE)
            .expect("close signal must wake an idle writer with live senders");
        waiter.join().expect("waiter join");
        assert!(lease_probe.is_cancelled());
    }

    #[test]
    fn writer_mid_write_exits_on_unblock_deterministically() {
        let frame = ping_len();
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_with_budget(
            outbound_tx,
            false,
            OutboundBudget::with_block_reserve(100, 100 * frame, 0),
        );

        for _ in 0..5 {
            lease
                .send(crate::Message::Ping(9))
                .expect("fresh queue admits a ping");
        }
        assert_eq!(lease.budget_handle().pending(), (5, 5 * frame));

        let (unblock_tx, unblock_rx) = crossbeam_channel::bounded(1);
        let (blocked_tx, blocked_rx) = crossbeam_channel::bounded(1);
        let mut writer = BlockingTestWriter {
            remaining: Cell::new(2 * frame),
            unblock: unblock_rx,
            blocked: blocked_tx,
        };
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let close_rx = lease.close_signal();
        let net_trace = crate::net_trace::NetTrace::outbound(
            9,
            "127.0.0.1:18444".parse().expect("valid socket address"),
            crate::peer_info::PeerRole::BlockRelayOnly,
        );
        let worker = std::thread::spawn(move || {
            run_writer_loop(
                &outbound_rx,
                close_rx,
                &mut writer,
                &mut crate::transport::SendTransport::V1(Magic::BITCOIN),
                &crate::PeerCounters::default(),
                Some(&net_trace),
            );
            let _ = done_tx.send(());
        });

        blocked_rx
            .recv_timeout(FAILSAFE)
            .expect("writer must exhaust its byte budget");
        assert_eq!(
            lease.budget_handle().pending(),
            (5, 5 * frame),
            "a burst in flight keeps its charge"
        );

        lease.cancel();
        let _ = unblock_tx.send(());
        done_rx
            .recv_timeout(FAILSAFE)
            .expect("unblock must release the blocked writer");
        worker.join().expect("worker join");

        assert_eq!(
            lease.budget_handle().pending(),
            (0, 0),
            "a failed write drops its burst, and each frame returns its own charge"
        );
    }

    #[test]
    fn writer_releases_budget_after_write() {
        let frame = ping_len();
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_with_budget(
            outbound_tx,
            false,
            OutboundBudget::with_block_reserve(100, 100 * frame, 0),
        );
        lease
            .send(crate::Message::Ping(9))
            .expect("fresh queue admits a ping");
        assert_eq!(lease.budget_handle().pending(), (1, frame));

        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let mut writer = EventWriter { events: event_tx };
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let budget = lease.budget_handle();
        let close_rx = lease.close_signal();
        let worker = std::thread::spawn(move || {
            run_writer_loop(
                &outbound_rx,
                close_rx,
                &mut writer,
                &mut crate::transport::SendTransport::V1(Magic::BITCOIN),
                &crate::PeerCounters::default(),
                None,
            );
            let _ = done_tx.send(());
        });

        drop(lease);

        event_rx
            .recv_timeout(FAILSAFE)
            .expect("writer must emit an event after write returns");
        done_rx
            .recv_timeout(FAILSAFE)
            .expect("writer must exit after senders drop");
        worker.join().expect("worker join");

        assert_eq!(
            budget.pending(),
            (0, 0),
            "written bytes must be fully released"
        );
    }

    #[test]
    fn writer_exit_shuts_down_the_reader_socket_clone() {
        let (mut client, server, peer_addr) = loopback_pair();
        let reader_stream = server.try_clone().expect("reader clone");
        client.set_nonblocking(true).expect("nonblocking client");
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let writer = spawn_connection_writer(
            crate::CountingStream::new(server, std::sync::Arc::new(crate::PeerCounters::default())),
            crate::transport::SendTransport::V1(Magic::BITCOIN),
            outbound_rx,
            lease.close_signal(),
            lease.budget_handle(),
            peer_addr,
            None,
        )
        .expect("spawn writer");

        lease.cancel();
        writer.join().expect("writer join");

        let mut byte = [0_u8; 1];
        assert_eq!(
            io::Read::read(&mut client, &mut byte).expect("shutdown must produce EOF"),
            0
        );
        drop(reader_stream);
    }

    #[test]
    fn run_connected_session_publishes_peer_relay_preference_and_joins_writer() {
        for peer_requested_wtxid in [false, true] {
            let (client, server, peer_addr) = loopback_pair();
            drop(client);

            let peer_table = Arc::new(crate::PeerTable::new());
            let (published_tx, published_rx) = crossbeam_channel::bounded(1);
            let observed_table = Arc::clone(&peer_table);
            let mut shared = test_shared(
                peer_table,
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            shared.peer_ready = Some(Arc::new(move |_source| {
                let requested = observed_table.infos()[0].wtxid_relay;
                let _ = published_tx.try_send(requested);
            }));

            let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
            let lease = crate::PeerLease::new(outbound_tx);
            let lease_probe = lease.clone();
            shared.peer_table.register(peer_addr, lease.clone());

            let info = crate::PeerInfo {
                endpoint: Some(peer_addr),
                network: peer_addr.net(),
                addr: crate::PeerRemote::Endpoint(peer_addr),
                version: 70_016,
                wtxid_relay: false,
                relay_transactions: true,
                compact_block_relay: false,
                send_headers: false,
                services: 0,
                user_agent: String::from("/test/"),
                start_height: 0,
                best_known_height: 0,
                conn_time: 0,
                inbound: false,
                addr_bind: crate::TransportRemote::new(
                    peer_addr
                        .socket_addr()
                        .unwrap_or_else(|| panic!("expected IP fixture")),
                ),
                time_offset: 0,
                counters: std::sync::Arc::new(crate::PeerCounters::default()),
                transport: crate::TransportProtocol::V1,
            };

            let (done_tx, done_rx) = crossbeam_channel::bounded(1);
            let worker = std::thread::spawn(move || {
                let mut peer = Peer::new(
                    crate::CountingStream::new(
                        server,
                        std::sync::Arc::new(crate::PeerCounters::default()),
                    ),
                    Magic::BITCOIN,
                );
                if peer_requested_wtxid {
                    peer.wtxid_relay.mark_peer_supported();
                }
                let result =
                    run_connected_session(&mut peer, peer_addr, &shared, lease, outbound_rx, info);
                let _ = done_tx.send(result);
            });

            let result = done_rx
                .recv_timeout(FAILSAFE)
                .expect("session must return while an external lease clone is alive");
            worker.join().expect("worker join");
            assert!(result.is_err(), "EOF on read must end the session");
            assert!(lease_probe.is_cancelled());
            assert_eq!(
                published_rx.try_recv().expect("published ready metadata"),
                peer_requested_wtxid
            );
        }
    }

    #[test]
    fn session_disconnect_updates_full_relay_and_preserves_block_relay_privacy() {
        for (block_relay, stale) in [(false, false), (true, false), (false, true)] {
            let (client, server, peer_addr) = loopback_pair();
            drop(client);

            let peer_table = Arc::new(crate::PeerTable::new());
            let mut shared = test_shared(
                peer_table,
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
            book.learn_dns("seed", &[peer_addr], 5000);
            shared.address_book = Some(Arc::clone(&book));

            let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
            let lease = if block_relay {
                crate::PeerLease::new_block_relay(outbound_tx)
            } else {
                crate::PeerLease::new(outbound_tx)
            };
            shared.peer_table.register(peer_addr, lease.clone());
            if stale {
                let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
                assert!(
                    shared
                        .peer_table
                        .register(peer_addr, crate::PeerLease::new(replacement_tx),)
                );
            }

            let info = crate::PeerInfo {
                endpoint: Some(peer_addr),
                network: peer_addr.net(),
                addr: crate::PeerRemote::Endpoint(peer_addr),
                version: 70_016,
                wtxid_relay: false,
                relay_transactions: true,
                compact_block_relay: false,
                send_headers: false,
                services: 9,
                user_agent: String::from("/test/"),
                start_height: 0,
                best_known_height: 0,
                conn_time: 0,
                inbound: false,
                addr_bind: crate::TransportRemote::new(
                    peer_addr
                        .socket_addr()
                        .unwrap_or_else(|| panic!("expected IP fixture")),
                ),
                time_offset: 0,
                counters: std::sync::Arc::new(crate::PeerCounters::default()),
                transport: crate::TransportProtocol::V1,
            };

            let mut peer = Peer::new(
                crate::CountingStream::new(
                    server,
                    std::sync::Arc::new(crate::PeerCounters::default()),
                ),
                Magic::BITCOIN,
            );
            let _ = run_connected_session(&mut peer, peer_addr, &shared, lease, outbound_rx, info);

            let last_seen = book.gossip(10_000)[0].time;
            if block_relay || stale {
                assert_eq!(
                    last_seen, 5000,
                    "block-relay or rejected ready session must never refresh last_seen"
                );
            } else {
                assert_ne!(
                    last_seen, 5000,
                    "full-relay disconnect must refresh last_seen"
                );
            }
        }
    }

    #[test]
    fn message_loop_disconnects_saturated_peer() {
        let (outbound_tx, _outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_with_budget(
            outbound_tx,
            false,
            OutboundBudget::new(1, ping_len()),
        );

        let mut wire = Vec::new();
        crate::wire::write_message(&mut wire, Magic::BITCOIN, &crate::Message::Ping(41))
            .expect("ping encodes");
        crate::wire::write_message(&mut wire, Magic::BITCOIN, &crate::Message::Ping(42))
            .expect("ping encodes");
        let mut peer = Peer::new(
            ScriptedStream {
                script: io::Cursor::new(wire),
            },
            Magic::BITCOIN,
        );
        peer.state = PeerState::Ready;

        let shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_447));

        let result = run_message_loop(&mut peer, addr, &lease, &shared, None);
        assert!(result.is_err(), "saturation must end the message loop");
        assert!(lease.is_cancelled());
    }

    fn queued(
        messages: &[crate::Message],
    ) -> (
        crate::PeerLease,
        crossbeam_channel::Receiver<crate::QueuedFrame>,
    ) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        for message in messages {
            lease
                .send(message.clone())
                .expect("a fresh queue admits the message");
        }
        (lease, rx)
    }

    #[test]
    fn collect_write_burst_coalesces_control_until_a_bulk_payload() {
        let (lease, rx) = queued(&[
            crate::Message::Ping(0),
            crate::Message::Pong(1),
            crate::Message::Block(bitcoin_rs_consensus::primitives::BlockImage::from_local(
                bitcoin_rs_consensus::primitives::Block::default(),
            )),
            crate::Message::Ping(2),
        ]);
        let first = rx.try_recv().expect("the first queued frame");

        let (burst, leftover) = collect_write_burst(first, &rx);

        let messages: Vec<_> = burst.iter().map(|frame| frame.message().clone()).collect();
        assert_eq!(
            messages,
            vec![crate::Message::Ping(0), crate::Message::Pong(1)]
        );
        assert!(matches!(
            leftover.as_ref().map(crate::QueuedFrame::message),
            Some(crate::Message::Block(_))
        ));
        assert_eq!(
            lease.budget_handle().pending().0,
            4,
            "every frame keeps its charge while it is in the burst or the leftover"
        );
        drop((burst, leftover));
        assert_eq!(
            lease.budget_handle().pending().0,
            1,
            "dropping the burst returns exactly its frames' charges"
        );
        assert!(matches!(
            rx.try_recv().map(crate::QueuedFrame::into_message),
            Ok(crate::Message::Ping(2))
        ));
    }

    #[test]
    fn collect_write_burst_emits_a_bulk_payload_alone() {
        let (_lease, rx) = queued(&[
            crate::Message::Block(bitcoin_rs_consensus::primitives::BlockImage::from_local(
                bitcoin_rs_consensus::primitives::Block::default(),
            )),
            crate::Message::Ping(1),
        ]);
        let first = rx.try_recv().expect("the bulk frame");
        let (burst, leftover) = collect_write_burst(first, &rx);
        assert_eq!(burst.len(), 1);
        assert!(leftover.is_none());
        assert!(matches!(
            rx.try_recv().map(crate::QueuedFrame::into_message),
            Ok(crate::Message::Ping(1))
        ));
    }

    /// Accepts at most `budget` bytes per vectored call, then fails once the
    /// budget is spent: a socket that took a prefix of the burst and broke.
    struct BrokenAfter {
        budget: usize,
    }

    impl io::Write for BrokenAfter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            panic!("the burst path must write vectored");
        }
        fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
            if self.budget == 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket broke"));
            }
            let offered: usize = buffers.iter().map(|slice| slice.len()).sum();
            let take = offered.min(self.budget);
            self.budget -= take;
            Ok(take)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Accepts at most `per_call` bytes per vectored call and never fails:
    /// backpressure that spreads one burst over many partial accepts.
    struct Dribble {
        per_call: usize,
    }

    impl io::Write for Dribble {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            panic!("the burst path must write vectored");
        }
        fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
            let offered: usize = buffers.iter().map(|slice| slice.len()).sum();
            Ok(offered.min(self.per_call))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_failed_burst_write_keeps_charges_only_for_fully_accepted_frames() {
        let (_lease, rx) = queued(&[crate::Message::Ping(0), crate::Message::Pong(1)]);
        let first = rx.try_recv().expect("the first queued frame");
        let ping_len = crate::wire::wire_len(&crate::Message::Ping(0)).expect("ping encodes");
        let mut writer = BrokenAfter { budget: ping_len };
        let mut transport = crate::transport::SendTransport::V1(Magic::BITCOIN);
        let counters = crate::PeerCounters::default();

        let alive = write_ready_burst(first, &rx, &mut writer, &mut transport, &counters, None);

        assert!(!alive, "a write error ends the writer");
        assert_eq!(
            counters.sent_per_message(),
            vec![("ping", u64::try_from(ping_len).expect("fits u64"))],
            "the frame the socket accepted in full keeps its charge; the torn one keeps none"
        );
    }

    #[test]
    fn partial_acceptance_across_calls_charges_every_frame() {
        let (_lease, rx) = queued(&[crate::Message::Ping(0), crate::Message::Pong(1)]);
        let first = rx.try_recv().expect("the first queued frame");
        let ping_len = crate::wire::wire_len(&crate::Message::Ping(0)).expect("ping encodes");
        let pong_len = crate::wire::wire_len(&crate::Message::Pong(1)).expect("pong encodes");
        let mut writer = Dribble { per_call: 7 };
        let mut transport = crate::transport::SendTransport::V1(Magic::BITCOIN);
        let counters = crate::PeerCounters::default();

        let alive = write_ready_burst(first, &rx, &mut writer, &mut transport, &counters, None);

        assert!(alive, "partial acceptance is backpressure, not an error");
        assert_eq!(
            counters.sent_per_message(),
            vec![
                ("ping", u64::try_from(ping_len).expect("fits u64")),
                ("pong", u64::try_from(pong_len).expect("fits u64")),
            ],
            "every fully written frame is charged exactly once across the retries"
        );
    }

    #[test]
    fn queued_frames_release_on_writer_exit() {
        use crate::connection::{OutboundBudget, SharedOutboundBudget};

        let shared = Arc::new(SharedOutboundBudget::with_limits(10_000, 500));
        let (bystander_tx, _bystander_rx) = crossbeam_channel::unbounded();
        let bystander = crate::PeerLease::new(bystander_tx).with_shared_budget(&shared);
        let bystander_credit = bystander
            .budget_handle()
            .try_charge(100)
            .expect("bystander charge");
        let (tx, rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_with_budget(
            tx,
            false,
            OutboundBudget::with_block_reserve(100, 1_000_000, 500),
        )
        .with_shared_budget(&shared);
        let frame = ping_len();
        for nonce in 0..3 {
            lease
                .send(crate::Message::Ping(nonce))
                .expect("queue admits a ping");
        }
        let reservation = lease
            .try_reserve_production()
            .expect("the session's live reservation");
        assert_eq!(shared.pending(), 100 + 3 * frame + 500);

        let exit = super::WriterExit {
            budget: lease.budget_handle(),
            outbound_rx: &rx,
        };
        drop(exit);

        assert!(lease.budget_handle().writer_dead());
        assert_eq!(
            shared.pending(),
            100 + 500,
            "the three queued frames returned their own charge, nothing more"
        );
        assert_eq!(lease.budget_handle().pending(), (1, 500));
        assert!(rx.is_empty());
        assert!(matches!(
            lease.send(crate::Message::Ping(9)),
            Err(crate::OutboundRefusal::Closed(_))
        ));
        assert!(lease.is_cancelled());

        drop(reservation);
        assert_eq!(shared.pending(), 100);
        assert_eq!(lease.budget_handle().pending(), (0, 0));
        drop(bystander_credit);
        assert_eq!(shared.pending(), 0);
    }

    #[test]
    fn forward_block_cancels_promptly_on_latch() {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::bounded(1);
        let latch = bitcoin_rs_consensus::latch::LatchWriter::new();
        let mut shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
        shared.session_cancel = latch.reader();
        let (outbound_tx, _outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let first = bitcoin_rs_consensus::primitives::BlockImage::from_raw(bytes::Bytes::from(
            bitcoin::consensus::encode::serialize(&genesis),
        ))
        .expect("payload");
        let second = first.clone();
        let source = lease.source(None);
        assert!(shared.forward_block(first, source, None, None));
        let (join_tx, join_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            let result = shared.forward_block(second, source, None, None);
            let _ = join_tx.send(result);
        });
        std::thread::sleep(Duration::from_millis(10));
        latch.trigger();
        let delivered = join_rx.recv_timeout(Duration::from_millis(40));
        assert!(
            delivered.is_ok(),
            "forward_block must unblock promptly upon latch trigger without waiting for poll timeout"
        );
        assert!(!delivered.expect("result"));
        let _ = worker.join();
    }

    #[test]
    fn enqueue_headers_cancels_promptly_on_latch() {
        let (headers_tx, _headers_rx) = crossbeam_channel::bounded(1);
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let latch = bitcoin_rs_consensus::latch::LatchWriter::new();
        let mut shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
        shared.session_cancel = latch.reader();
        let (outbound_tx, _outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let source = lease.source(None);
        shared.send_headers_response(&lease, source, Vec::new());
        let (join_tx, join_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            shared.send_headers_response(&lease, source, Vec::new());
            let _ = join_tx.send(());
        });
        std::thread::sleep(Duration::from_millis(10));
        latch.trigger();
        assert!(
            join_rx.recv_timeout(Duration::from_millis(40)).is_ok(),
            "enqueue_headers must unblock promptly upon latch trigger without waiting for poll timeout"
        );
        let _ = worker.join();
    }
}

#[cfg(test)]
mod ready_notify_tests {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{ConnectionShared, test_shared};

    fn peer_info(addr: PeerEndpoint, start_height: i32) -> crate::PeerInfo {
        crate::PeerInfo {
            endpoint: Some(addr),
            network: addr.net(),
            addr: addr.into(),
            version: 70_016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 1,
            user_agent: String::from("/test/"),
            start_height,
            conn_time: 0,
            best_known_height: start_height,
            inbound: false,
            addr_bind: crate::TransportRemote::new(
                addr.socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            ),
            time_offset: 0,
            counters: Arc::new(crate::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
        }
    }

    #[test]
    fn manual_outbound_ready_updates_known_address_health_without_automatic_claims() {
        let mut shared = shared_with_notify_counter(&Arc::new(AtomicUsize::new(0)));
        let now = crate::addrman::now();
        let known = PeerEndpoint::from(([127, 0, 0, 1], 8333));
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
        book.learn_dns("seed", &[known], now);
        shared.address_book = Some(Arc::clone(&book));
        let (tx, _) = crossbeam_channel::bounded(1);
        let lease = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
        shared.peer_table.register(known, lease.clone());
        assert!(shared.publish_info_and_notify_ready_with_package(
            known,
            &lease,
            &peer_info(known, 0),
            0
        ));
        assert_eq!(book.gossip(now)[0].services.to_u64(), 1);
        assert_eq!(book.pending_count_excluding(&[]), 0);
        book.queued(known);
        assert!(shared.publish_info_and_notify_ready_with_package(
            known,
            &lease,
            &peer_info(known, 0),
            0
        ));
        assert_eq!(
            book.pending_count_excluding(&[]),
            1,
            "manual success does not transfer an existing automatic claim"
        );
        let unknown = PeerEndpoint::from(([127, 0, 0, 2], 8333));
        let manual = crate::PeerLease::new_manual(tx, crate::PeerRole::FullRelay);
        shared.peer_table.register(unknown, manual.clone());
        assert!(shared.publish_info_and_notify_ready_with_package(
            unknown,
            &manual,
            &peer_info(unknown, 0),
            0
        ));
        assert_eq!(book.len(), 1, "Good does not insert manual endpoints");
        assert_eq!(book.pending_count_excluding(&[]), 1);
    }

    fn shared_with_notify_counter(notified: &Arc<AtomicUsize>) -> ConnectionShared {
        let notified = Arc::clone(notified);
        let mut shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        shared.peer_ready = Some(Arc::new(move |_| {
            notified.fetch_add(1, Ordering::Relaxed);
        }));
        shared
    }

    #[test]
    fn stale_predecessor_does_not_notify_peer_ready() {
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_450));
        let notified = Arc::new(AtomicUsize::new(0));
        let shared = shared_with_notify_counter(&notified);

        let (stale_tx, _stale_rx) = crossbeam_channel::unbounded();
        let stale = crate::PeerLease::new(stale_tx);
        let (current_tx, _current_rx) = crossbeam_channel::unbounded();
        let current = crate::PeerLease::new(current_tx);
        shared.peer_table.register(addr, stale.clone());
        shared.peer_table.register(addr, current.clone());

        assert!(
            !shared.publish_info_and_notify_ready_with_package(
                addr,
                &stale,
                &peer_info(addr, 1),
                0
            ),
            "replaced predecessor must not publish or notify"
        );
        assert_eq!(notified.load(Ordering::Relaxed), 0);
        assert_eq!(shared.peer_table.infos(), []);

        assert!(shared.publish_info_and_notify_ready_with_package(
            addr,
            &current,
            &peer_info(addr, 2),
            0
        ));
        assert_eq!(notified.load(Ordering::Relaxed), 1);
        assert_eq!(shared.peer_table.infos()[0].start_height, 2);
    }

    #[test]
    fn current_lease_publishes_then_notifies_ready() {
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_451));
        let notified = Arc::new(AtomicUsize::new(0));
        let shared = shared_with_notify_counter(&notified);

        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        shared.peer_table.register(addr, lease.clone());

        assert!(shared.publish_info_and_notify_ready_with_package(
            addr,
            &lease,
            &peer_info(addr, 3),
            0
        ));
        assert_eq!(notified.load(Ordering::Relaxed), 1);
        assert_eq!(shared.peer_table.infos(), vec![peer_info(addr, 3)]);
    }

    #[test]
    fn negotiated_package_bits_publish_before_ready() {
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_452));
        let notified = Arc::new(AtomicUsize::new(0));
        let shared = shared_with_notify_counter(&notified);

        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        shared.peer_table.register(addr, lease.clone());

        let both = crate::packages::PKG_RELAY_PKGTXNS | crate::packages::PKG_RELAY_ANC;
        assert!(shared.publish_info_and_notify_ready_with_package(
            addr,
            &lease,
            &peer_info(addr, 4),
            both
        ));
        assert_eq!(notified.load(Ordering::Relaxed), 1);
        let source = lease.source(Some(addr));
        let snapshot = shared
            .peer_table
            .package_relay_versions_for_endpoint(source.endpoint, source.connection_id().get());
        assert_eq!(
            snapshot, both,
            "peer-table must retain negotiated package bits"
        );
        assert_ne!(
            snapshot & crate::packages::PKG_RELAY_ANC,
            0,
            "TxIngressConsumer gates ancestor-package requests on PKG_RELAY_ANC"
        );
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test assertions and socket setup")]
mod address_tests {
    use super::*;
    use crate::test_support::QueuedMessages as _;
    use crate::{Message, PeerState};
    use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};

    /// The message loop originates one keepalive ping on its first pass; the
    /// once-per-connection assertions below strip that probe so they keep
    /// judging only the address replies.
    fn keepalive_probes_stripped(replies: Vec<Message>) -> Vec<Message> {
        replies
            .into_iter()
            .filter(|message| !matches!(message, Message::Ping(_)))
            .collect()
    }

    #[test]
    fn local_dial_cancellation_is_not_attempt_evidence_but_tcp_failure_is() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let target = listener.local_addr().expect("address");
        drop(listener);
        let now = crate::addrman::now();
        for cancelled in [true, false] {
            let table = Arc::new(crate::PeerTable::new());
            let (headers, _) = crossbeam_channel::unbounded();
            let (blocks, _) = crossbeam_channel::unbounded();
            let mut shared = test_shared(table, headers, blocks);
            let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
            book.learn_dns("seed", &[target.into()], now - 31 * 86400);
            shared.address_book = Some(Arc::clone(&book));
            if cancelled {
                let session_cancel = bitcoin_rs_consensus::latch::LatchWriter::new();
                session_cancel.trigger();
                shared.session_cancel = session_cancel.reader();
            }
            assert!(
                run_outbound_connection(
                    target.into(),
                    &shared,
                    crate::PeerRole::FullRelay,
                    ConnectionOrigin::Automatic,
                    FailureAccounting::Ignore,
                )
                .is_err()
            );
            assert_eq!(
                book.gossip(now).is_empty(),
                cancelled,
                "only an actual TCP attempt supplies Core's recent-attempt protection"
            );
            assert_eq!(
                book.pending_count_excluding(&[]),
                0,
                "health updates do not invent automatic claims"
            );
        }
    }

    #[test]
    fn outbound_wire_getaddr_never_serves_the_address_book() {
        let table = Arc::new(crate::PeerTable::new());
        let (headers_tx, _) = crossbeam_channel::unbounded();
        let (blocks_tx, _) = crossbeam_channel::unbounded();
        let mut shared = test_shared(Arc::clone(&table), headers_tx, blocks_tx);
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
        book.learn_dns(
            "seed",
            &[PeerEndpoint::from(([127, 0, 0, 2], 8333))],
            crate::addrman::now(),
        );
        shared.address_book = Some(book);
        let (sender, receiver) = crossbeam_channel::unbounded();
        let source = PeerEndpoint::from(([127, 0, 0, 1], 9000));
        let lease = crate::PeerLease::new(sender);
        table.register(source, lease.clone());
        let mut input = Vec::new();
        for _ in 0..2 {
            crate::wire::write_message(&mut input, shared.magic, &Message::GetAddr).expect("frame");
        }
        let mut peer = Peer::new(std::io::Cursor::new(input), shared.magic);
        peer.state = PeerState::Ready;
        let _ = run_message_loop(&mut peer, source, &lease, &shared, None);
        assert!(
            !receiver
                .try_iter()
                .any(|frame| matches!(frame.message(), Message::Addr(_) | Message::AddrV2(_))),
            "an outbound peer cannot query our address book"
        );
    }

    #[test]
    fn wire_address_messages_share_one_book_and_getaddr_is_once_per_connection() {
        let table = Arc::new(crate::PeerTable::new());
        let (headers_tx, _) = crossbeam_channel::unbounded();
        let (blocks_tx, _) = crossbeam_channel::unbounded();
        let mut shared = test_shared(Arc::clone(&table), headers_tx, blocks_tx);
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
        shared.address_book = Some(Arc::clone(&book));
        let (sender, receiver) = crossbeam_channel::unbounded();
        let source = PeerEndpoint::from(([127, 0, 0, 1], 9000));
        let candidate = PeerEndpoint::from(([127, 0, 0, 2], 8333));
        let lease = crate::PeerLease::new_inbound(sender);
        table.register(source, lease.clone());
        let timestamp = u32::try_from(crate::addrman::now()).expect("timestamp");
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let mut input = Vec::new();
        for message in [
            Message::Addr(vec![(
                timestamp,
                Address::new(
                    &candidate
                        .socket_addr()
                        .unwrap_or_else(|| panic!("expected IP fixture")),
                    services,
                ),
            )]),
            Message::AddrV2(vec![AddrV2Message {
                time: timestamp,
                services,
                addr: AddrV2::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 2)),
                port: 8333,
            }]),
            Message::GetAddr,
            Message::GetAddr,
        ] {
            crate::wire::write_message(&mut input, shared.magic, &message).expect("frame");
        }
        let mut peer = Peer::new(std::io::Cursor::new(input), shared.magic);
        peer.state = PeerState::Ready;
        let _ = run_message_loop(&mut peer, source, &lease, &shared, None);
        assert_eq!(book.len(), 1);
        let replies = keepalive_probes_stripped(receiver.drain_messages());
        let [Message::Addr(addresses)] = replies.as_slice() else {
            panic!("expected exactly one addr response: {replies:?}");
        };
        assert_eq!(addresses.len(), 1);
        assert_eq!(
            addresses[0].1.socket_addr().expect("socket"),
            candidate
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture"))
        );
    }

    #[test]
    fn negotiated_sendaddrv2_answers_getaddr_with_addrv2_once() {
        let table = Arc::new(crate::PeerTable::new());
        let (headers_tx, _) = crossbeam_channel::unbounded();
        let (blocks_tx, _) = crossbeam_channel::unbounded();
        let mut shared = test_shared(Arc::clone(&table), headers_tx, blocks_tx);
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
        shared.address_book = Some(Arc::clone(&book));
        let (sender, receiver) = crossbeam_channel::unbounded();
        let source = PeerEndpoint::from(([127, 0, 0, 1], 9000));
        let candidate = PeerEndpoint::from(([127, 0, 0, 2], 8333));
        let lease = crate::PeerLease::new_inbound(sender);
        table.register(source, lease.clone());
        let timestamp = u32::try_from(crate::addrman::now()).expect("timestamp");
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let mut input = Vec::new();
        for message in [
            Message::Addr(vec![(
                timestamp,
                Address::new(
                    &candidate
                        .socket_addr()
                        .unwrap_or_else(|| panic!("expected IP fixture")),
                    services,
                ),
            )]),
            Message::SendAddrV2,
            Message::GetAddr,
            Message::GetAddr,
        ] {
            crate::wire::write_message(&mut input, shared.magic, &message).expect("frame");
        }
        let mut peer = Peer::new(std::io::Cursor::new(input), shared.magic);
        peer.state = PeerState::Ready;
        let _ = run_message_loop(&mut peer, source, &lease, &shared, None);
        let replies = keepalive_probes_stripped(receiver.drain_messages());
        let [Message::AddrV2(rows)] = replies.as_slice() else {
            panic!("expected exactly one addrv2 response: {replies:?}");
        };
        assert_eq!(
            rows.as_slice(),
            &[AddrV2Message {
                time: timestamp - 2 * 60 * 60,
                services,
                addr: AddrV2::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 2)),
                port: 8333,
            }],
            "the reply renders the same learned row in BIP155 form"
        );
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod feeler_tests {
    use super::*;
    use bitcoin_rs_consensus::primitives::USER_AGENT;
    use std::sync::atomic::AtomicUsize;

    struct Scripted(std::io::Cursor<Vec<u8>>);
    impl std::io::Read for Scripted {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.0, bytes)
        }
    }
    impl std::io::Write for Scripted {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn feeler_version(services: u64) -> crate::Message {
        crate::Message::Version(crate::handshake::version_message(
            123,
            0,
            crate::PeerRole::FullRelay,
            ServiceFlags::from(services),
            USER_AGENT,
        ))
    }

    #[test]
    fn version_only_feeler_uses_native_acceptance_without_publishing_work() {
        for (services, revoked) in [(0_u64, 0), (1, 0), (9, 0), (9, 1), (9, 2)] {
            let server = TcpListener::bind("127.0.0.1:0").expect("listener");
            let address = server.local_addr().expect("address");
            let table = Arc::new(crate::PeerTable::new());
            let mut shared = test_shared(
                Arc::clone(&table),
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let path = directory.path().join("peers-f9beb4d9.dat");
            let book =
                crate::addrman::AddressBook::open(Some(base), shared.magic.to_bytes(), true, None);
            book.learn_peer(
                crate::PeerRemote::Endpoint(address.into()),
                &[(address.into(), 9, unix_time_secs())],
                unix_time_secs(),
            );
            book.set_services(address.into(), 1);
            shared.address_book = Some(Arc::clone(&book));
            shared.feeler = true;
            assert!(book.queued_feeler(address.into()));
            let notifications = Arc::new(AtomicUsize::new(0));
            let count = Arc::clone(&notifications);
            shared.peer_ready = Some(Arc::new(move |_| {
                count.fetch_add(1, Ordering::Relaxed);
            }));
            let magic = shared.magic;
            let remote_table = Arc::clone(&table);
            let remote = std::thread::spawn(move || {
                let (stream, _) = server.accept().expect("accept");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .expect("timeout");
                let mut peer = Peer::new(stream, magic);
                let (initial, _) = peer
                    .read_message()
                    .expect("initial version")
                    .expect("a v1 frame");
                assert!(matches!(initial, crate::Message::Version(_)));
                assert!(
                    remote_table
                        .sessions()
                        .iter()
                        .all(|session| session.info.is_none())
                );
                if revoked == 1 {
                    remote_table.cancel_all();
                } else if revoked == 2 {
                    let replacement = crate::PeerLease::new(crossbeam_channel::unbounded().0);
                    remote_table.register(address, replacement);
                }
                let sent = peer.send(&feeler_version(services));
                if revoked == 0 {
                    sent.expect("VERSION only");
                }
                while let Ok(Some((message, _))) = peer.read_message() {
                    assert!(
                        !matches!(message, crate::Message::GetAddr | crate::Message::Verack),
                        "no ready/post-verack publication: {message:?}"
                    );
                }
            });
            spawn_outbound_connection(address.into(), shared, crate::PeerRole::BlockRelayOnly)
                .join()
                .expect("thread")
                .expect("probe");
            remote.join().expect("remote");
            assert!(
                book.is_feeler(address.into()),
                "the service reaper owns claim release"
            );
            book.unqueue(address.into());
            assert_eq!(notifications.load(Ordering::Relaxed), 0);
            assert_eq!(table.sessions().len(), usize::from(revoked == 2));
            assert!(
                table
                    .sessions()
                    .iter()
                    .all(|session| session.info.is_none() && session.demonstrated_tips.is_empty())
            );
            book.save();
            let bytes = std::fs::read(path).expect("book");
            let stored: sonic_rs::Value =
                sonic_rs::from_slice(&bytes[..bytes.len() - 32]).expect("JSON");
            assert_eq!(
                stored["records"][0]["tried"],
                revoked == 0,
                "services={services} revoked={revoked}"
            );
        }
    }

    #[test]
    fn ordinary_handshake_still_requires_services_and_verack() {
        for services in [1_u64, 9] {
            let mut wire = Vec::new();
            crate::wire::write_message(
                &mut wire,
                Magic::BITCOIN,
                &crate::Message::Version(crate::handshake::version_message(
                    123,
                    0,
                    crate::PeerRole::FullRelay,
                    ServiceFlags::from(services),
                    USER_AGENT,
                )),
            )
            .expect("wire");
            let mut peer = Peer::new(Scripted(std::io::Cursor::new(wire)), Magic::BITCOIN);
            let lease = crate::PeerLease::new(crossbeam_channel::unbounded().0);
            let shared = test_shared(
                Arc::new(crate::PeerTable::new()),
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            let result = run_outbound_handshake(
                &mut peer,
                124,
                0,
                &lease,
                Instant::now() + Duration::from_secs(1),
                crate::PeerEndpoint::Ip("127.0.0.1:8333".parse().expect("address")),
                &shared,
            );
            assert!(
                result.is_err(),
                "services={services} without VERACK must not complete"
            );
            assert_ne!(peer.state, crate::peer::PeerState::Ready);
        }
    }
    #[test]
    fn rejected_ordinary_version_updates_services_without_good() {
        for (prior_good, services) in [(false, 1_u64), (false, 0), (true, 1), (true, 0)] {
            let directory = tempfile::tempdir().expect("directory");
            let address: PeerEndpoint = "127.0.0.1:8333".parse().expect("address");
            let table = Arc::new(crate::PeerTable::new());
            let mut shared = test_shared(
                Arc::clone(&table),
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            let book = crate::addrman::AddressBook::open(
                Some(directory.path().join("peers.dat")),
                shared.magic.to_bytes(),
                true,
                None,
            );
            book.learn_dns("seed", &[address], 10_000);
            book.set_services(address, 9);
            if prior_good {
                book.succeeded(address, 9, 10_000);
            }
            shared.address_book = Some(Arc::clone(&book));
            let lease = crate::PeerLease::new(crossbeam_channel::unbounded().0);
            table.register(address, lease.clone());
            let mut wire = Vec::new();
            crate::wire::write_message(
                &mut wire,
                shared.magic,
                &crate::Message::Version(crate::handshake::version_message(
                    123,
                    0,
                    crate::PeerRole::FullRelay,
                    ServiceFlags::from(services),
                    USER_AGENT,
                )),
            )
            .expect("VERSION");
            let mut peer = Peer::new(Scripted(std::io::Cursor::new(wire)), shared.magic);
            assert!(
                run_outbound_handshake(
                    &mut peer,
                    124,
                    0,
                    &lease,
                    Instant::now() + Duration::from_secs(1),
                    address,
                    &shared
                )
                .is_err()
            );
            book.save();
            let bytes = std::fs::read(directory.path().join("peers-f9beb4d9.dat")).expect("book");
            let stored: sonic_rs::Value =
                sonic_rs::from_slice(&bytes[..bytes.len() - 32]).expect("JSON");
            let record = &stored["records"][0];
            assert_eq!(record["services"], services);
            assert_eq!(record["last_success"], if prior_good { 10_000 } else { 0 });
            assert_eq!(record["tried"], prior_good);
            assert!(
                !book.ordinary_services_eligible(address, u64::MAX),
                "an observed VERSION is known even when it advertises zero services; no fabricated success"
            );
        }
    }
    #[test]
    fn manual_dial_bypasses_known_incomplete_stored_services() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let mut shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
        book.learn_peer(
            crate::PeerRemote::Endpoint(address.into()),
            &[(address.into(), 1, unix_time_secs())],
            unix_time_secs(),
        );
        shared.address_book = Some(book);
        let ordinary =
            spawn_outbound_connection(address.into(), shared.clone(), crate::PeerRole::FullRelay)
                .join()
                .expect("ordinary thread");
        assert!(matches!(
            ordinary,
            Err(crate::PeerError::Protocol(
                "outbound peer lacks desirable services"
            ))
        ));
        let manual =
            spawn_pinned_outbound_connection(address.into(), shared, crate::PeerRole::FullRelay)
                .join()
                .expect("manual thread");
        assert!(
            matches!(manual, Err(crate::PeerError::Io(_))),
            "explicit manual dial reaches TCP instead of applying stored-service policy"
        );
    }
}

#[cfg(test)]
mod discouragement_tests {
    use super::*;
    use crate::{Message, PeerError, PeerLease, PeerRole};
    use bitcoin_rs_consensus::primitives::USER_AGENT;

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        AddrParse(#[from] std::net::AddrParseError),
        #[error(transparent)]
        Peer(#[from] crate::PeerError),
        #[error(transparent)]
        TryFromInt(#[from] std::num::TryFromIntError),
        #[error(transparent)]
        Sonic(#[from] sonic_rs::Error),
        #[error("missing: {0}")]
        Missing(&'static str),
    }

    impl From<&'static str> for TestError {
        fn from(msg: &'static str) -> Self {
            Self::Missing(msg)
        }
    }

    type TestResult = Result<(), TestError>;

    fn shared() -> ConnectionShared {
        let (headers, _) = crossbeam_channel::unbounded();
        let (blocks, _) = crossbeam_channel::unbounded();
        test_shared(Arc::new(crate::PeerTable::new()), headers, blocks)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum LeaseOrigin {
        Automatic,
        Manual,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BanProtection {
        Protected,
        Unprotected,
    }

    fn test_lease(origin: LeaseOrigin, protection: BanProtection) -> PeerLease {
        let (tx, _) = crossbeam_channel::unbounded();
        let lease = match origin {
            LeaseOrigin::Manual => PeerLease::new_manual(tx, PeerRole::FullRelay),
            LeaseOrigin::Automatic => PeerLease::new(tx),
        };
        lease.with_no_ban(protection == BanProtection::Protected)
    }

    struct ServiceUpdateScript {
        bytes: std::io::Cursor<Vec<u8>>,
        update_at: Option<u64>,
        book: Arc<crate::addrman::AddressBook>,
        addr: PeerEndpoint,
    }
    impl std::io::Read for ServiceUpdateScript {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            if self.update_at.is_some_and(|at| self.bytes.position() >= at) {
                self.update_at = None;
                self.book.learn_peer(
                    crate::PeerRemote::Endpoint(self.addr),
                    &[(self.addr, 1024, unix_time_secs())],
                    unix_time_secs(),
                );
            }
            std::io::Read::read(&mut self.bytes, bytes)
        }
    }
    impl std::io::Write for ServiceUpdateScript {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn accepted_version_updates_once_without_replaying_on_later_steps() -> TestResult {
        for (repeated_version, protected) in
            [(true, false), (true, true), (false, false), (false, true)]
        {
            let directory = tempfile::tempdir()?;
            let address: PeerEndpoint = "8.8.8.8:8333".parse()?;
            let mut shared = shared();
            let book = crate::addrman::AddressBook::open(
                Some(directory.path().join("peers.dat")),
                shared.magic.to_bytes(),
                false,
                None,
            );
            book.learn_peer(
                crate::PeerRemote::Endpoint(address),
                &[(address, 9, unix_time_secs())],
                unix_time_secs(),
            );
            shared.address_book = Some(Arc::clone(&book));
            let lease = test_lease(
                LeaseOrigin::Automatic,
                if protected {
                    BanProtection::Protected
                } else {
                    BanProtection::Unprotected
                },
            );
            shared.peer_table.register(address, lease.clone());
            let mut wire = Vec::new();
            if protected {
                crate::wire::write_message(&mut wire, shared.magic, &Message::Verack)?;
            }
            crate::wire::write_message(
                &mut wire,
                shared.magic,
                &Message::Version(crate::handshake::version_message(
                    42,
                    0,
                    PeerRole::FullRelay,
                    ServiceFlags::from(9),
                    USER_AGENT,
                )),
            )?;
            let update_at = (!repeated_version).then_some(u64::try_from(wire.len())?);
            if repeated_version {
                crate::wire::write_message(
                    &mut wire,
                    shared.magic,
                    &Message::Version(crate::handshake::version_message(
                        43,
                        0,
                        PeerRole::FullRelay,
                        ServiceFlags::from(1),
                        USER_AGENT,
                    )),
                )?;
            } else {
                crate::wire::write_message(&mut wire, shared.magic, &Message::WtxidRelay)?;
                crate::wire::write_message(&mut wire, shared.magic, &Message::Verack)?;
            }
            let mut peer = Peer::new(
                ServiceUpdateScript {
                    bytes: std::io::Cursor::new(wire),
                    update_at,
                    book: Arc::clone(&book),
                    addr: address,
                },
                shared.magic,
            );
            let result = run_outbound_handshake(
                &mut peer,
                44,
                0,
                &lease,
                Instant::now() + Duration::from_secs(1),
                address,
                &shared,
            );
            if repeated_version {
                if protected {
                    assert!(matches!(result, Err(PeerError::Io(_))));
                } else {
                    assert!(matches!(
                        result,
                        Err(PeerError::Misbehavior("duplicate version message"))
                    ));
                }
            } else {
                result?;
                assert_eq!(peer.state, crate::PeerState::Ready);
            }
            book.save();
            let bytes = std::fs::read(directory.path().join("peers-f9beb4d9.dat"))?;
            let stored: sonic_rs::Value = sonic_rs::from_slice(&bytes[..bytes.len() - 32])?;
            assert_eq!(
                stored["records"][0]["services"],
                if repeated_version { 9 } else { 1033 },
                "accepted VERSION replaces flags; later feature/VERACK must preserve a fresh gossip update"
            );
            assert_eq!(stored["records"][0]["last_success"], 0);
            assert_eq!(stored["records"][0]["tried"], false);
        }
        Ok(())
    }

    #[test]
    fn invalid_wire_session_closes_and_refuses_the_link_with_reconnection_delay() -> TestResult {
        let shared = shared();
        let address: PeerEndpoint = "8.8.8.8:8333".parse()?;
        let stale = test_lease(LeaseOrigin::Automatic, BanProtection::Unprotected);
        shared.peer_table.register(address, stale.clone());
        let current = test_lease(LeaseOrigin::Automatic, BanProtection::Unprotected);
        shared.peer_table.register(address, current.clone());
        let fault = PeerError::Incoming(Box::new(PeerError::BadChecksum));
        shared.note_misbehavior(address, &stale, &fault);
        assert!(!shared.banned.is_discouraged(address.address()));
        for error in [
            PeerError::Protocol("outbound queue closed"),
            PeerError::Protocol("network inactive"),
            PeerError::Protocol("p2p startup cancelled"),
            PeerError::Protocol("outbound peer lacks desirable services"),
            PeerError::PayloadTooLarge(usize::MAX),
            PeerError::Io(io::Error::from(io::ErrorKind::TimedOut)),
            PeerError::inbound(PeerError::WrongNetwork {
                expected: Magic::BITCOIN,
                actual: Magic::from_bytes([0x2f, 0x1a, 0x7c, 0x05]),
            }),
        ] {
            shared.note_misbehavior(address, &current, &error);
        }
        assert!(
            !shared.banned.is_discouraged(address.address()),
            "local/backpressure/policy failures are not remote misbehavior"
        );
        shared.note_misbehavior(address, &current, &fault);
        assert!(shared.banned.is_discouraged(address.address()));
        assert!(
            shared.banned.read().is_empty(),
            "automatic avoidance must not become a manual ban"
        );
        assert!(matches!(
            shared.check_automatic_destination(address),
            Err(PeerError::DiscouragedDestination(_))
        ));
        assert!(
            shared.check_manual_destination(address).is_ok(),
            "manual dials bypass automatic avoidance"
        );
        assert!(
            !shared
                .banned
                .automatic_snapshot(SystemTime::now())
                .allows(address.address())
        );
        Ok(())
    }

    #[test]
    fn manual_and_protected_local_connections_never_discourage_an_ip() -> TestResult {
        for inbound in [false, true] {
            let shared = shared();
            let address: PeerEndpoint = "8.8.8.8:8333".parse()?;
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let mut sender = TcpStream::connect(listener.local_addr()?)?;
            let (stream, _) = listener.accept()?;
            configure_peer_stream(&stream)?;
            let counters = Arc::new(crate::PeerCounters::default());
            let local = stream.local_addr()?;
            let mut peer = Peer::new(
                crate::CountingStream::new(stream, Arc::clone(&counters)),
                Magic::BITCOIN,
            );
            peer.state = crate::PeerState::Ready;
            let (tx, rx) = crossbeam_channel::unbounded();
            let lease = if inbound {
                PeerLease::new_inbound(tx)
            } else {
                PeerLease::new(tx)
            };
            let probe = lease.clone();
            shared.peer_table.register(address, lease.clone());
            let version = crate::handshake::version_message(
                42,
                0,
                PeerRole::FullRelay,
                ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                USER_AGENT,
            );
            let mut info =
                crate::PeerInfo::outbound_from_version(address, local, &version, 0, 0, counters);
            info.inbound = inbound;
            let mut malformed = Vec::new();
            crate::wire::write_message(&mut malformed, Magic::BITCOIN, &Message::Ping(7))?;
            malformed[20] ^= 1;
            io::Write::write_all(&mut sender, &malformed)?;
            io::Write::write_all(&mut sender, &malformed)?;
            let Err(error) = run_connected_session(&mut peer, address, &shared, lease, rx, info)
            else {
                return Err(TestError::Missing(
                    "malformed frames must close the session with an error",
                ));
            };
            assert!(matches!(error, PeerError::Incoming(_)));
            assert!(probe.is_cancelled());
            assert!(shared.peer_table.sessions().is_empty());
            assert!(matches!(
                shared.check_automatic_destination(address),
                Err(PeerError::DiscouragedDestination(_))
            ));
            assert!(shared.banned.read().is_empty());
        }
        Ok(())
    }

    #[test]
    fn protected_handshake_discards_bad_order_without_extending_deadline() -> TestResult {
        for (ip, manual, noban) in [
            ("8.8.8.8", true, false),
            ("8.8.4.4", false, true),
            ("127.0.0.1", false, false),
            ("::ffff:127.0.0.1", false, false),
            ("::1", false, false),
        ] {
            let shared = shared();
            let address = PeerEndpoint::new(ip.parse::<std::net::IpAddr>()?, 8333);
            let origin = if manual {
                LeaseOrigin::Manual
            } else {
                LeaseOrigin::Automatic
            };
            let protection = if noban {
                BanProtection::Protected
            } else {
                BanProtection::Unprotected
            };
            let lease = test_lease(origin, protection);
            shared.peer_table.register(address, lease.clone());
            let error = PeerError::Misbehavior("getheaders locator too large");
            shared.note_misbehavior(address, &lease, &error);
            assert!(!shared.banned.is_discouraged(address.address()), "{ip}");
            assert_eq!(lease.ignores_protocol_error(&error), manual || noban);
            assert!(
                !lease.ignores_protocol_error(&PeerError::inbound(PeerError::WrongNetwork {
                    expected: Magic::BITCOIN,
                    actual: Magic::REGTEST
                })),
                "unread framing cannot be safely resumed"
            );
        }
        Ok(())
    }

    #[test]
    fn only_current_remote_protocol_faults_change_automatic_avoidance() -> TestResult {
        for manual in [false, true] {
            let origin = if manual {
                LeaseOrigin::Manual
            } else {
                LeaseOrigin::Automatic
            };
            let protection = if manual {
                BanProtection::Unprotected
            } else {
                BanProtection::Protected
            };
            let lease = test_lease(origin, protection);
            let mut bytes = Vec::new();
            crate::wire::write_message(&mut bytes, Magic::REGTEST, &Message::Verack)?;
            crate::wire::write_message(
                &mut bytes,
                Magic::REGTEST,
                &Message::Version(crate::handshake::version_message(
                    42,
                    0,
                    PeerRole::FullRelay,
                    ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                    USER_AGENT,
                )),
            )?;
            crate::wire::write_message(&mut bytes, Magic::REGTEST, &Message::Verack)?;
            let mut peer = Peer::new(std::io::Cursor::new(bytes), Magic::REGTEST);
            let (accepted, _) = crate::handshake::next_handshake_step(
                &mut peer,
                &lease,
                Instant::now() + Duration::from_secs(1),
            )?;
            assert!(matches!(accepted, Message::Version(_)));
            let (accepted, _) = crate::handshake::next_handshake_step(
                &mut peer,
                &lease,
                Instant::now() + Duration::from_secs(1),
            )?;
            assert!(matches!(accepted, Message::Verack));
            assert_eq!(peer.state, crate::peer::PeerState::Ready);
        }
        Ok(())
    }
}

#[cfg(test)]
mod dial_cleanup_tests {
    #![expect(clippy::expect_used, reason = "fixture setup must fail loudly")]

    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use super::{ConnectionOrigin, FailureAccounting, TransportChoice, dial, test_shared};
    use crate::PeerRole;

    #[test]
    fn a_failed_cancel_guard_removes_the_registered_outbound_lease() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let shared = Arc::new(test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        ));
        shared.fail_cancel_clone.store(true, Ordering::Relaxed);

        let outcome = dial(
            address.into(),
            &shared,
            PeerRole::FullRelay,
            ConnectionOrigin::Manual,
            FailureAccounting::Ignore,
            TransportChoice::ForceV1,
        );

        assert!(
            matches!(
                &outcome,
                Err(crate::PeerError::Io(error))
                    if error.to_string() == "test-injected cancel clone failure"
            ),
            "the injected cancel-guard failure must fail the dial: {outcome:?}"
        );
        assert!(
            !shared.peer_table.is_connected(address),
            "the dial must not leave the registered lease in the peer table"
        );
    }
}

#[cfg(test)]
mod keepalive_loop_tests {
    #![expect(
        clippy::expect_used,
        reason = "fixture setup and frame reads must fail loudly"
    )]

    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bitcoin::p2p::Magic;

    use super::{run_connected_session, test_shared};
    use crate::peer::PeerState;
    use crate::test_support::synthetic_peer;
    use crate::{Message, Peer, PeerEndpoint, PeerRemote};

    #[test]
    fn a_silent_outbound_peer_gets_the_keepalive_ping_and_is_expired() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).expect("client connect");
        let (server, _accepted_addr) = listener.accept().expect("accept");

        let table = Arc::new(crate::PeerTable::new());
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = Arc::new(test_shared(Arc::clone(&table), headers_tx, blocks_tx));
        let _ = shared
            .test_keepalive_intervals
            .set((Duration::from_millis(100), Duration::from_millis(2_500)));

        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let source = PeerEndpoint::from(address);
        table.register(source, lease.clone());

        let counters = Arc::new(crate::PeerCounters::default());
        let stream =
            crate::CountingStream::from_connected(server, counters).expect("counting stream");
        let negotiated = crate::transport::Negotiated::v1(shared.magic);
        let mut peer = Peer::with_transport(stream, shared.magic, negotiated);
        peer.state = PeerState::Ready;

        let info = synthetic_peer(PeerRemote::Endpoint(source), 0);
        let session_shared = Arc::clone(&shared);
        let session = std::thread::spawn(move || {
            run_connected_session(&mut peer, source, &session_shared, lease, outbound_rx, info)
        });

        let started = Instant::now();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("client read timeout");
        let ping = read_ping(&client, shared.magic);
        drop(ping);
        assert!(
            started.elapsed() <= Duration::from_secs(3),
            "the keepalive ping must arrive at the first poll after the ping interval"
        );

        let exit = session.join().expect("session thread");
        assert!(
            exit.is_ok(),
            "expiry closes the session without a transport error: {exit:?}"
        );
        assert!(
            started.elapsed() <= Duration::from_secs(6),
            "a silent peer is expired after the timeout interval, not held forever"
        );
    }

    fn read_ping(client: &TcpStream, magic: Magic) -> Message {
        loop {
            let (message, _raw) = crate::wire::read_message(&mut &*client, magic)
                .expect("client reads session frames");
            if matches!(message, Message::Ping(_)) {
                return message;
            }
        }
    }
}

#[cfg(test)]
mod v2_transport_tests {
    use bitcoin_rs_consensus::primitives::{PeerEndpoint, USER_AGENT};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use bitcoin::p2p::{Magic, ServiceFlags};
    use bitcoin::secp256k1::rand::SeedableRng as _;
    use bitcoin::secp256k1::rand::rngs::StdRng;

    use super::configure_peer_stream;
    use super::{
        ConnectionShared, bind_listener, run_message_loop, run_outbound_handshake, serve,
        spawn_pinned_outbound_connection, test_shared,
    };
    use crate::bip324::{Handshake, msg_type};
    use crate::connection::QueuedFrame;
    use crate::transport::{Negotiated, SendTransport, TransportProtocol, establish};
    use crate::{Message, Peer, PeerError, PeerLease, PeerRole, PeerTable, wire};

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Peer(#[from] PeerError),
        #[error(transparent)]
        RecvTimeout(#[from] crossbeam_channel::RecvTimeoutError),
        #[error(transparent)]
        Listener(#[from] crate::listener::ListenerError),
        #[error("missing: {0}")]
        Missing(&'static str),
        #[error("failure: {0}")]
        Failure(String),
    }

    impl From<&'static str> for TestError {
        fn from(msg: &'static str) -> Self {
            Self::Failure(msg.to_string())
        }
    }

    impl From<String> for TestError {
        fn from(msg: String) -> Self {
            Self::Failure(msg)
        }
    }

    type TestResult = Result<(), TestError>;

    const MAGIC: Magic = Magic::BITCOIN;

    fn v1_shared() -> (ConnectionShared, Arc<PeerTable>) {
        let table = Arc::new(PeerTable::new());
        let mut shared = test_shared(
            Arc::clone(&table),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        shared.v2_transport = false;
        (shared, table)
    }

    fn v2_shared() -> (ConnectionShared, Arc<PeerTable>) {
        let table = Arc::new(PeerTable::new());
        let mut shared = test_shared(
            Arc::clone(&table),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        shared.v2_transport = true;
        shared.local_services |= ServiceFlags::P2P_V2;
        (shared, table)
    }

    fn lease() -> PeerLease {
        PeerLease::new(crossbeam_channel::unbounded().0)
    }

    fn lease_with_replies() -> (PeerLease, crossbeam_channel::Receiver<QueuedFrame>) {
        let (outbound, replies) = crossbeam_channel::unbounded();
        (PeerLease::new(outbound), replies)
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(20)
    }

    type Listening = (
        PeerEndpoint,
        bitcoin_rs_consensus::latch::LatchWriter,
        std::thread::JoinHandle<()>,
    );

    fn listen(shared: ConnectionShared) -> Result<Listening, TestError> {
        let listener = bind_listener(
            PeerEndpoint::from(([127, 0, 0, 1], 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;
        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let reader = shutdown.reader();
        let handle = std::thread::spawn(move || {
            let _ = serve(listener, reader, shared);
        });
        Ok((addr.into(), shutdown, handle))
    }

    fn connect(addr: PeerEndpoint) -> Result<TcpStream, TestError> {
        let stream = TcpStream::connect(
            addr.socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        configure_peer_stream(&stream)?;
        Ok(stream)
    }

    fn read_until(peer: &mut Peer<TcpStream>, wanted: &Message) -> Result<(), TestError> {
        let deadline = deadline();
        while Instant::now() < deadline {
            match peer.read_message() {
                Ok(Some((message, _))) if &message == wanted => return Ok(()),
                Ok(_) => {}
                Err(PeerError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(TestError::Missing("the wanted message never arrived"))
    }

    fn handshake_and_ping(
        addr: PeerEndpoint,
        stream: TcpStream,
        negotiated: Negotiated,
    ) -> TestResult {
        let (client, _) = v1_shared();
        let lease = lease();
        let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
        run_outbound_handshake(&mut peer, 7, 0, &lease, deadline(), addr, &client)?;
        peer.send(&Message::Ping(41))?;
        read_until(&mut peer, &Message::Pong(41))
    }

    #[test]
    fn bip434_windows_preserve_bip332_and_package_negotiation_on_v1_and_v2() -> TestResult {
        use crate::feature::{FEATURE_VERSION, FeatureAnnouncement};
        use crate::packages::{PKG_RELAY_ANC, PKG_RELAY_PKGTXNS, SendPackages};
        for v2 in [false, true] {
            for version in [FEATURE_VERSION - 1, FEATURE_VERSION] {
                let (mut listener_shared, table) = if v2 { v2_shared() } else { v1_shared() };
                listener_shared.relay_offers = super::RelayOffers {
                    package_relay: true,
                    stale_tip_relay: true,
                    stale_tip_prefers_blocks: true,
                };
                let (addr, shutdown, handle) = listen(listener_shared)?;
                let result = (|| -> TestResult {
                    let mut stream = connect(addr)?;
                    let negotiated = if v2 {
                        let mut handshake =
                            Handshake::initiator(MAGIC, &mut StdRng::seed_from_u64(434));
                        establish(&mut stream, &mut handshake, MAGIC, &lease(), deadline())?
                    } else {
                        Negotiated::v1(MAGIC)
                    };
                    let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
                    let mut announcement = crate::handshake::version_message(
                        434,
                        0,
                        PeerRole::FullRelay,
                        ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                        USER_AGENT,
                    );
                    announcement.version = version;
                    peer.send(&Message::Version(announcement))?;
                    let until = deadline();
                    let mut commands = Vec::new();
                    loop {
                        if Instant::now() >= until {
                            return Err("server handshake timed out".into());
                        }
                        match peer.read_message() {
                            Ok(Some((message, _))) => {
                                commands.push(message.command().to_string());
                                crate::fsm::step(&mut peer, &message)?;
                                if message == Message::Verack {
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(PeerError::Io(error)) if crate::recv::is_poll_timeout(&error) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    let mut expected = vec!["version", "wtxidrelay", "sendaddrv2", "sendheaders"];
                    if version >= FEATURE_VERSION {
                        expected.push("feature");
                    }
                    expected.extend(["sendpackages", "verack"]);
                    assert_eq!(commands, expected);
                    assert_eq!(
                        peer.remote_feature(b"BIP332"),
                        (version >= FEATURE_VERSION).then_some([1].as_slice())
                    );
                    if version >= FEATURE_VERSION {
                        peer.send(&Message::Feature(FeatureAnnouncement::bip332(true)))?;
                    }
                    peer.send(&Message::WtxidRelay)?;
                    peer.send(&Message::SendPackages(SendPackages {
                        versions: PKG_RELAY_PKGTXNS | PKG_RELAY_ANC,
                    }))?;
                    peer.send(&Message::Verack)?;
                    assert!(matches!(
                        peer.send(&Message::Feature(FeatureAnnouncement::bip332(true))),
                        Err(PeerError::Protocol(_))
                    ));
                    peer.send(&Message::Ping(434))?;
                    read_until(&mut peer, &Message::Pong(434))?;
                    Ok(())
                })();
                table.cancel_all();
                shutdown.trigger();
                handle.join().map_err(|_| "listener panicked")?;
                result?;
            }
        }
        Ok(())
    }

    // P2P-11
    #[test]
    fn a_v2_listener_negotiates_bip324_with_a_v2_initiator() -> TestResult {
        let (listener_shared, _) = v2_shared();
        let (addr, shutdown, handle) = listen(listener_shared)?;

        let mut stream = connect(addr)?;
        let mut handshake = Handshake::initiator(MAGIC, &mut StdRng::seed_from_u64(1));
        let negotiated = establish(&mut stream, &mut handshake, MAGIC, &lease(), deadline())?;
        assert!(matches!(negotiated.protocol, TransportProtocol::V2 { .. }));
        handshake_and_ping(addr, stream, negotiated)?;

        shutdown.trigger();
        handle.join().map_err(|_| "listener panicked")?;
        Ok(())
    }

    #[test]
    fn a_v2_listener_still_serves_a_v1_peer() -> TestResult {
        let (listener_shared, _) = v2_shared();
        let (addr, shutdown, handle) = listen(listener_shared)?;

        handshake_and_ping(addr, connect(addr)?, Negotiated::v1(MAGIC))?;

        shutdown.trigger();
        handle.join().map_err(|_| "listener panicked")?;
        Ok(())
    }

    #[test]
    fn an_outbound_v2_dial_negotiates_bip324() -> TestResult {
        let server = TcpListener::bind(
            PeerEndpoint::from(([127, 0, 0, 1], 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = server.local_addr()?;
        let responder = std::thread::spawn(move || -> Result<TransportProtocol, String> {
            let (stream, _) = server.accept().map_err(|error| error.to_string())?;
            configure_peer_stream(&stream).map_err(|error| error.to_string())?;
            let mut stream = stream;
            let lease = lease();
            let mut handshake = Handshake::responder(MAGIC, &mut StdRng::seed_from_u64(2));
            let negotiated = establish(&mut stream, &mut handshake, MAGIC, &lease, deadline())
                .map_err(|error| error.to_string())?;
            let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
            crate::handshake::run_inbound_handshake(
                &mut peer,
                9,
                0,
                ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                USER_AGENT,
                &lease,
                deadline(),
            )
            .map_err(|error| error.to_string())?;
            peer.send(&Message::Ping(42))
                .map_err(|error| error.to_string())?;
            read_until(&mut peer, &Message::Pong(42)).map_err(|error| error.to_string())?;
            Ok(peer.transport())
        });

        let (dialer, dialer_table) = v2_shared();
        let dial = spawn_pinned_outbound_connection(addr.into(), dialer, PeerRole::FullRelay);
        let protocol = responder.join().map_err(|_| "responder panicked")??;
        assert!(matches!(protocol, TransportProtocol::V2 { .. }));

        dialer_table.cancel_all();
        let _ = dial.join().map_err(|_| "dialer panicked")?;
        Ok(())
    }

    // P2P-11
    #[test]
    fn both_ends_publish_the_negotiated_v2_session() -> TestResult {
        let (listener_shared, listener_table) = v2_shared();
        let (addr, shutdown, handle) = listen(listener_shared)?;

        let (dialer, dialer_table) = v2_shared();
        let dial = spawn_pinned_outbound_connection(addr, dialer, PeerRole::FullRelay);
        let deadline = deadline();
        let published = loop {
            if let (Some(outbound), Some(inbound)) = (
                dialer_table.infos().into_iter().next(),
                listener_table.infos().into_iter().next(),
            ) {
                break Some((outbound, inbound));
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };

        dialer_table.cancel_all();
        let _ = dial.join().map_err(|_| "dialer panicked")?;
        shutdown.trigger();
        handle.join().map_err(|_| "listener panicked")?;

        let (outbound, inbound) = published.ok_or("the v2 connection never published both ends")?;
        let TransportProtocol::V2 { session_id } = outbound.transport else {
            return Err(format!("the dialer published {:?}", outbound.transport).into());
        };
        assert_eq!(
            inbound.transport,
            TransportProtocol::V2 { session_id },
            "both ends derive the same session id"
        );
        Ok(())
    }

    // P2P-11
    #[test]
    fn an_unanswered_v2_dial_retries_once_over_v1() -> TestResult {
        let (listener_shared, listener_table) = v1_shared();
        let (addr, shutdown, handle) = listen(listener_shared)?;

        let (dialer, dialer_table) = v2_shared();
        let dial = spawn_pinned_outbound_connection(addr, dialer, PeerRole::FullRelay);
        let deadline = deadline();
        let dialed = loop {
            let dialed = dialer_table.infos();
            if !dialed.is_empty() && !listener_table.infos().is_empty() {
                break Some(dialed);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let accepted = listener_table.len();

        dialer_table.cancel_all();
        let _ = dial.join().map_err(|_| "dialer panicked")?;
        shutdown.trigger();
        handle.join().map_err(|_| "listener panicked")?;

        let dialed = dialed.ok_or("the v1 retry never completed its handshake")?;
        assert_eq!(accepted, 1, "only the v1 retry stayed connected");
        assert!(
            dialed
                .iter()
                .all(|info| info.transport == TransportProtocol::V1),
            "the retry publishes v1"
        );
        Ok(())
    }

    #[test]
    fn a_silent_responder_ends_at_the_handshake_deadline() -> TestResult {
        let server = TcpListener::bind(
            PeerEndpoint::from(([127, 0, 0, 1], 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = server.local_addr()?;
        let mut stream = connect(addr.into())?;
        let (_held, _) = server.accept()?;
        let mut handshake = Handshake::initiator(MAGIC, &mut StdRng::seed_from_u64(3));
        let started = Instant::now();
        let result = establish(
            &mut stream,
            &mut handshake,
            MAGIC,
            &lease(),
            started + Duration::from_millis(1500),
        );
        assert!(
            matches!(&result, Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut),
            "{result:?}"
        );
        assert!(!handshake.received_any(), "a silent peer allows a v1 retry");
        assert!(started.elapsed() < Duration::from_secs(10));
        Ok(())
    }

    fn wait_for_writer_done(done_wait: &crossbeam_channel::Receiver<()>) {
        let started = Instant::now();
        loop {
            match done_wait.recv_timeout(Duration::from_millis(200)) {
                Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the decoy writer never finished after the stop"
            );
        }
    }

    fn spawn_decoy_then_ping_writer(
        server: TcpListener,
        stop: Arc<AtomicBool>,
        writer_lease: PeerLease,
        done: crossbeam_channel::Sender<()>,
    ) -> std::thread::JoinHandle<Result<(), String>> {
        std::thread::spawn(move || -> Result<(), String> {
            let (stream, _) = loop {
                match server.accept() {
                    Ok(pair) => break pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::Relaxed) {
                            return Ok(());
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            };
            configure_peer_stream(&stream).map_err(|error| error.to_string())?;
            let mut stream = stream;
            let mut handshake = Handshake::initiator(MAGIC, &mut StdRng::seed_from_u64(4));
            let negotiated = establish(
                &mut stream,
                &mut handshake,
                MAGIC,
                &writer_lease,
                deadline(),
            )
            .map_err(|error| error.to_string())?;
            if !matches!(negotiated.protocol, TransportProtocol::V2 { .. }) {
                return Err("expected a v2 transport".into());
            }
            let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
            crate::handshake::run_inbound_handshake(
                &mut peer,
                9,
                0,
                ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                USER_AGENT,
                &writer_lease,
                deadline(),
            )
            .map_err(|error| error.to_string())?;
            let mut cipher = match peer.take_send_transport() {
                Some(SendTransport::V2(cipher)) => cipher,
                _ => return Err("expected a v2 send transport".into()),
            };
            for _ in 0..2 {
                let decoy = cipher
                    .seal(&[0; 16], &[], true)
                    .map_err(|error| error.to_string())?;
                std::io::Write::write_all(&mut peer.stream, &decoy)
                    .map_err(|error| error.to_string())?;
            }
            let payload =
                wire::encode_payload(&Message::Ping(41)).map_err(|error| error.to_string())?;
            let contents = msg_type::encode(&Message::Ping(41).command(), &payload);
            let ping = cipher
                .seal(&contents, &[], false)
                .map_err(|error| error.to_string())?;
            std::io::Write::write_all(&mut peer.stream, &ping)
                .map_err(|error| error.to_string())?;

            while !stop.load(Ordering::Relaxed) {
                let decoy = cipher
                    .seal(&[0; 16], &[], true)
                    .map_err(|error| error.to_string())?;
                match std::io::Write::write_all(&mut peer.stream, &decoy) {
                    Ok(()) => {}
                    Err(_) if stop.load(Ordering::Relaxed) => break,
                    Err(error) => return Err(error.to_string()),
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = done.send(());
            Ok(())
        })
    }

    #[test]
    fn a_decoy_only_peer_yields_and_lease_cancel_ends_the_loop() -> TestResult {
        let server = TcpListener::bind(
            PeerEndpoint::from(([127, 0, 0, 1], 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = server.local_addr()?;
        server.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let (writer_lease, _) = lease_with_replies();
        let (done, done_wait) = crossbeam_channel::bounded(0);
        let writer =
            spawn_decoy_then_ping_writer(server, Arc::clone(&stop), writer_lease.clone(), done);

        let result = (|| -> Result<(Result<(), PeerError>, Duration), TestError> {
            let mut stream = connect(addr.into())?;
            let mut handshake = Handshake::responder(MAGIC, &mut StdRng::seed_from_u64(5));
            let negotiated = establish(&mut stream, &mut handshake, MAGIC, &lease(), deadline())?;
            if !matches!(negotiated.protocol, TransportProtocol::V2 { .. }) {
                return Err("expected a v2 transport".into());
            }

            let (client, _) = v1_shared();
            let (lease, replies) = lease_with_replies();
            let cancel_handle = lease.clone();
            let mut peer = Peer::with_transport(stream, MAGIC, negotiated);
            run_outbound_handshake(&mut peer, 7, 0, &lease, deadline(), addr.into(), &client)?;
            let loop_handle = std::thread::spawn(move || {
                run_message_loop(&mut peer, addr, &lease, &client, None)
            });
            let arrived = Instant::now();
            let pong = loop {
                let frame = match replies.recv_timeout(Duration::from_millis(200)) {
                    Ok(frame) => frame,
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        if arrived.elapsed() >= Duration::from_secs(10) {
                            return Err(
                                "the loop never dispatched the peer's ping past the decoy run"
                                    .into(),
                            );
                        }
                        continue;
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        return Err("the loop dropped the reply queue".into());
                    }
                };
                let message = frame.into_message();
                if matches!(message, Message::Ping(_)) {
                    // The loop originates its first keepalive probe right after
                    // the handshake; it is this node's own traffic, not the
                    // peer's real message crossing the decoy run.
                    continue;
                }
                break message;
            };
            if pong != Message::Pong(41) {
                return Err("the decoy run must precede exactly one real message".into());
            }
            if replies.try_recv().is_ok() {
                return Err("the peer sent more than one real message".into());
            }
            let started = Instant::now();
            cancel_handle.cancel();
            let outcome = loop_handle
                .join()
                .map_err(|_| TestError::Missing("loop panicked"))?;
            if started.elapsed() >= Duration::from_secs(2) {
                return Err("lease cancel must end a decoy-only session promptly".into());
            }
            Ok((outcome, started.elapsed()))
        })();
        stop.store(true, Ordering::Relaxed);
        writer_lease.cancel();
        wait_for_writer_done(&done_wait);
        let writer_failure = writer
            .join()
            .map_err(|_| TestError::Missing("decoy writer panicked"));
        let (outcome, elapsed) = result?;
        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(
            elapsed < Duration::from_secs(2),
            "lease cancel must end a decoy-only session promptly"
        );
        writer_failure?.map_err(TestError::Failure)?;
        Ok(())
    }
}

#[cfg(test)]
mod getdata_pause_tests {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::io::{self, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use bitcoin::bip152::BlockTransactionsRequest;
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, Hash256, Header, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut,
        Txid, Witness, Wtxid,
    };
    use crossbeam_channel::{Receiver, Sender};

    use super::{
        ConnectionShared, Keepalive, ParkedStep, TIMEOUT_INTERVAL, WriterExit,
        configure_peer_stream, parked_tail_expired, run_message_loop, run_writer_loop,
        spawn_connection_writer, step_parked_getdata, test_shared,
    };
    use crate::connection::{OutboundBudget, SharedOutboundBudget};
    use crate::transport::SendTransport;
    use crate::{
        ChainQuery, InventoryServing, Message, Peer, PeerError, PeerLease, PeerState, PeerTable,
        TxInventory,
    };

    #[derive(Debug, thiserror::Error)]
    pub(super) enum TestError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Peer(#[from] PeerError),
        #[error(transparent)]
        Consensus(#[from] bitcoin::consensus::encode::Error),
        #[error("timeout: {0}")]
        Timeout(String),
        #[error("failure: {0}")]
        Failure(String),
        #[error("missing: {0}")]
        Missing(&'static str),
    }

    impl From<String> for TestError {
        fn from(msg: String) -> Self {
            Self::Failure(msg)
        }
    }

    impl From<&'static str> for TestError {
        fn from(msg: &'static str) -> Self {
            Self::Missing(msg)
        }
    }

    pub(super) type TestResult = Result<(), TestError>;

    pub(super) const MAGIC: Magic = Magic::BITCOIN;

    pub(super) const FAILSAFE: Duration = Duration::from_secs(20);

    pub(super) struct ScriptedChain {
        pub(super) blocks: Vec<([u8; 32], bytes::Bytes)>,
    }

    impl ChainQuery for ScriptedChain {
        fn stale_tip_announcement(
            &self,
            _tip: bitcoin_rs_consensus::primitives::Hash256,
            _peer_tips: &[bitcoin_rs_consensus::primitives::Hash256],
        ) -> Option<crate::dispatch::StaleTipHeaders> {
            None
        }
        fn headers_after(
            &self,
            _locator_hashes: &[BlockHash],
            _stop_hash: BlockHash,
            _limit: usize,
        ) -> Vec<Header> {
            Vec::new()
        }

        fn serve_inventory_blocks(
            &self,
            items: &[Inventory],
            _compact_version: Option<u64>,
            headroom: &dyn Fn() -> bool,
            serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            let mut outcome = InventoryServing::default();
            for item in items {
                let payload = match item {
                    Inventory::Block(hash) | Inventory::WitnessBlock(hash) => self
                        .blocks
                        .iter()
                        .find(|(known, _)| *known == hash.to_byte_array())
                        .map(|(_, payload)| payload),
                    _ => None,
                };
                let Some(payload) = payload else {
                    outcome.not_found.push(*item);
                    continue;
                };
                if !headroom() {
                    outcome.halted = true;
                    return Ok(outcome);
                }
                serve(Message::BlockBytes(payload.clone()))?;
            }
            Ok(outcome)
        }

        fn block_transactions(
            &self,
            _request: &BlockTransactionsRequest,
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
        ) -> Result<Option<Message>, PeerError> {
            Ok(None)
        }
    }

    pub(super) fn block(nonce: u32) -> Block {
        let mut block = Block::default();
        block.header.nonce = nonce;
        block
    }

    pub(super) fn hash_of(block: &Block) -> [u8; 32] {
        *block.block_hash().as_bytes()
    }

    pub(super) fn inventory_of(block: &Block) -> Inventory {
        Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(hash_of(block)))
    }

    pub(super) fn scripted(block: &Block) -> ([u8; 32], bytes::Bytes) {
        (
            hash_of(block),
            bytes::Bytes::from(bitcoin_rs_consensus::primitives::consensus_bytes(block)),
        )
    }

    pub(super) fn wire_len_of(message: &Message) -> Result<usize, PeerError> {
        crate::wire::wire_len(message)
    }

    struct ScriptedTxs {
        txs: Vec<Tx>,
    }

    impl TxInventory for ScriptedTxs {
        fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool {
            self.txs.iter().any(|tx| {
                let identity = if hash_is_wtxid {
                    *tx.wtxid().as_bytes()
                } else {
                    *tx.txid().as_bytes()
                };
                identity == *hash.as_byte_array()
            })
        }

        fn get_tx(&self, txid: Txid, _last_inv_sequence: u64) -> Option<Tx> {
            self.txs
                .iter()
                .find(|tx| tx.txid().as_bytes() == txid.as_bytes())
                .cloned()
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid, _last_inv_sequence: u64) -> Option<Tx> {
            self.txs
                .iter()
                .find(|tx| tx.wtxid().as_bytes() == wtxid.as_bytes())
                .cloned()
        }

        fn resident_ancestor_package(
            &self,
            _wtxid: Wtxid,
            _last_inv_sequence: u64,
        ) -> Option<Vec<Wtxid>> {
            None
        }

        fn resident_package(&self, _wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
            None
        }

        fn package_for_relay(
            &self,
            _wtxids: &[Wtxid],
            _last_inv_sequence: u64,
        ) -> Option<Vec<Arc<Tx>>> {
            self.resident_package(_wtxids)
        }
    }

    fn tiny_tx(byte: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                    vout: 0,
                },
                script_sig: vec![byte].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x6A].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn tx_inventory_of(tx: &Tx) -> Inventory {
        Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()))
    }

    pub(super) fn shared_with(chain: ScriptedChain) -> ConnectionShared {
        shared_with_query(chain)
    }

    pub(super) fn shared_with_query(chain: impl ChainQuery + 'static) -> ConnectionShared {
        let mut shared = test_shared(
            Arc::new(PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        shared.chain_query = Some(Arc::new(chain));
        shared
    }

    fn shared_with_txs(chain: ScriptedChain, txs: ScriptedTxs) -> ConnectionShared {
        let mut shared = shared_with(chain);
        shared.tx_inventory = Some(Arc::new(txs));
        let policy = super::transaction_poll_tests::MockTxPolicy::with_serving_sequence(0);
        shared.tx_policy = Some(Arc::new(policy));
        shared
    }

    struct GatedSocketWriter {
        socket: TcpStream,
        gate: Receiver<()>,
    }

    impl Write for GatedSocketWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _ = self.gate.recv();
            self.socket.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.socket.flush()
        }
    }

    pub(super) enum WriterKind {
        Gated,
        Production { write_timeout: Duration },
    }

    pub(super) struct Served {
        pub(super) client: Peer<TcpStream>,
        pub(super) lease: PeerLease,
        pub(super) budget: Arc<OutboundBudget>,
        gate: Option<Sender<()>>,
        outcome: Receiver<Result<(), PeerError>>,
        session: Option<JoinHandle<()>>,
        writer: Option<JoinHandle<()>>,
    }

    impl Served {
        pub(super) fn start(
            shared: ConnectionShared,
            budget: OutboundBudget,
            writer: &WriterKind,
        ) -> Result<Self, TestError> {
            Self::start_on(shared, budget, None, writer)
        }

        pub(super) fn start_on(
            shared: ConnectionShared,
            budget: OutboundBudget,
            aggregate: Option<&Arc<SharedOutboundBudget>>,
            writer: &WriterKind,
        ) -> Result<Self, TestError> {
            let listener = TcpListener::bind(
                PeerEndpoint::from(([127, 0, 0, 1], 0))
                    .socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            )?;
            let client_stream = TcpStream::connect(listener.local_addr()?)?;
            let (server_stream, addr) = listener.accept()?;
            configure_peer_stream(&client_stream)?;
            configure_peer_stream(&server_stream)?;
            if let WriterKind::Production { write_timeout } = writer {
                server_stream.set_write_timeout(Some(*write_timeout))?;
            }
            let writer_socket = server_stream.try_clone()?;

            let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
            let mut lease = PeerLease::new_with_budget(outbound_tx, true, budget);
            if let Some(aggregate) = aggregate {
                lease = lease.with_shared_budget(aggregate);
            }
            let handle = lease.budget_handle();
            let close = lease.close_signal();

            let (gate, writer_thread) = match writer {
                WriterKind::Gated => {
                    let (gate_tx, gate_rx) = crossbeam_channel::bounded::<()>(0);
                    let writer_budget = Arc::clone(&handle);
                    let thread = std::thread::spawn(move || {
                        let _exit = WriterExit {
                            budget: writer_budget,
                            outbound_rx: &outbound_rx,
                        };
                        let mut gated = GatedSocketWriter {
                            socket: writer_socket,
                            gate: gate_rx,
                        };
                        run_writer_loop(
                            &outbound_rx,
                            close,
                            &mut gated,
                            &mut SendTransport::V1(MAGIC),
                            &crate::PeerCounters::default(),
                            None,
                        );
                        let _ = gated.socket.shutdown(Shutdown::Both);
                    });
                    (Some(gate_tx), thread)
                }
                WriterKind::Production { .. } => {
                    let thread = spawn_connection_writer(
                        crate::CountingStream::new(
                            writer_socket,
                            Arc::new(crate::PeerCounters::default()),
                        )
                        .recording_send_activity(lease.send_activity()),
                        SendTransport::V1(MAGIC),
                        outbound_rx,
                        close,
                        Arc::clone(&handle),
                        addr,
                        None,
                    )?;
                    (None, thread)
                }
            };

            let mut peer = Peer::new(server_stream, MAGIC);
            peer.state = PeerState::Ready;
            let session_lease = lease.clone();
            let (outcome_tx, outcome) = crossbeam_channel::bounded(1);
            let session = std::thread::spawn(move || {
                let result = run_message_loop(&mut peer, addr, &session_lease, &shared, None);
                let _ = outcome_tx.send(result);
            });
            Ok(Self {
                client: Peer::new(client_stream, MAGIC),
                lease,
                budget: handle,
                gate,
                outcome,
                session: Some(session),
                writer: Some(writer_thread),
            })
        }

        pub(super) fn open_gate(&mut self) {
            drop(self.gate.take());
        }

        pub(super) fn session_outcome(
            &self,
            within: Duration,
        ) -> Result<Result<(), PeerError>, String> {
            self.outcome
                .recv_timeout(within)
                .map_err(|_| format!("the session loop did not return within {within:?}"))
        }
    }

    impl Drop for Served {
        fn drop(&mut self) {
            self.open_gate();
            self.lease.cancel();
            let _ = self.client.stream.shutdown(Shutdown::Both);
            for thread in [self.session.take(), self.writer.take()]
                .into_iter()
                .flatten()
            {
                let _ = thread.join();
            }
        }
    }

    pub(super) fn wait_until(what: &str, mut condition: impl FnMut() -> bool) -> TestResult {
        let deadline = Instant::now() + FAILSAFE;
        while !condition() {
            if Instant::now() >= deadline {
                return Err(TestError::Timeout(format!("timed out waiting for {what}")));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    pub(super) fn read_messages(
        client: &mut Peer<TcpStream>,
        count: usize,
    ) -> Result<Vec<Message>, TestError> {
        let deadline = Instant::now() + FAILSAFE;
        let mut received = Vec::new();
        while received.len() < count {
            if Instant::now() >= deadline {
                return Err(TestError::Timeout(format!(
                    "only {received:?} arrived, wanted {count} messages"
                )));
            }
            match client.read_message() {
                Ok(Some((message, _))) => received.push(message),
                Ok(None) => {}
                Err(PeerError::Io(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(received)
    }

    // P2P-01
    #[test]
    fn block_and_control_messages_do_not_read_transaction_serving_cutoff() -> TestResult {
        let policy =
            Arc::new(super::transaction_poll_tests::MockTxPolicy::with_serving_sequence(0));
        let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
        shared.tx_policy = Some(policy.clone());
        let mut served = Served::start(
            shared,
            OutboundBudget::with_block_reserve(8, 1 << 20, 1024),
            &WriterKind::Production {
                write_timeout: FAILSAFE,
            },
        )?;
        let block = Inventory::Block(bitcoin::BlockHash::from_byte_array([7; 32]));
        for message in [
            Message::Headers(Vec::new()),
            Message::Inv(vec![block]),
            Message::GetData(vec![block]),
            Message::Ping(12),
        ] {
            served.client.send(&message)?;
        }
        let received = read_messages(&mut served.client, 3)?;
        assert!(matches!(received.first(), Some(Message::Ping(_))));
        assert_eq!(
            &received[1..],
            &[Message::NotFound(vec![block]), Message::Pong(12)]
        );
        assert_eq!(
            policy
                .serving_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        let tx = Inventory::WTx(bitcoin::Wtxid::from_byte_array([8; 32]));
        served.client.send(&Message::GetData(vec![tx]))?;
        served.client.send(&Message::Ping(13))?;
        assert_eq!(
            read_messages(&mut served.client, 2)?,
            vec![Message::NotFound(vec![tx]), Message::Pong(13)]
        );
        assert_eq!(
            policy
                .serving_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(!served.lease.is_cancelled());
        Ok(())
    }

    // P2P-01
    #[test]
    fn unannounced_transaction_requests_fail_closed_in_message_loop() -> TestResult {
        for observer_installed in [false, true] {
            let tx = tiny_tx(1);
            let txid = bitcoin::Txid::from_byte_array(*tx.txid().as_bytes());
            let items = vec![
                Inventory::Transaction(txid),
                Inventory::WitnessTransaction(txid),
                Inventory::WTx(bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes())),
            ];
            let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
            shared.tx_inventory = Some(Arc::new(ScriptedTxs { txs: vec![tx] }));
            if observer_installed {
                shared.tx_policy = Some(Arc::new(
                    super::transaction_poll_tests::MockTxPolicy::default(),
                ));
            }
            let mut served = Served::start(
                shared,
                OutboundBudget::with_block_reserve(8, 1 << 20, 1024),
                &WriterKind::Production {
                    write_timeout: FAILSAFE,
                },
            )?;
            served.client.send(&Message::GetData(items.clone()))?;
            served.client.send(&Message::Ping(12))?;
            let received = read_messages(&mut served.client, 3)?;
            assert!(matches!(received.first(), Some(Message::Ping(_))));
            assert_eq!(
                &received[1..],
                &[Message::NotFound(items), Message::Pong(12)]
            );
            assert!(!served.lease.is_cancelled());
        }
        Ok(())
    }

    // P2P-01
    #[test]
    fn parked_transaction_tail_checks_current_inventory_cutoff() -> TestResult {
        for announced_while_parked in [false, true] {
            let tx = tiny_tx(1);
            let item = tx_inventory_of(&tx);
            let (outbound_tx, outbound_rx) = crate::test_support::message_channel();
            let lease = PeerLease::new_with_budget(
                outbound_tx,
                true,
                OutboundBudget::with_block_reserve(1, 1 << 20, 1024),
            );
            lease
                .send(Message::Ping(1))
                .map_err(|_| "fixture queue admits one frame")?;
            let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
            shared.tx_inventory = Some(Arc::new(ScriptedTxs {
                txs: vec![tx.clone()],
            }));
            let mut peer = parked_peer(vec![item]);
            let mut keepalive = Keepalive::starting(Instant::now());
            let mut parked_since = None;
            step_parked_getdata(
                &mut peer,
                &shared,
                &lease,
                lease.source(None),
                &mut keepalive,
                &mut parked_since,
            )?;
            assert_eq!(peer.pending_getdata, vec![item]);
            assert_eq!(outbound_rx.try_recv(), Ok(Message::Ping(1)));
            if announced_while_parked {
                let policy = super::transaction_poll_tests::MockTxPolicy::with_serving_sequence(0);
                shared.tx_policy = Some(Arc::new(policy));
            }
            step_parked_getdata(
                &mut peer,
                &shared,
                &lease,
                lease.source(None),
                &mut keepalive,
                &mut parked_since,
            )?;
            assert!(peer.pending_getdata.is_empty());
            if announced_while_parked {
                assert_eq!(outbound_rx.try_recv(), Ok(Message::Tx(tx)));
                assert!(peer.pending_notfound.is_empty());
            } else {
                assert_eq!(outbound_rx.try_recv(), Ok(Message::NotFound(vec![item])));
                assert!(peer.pending_notfound.is_empty());
            }
            assert!(!lease.is_cancelled());
        }
        Ok(())
    }

    #[test]
    fn saturated_getdata_parks_tail_and_serves_it_after_drain() -> TestResult {
        let (block_a, block_b) = (block(1), block(2));
        let (entry_a, entry_b) = (scripted(&block_a), scripted(&block_b));
        let unknown_tx = Inventory::Transaction(bitcoin::Txid::from_byte_array([7; 32]));
        let block_len = wire_len_of(&Message::BlockBytes(entry_a.1.clone()))?;
        let notfound_len = wire_len_of(&Message::NotFound(vec![unknown_tx]))?;
        let ping_len = wire_len_of(&Message::Ping(3))?;
        // Sized so block A plus the miss's notfound fill the data lane while
        // block B and the pong park; the keepalive probe rides the bounded
        // control lane and never enters these counts.
        let budget = OutboundBudget::with_block_reserve(100, block_len + notfound_len, block_len);
        let chain = ScriptedChain {
            blocks: vec![entry_a, entry_b],
        };
        let mut served = Served::start(shared_with(chain), budget, &WriterKind::Gated)?;

        served.client.send(&Message::GetData(vec![
            unknown_tx,
            inventory_of(&block_a),
            inventory_of(&block_b),
        ]))?;
        served.client.send(&Message::Ping(7))?;

        let parked = (2, block_len + notfound_len);
        wait_until("block A and the notfound to be queued", || {
            served.budget.pending() == parked && served.budget.control_pending() == (1, ping_len)
        })?;
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            served.budget.pending(),
            parked,
            "a parked tail and an unread ping queue nothing more behind a saturated writer"
        );
        assert!(
            !served.lease.is_cancelled(),
            "saturation parks the peer instead of disconnecting it"
        );

        served.open_gate();
        let received = read_messages(&mut served.client, 5)?;
        let [probe, drained @ ..] = &received[..] else {
            panic!("expected five drained messages, got {received:?}");
        };
        assert!(
            matches!(probe, Message::Ping(_)),
            "the originated keepalive probe drains first: {received:?}"
        );
        assert_eq!(
            drained,
            vec![
                Message::Block(bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    block_a
                )),
                Message::NotFound(vec![unknown_tx]),
                Message::Block(bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    block_b
                )),
                Message::Pong(7),
            ],
            "request order, the miss before the tail, and the waiting ping last"
        );
        assert!(!served.lease.is_cancelled());

        served.lease.cancel();
        let outcome = served.session_outcome(FAILSAFE)?;
        assert!(outcome.is_ok(), "{outcome:?}");
        Ok(())
    }

    #[test]
    fn paused_peer_that_never_reads_ends_on_write_timeout() -> TestResult {
        let flood = block(3);
        let payload = bytes::Bytes::from(vec![0_u8; 1 << 20]);
        let block_len = wire_len_of(&Message::BlockBytes(payload.clone()))?;
        let budget = OutboundBudget::with_block_reserve(100_000, 3 * block_len, block_len);
        let chain = ScriptedChain {
            blocks: vec![(hash_of(&flood), payload)],
        };
        let mut served = Served::start(
            shared_with(chain),
            budget,
            &WriterKind::Production {
                write_timeout: Duration::from_millis(500),
            },
        )?;

        served
            .client
            .send(&Message::GetData(vec![inventory_of(&flood); 256]))?;

        let outcome = served.session_outcome(FAILSAFE)?;
        assert!(
            outcome.is_ok(),
            "the writer's death ends the parked session cleanly: {outcome:?}"
        );
        assert!(served.budget.writer_dead());
        wait_until("the dead writer's queued frames to release", || {
            served.budget.pending() == (0, 0)
        })?;
        Ok(())
    }

    #[test]
    fn lease_cancel_ends_a_parked_session() -> TestResult {
        let (block_a, block_b) = (block(4), block(5));
        let (entry_a, entry_b) = (scripted(&block_a), scripted(&block_b));
        let block_len = wire_len_of(&Message::BlockBytes(entry_a.1.clone()))?;
        let ping_len = wire_len_of(&Message::Ping(3))?;
        let budget = OutboundBudget::with_block_reserve(100, 2 * block_len - 1, block_len);
        let chain = ScriptedChain {
            blocks: vec![entry_a, entry_b],
        };
        let mut served = Served::start(shared_with(chain), budget, &WriterKind::Gated)?;
        served.client.send(&Message::GetData(vec![
            inventory_of(&block_a),
            inventory_of(&block_b),
        ]))?;
        wait_until("block A to be queued", || {
            served.budget.pending() == (1, block_len)
                && served.budget.control_pending() == (1, ping_len)
        })?;
        std::thread::sleep(Duration::from_millis(200));

        let started = Instant::now();
        served.lease.cancel();
        let outcome = served.session_outcome(FAILSAFE)?;

        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a parked session wakes within its poll interval"
        );
        Ok(())
    }

    #[test]
    fn tiny_item_flood_pauses_at_the_item_cap_and_drains_in_order() -> TestResult {
        let txs: Vec<Tx> = (1..=5).map(tiny_tx).collect();
        let tx_len = wire_len_of(&Message::Tx(tiny_tx(1)))?;
        let budget = OutboundBudget::with_block_reserve(3, 1 << 20, tx_len);
        let shared = shared_with_txs(
            ScriptedChain { blocks: Vec::new() },
            ScriptedTxs { txs: txs.clone() },
        );
        let mut served = Served::start(shared, budget, &WriterKind::Gated)?;
        let unknown = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([9; 32]));
        let mut items = vec![unknown];
        items.extend(txs.iter().map(tx_inventory_of));

        served.client.send(&Message::GetData(items))?;

        // Regression guard: the originated keepalive probe rides the bounded
        // control lane, so a saturated data queue still carries three whole
        // transactions of useful outbound data instead of two behind a probe.
        let ping_len = wire_len_of(&Message::Ping(0))?;
        let full = (3, 3 * tx_len);
        wait_until("the probe and three transactions to be queued", || {
            served.budget.pending() == full && served.budget.control_pending() == (1, ping_len)
        })?;
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            served.budget.pending(),
            full,
            "a full queue takes not even the parked miss's notfound"
        );
        assert!(
            !served.lease.is_cancelled(),
            "a queue full by item count parks the peer instead of disconnecting it"
        );

        served.open_gate();
        let received = read_messages(&mut served.client, 7)?;
        let [probe, drained @ ..] = &received[..] else {
            panic!("expected seven drained messages, got {received:?}");
        };
        assert!(
            matches!(probe, Message::Ping(_)),
            "the originated keepalive probe drains first: {received:?}"
        );
        assert_eq!(
            drained,
            vec![
                Message::Tx(txs[0].clone()),
                Message::Tx(txs[1].clone()),
                Message::Tx(txs[2].clone()),
                Message::NotFound(vec![unknown]),
                Message::Tx(txs[3].clone()),
                Message::Tx(txs[4].clone()),
            ],
            "request order, with the miss reported once the queue could take it"
        );
        wait_until("the writer to release every frame", || {
            served.budget.pending() == (0, 0)
        })?;
        served.client.send(&Message::Ping(9))?;
        assert_eq!(
            read_messages(&mut served.client, 1)?,
            vec![Message::Pong(9)],
            "the session reads again once the tail is served"
        );
        assert!(!served.lease.is_cancelled());

        served.lease.cancel();
        let outcome = served.session_outcome(FAILSAFE)?;
        assert!(outcome.is_ok(), "{outcome:?}");
        Ok(())
    }

    #[test]
    fn a_getdata_that_fills_the_last_slot_parks_its_trailing_notfound_and_the_next_pong()
    -> TestResult {
        let txs: Vec<Tx> = (1..=3).map(tiny_tx).collect();
        let tx_len = wire_len_of(&Message::Tx(tiny_tx(1)))?;
        let budget = OutboundBudget::with_block_reserve(3, 1 << 20, tx_len);
        let shared = shared_with_txs(
            ScriptedChain { blocks: Vec::new() },
            ScriptedTxs { txs: txs.clone() },
        );
        let mut served = Served::start(shared, budget, &WriterKind::Gated)?;
        let unknown = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([9; 32]));

        served.client.send(&Message::GetData(vec![
            tx_inventory_of(&txs[0]),
            tx_inventory_of(&txs[1]),
            unknown,
            tx_inventory_of(&txs[2]),
        ]))?;
        served.client.send(&Message::Ping(11))?;

        // The keepalive probe rides the control lane; the data lane fills with
        // the three request hits.
        let ping_len = wire_len_of(&Message::Ping(0))?;
        let full = (3, 3 * tx_len);
        wait_until("the probe and three transactions to be queued", || {
            served.budget.pending() == full && served.budget.control_pending() == (1, ping_len)
        })?;
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            served.budget.pending(),
            full,
            "the full queue takes neither the trailing notfound nor the next pong"
        );
        assert!(
            !served.lease.is_cancelled(),
            "filling the last slot is not a reason to disconnect a reader"
        );

        served.open_gate();
        let received = read_messages(&mut served.client, 6)?;
        let [probe, drained @ ..] = &received[..] else {
            panic!("expected six drained messages, got {received:?}");
        };
        assert!(
            matches!(probe, Message::Ping(_)),
            "the originated keepalive probe drains first: {received:?}"
        );
        assert_eq!(
            drained,
            vec![
                Message::Tx(txs[0].clone()),
                Message::Tx(txs[1].clone()),
                Message::Tx(txs[2].clone()),
                Message::NotFound(vec![unknown]),
                Message::Pong(11),
            ],
            "the notfound follows the transactions and the pong follows the notfound"
        );
        assert!(!served.lease.is_cancelled());

        served.lease.cancel();
        let outcome = served.session_outcome(FAILSAFE)?;
        assert!(outcome.is_ok(), "{outcome:?}");
        Ok(())
    }

    #[test]
    fn a_drained_getdata_holds_reads_until_the_queue_can_take_a_reply() -> TestResult {
        let (outbound_tx, outbound_rx) = crate::test_support::message_channel();
        let lease = PeerLease::new_with_budget(
            outbound_tx,
            true,
            OutboundBudget::with_block_reserve(1, 1 << 20, 1),
        );
        lease
            .send(Message::Ping(1))
            .map_err(|_| "a fresh queue admits its one message")?;
        let shared = shared_with(ScriptedChain { blocks: Vec::new() });
        let mut peer = parked_peer(Vec::new());
        let mut keepalive = Keepalive::starting(Instant::now());
        let mut parked_since = Some(Instant::now());

        let held = step_parked_getdata(
            &mut peer,
            &shared,
            &lease,
            lease.source(None),
            &mut keepalive,
            &mut parked_since,
        )?;

        assert_eq!(held, ParkedStep::StillParked, "the one slot is taken");
        assert!(parked_since.is_some(), "the hold keeps its start");
        assert!(!lease.is_cancelled());

        assert_eq!(
            outbound_rx.try_recv(),
            Ok(Message::Ping(1)),
            "the writer takes the queued ping, and its slot returns"
        );
        let released = step_parked_getdata(
            &mut peer,
            &shared,
            &lease,
            lease.source(None),
            &mut keepalive,
            &mut parked_since,
        )?;

        assert_eq!(released, ParkedStep::NotParked, "a slot is free again");
        assert_eq!(parked_since, None, "reads resume and the marker clears");
        assert!(outbound_rx.is_empty(), "the hold sends nothing");
        Ok(())
    }

    #[test]
    fn production_writer_marks_the_budget_dead_when_a_write_fails() -> TestResult {
        let listener = TcpListener::bind(
            PeerEndpoint::from(([127, 0, 0, 1], 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (server, addr) = listener.accept()?;
        drop(client);
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(outbound_tx);
        let writer = spawn_connection_writer(
            crate::CountingStream::new(server, Arc::new(crate::PeerCounters::default())),
            SendTransport::V1(MAGIC),
            outbound_rx,
            lease.close_signal(),
            lease.budget_handle(),
            addr,
            None,
        )?;

        let died = wait_until("the writer to die", || {
            let _ = lease.send(Message::Ping(1));
            lease.budget_handle().writer_dead()
        });
        lease.cancel();
        let _ = writer.join();
        died
    }

    #[test]
    fn a_full_queue_keeps_the_misses_and_sends_nothing() -> TestResult {
        let (outbound_tx, outbound_rx) = crate::test_support::message_channel();
        let lease = PeerLease::new_with_budget(
            outbound_tx,
            true,
            OutboundBudget::with_block_reserve(1, 1 << 20, 1),
        );
        lease
            .send(Message::Ping(1))
            .map_err(|_| "a fresh queue admits one message")?;
        let shared = shared_with(ScriptedChain { blocks: Vec::new() });
        let tail = vec![Inventory::WitnessBlock(
            bitcoin::BlockHash::from_byte_array([2; 32]),
        )];
        let miss = Inventory::Transaction(bitcoin::Txid::from_byte_array([3; 32]));
        let mut peer = parked_peer(tail.clone());
        peer.pending_notfound = vec![miss];
        let mut keepalive = Keepalive::starting(Instant::now());
        let mut parked_since = None;

        let step = step_parked_getdata(
            &mut peer,
            &shared,
            &lease,
            lease.source(None),
            &mut keepalive,
            &mut parked_since,
        )?;

        assert_eq!(step, ParkedStep::StillParked);
        assert_eq!(
            outbound_rx.try_iter().collect::<Vec<_>>(),
            vec![Message::Ping(1)],
            "nothing was sent into the full queue"
        );
        assert_eq!(peer.pending_notfound, vec![miss]);
        assert_eq!(peer.pending_getdata, tail);
        assert!(!lease.is_cancelled());
        Ok(())
    }

    pub(super) fn parked_peer(tail: Vec<Inventory>) -> Peer<io::Cursor<Vec<u8>>> {
        let mut peer = Peer::new(io::Cursor::new(Vec::new()), MAGIC);
        peer.state = PeerState::Ready;
        peer.pending_getdata = tail;
        peer
    }

    #[test]
    fn nothing_parked_clears_the_marker_and_reads_on() -> TestResult {
        let lease = PeerLease::new(crossbeam_channel::unbounded().0);
        let shared = shared_with(ScriptedChain { blocks: Vec::new() });
        let mut peer = parked_peer(Vec::new());
        let mut keepalive = Keepalive::starting(Instant::now());
        let mut parked_since = Some(Instant::now());

        let step = step_parked_getdata(
            &mut peer,
            &shared,
            &lease,
            lease.source(None),
            &mut keepalive,
            &mut parked_since,
        )?;

        assert_eq!(step, ParkedStep::NotParked);
        assert_eq!(parked_since, None, "a drained tail forgets its start");
        Ok(())
    }

    #[test]
    fn a_dead_writer_ends_a_parked_step_without_waiting() -> TestResult {
        let lease = PeerLease::new(crossbeam_channel::unbounded().0);
        lease.budget_handle().mark_writer_dead();
        let shared = shared_with(ScriptedChain { blocks: Vec::new() });
        let tail = vec![Inventory::WitnessBlock(
            bitcoin::BlockHash::from_byte_array([1; 32]),
        )];
        let mut peer = parked_peer(tail.clone());
        let mut keepalive = Keepalive::starting(Instant::now());
        let mut parked_since = None;

        let started = Instant::now();
        let step = step_parked_getdata(
            &mut peer,
            &shared,
            &lease,
            lease.source(None),
            &mut keepalive,
            &mut parked_since,
        )?;

        assert_eq!(step, ParkedStep::Ended);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            parked_since.is_some(),
            "the tail's age starts at its first park"
        );
        assert_eq!(
            peer.pending_getdata, tail,
            "ending the session drops nothing silently"
        );
        Ok(())
    }

    #[test]
    fn a_tail_expires_only_after_the_timeout_interval() {
        let parked = Instant::now();
        assert!(!parked_tail_expired(parked, parked));
        assert!(!parked_tail_expired(parked, parked + TIMEOUT_INTERVAL));
        assert!(parked_tail_expired(
            parked,
            parked + TIMEOUT_INTERVAL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn an_open_queue_resumes_notfound_first_and_reparks_what_the_gate_stops() -> TestResult {
        let (block_a, block_b) = (block(6), block(7));
        let (entry_a, entry_b) = (scripted(&block_a), scripted(&block_b));
        let block_len = wire_len_of(&Message::BlockBytes(entry_a.1.clone()))?;
        let (outbound_tx, outbound_rx) = crate::test_support::message_channel();
        let lease = PeerLease::new_with_budget(
            outbound_tx,
            true,
            OutboundBudget::with_block_reserve(100, 2 * block_len - 1, block_len),
        );
        let shared = shared_with(ScriptedChain {
            blocks: vec![entry_a.clone(), entry_b],
        });
        let miss = Inventory::Transaction(bitcoin::Txid::from_byte_array([8; 32]));
        let mut peer = parked_peer(vec![inventory_of(&block_a), inventory_of(&block_b)]);
        peer.pending_notfound = vec![miss];
        let mut keepalive = Keepalive::starting(Instant::now());
        let mut parked_since = None;

        let step = step_parked_getdata(
            &mut peer,
            &shared,
            &lease,
            lease.source(None),
            &mut keepalive,
            &mut parked_since,
        )?;

        assert_eq!(step, ParkedStep::StillParked);
        assert_eq!(
            outbound_rx.try_iter().collect::<Vec<_>>(),
            vec![
                Message::NotFound(vec![miss]),
                Message::BlockBytes(entry_a.1),
            ],
            "the earlier miss is reported before any resumed item"
        );
        assert_eq!(peer.pending_getdata, vec![inventory_of(&block_b)]);
        assert_eq!(peer.pending_notfound, Vec::new());
        assert!(!lease.is_cancelled(), "re-parking is not a disconnect");
        Ok(())
    }

    /// A reader that replays concatenated framed pings, then paces its dry
    /// reads with `WouldBlock`: inbound traffic stays live indefinitely while
    /// this side of the connection never writes.
    struct InboundPingStream {
        script: io::Cursor<Vec<u8>>,
    }

    impl io::Read for InboundPingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match io::Read::read(&mut self.script, buf) {
                Ok(0) => {
                    std::thread::sleep(Duration::from_millis(100));
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                }
                Ok(read) => Ok(read),
                Err(error) => Err(error),
            }
        }
    }

    impl io::Write for InboundPingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The socket a healthy writer owns: accepts every offered byte.
    struct AcceptsAll;

    impl io::Write for AcceptsAll {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
            Ok(buffers.iter().map(|buffer| buffer.len()).sum())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn framed_pings(count: usize) -> Vec<u8> {
        let mut script = Vec::new();
        for nonce in 0..u64::try_from(count).unwrap_or(u64::MAX) {
            crate::wire::write_message(&mut script, MAGIC, &Message::Ping(nonce))
                .unwrap_or_else(|error| panic!("encode ping {nonce}: {error}"));
        }
        script
    }

    /// Backdates the lease's send-activity clock so `margin` of real time
    /// separates `last_write` from the send-silence threshold.
    fn backdated_send_clock(margin: Duration) -> Result<Instant, TestError> {
        let since_last_write = TIMEOUT_INTERVAL
            .checked_sub(margin)
            .ok_or("the margin must stay under the timeout interval")?;
        Instant::now()
            .checked_sub(since_last_write)
            .ok_or_else(|| "test instant underflow".into())
    }

    #[test]
    fn blocked_writer_send_silence_expires_despite_inbound_traffic() -> TestResult {
        // A stalled writer: no thread consumes the outbound queue, so the
        // socket accepts nothing while the queue keeps admitting frames.
        let margin = Duration::from_secs(10);
        let last_write = backdated_send_clock(margin)?;
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(outbound_tx);
        *lease.send_activity().lock() = last_write;
        let shared = shared_with(ScriptedChain { blocks: Vec::new() });
        let mut peer = crate::Peer::new(
            InboundPingStream {
                script: io::Cursor::new(framed_pings(64)),
            },
            MAGIC,
        );
        peer.state = PeerState::Ready;
        let session_lease = lease.clone();
        let (outcome_tx, outcome_rx) = crossbeam_channel::bounded(1);
        let session = std::thread::spawn(move || {
            let _ = outcome_tx.send(run_message_loop(
                &mut peer,
                PeerEndpoint::from(([127, 0, 0, 1], 18_449)),
                &session_lease,
                &shared,
                None,
            ));
        });

        // Below the threshold the session must stay up: inbound pings keep the
        // receive clock fresh and the originated probe merely queues.
        std::thread::sleep(margin / 2);
        assert!(
            matches!(
                outcome_rx.try_recv(),
                Err(crossbeam_channel::TryRecvError::Empty)
            ),
            "an admit-only probe and fresh inbound traffic must not expire the loop early"
        );
        let ping_len = wire_len_of(&Message::Ping(0))?;
        assert_eq!(
            lease.budget_handle().control_pending(),
            (1, ping_len),
            "the probe was admitted to the control lane while nothing was written"
        );

        let outcome = outcome_rx
            .recv_timeout(FAILSAFE)
            .map_err(|_| "the session did not expire within the failsafe")?;
        session.join().map_err(|_| "session join")?;
        assert!(
            outcome.is_ok(),
            "send-silence expiry at TIMEOUT_INTERVAL past the last actual write is a clean close: {outcome:?}"
        );
        assert!(
            last_write.elapsed() >= margin,
            "expiry must wait out the send clock, not fire on the first pass"
        );
        assert!(
            matches!(
                outbound_rx.try_recv().map(|frame| frame.into_message()),
                Ok(Message::Ping(_))
            ),
            "the probe stayed queued ahead of the pongs: admitted, never written"
        );
        Ok(())
    }

    #[test]
    fn healthy_writer_actual_writes_reset_the_send_silence_clock() -> TestResult {
        let margin = Duration::from_secs(10);
        let last_write = backdated_send_clock(margin)?;
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(outbound_tx);
        *lease.send_activity().lock() = last_write;
        let shared = shared_with(ScriptedChain { blocks: Vec::new() });

        let counters = Arc::new(crate::PeerCounters::default());
        let writer = {
            let budget = lease.budget_handle();
            let close = lease.close_signal();
            let activity = lease.send_activity();
            let counters = Arc::clone(&counters);
            std::thread::spawn(move || {
                let _exit = WriterExit {
                    budget,
                    outbound_rx: &outbound_rx,
                };
                let mut sink = crate::CountingStream::new(AcceptsAll, counters)
                    .recording_send_activity(activity);
                run_writer_loop(
                    &outbound_rx,
                    close,
                    &mut sink,
                    &mut SendTransport::V1(MAGIC),
                    &crate::PeerCounters::default(),
                    None,
                );
            })
        };
        let mut peer = crate::Peer::new(
            InboundPingStream {
                script: io::Cursor::new(framed_pings(64)),
            },
            MAGIC,
        );
        peer.state = PeerState::Ready;
        let session_lease = lease.clone();
        let (outcome_tx, outcome_rx) = crossbeam_channel::bounded(1);
        let session = std::thread::spawn(move || {
            let _ = outcome_tx.send(run_message_loop(
                &mut peer,
                PeerEndpoint::from(([127, 0, 0, 1], 18_450)),
                &session_lease,
                &shared,
                None,
            ));
        });

        // The writer's accepted bytes stamp the same send-activity clock the
        // loop observes; without those stamps the backdated clock would
        // expire the session `margin` after start.
        wait_until(
            "the writer's first accepted bytes to stamp the clock",
            || lease.last_send() > last_write,
        )?;
        let started = Instant::now();
        while started.elapsed() < margin + Duration::from_secs(3) {
            assert!(
                matches!(
                    outcome_rx.try_recv(),
                    Err(crossbeam_channel::TryRecvError::Empty)
                ),
                "actual writes (the probe included) must reset the send-silence clock"
            );
            std::thread::sleep(Duration::from_millis(200));
        }

        lease.cancel();
        let outcome = outcome_rx
            .recv_timeout(FAILSAFE)
            .map_err(|_| "the session did not end after cancel")?;
        session.join().map_err(|_| "session join")?;
        writer.join().map_err(|_| "writer join")?;
        assert!(outcome.is_ok(), "{outcome:?}");
        Ok(())
    }
}

#[cfg(test)]
#[cfg(test)]
mod aggregate_budget_tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bitcoin::bip152::{BlockTransactionsRequest, HeaderAndShortIds, ShortId};
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
    use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
    use bitcoin::p2p::message_compact_blocks::{CmpctBlock, GetBlockTxn};
    use bitcoin_rs_consensus::primitives::Header;

    use super::getdata_pause_tests::{
        FAILSAFE, MAGIC, ScriptedChain, Served, TestResult, WriterKind, block, inventory_of,
        parked_peer, read_messages, scripted, shared_with, wait_until, wire_len_of,
    };
    use super::{
        DeferredStep, Keepalive, KeepaliveAction, ParkedStep, ProductionSink, TIMEOUT_INTERVAL,
        notfound_wire_bound, reply_bound, retry_deferred_request, step_parked_getdata,
    };
    use crate::connection::{OutboundBudget, Refusal, SharedOutboundBudget};
    use crate::test_support::hog;
    use crate::{Message, PeerLease};

    #[test]
    fn compact_completion_reserves_before_consuming_pending_and_transfers_image_credit()
    -> TestResult {
        struct EmptyHints;
        impl crate::compact_blocks::CompactBlockHints for EmptyHints {
            fn for_each_identity(
                &self,
                _: &mut dyn FnMut(
                    bitcoin_rs_consensus::primitives::Txid,
                    bitcoin_rs_consensus::primitives::Wtxid,
                ),
            ) {
            }
            fn get_tx_by_txid(
                &self,
                _: bitcoin_rs_consensus::primitives::Txid,
            ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
                None
            }
            fn get_tx_by_wtxid(
                &self,
                _: bitcoin_rs_consensus::primitives::Wtxid,
            ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
                None
            }
        }
        for scenario in ["complete", "cancelled", "full"] {
            let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
            let mut compact = HeaderAndShortIds::from_block(&block, 7, 2, &[])
                .map_err(|_| "genesis compact block")?;
            let keys = ShortId::calculate_siphash_keys(&block.header, 7);
            compact.prefilled_txs.clear();
            compact.short_ids = vec![ShortId::with_siphash_keys(
                block.txdata[0].compute_wtxid().as_byte_array(),
                keys,
            )];
            let mut reconstruction = crate::compact_blocks::Reconstruction::new();
            assert!(matches!(
                reconstruction.receive_cmpctblock(
                    &CmpctBlock {
                        compact_block: compact
                    },
                    2,
                    &EmptyHints,
                    Instant::now(),
                ),
                crate::compact_blocks::Outcome::RequestMissing(_)
            ));
            let message = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
                transactions: bitcoin::bip152::BlockTransactions {
                    block_hash: block.block_hash(),
                    transactions: block.txdata.clone(),
                },
            });
            let (queue, _receiver) = crate::test_support::message_channel();
            let lease = PeerLease::new(queue);
            let sink = ProductionSink::new(&lease, None);
            let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
            let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(1);
            shared.blocks_tx = blocks_tx;
            let ledger = Arc::clone(shared.block_memory.ledger());
            let capacity = ledger.capacity();
            let held = if scenario == "full" {
                Some(shared.block_memory.reserve(capacity, || false)?)
            } else {
                None
            };
            if scenario == "cancelled" {
                lease.cancel();
            }
            super::process_compact_wire_message(
                &message,
                &mut reconstruction,
                Some(2),
                None,
                &sink,
                bitcoin_rs_consensus::primitives::PeerEndpoint::from(([127, 0, 0, 1], 8333)),
                &shared,
            );
            if scenario != "complete" {
                assert_eq!(reconstruction.pending_len(), 1);
                assert!(blocks_rx.is_empty());
            } else {
                assert_eq!(reconstruction.pending_len(), 0);
                let inbound = blocks_rx
                    .recv_timeout(FAILSAFE)
                    .map_err(|_| "reconstructed block was not delivered")?;
                assert!(!ledger.try_take(capacity));
                drop(inbound);
            }
            drop(reconstruction);
            drop(held);
            assert!(ledger.try_take(capacity));
            ledger.give_back(capacity);
        }
        Ok(())
    }

    #[test]
    fn headroom_retains_one_credit() -> TestResult {
        let reserve = 1_000;
        let aggregate = Arc::new(SharedOutboundBudget::with_limits(reserve + 64, 64));
        let (queue, receiver) = crate::test_support::message_channel();
        let lease = PeerLease::new_with_budget(
            queue,
            true,
            OutboundBudget::with_block_reserve(100, 1 << 20, reserve),
        )
        .with_shared_budget(&aggregate);
        let sink = ProductionSink::new(&lease, None);

        assert!(sink.headroom());
        assert!(
            sink.headroom(),
            "a second reservation would not fit; the held credit is reused"
        );
        assert!(sink.headroom());
        assert_eq!(
            aggregate.pending(),
            reserve,
            "repeated headroom charges the aggregate once"
        );
        assert!(
            matches!(lease.try_reserve_production(), Err(Refusal::Shared)),
            "the one credit the bulk limit allows is the sink's"
        );
        assert_eq!(sink.refusal(), None, "nothing was refused to the sink");

        sink.send(Message::Pong(1))
            .map_err(|_| "a send under the held reservation")?;
        assert_eq!(
            aggregate.pending(),
            wire_len_of(&Message::Pong(1))?,
            "the spent credit shrank to the frame it carries"
        );
        assert!(
            !sink.headroom(),
            "with the frame still queued, a new reservation no longer fits"
        );
        assert_eq!(sink.refusal(), Some(Refusal::Shared));

        assert_eq!(receiver.try_recv(), Ok(Message::Pong(1)));
        assert_eq!(
            aggregate.pending(),
            0,
            "the writer's drop returns the frame"
        );
        assert!(sink.headroom(), "room is reserved again once it returns");
        Ok(())
    }

    #[test]
    fn parked_misses_reserved_before_build() -> TestResult {
        let miss = Inventory::Transaction(bitcoin::Txid::from_byte_array([3; 32]));
        let bound = notfound_wire_bound(1);
        let aggregate = Arc::new(SharedOutboundBudget::with_limits(10 * bound, 0));
        let hogged = 10 * bound - (bound - 1);
        let hold = hog(&aggregate, hogged);
        let (queue, receiver) = crate::test_support::message_channel();
        let lease = PeerLease::new(queue).with_shared_budget(&aggregate);
        let shared = shared_with(ScriptedChain { blocks: Vec::new() });
        let mut peer = parked_peer(Vec::new());
        peer.pending_notfound = vec![miss];
        let mut keepalive = Keepalive::starting(Instant::now());
        let mut parked_since = None;

        let step = step_parked_getdata(
            &mut peer,
            &shared,
            &lease,
            lease.source(None),
            &mut keepalive,
            &mut parked_since,
        )?;

        assert_eq!(step, ParkedStep::StillParked);
        assert_eq!(
            peer.pending_notfound,
            vec![miss],
            "a refused reservation takes nothing out of the list"
        );
        assert!(receiver.is_empty());
        assert_eq!(aggregate.pending(), hogged, "a refusal charges nothing");
        assert!(
            keepalive.shared_refused,
            "the aggregate's refusal is a stall, not an error"
        );
        assert!(!lease.is_cancelled());

        drop(hold);
        step_parked_getdata(
            &mut peer,
            &shared,
            &lease,
            lease.source(None),
            &mut keepalive,
            &mut parked_since,
        )?;

        assert_eq!(peer.pending_notfound, Vec::new());
        assert_eq!(receiver.try_recv(), Ok(Message::NotFound(vec![miss])));
        assert_eq!(aggregate.pending(), 0);
        Ok(())
    }

    #[test]
    fn reply_bound_covers_actual_replies() -> TestResult {
        assert_eq!(
            reply_bound(&Message::Ping(1), false),
            Some(wire_len_of(&Message::Pong(u64::MAX))?)
        );

        let get_headers = Message::GetHeaders(GetHeadersMessage::new(
            Vec::new(),
            bitcoin::BlockHash::all_zeros(),
        ));
        let full_headers = Message::Headers(vec![
            Header::default();
            crate::wire::MAX_HEADERS_MESSAGE_COUNT
        ]);
        assert_eq!(
            reply_bound(&get_headers, false),
            Some(wire_len_of(&full_headers)?)
        );

        assert_eq!(reply_bound(&Message::GetAddr, false), None);
        let socket = bitcoin_rs_consensus::primitives::PeerEndpoint::from(([1, 2, 3, 4], 8333));
        let addr_v1 = Message::Addr(vec![
            (
                0,
                Address::new(
                    &socket
                        .socket_addr()
                        .unwrap_or_else(|| panic!("expected IP fixture")),
                    ServiceFlags::NONE
                )
            );
            crate::wire::MAX_ADDR_MESSAGE_COUNT
        ]);
        let addr_v2 = Message::AddrV2(vec![
            AddrV2Message {
                time: 0,
                services: ServiceFlags::from(u64::MAX),
                addr: AddrV2::Ipv6(std::net::Ipv6Addr::LOCALHOST),
                port: 8333,
            };
            crate::wire::MAX_ADDR_MESSAGE_COUNT
        ]);
        let addr_bound = reply_bound(&Message::GetAddr, true).ok_or("an answerable getaddr")?;
        assert!(addr_bound >= wire_len_of(&addr_v1)?);
        assert!(addr_bound >= wire_len_of(&addr_v2)?);
        Ok(())
    }

    #[test]
    fn reply_bound_covers_compact_follow_ups() -> TestResult {
        let slots = 3_000_u64;
        let keys = (1, 2);
        let short_ids = (0..slots)
            .map(|slot| ShortId::with_siphash_keys(&[slot.to_le_bytes()[0]; 32], keys))
            .collect();
        let header: bitcoin::block::Header = bitcoin::consensus::deserialize(&[0_u8; 80])?;
        let cmpct = Message::CmpctBlock(CmpctBlock {
            compact_block: HeaderAndShortIds {
                header,
                nonce: 0,
                short_ids,
                prefilled_txs: Vec::new(),
            },
        });
        let block_hash = bitcoin::BlockHash::all_zeros();
        let worst_getblocktxn = Message::GetBlockTxn(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash,
                indexes: (0..slots).map(|slot| slot * 70_000).collect(),
            },
        });
        let fallback = Message::GetData(vec![Inventory::WitnessBlock(block_hash)]);
        let cmpct_bound = reply_bound(&cmpct, false).ok_or("a reserved cmpctblock")?;
        assert!(cmpct_bound >= wire_len_of(&worst_getblocktxn)?);
        assert!(cmpct_bound >= wire_len_of(&fallback)?);

        let blocktxn = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
            transactions: bitcoin::bip152::BlockTransactions {
                block_hash,
                transactions: Vec::new(),
            },
        });
        let blocktxn_bound = reply_bound(&blocktxn, false).ok_or("a reserved blocktxn")?;
        assert!(blocktxn_bound >= wire_len_of(&fallback)?);
        Ok(())
    }

    #[test]
    fn notfound_wire_bound_is_exact() -> TestResult {
        for items in [1, 2, 252, 253, 1_000] {
            let miss = Inventory::Transaction(bitcoin::Txid::from_byte_array([9; 32]));
            assert_eq!(
                notfound_wire_bound(items),
                wire_len_of(&Message::NotFound(vec![miss; items]))?,
                "{items} items"
            );
        }
        Ok(())
    }

    #[test]
    fn stall_exclusion_removes_only_shared_refusals() {
        let t0 = Instant::now();
        let since = t0 + Duration::from_secs(10);
        let long_after = t0 + TIMEOUT_INTERVAL + Duration::from_secs(100);

        let mut shared = Keepalive::starting(t0);
        let mut parked = Some(since);
        shared.note_refusal(Refusal::Shared);
        shared.settle_pass(since, &mut parked);
        assert_eq!(
            shared.stall,
            Some(since),
            "an aggregate refusal opens a stall"
        );
        assert_ne!(
            shared.next_action(long_after),
            KeepaliveAction::Expired,
            "the open stall is not silence in either direction"
        );
        assert_ne!(
            shared.next_action_while_parked(long_after),
            KeepaliveAction::Expired
        );

        shared.note_refusal(Refusal::Shared);
        shared.settle_pass(long_after, &mut parked);
        assert_eq!(
            shared.stall,
            Some(since),
            "a continued refusal keeps one stall"
        );

        shared.settle_pass(long_after, &mut parked);
        assert_eq!(shared.stall, None, "a pass without a refusal closes it");
        assert_eq!(
            parked,
            Some(long_after),
            "the parked marker moves past the stalled time"
        );
        assert_ne!(
            shared.next_action(long_after),
            KeepaliveAction::Expired,
            "the closed stall stays excluded from both directions"
        );
        assert_eq!(
            shared.next_action(long_after + TIMEOUT_INTERVAL + Duration::from_secs(1)),
            KeepaliveAction::Expired,
            "silence after the stall is counted"
        );

        let mut local = Keepalive::starting(t0);
        let mut none = None;
        local.note_refusal(Refusal::Local);
        local.settle_pass(since, &mut none);
        assert_eq!(local.stall, None, "the connection's own queue is no stall");
        assert_eq!(local.next_action(long_after), KeepaliveAction::Expired);
    }

    struct DeferredHarness {
        lease: PeerLease,
        peer: crate::Peer<std::io::Cursor<Vec<u8>>>,
        keepalive: Keepalive,
        parked_since: Option<Instant>,
    }

    impl DeferredHarness {
        fn retry(&mut self, message: Option<Message>, now: Instant) -> DeferredStep {
            self.peer.deferred_inbound = message;
            retry_deferred_request(
                &mut self.peer,
                &self.lease,
                &mut self.keepalive,
                &mut self.parked_since,
                false,
                now,
            )
        }

        fn retry_held(&mut self, now: Instant) -> DeferredStep {
            retry_deferred_request(
                &mut self.peer,
                &self.lease,
                &mut self.keepalive,
                &mut self.parked_since,
                false,
                now,
            )
        }
    }

    #[test]
    fn deferred_request_retries_and_keeps_the_existing_local_rules() -> TestResult {
        let bound = reply_bound(&Message::Ping(1), false).ok_or("a reserved ping")?;
        let aggregate = Arc::new(SharedOutboundBudget::with_limits(4 * bound, 0));
        let hold = hog(&aggregate, 3 * bound + 1);
        let (queue, _receiver) = crate::test_support::message_channel();
        let t0 = Instant::now();
        let mut harness = DeferredHarness {
            lease: PeerLease::new(queue).with_shared_budget(&aggregate),
            peer: parked_peer(Vec::new()),
            keepalive: Keepalive::starting(t0),
            parked_since: None,
        };

        assert!(matches!(harness.retry(None, t0), DeferredStep::NoneHeld));

        assert!(matches!(
            harness.retry(Some(Message::Ping(7)), t0),
            DeferredStep::Waiting
        ));
        assert_eq!(harness.peer.deferred_inbound, Some(Message::Ping(7)));
        assert!(
            harness.keepalive.shared_refused,
            "the refusal is reported as a stall"
        );
        assert!(harness.parked_since.is_some());
        assert!(!harness.lease.is_cancelled());

        drop(hold);
        let DeferredStep::Ready(message, Some(credit)) = harness.retry_held(t0) else {
            return Err("the reply is reserved once the aggregate has room".into());
        };
        assert_eq!(message, Message::Ping(7));
        assert_eq!(credit.bytes(), bound);
        assert_eq!(harness.parked_since, None);
        assert_eq!(harness.peer.deferred_inbound, None);
        drop(credit);

        let (queue, _receiver) = crate::test_support::message_channel();
        harness.lease = PeerLease::new_with_budget(
            queue,
            true,
            OutboundBudget::with_block_reserve(1, 1 << 20, 1),
        );
        harness
            .lease
            .send(Message::Ping(1))
            .map_err(|_| "a fresh queue admits one message")?;
        assert!(matches!(
            harness.retry(Some(Message::Ping(8)), t0),
            DeferredStep::Ended
        ));
        assert!(harness.lease.is_cancelled());

        let (queue, _receiver) = crate::test_support::message_channel();
        harness.lease = PeerLease::new(queue);
        harness.lease.budget_handle().mark_writer_dead();
        assert!(matches!(
            harness.retry(Some(Message::Ping(9)), t0),
            DeferredStep::Ended
        ));

        let later = t0 + TIMEOUT_INTERVAL + Duration::from_secs(5);
        let hold = hog(&aggregate, 3 * bound + 1);
        let (queue, _receiver) = crate::test_support::message_channel();
        harness.lease = PeerLease::new(queue).with_shared_budget(&aggregate);
        harness.keepalive = Keepalive::starting(t0);
        harness.parked_since = Some(t0);
        assert!(matches!(
            harness.retry(Some(Message::Ping(10)), later),
            DeferredStep::Ended
        ));
        harness.keepalive = Keepalive::starting(t0);
        harness.keepalive.stall = Some(t0);
        harness.parked_since = Some(t0);
        assert!(matches!(
            harness.retry(Some(Message::Ping(11)), later),
            DeferredStep::Waiting
        ));
        drop(hold);
        Ok(())
    }

    fn answered_once_after_the_aggregate_drains(
        request: &Message,
        expected: Message,
    ) -> TestResult {
        let bound = reply_bound(request, true).ok_or("a request-scoped reply")?;
        let aggregate = Arc::new(SharedOutboundBudget::with_limits(4 * bound, 0));
        let hold = hog(&aggregate, 3 * bound + 1);
        let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
        shared.address_book = Some(crate::addrman::AddressBook::open(
            None,
            MAGIC.to_bytes(),
            true,
            None,
        ));
        let mut served = Served::start_on(
            shared,
            OutboundBudget::with_block_reserve(100, 1 << 20, 1),
            Some(&aggregate),
            &WriterKind::Gated,
        )?;

        served.client.send(request)?;
        std::thread::sleep(Duration::from_millis(300));
        let ping_len = wire_len_of(&Message::Ping(0))?;
        assert!(
            served.budget.pending() == (0, 0) && served.budget.control_pending() <= (1, ping_len),
            "{request:?}: no reply is reserved or queued while the aggregate is full \
         (only the originated control probe may sit, on its bounded lane): {:?}",
            served.budget.pending()
        );
        assert!(
            !served.lease.is_cancelled(),
            "{request:?}: the aggregate never ends a session"
        );

        drop(hold);
        served.open_gate();
        // The message loop's first-pass keepalive probe met the same full
        // aggregate as the deferred reply: whether it was refused or queued
        // under the remaining room depends on the request's reply bound (the
        // relaxed pending check above accepts either). With room again it
        // drains first (top-of-pass), then the deferred reply follows.
        assert!(
            matches!(
                read_messages(&mut served.client, 1)?.as_slice(),
                [Message::Ping(_)]
            ),
            "{request:?}: the originated keepalive probe drains with the aggregate"
        );
        assert_eq!(
            read_messages(&mut served.client, 1)?,
            vec![expected],
            "{request:?}: the deferred request was answered exactly once"
        );
        served.client.send(&Message::Ping(99))?;
        assert_eq!(
            read_messages(&mut served.client, 1)?,
            vec![Message::Pong(99)],
            "{request:?}: the session serves fresh traffic after the drain"
        );

        served.lease.cancel();
        let outcome = served.session_outcome(FAILSAFE)?;
        assert!(outcome.is_ok(), "{outcome:?}");
        Ok(())
    }

    #[test]
    fn request_deferred_not_reply() -> TestResult {
        answered_once_after_the_aggregate_drains(&Message::Ping(7), Message::Pong(7))?;
        answered_once_after_the_aggregate_drains(
            &Message::GetHeaders(GetHeadersMessage::new(
                Vec::new(),
                bitcoin::BlockHash::all_zeros(),
            )),
            Message::Headers(Vec::new()),
        )?;
        answered_once_after_the_aggregate_drains(&Message::GetAddr, Message::Addr(Vec::new()))
    }

    #[test]
    fn a_bulk_tail_parked_on_the_aggregate_leaves_the_margin_for_control() -> TestResult {
        let block_a = block(11);
        let entry = scripted(&block_a);
        let block_len = wire_len_of(&Message::BlockBytes(entry.1.clone()))?;
        let aggregate = Arc::new(SharedOutboundBudget::with_limits(10 * block_len, block_len));
        let hold = hog(&aggregate, 8 * block_len + 1);
        let mut served = Served::start_on(
            shared_with(ScriptedChain {
                blocks: vec![entry],
            }),
            OutboundBudget::with_block_reserve(100, 1 << 20, block_len),
            Some(&aggregate),
            &WriterKind::Gated,
        )?;

        served
            .client
            .send(&Message::GetData(vec![inventory_of(&block_a)]))?;
        std::thread::sleep(Duration::from_millis(300));
        let ping_len = wire_len_of(&Message::Ping(3))?;
        wait_until("the originated keepalive probe to be queued", || {
            served.budget.control_pending() == (1, ping_len)
        })?;
        served
            .lease
            .send(Message::Ping(3))
            .map_err(|_| "the margin keeps control traffic flowing")?;
        assert_eq!(served.budget.pending(), (1, ping_len));
        assert_eq!(served.budget.control_pending(), (1, ping_len));
        assert_eq!(aggregate.pending(), 8 * block_len + 1 + 2 * ping_len);
        assert!(
            !served.lease.is_cancelled(),
            "a parked bulk tail never cancels the lease"
        );

        served.open_gate();
        assert!(
            matches!(
                read_messages(&mut served.client, 2)?.as_slice(),
                [Message::Ping(_), Message::Ping(3)],
            ),
            "the originated probe and the queued control ping drain in order"
        );
        drop(hold);
        assert_eq!(
            read_messages(&mut served.client, 1)?,
            vec![Message::Block(
                bitcoin_rs_consensus::primitives::BlockImage::from_local(block_a),
            )],
            "the tail is served once the aggregate has room"
        );

        served.lease.cancel();
        let outcome = served.session_outcome(FAILSAFE)?;
        assert!(outcome.is_ok(), "{outcome:?}");
        Ok(())
    }

    #[test]
    fn conditional_compact_defers_on_locally_full_queue() -> TestResult {
        let mut served = Served::start(
            shared_with(ScriptedChain { blocks: Vec::new() }),
            OutboundBudget::with_block_reserve(1, 1 << 20, 1),
            &WriterKind::Gated,
        )?;
        let ping_len = wire_len_of(&Message::Ping(1))?;
        // The message loop's first-pass keepalive probe rides the bounded
        // control lane; a data-path send fills the one slot the queue admits.
        wait_until(
            "the originated keepalive probe to take the control lane",
            || served.budget.control_pending() == (1, ping_len),
        )?;
        served
            .lease
            .send(Message::Ping(1))
            .map_err(|_| "a fresh queue admits its one message")?;
        assert!(
            !served.budget.writer_dead(),
            "the gated writer is live while its gate stays shut"
        );
        assert!(!served.lease.is_cancelled());

        let stray = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
            transactions: bitcoin::bip152::BlockTransactions {
                block_hash: bitcoin::BlockHash::all_zeros(),
                transactions: Vec::new(),
            },
        });
        served.client.send(&stray)?;
        std::thread::sleep(Duration::from_millis(1200));
        assert!(
            !served.lease.is_cancelled(),
            "a locally full queue defers a conditional compact reply instead of closing"
        );
        assert_eq!(
            served.budget.pending(),
            (1, ping_len),
            "an Idle compact outcome reserves and queues nothing while parked"
        );

        served.open_gate();
        assert!(
            matches!(
                read_messages(&mut served.client, 2)?.as_slice(),
                [Message::Ping(_), Message::Ping(1)]
            ),
            "the originated keepalive probe and the queued ping drain in order"
        );
        served.client.send(&Message::Ping(99))?;
        assert_eq!(
            read_messages(&mut served.client, 1)?,
            vec![Message::Pong(99)],
            "the deferred conditional was answered with nothing and the session still serves"
        );

        served.lease.cancel();
        let outcome = served.session_outcome(FAILSAFE)?;
        assert!(outcome.is_ok(), "{outcome:?}");
        Ok(())
    }

    #[test]
    fn conditional_local_retry_defers_then_readies_with_no_reply() -> TestResult {
        let t0 = Instant::now();
        let stray = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
            transactions: bitcoin::bip152::BlockTransactions {
                block_hash: bitcoin::BlockHash::all_zeros(),
                transactions: Vec::new(),
            },
        });
        let bound = reply_bound(&stray, false).ok_or("a reserved blocktxn")?;
        let (queue, receiver) = crate::test_support::message_channel();
        let lease = PeerLease::new_with_budget(
            queue,
            true,
            OutboundBudget::with_block_reserve(1, 1 << 20, 1),
        );
        lease
            .send(Message::Ping(1))
            .map_err(|_| "a fresh queue admits one message")?;
        let ping_len = wire_len_of(&Message::Ping(1))?;
        assert_eq!(lease.budget_handle().pending(), (1, ping_len));
        assert!(!lease.budget_handle().writer_dead());
        assert_eq!(lease.try_reserve_reply(bound).err(), Some(Refusal::Local));
        let mut peer = parked_peer(Vec::new());
        let mut keepalive = Keepalive::starting(t0);
        let mut parked_since = None;
        peer.deferred_inbound = Some(stray.clone());
        assert!(matches!(
            retry_deferred_request(
                &mut peer,
                &lease,
                &mut keepalive,
                &mut parked_since,
                false,
                t0
            ),
            DeferredStep::Waiting
        ));
        assert_eq!(peer.deferred_inbound, Some(stray.clone()));
        assert!(!lease.is_cancelled());
        assert!(parked_since.is_some());
        assert_eq!(lease.budget_handle().pending(), (1, ping_len));
        assert_eq!(receiver.try_recv(), Ok(Message::Ping(1)));
        assert_eq!(lease.budget_handle().pending(), (0, 0));
        let step = retry_deferred_request(
            &mut peer,
            &lease,
            &mut keepalive,
            &mut parked_since,
            false,
            t0,
        );
        let DeferredStep::Ready(message, Some(credit)) = step else {
            return Err("the reply is reserved once the local queue has room".into());
        };
        assert_eq!(message, stray);
        assert_eq!(peer.deferred_inbound, None);
        assert_eq!(parked_since, None);
        let mut recon = crate::compact_blocks::Reconstruction::new();
        let outcome = super::process_compact_message(
            &mut recon,
            &message,
            crate::peer::COMPACT_BLOCK_VERSION,
            None,
            Instant::now(),
        );
        assert!(matches!(outcome, crate::compact_blocks::Outcome::Idle));
        let sink = ProductionSink::new(&lease, Some(credit));
        let shared = shared_with(ScriptedChain { blocks: Vec::new() });
        let addr = bitcoin_rs_consensus::primitives::PeerEndpoint::from(([127, 0, 0, 1], 8333));
        assert!(super::handle_compact_outcome(outcome, &sink, addr, &shared, None).is_none());
        assert!(receiver.is_empty());
        assert!(!lease.is_cancelled());
        drop(sink);
        assert_eq!(lease.budget_handle().pending(), (0, 0));
        Ok(())
    }

    #[test]
    fn unconditional_ping_on_locally_full_queue_ends() -> TestResult {
        let t0 = Instant::now();
        let (queue, _receiver) = crate::test_support::message_channel();
        let lease = PeerLease::new_with_budget(
            queue,
            true,
            OutboundBudget::with_block_reserve(1, 1 << 20, 1),
        );
        lease
            .send(Message::Ping(1))
            .map_err(|_| "a fresh queue admits one message")?;
        let mut peer = parked_peer(Vec::new());
        let mut keepalive = Keepalive::starting(t0);
        let mut parked_since = None;
        peer.deferred_inbound = Some(Message::Ping(8));
        assert!(matches!(
            retry_deferred_request(
                &mut peer,
                &lease,
                &mut keepalive,
                &mut parked_since,
                false,
                t0
            ),
            DeferredStep::Ended
        ));
        assert!(lease.is_cancelled());
        Ok(())
    }

    #[test]
    fn conditional_local_retry_with_dead_writer_ends() {
        let t0 = Instant::now();
        let stray = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
            transactions: bitcoin::bip152::BlockTransactions {
                block_hash: bitcoin::BlockHash::all_zeros(),
                transactions: Vec::new(),
            },
        });
        let (queue, _receiver) = crate::test_support::message_channel();
        let lease = PeerLease::new(queue);
        lease.budget_handle().mark_writer_dead();
        let mut peer = parked_peer(Vec::new());
        let mut keepalive = Keepalive::starting(t0);
        let mut parked_since = None;
        peer.deferred_inbound = Some(stray);
        assert!(matches!(
            retry_deferred_request(
                &mut peer,
                &lease,
                &mut keepalive,
                &mut parked_since,
                false,
                t0
            ),
            DeferredStep::Ended
        ));
    }

    #[test]
    fn conditional_local_wait_expires_after_timeout_interval() -> TestResult {
        let t0 = Instant::now();
        let (queue, _receiver) = crate::test_support::message_channel();
        let lease = PeerLease::new_with_budget(
            queue,
            true,
            OutboundBudget::with_block_reserve(1, 1 << 20, 1),
        );
        lease
            .send(Message::Ping(1))
            .map_err(|_| "a fresh queue admits one message")?;
        let mut peer = parked_peer(Vec::new());
        let mut keepalive = Keepalive::starting(t0);
        let mut parked_since = None;
        peer.deferred_inbound = Some(Message::BlockTxn(
            bitcoin::p2p::message_compact_blocks::BlockTxn {
                transactions: bitcoin::bip152::BlockTransactions {
                    block_hash: bitcoin::BlockHash::all_zeros(),
                    transactions: Vec::new(),
                },
            },
        ));
        assert!(matches!(
            retry_deferred_request(
                &mut peer,
                &lease,
                &mut keepalive,
                &mut parked_since,
                false,
                t0
            ),
            DeferredStep::Waiting
        ));
        keepalive.settle_pass(t0, &mut parked_since);
        assert!(matches!(
            retry_deferred_request(
                &mut peer,
                &lease,
                &mut keepalive,
                &mut parked_since,
                false,
                t0 + TIMEOUT_INTERVAL + Duration::from_secs(1)
            ),
            DeferredStep::Ended
        ));
        Ok(())
    }

    // P2P-02
    #[test]
    fn holding_maximum_share_leaves_room_for_second_connection() -> TestResult {
        let aggregate = Arc::new(SharedOutboundBudget::new());
        let (tx1, _rx1) = crate::test_support::message_channel();
        let lease1 = PeerLease::new(tx1).with_shared_budget(&aggregate);
        let (tx2, _rx2) = crate::test_support::message_channel();
        let lease2 = PeerLease::new(tx2).with_shared_budget(&aggregate);

        let budget1 = lease1.budget_handle();
        let max_share = budget1.max_bytes();
        let hold = budget1
            .try_charge(max_share)
            .map_err(|_| "independent oracle requires connection to hold its full share")?;
        assert!(
            matches!(budget1.try_charge(1), Err(Refusal::Local)),
            "independent oracle: exceeding connection share must yield Local refusal"
        );

        let ping = Message::Ping(1);
        lease2.send(ping).map_err(|refusal| {
        format!("independent oracle violated: second connection starved by peer holding share: {refusal:?}")
    })?;
        assert!(
            lease2.try_reserve_production().is_ok(),
            "independent oracle: aggregate bulk headroom must remain open for other peers"
        );

        drop(hold);
        Ok(())
    }

    // P2P-02
    #[test]
    fn aggregate_never_exceeds_cap_with_concurrent_reservers() -> TestResult {
        let aggregate = Arc::new(SharedOutboundBudget::new());
        let cap = aggregate.max_bytes();
        let threads = 8;
        let iterations = 200;
        let barrier = Arc::new(std::sync::Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
        .map(|i| {
            let agg = Arc::clone(&aggregate);
            let bar = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let (tx, _rx) = crate::test_support::message_channel();
                let lease = PeerLease::new(tx).with_shared_budget(&agg);
                let budget = lease.budget_handle();
                bar.wait();
                let mut held = Vec::new();
                for step in 0..iterations {
                    let size = ((i + step) % 5 + 1) * 1024 * 1024;
                    if let Ok(credit) = budget.try_charge(size) {
                        let used = agg.pending();
                        assert!(
                            used <= cap,
                            "independent oracle violated: aggregate pending {used} exceeded cap {cap}"
                        );
                        held.push(credit);
                    }
                    if held.len() > 2 {
                        let _ = held.remove(0);
                    }
                    let used = agg.pending();
                    assert!(
                        used <= cap,
                        "independent oracle violated: aggregate pending {used} exceeded cap {cap}"
                    );
                }
                drop(held);
            })
        })
        .collect();

        for handle in handles {
            handle
                .join()
                .map_err(|_| "reserver thread joined cleanly")?;
        }

        assert_eq!(
            aggregate.pending(),
            0,
            "independent oracle: releasing all credits must return aggregate used bytes to 0"
        );
        Ok(())
    }

    // P2P-02
    #[test]
    fn releasing_credits_returns_used_to_zero() -> TestResult {
        let aggregate = Arc::new(SharedOutboundBudget::new());
        let (tx, _rx) = crate::test_support::message_channel();
        let lease = PeerLease::new(tx).with_shared_budget(&aggregate);
        let budget = lease.budget_handle();

        let credit = budget
            .try_charge(1_000_000)
            .map_err(|_| "independent oracle: fresh budget admits reservation")?;
        assert_eq!(
            aggregate.pending(),
            1_000_000,
            "independent oracle: aggregate pending equals charged credit"
        );
        drop(credit);
        assert_eq!(
            aggregate.pending(),
            0,
            "independent oracle: dropping credit returns aggregate pending bytes to 0"
        );
        Ok(())
    }
    #[derive(Debug, thiserror::Error)]
    enum CompactIngressTestError {
        #[error(transparent)]
        Peer(#[from] crate::PeerError),
        #[error(transparent)]
        Compact(#[from] bitcoin::bip152::Error),
        #[error(transparent)]
        HeaderReceive(#[from] crossbeam_channel::TryRecvError),
        #[error(transparent)]
        ForwardReceive(#[from] crossbeam_channel::RecvTimeoutError),
        #[error(transparent)]
        ForwardSignal(#[from] crossbeam_channel::SendError<()>),
        #[error("missing: {0}")]
        Missing(&'static str),
        #[error("block decoder returned another command")]
        UnexpectedCommand,
        #[error("compact worker panicked: {0:?}")]
        WorkerPanicked(Box<dyn std::any::Any + Send>),
    }

    type CompactTestResult = Result<(), CompactIngressTestError>;

    struct CompactForwarding {
        reached: crossbeam_channel::Sender<()>,
        result: parking_lot::Mutex<Option<Result<(), crossbeam_channel::SendError<()>>>>,
    }

    struct CompactAdmissionObserver {
        forwarding: Option<Arc<CompactForwarding>>,
    }

    impl super::BlockSyncObserver for CompactAdmissionObserver {
        fn announce_block(
            &self,
            _: crate::PeerSource,
            _: bitcoin_rs_consensus::primitives::Hash256,
        ) {
        }
        fn block_not_found(&self, _: crate::PeerSource, _: &[Inventory]) -> bool {
            false
        }
        fn note_header_response_received(&self, _: crate::PeerSource) {}
        fn owns_body_fetch(
            &self,
            _: crate::PeerSource,
            _: bitcoin_rs_consensus::primitives::Hash256,
        ) -> bool {
            if let Some(forwarding) = &self.forwarding {
                let result = forwarding.reached.send(());
                let delivered = result.is_ok();
                *forwarding.result.lock() = Some(result);
                return delivered;
            }
            true
        }
        fn compact_reconstruction_admissible(&self, _: crate::PeerSource, _: &Header) -> bool {
            true
        }
        fn enqueue_owned_body_fetch(
            &self,
            _: crate::PeerSource,
            _: bitcoin_rs_consensus::primitives::Hash256,
            follow_up: &mut dyn FnMut() -> bool,
        ) -> bool {
            follow_up()
        }
        fn note_stale_tip_heard(
            &self,
            _: crate::PeerSource,
            _: bitcoin_rs_consensus::primitives::Hash256,
        ) {
        }
        fn allow_extra_full_relay_dial(&self) -> bool {
            false
        }
        fn is_downloading_bodies(&self, _: crate::PeerSource) -> bool {
            true
        }
    }

    struct NoCompactTransactions;

    impl crate::compact_blocks::CompactBlockHints for NoCompactTransactions {
        fn for_each_identity(
            &self,
            _: &mut dyn FnMut(
                bitcoin_rs_consensus::primitives::Txid,
                bitcoin_rs_consensus::primitives::Wtxid,
            ),
        ) {
        }
        fn get_tx_by_txid(
            &self,
            _: bitcoin_rs_consensus::primitives::Txid,
        ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
            None
        }
        fn get_tx_by_wtxid(
            &self,
            _: bitcoin_rs_consensus::primitives::Wtxid,
        ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
            None
        }
    }

    // BUD-03, BUD-07, P2P-06, SYNC-03
    #[test]
    fn compact_admission_refusal_preserves_header_for_ordinary_sync() -> CompactTestResult {
        for remaining in [0, crate::compact_blocks::MAX_PENDING_RETAINED_BYTES] {
            let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
            let message = Message::CmpctBlock(CmpctBlock {
                compact_block: HeaderAndShortIds::from_block(&block, 7, 2, &[])?,
            });
            let expected = crate::compact_blocks::native_header(&block.header)
                .ok_or(CompactIngressTestError::Missing("native header"))?;
            let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
            shared.block_sync = Some(Arc::new(CompactAdmissionObserver { forwarding: None }));
            let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
            shared.headers_tx = headers_tx;
            let ledger = shared.block_memory.ledger();
            let held = shared
                .block_memory
                .try_reserve(ledger.capacity() - remaining)?;
            let (queue, _receiver) = crate::test_support::message_channel();
            let lease = PeerLease::new(queue);
            let endpoint =
                bitcoin_rs_consensus::primitives::PeerEndpoint::from(([127, 0, 0, 1], 8333));
            let mut reconstruction = crate::compact_blocks::Reconstruction::new();
            super::process_compact_wire_message(
                &message,
                &mut reconstruction,
                Some(2),
                Some(&NoCompactTransactions),
                &ProductionSink::new(&lease, None),
                endpoint,
                &shared,
            );
            let delivered = headers_rx.try_recv()?;
            assert_eq!(delivered.headers, vec![expected]);
            assert_eq!(delivered.source, Some(lease.source(Some(endpoint))));
            assert!(!delivered.wire_response);
            assert!(
                headers_rx.is_empty(),
                "one discovery announcement per refused compact block"
            );
            assert_eq!(reconstruction.pending_len(), 0);
            drop(held);
            assert!(
                ledger.try_take(ledger.capacity()),
                "refused optional work retains no reservation"
            );
            ledger.give_back(ledger.capacity());
        }
        Ok(())
    }

    // BUD-01, BUD-06
    #[test]
    fn compact_forward_backpressure_keeps_source_and_image_charged() -> CompactTestResult {
        for (completion, deliver) in [
            ("cmpctblock", true),
            ("blocktxn", true),
            ("cmpctblock", false),
            ("blocktxn", false),
        ] {
            let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
            let mut reconstruction = crate::compact_blocks::Reconstruction::new();
            let compact = HeaderAndShortIds::from_block(&block, 7, 2, &[])?;
            let message = if completion == "cmpctblock" {
                Message::CmpctBlock(CmpctBlock {
                    compact_block: compact,
                })
            } else {
                let mut missing = compact;
                let keys = ShortId::calculate_siphash_keys(&block.header, 7);
                missing.prefilled_txs.clear();
                missing.short_ids = vec![ShortId::with_siphash_keys(
                    block.txdata[0].compute_wtxid().as_byte_array(),
                    keys,
                )];
                assert!(matches!(
                    reconstruction.receive_cmpctblock(
                        &CmpctBlock {
                            compact_block: missing
                        },
                        2,
                        &NoCompactTransactions,
                        Instant::now(),
                    ),
                    crate::compact_blocks::Outcome::RequestMissing(_)
                ));
                Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
                    transactions: bitcoin::bip152::BlockTransactions {
                        block_hash: block.block_hash(),
                        transactions: block.txdata.clone(),
                    },
                })
            };
            let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
            let (forwarding_tx, forwarding_rx) = crossbeam_channel::bounded(1);
            let forwarding = Arc::new(CompactForwarding {
                reached: forwarding_tx,
                result: parking_lot::Mutex::new(None),
            });
            shared.block_sync = Some(Arc::new(CompactAdmissionObserver {
                forwarding: Some(Arc::clone(&forwarding)),
            }));
            let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(0);
            shared.blocks_tx = blocks_tx;
            let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
            shared.headers_tx = headers_tx;
            let ledger = Arc::clone(shared.block_memory.ledger());
            let payload = bytes::Bytes::from(bitcoin::consensus::serialize(&block));
            let Message::Block(image) = crate::wire::decode_payload("block", &payload)? else {
                return Err(CompactIngressTestError::UnexpectedCommand);
            };
            let image_bytes = image.bytes().len() + image.retained_heap_bytes();
            drop(image);
            let mut frame = Vec::new();
            crate::wire::write_message(&mut frame, MAGIC, &message)?;
            let mut peer = crate::Peer::new(std::io::Cursor::new(frame), MAGIC);
            peer.state = crate::PeerState::Ready;
            let (source_message, raw, source_credit) = peer
                .read_message_bounded(&shared.block_memory, || false)?
                .ok_or(CompactIngressTestError::Missing(
                    "one compact source message",
                ))?;
            let used_bytes = || {
                let mut available = 0;
                let mut upper = ledger.capacity();
                while available < upper {
                    let probe = available + (upper - available).div_ceil(2);
                    if ledger.try_take(probe) {
                        ledger.give_back(probe);
                        available = probe;
                    } else {
                        upper = probe - 1;
                    }
                }
                ledger.capacity() - available
            };
            let source_bytes = used_bytes();
            assert!(
                source_bytes > 0,
                "bounded receive must charge its live source"
            );
            let (queue, _receiver) = crate::test_support::message_channel();
            let lease = PeerLease::new(queue);
            let source = (source_credit, source_message, raw);
            let worker = std::thread::spawn(move || {
                let (source_credit, source_message, raw) = source;
                super::process_compact_wire_message(
                    &source_message,
                    &mut reconstruction,
                    Some(2),
                    Some(&NoCompactTransactions),
                    &ProductionSink::new(&lease, None),
                    bitcoin_rs_consensus::primitives::PeerEndpoint::from(([127, 0, 0, 1], 8333)),
                    &shared,
                );
                drop(source_message);
                drop(raw);
                drop(source_credit);
            });
            forwarding_rx.recv_timeout(FAILSAFE)?;
            let blocked_bytes = used_bytes();
            let inbound = if deliver {
                Some(blocks_rx.recv_timeout(FAILSAFE)?)
            } else {
                drop(blocks_rx);
                None
            };
            worker
                .join()
                .map_err(CompactIngressTestError::WorkerPanicked)?;
            forwarding
                .result
                .lock()
                .take()
                .ok_or(CompactIngressTestError::Missing(
                    "forwarding observer result",
                ))??;
            let downstream_bytes = used_bytes();
            drop(inbound);
            assert_eq!(
                blocked_bytes,
                source_bytes + image_bytes,
                "{completion}: blocked forwarding retains both source and reconstructed image"
            );
            assert_eq!(
                downstream_bytes,
                if deliver { image_bytes } else { 0 },
                "{completion}: source disposal leaves only the delivered image charged"
            );
            assert!(
                ledger.try_take(ledger.capacity()),
                "all retained allocations released"
            );
            ledger.give_back(ledger.capacity());
        }
        Ok(())
    }

    // BUD-06
    #[test]
    fn refused_block_forward_keeps_image_charged_until_backing_disposal() -> CompactTestResult {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        struct ImageBacking {
            bytes: Vec<u8>,
            ledger: Arc<dyn crate::inbound::block_memory::IngressLedger>,
            charge: Arc<AtomicUsize>,
            observed: Arc<AtomicBool>,
        }

        impl AsRef<[u8]> for ImageBacking {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl Drop for ImageBacking {
            fn drop(&mut self) {
                let headroom = self.ledger.capacity() - self.charge.load(Ordering::Acquire);
                let admitted_headroom = self.ledger.try_take(headroom);
                let admitted_extra = self.ledger.try_take(1);
                if admitted_extra {
                    self.ledger.give_back(1);
                }
                if admitted_headroom {
                    self.ledger.give_back(headroom);
                }
                self.observed
                    .store(admitted_headroom && !admitted_extra, Ordering::Release);
            }
        }

        let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
        shared.block_sync = None;
        let ledger = Arc::clone(shared.block_memory.ledger());
        let charge = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(AtomicBool::new(false));
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let raw = bytes::Bytes::from_owner(ImageBacking {
            bytes: bitcoin::consensus::serialize(&block),
            ledger: Arc::clone(&ledger),
            charge: Arc::clone(&charge),
            observed: Arc::clone(&observed),
        });
        let Message::Block(image) = crate::wire::decode_payload("block", &raw)? else {
            return Err(CompactIngressTestError::UnexpectedCommand);
        };
        let image_bytes = image.bytes().len() + image.retained_heap_bytes();
        let image_credit = shared.block_memory.try_reserve(image_bytes)?;
        charge.store(image_bytes, Ordering::Release);
        drop(raw);
        let (queue, _receiver) = crate::test_support::message_channel();
        let lease = PeerLease::new(queue);
        let endpoint = bitcoin_rs_consensus::primitives::PeerEndpoint::from(([127, 0, 0, 1], 8333));
        let source = lease.source(Some(endpoint));
        let hash = bitcoin_rs_consensus::primitives::Hash256::from(image.block_hash());
        let forwards: Vec<_> = (0..crate::connection::MAX_UNSOLICITED_BLOCK_FORWARDS)
            .map(|_| {
                lease.admit_block_forward(source, hash, false).ok_or(
                    CompactIngressTestError::Missing("unsolicited forwarding slot"),
                )
            })
            .collect::<Result<_, _>>()?;

        shared.send_block(&lease, endpoint, image, Some(image_credit));

        assert!(
            observed.load(Ordering::Acquire),
            "final image backing disposal must observe its complete retained-image charge"
        );
        assert!(
            ledger.try_take(ledger.capacity()),
            "refused image releases its full charge"
        );
        ledger.give_back(ledger.capacity());
        drop(forwards);
        Ok(())
    }
}

#[cfg(test)]
mod aggregate_filter_tests {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use bitcoin::bip152::BlockTransactionsRequest;
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin::p2p::message_filter::{CFilter, GetCFilters};
    use bitcoin_rs_consensus::primitives::{BlockHash, Header};

    use super::getdata_pause_tests::{
        FAILSAFE, MAGIC, Served, TestResult, WriterKind, read_messages, shared_with_query,
    };
    use super::run_message_loop;
    use crate::connection::{OutboundBudget, SharedOutboundBudget};
    use crate::peer::{FilterHalt, ParkedFilter};
    use crate::test_support::hog;
    use crate::{
        ChainQuery, FilterRequest, FilterServing, InventoryServing, Message, Peer, PeerError,
        PeerLease, PeerState,
    };

    const RESERVE: usize = 1_000;

    struct FilterChain {
        published: Arc<AtomicBool>,
        cancel_after_refusal: Option<PeerLease>,
    }

    impl FilterChain {
        fn published() -> Self {
            Self {
                published: Arc::new(AtomicBool::new(true)),
                cancel_after_refusal: None,
            }
        }

        fn unpublished() -> Self {
            Self {
                published: Arc::new(AtomicBool::new(false)),
                cancel_after_refusal: None,
            }
        }
    }

    impl ChainQuery for FilterChain {
        fn stale_tip_announcement(
            &self,
            _: bitcoin_rs_consensus::primitives::Hash256,
            _: &[bitcoin_rs_consensus::primitives::Hash256],
        ) -> Option<crate::dispatch::StaleTipHeaders> {
            None
        }
        fn serve_compact_filters(
            &self,
            request: &FilterRequest,
            headroom: &dyn Fn() -> bool,
            send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<FilterServing, PeerError> {
            if !headroom() {
                if let Some(lease) = &self.cancel_after_refusal {
                    lease.cancel();
                }
                return Ok(FilterServing::Pending(request.clone()));
            }
            if !self.published.load(Ordering::Acquire) {
                return Ok(FilterServing::Pending(request.clone()));
            }
            send(Message::CFilter(CFilter {
                filter_type: 0,
                block_hash: bitcoin::BlockHash::all_zeros(),
                filter: vec![0],
            }))?;
            Ok(FilterServing::Done)
        }

        fn headers_after(&self, _: &[BlockHash], _: BlockHash, _: usize) -> Vec<Header> {
            Vec::new()
        }

        fn serve_inventory_blocks(
            &self,
            _: &[Inventory],
            _: Option<u64>,
            _: &dyn Fn() -> bool,
            _: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            Ok(InventoryServing::default())
        }

        fn block_transactions(
            &self,
            _: &BlockTransactionsRequest,
            _: Option<u64>,
            _: &dyn Fn() -> bool,
        ) -> Result<Option<Message>, PeerError> {
            Ok(None)
        }
    }

    fn get_cfilters() -> Message {
        Message::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: 0,
            stop_hash: bitcoin::BlockHash::all_zeros(),
        })
    }

    fn small_aggregate() -> Arc<SharedOutboundBudget> {
        Arc::new(SharedOutboundBudget::with_limits(4 * RESERVE, 0))
    }

    fn local_budget() -> OutboundBudget {
        OutboundBudget::with_block_reserve(100, 1 << 20, RESERVE)
    }

    fn refuse_reservations(
        aggregate: &Arc<SharedOutboundBudget>,
    ) -> crate::connection::OutboundCredit {
        hog(aggregate, 3 * RESERVE + RESERVE / 2)
    }

    #[test]
    fn a_filter_request_waits_out_an_aggregate_refusal_longer_than_its_allowance() -> TestResult {
        let aggregate = small_aggregate();
        let hold = refuse_reservations(&aggregate);
        let mut served = Served::start_on(
            shared_with_query(FilterChain::published()),
            local_budget(),
            Some(&aggregate),
            &WriterKind::Gated,
        )?;
        served.open_gate();

        served.client.send(&get_cfilters())?;
        std::thread::sleep(ParkedFilter::ALLOWANCE + Duration::from_secs(2));

        if let Ok(ended) = served.session_outcome(Duration::from_millis(50)) {
            return Err(
                format!("the session ended while the aggregate refused it: {ended:?}").into(),
            );
        }
        assert_eq!(
            served.budget.pending(),
            (0, 0),
            "nothing is reserved or queued while the aggregate refuses"
        );
        assert!(!served.lease.is_cancelled());

        drop(hold);
        // The first-pass keepalive probe was refused with the aggregate full; it
        // drains first, then the parked filter request is served.
        let received = read_messages(&mut served.client, 2)?;
        assert!(
            matches!(&received[..], [Message::Ping(_), Message::CFilter(_)]),
            "the probe and the parked request are served once there is room: {received:?}"
        );

        served.lease.cancel();
        let outcome = served.session_outcome(FAILSAFE)?;
        assert!(outcome.is_ok(), "{outcome:?}");
        Ok(())
    }

    #[test]
    fn a_filter_request_waiting_on_the_index_after_an_aggregate_refusal_still_times_out()
    -> TestResult {
        let aggregate = small_aggregate();
        let hold = refuse_reservations(&aggregate);
        let mut served = Served::start_on(
            shared_with_query(FilterChain::unpublished()),
            local_budget(),
            Some(&aggregate),
            &WriterKind::Gated,
        )?;
        served.open_gate();

        served.client.send(&get_cfilters())?;
        std::thread::sleep(Duration::from_millis(2_500));
        if let Ok(ended) = served.session_outcome(Duration::from_millis(50)) {
            return Err(
                format!("the session ended while the aggregate refused it: {ended:?}").into(),
            );
        }

        drop(hold);
        let outcome = served.session_outcome(FAILSAFE)?;
        assert!(
            matches!(&outcome, Err(PeerError::Io(error))
            if error.to_string().contains("publication timed out")),
            "{outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn the_first_filter_pass_records_an_aggregate_refusal() -> TestResult {
        let aggregate = small_aggregate();
        let _hold = refuse_reservations(&aggregate);
        let (queue, _receiver) = crate::test_support::message_channel();
        let lease =
            PeerLease::new_with_budget(queue, true, local_budget()).with_shared_budget(&aggregate);
        let shared = shared_with_query(FilterChain {
            cancel_after_refusal: Some(lease.clone()),
            ..FilterChain::published()
        });
        let mut input = Vec::new();
        crate::wire::write_message(&mut input, MAGIC, &get_cfilters())?;
        let mut peer = Peer::new(io::Cursor::new(input), MAGIC);
        peer.state = PeerState::Ready;
        let addr = PeerEndpoint::from(([127, 0, 0, 1], 18_444));

        run_message_loop(&mut peer, addr, &lease, &shared, None)?;

        assert!(lease.is_cancelled(), "the chain closed the lease");
        let parked = peer
            .pending_filter_request
            .as_ref()
            .ok_or("the refused request was not parked")?;
        assert_eq!(parked.last, FilterHalt::Shared);
        assert_eq!(parked.allowance, ParkedFilter::ALLOWANCE);
        Ok(())
    }
}

#[cfg(test)]
#[cfg(test)]
#[expect(clippy::expect_used)]
mod anonymous_inbound_tests {
    use super::*;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let client = TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
        (client, listener.accept().expect("accept").0)
    }

    #[test]
    fn anonymous_admission_uses_capacity_without_learning_or_loopback_privilege() {
        let table = Arc::new(crate::PeerTable::new());
        let mut shared = test_shared(
            Arc::clone(&table),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        shared.overlay = Arc::new(crate::overlay::OverlayTransport::new(Arc::new(
            crate::overlay::OverlayConfig {
                onion_proxy: Some("127.0.0.1:9050".parse().expect("proxy")),
                ..crate::overlay::OverlayConfig::default()
            },
        )));
        shared.max_inbound = 2;
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), false, None);
        shared.address_book = Some(Arc::clone(&book));
        let (first_client, first) = pair();
        let (second_client, second) = pair();
        let (third_client, third) = pair();
        admit_anonymous_tor(first, &shared);
        admit_anonymous_tor(second, &shared);
        let sessions = table.sessions();
        assert_eq!(sessions.len(), 2);
        assert_ne!(sessions[0].addr, sessions[1].addr);
        for session in &sessions {
            assert_eq!(session.addr.endpoint(), None);
            assert_eq!(session.addr.network(), crate::PeerNetwork::Onion);
            assert!(!session.lease.is_no_ban());
            assert_eq!(
                session
                    .addr
                    .to_string()
                    .parse::<crate::PeerRemote>()
                    .expect("RPC handle"),
                session.addr
            );
        }
        admit_anonymous_tor(third, &shared);
        assert_eq!(table.live_inbound_count(), 2);
        let first = &sessions[0];
        let mut allowance = 32;
        let mut refill = crate::addrman::now();
        learn_addresses(
            &shared,
            &first.lease,
            first.addr,
            &[("8.8.8.8:8333".parse().expect("destination"), 9, refill)],
            &mut allowance,
            &mut refill,
        );
        assert_eq!(book.len(), 0);
        shared.note_misbehavior(
            first.addr,
            &first.lease,
            &crate::PeerError::Protocol("invalid peer message"),
        );
        assert!(
            !shared
                .banned
                .is_discouraged(std::net::IpAddr::from([127, 0, 0, 1]))
        );
        table.cancel_all();
        drop((first_client, second_client, third_client));
        let deadline = Instant::now() + Duration::from_secs(3);
        while !table.is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(table.len(), 0);
    }
}
