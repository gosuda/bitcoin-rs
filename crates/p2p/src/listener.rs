use bitcoin_rs_primitives::PeerEndpoint;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_primitives::{Network, unix_time_secs};
use crossbeam_channel::{SendTimeoutError, Sender};
use thiserror::Error;

use crate::handshake::run_inbound_handshake;
use crate::peer::Peer;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_mins(1);
const STREAM_POLL_INTERVAL: Duration = Duration::from_secs(1);

fn configure_peer_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(STREAM_POLL_INTERVAL))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    Ok(())
}

const POLL_INTERVAL: Duration = Duration::from_millis(100);

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
    /// Compact-block short-ID hints (the shared mempool gateway) for BIP152
    pub compact_hints: CompactHintsHandle,
    pub inbound_tx: Option<Sender<crate::InboundBody>>,
    pub package_capacity: Option<crate::PackageCapacity>,
    pub ibd: Option<(Arc<bitcoin_rs_chain::InitialBlockDownload>, Network)>,
    pub block_sync: Option<Arc<crate::sync::BlockSync>>,
    pub block_announcer: Option<Arc<crate::block_announce::BlockAnnouncer>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayOffers {
    /// Whether this node offers BIP331 ancestor package relay: `sendpackages`
    pub package_relay: bool,
    /// Whether this node announces BIP332 stale-tip relay in its BIP434
    pub stale_tip_relay: bool,
    /// The `prefers_blocks` byte of the BIP332 announcement. Read only with
    pub stale_tip_prefers_blocks: bool,
}

#[derive(Clone)]
pub struct ConnectionShared {
    pub peer_table: Arc<crate::PeerTable>,
    pub banned: crate::BannedReader,
    pub(crate) address_book: Option<Arc<crate::addrman::AddressBook>>,
    pub(crate) feeler: bool,
    pub activity: Arc<crate::NetworkActivity>,
    pub session_cancel: bitcoin_rs_chain::LatchReader,
    pub peer_ready: PeerReadyHandle,
    pub magic: Magic,
    pub headers_tx: Sender<crate::InboundHeaders>,
    pub blocks_tx: Sender<crate::InboundBlock>,
    pub chain_query: ChainQueryHandle,
    pub wake_tx: SyncWakeHandle,
    pub tx_inventory: TxInventoryHandle,
    /// Compact-block short-ID hints for BIP152 reconstruction.
    pub compact_hints: CompactHintsHandle,
    pub inbound_tx: Option<Sender<crate::InboundBody>>,
    pub package_capacity: Option<crate::PackageCapacity>,
    pub ibd: Option<(Arc<bitcoin_rs_chain::InitialBlockDownload>, Network)>,
    pub block_sync: Option<Arc<crate::sync::BlockSync>>,
    pub block_announcer: Option<Arc<crate::block_announce::BlockAnnouncer>>,
    pub max_inbound: usize,
    pub local_services: ServiceFlags,
    /// The subversion this node advertises in its version handshake.
    pub user_agent: String,
    /// Whether connections try BIP324 v2: inbound detects v1 and v2, and
    pub v2_transport: bool,
    pub relay_offers: RelayOffers,
    pub(crate) overlay: Arc<crate::overlay::OverlayTransport>,
    pub(crate) shared_outbound: Arc<crate::connection::SharedOutboundBudget>,
    block_memory: Arc<crate::inbound::block_memory::BlockMemory>,
    pub dial_routes: crate::DialRoutes,
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
        session_cancel: impl Into<bitcoin_rs_chain::LatchReader>,
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
            session_cancel: session_cancel.into(),
            peer_ready,
            magic,
            headers_tx,
            blocks_tx,
            chain_query,
            wake_tx,
            tx_inventory: extras.tx_inventory,
            compact_hints: extras.compact_hints,
            inbound_tx: extras.inbound_tx,
            package_capacity: extras.package_capacity,
            ibd: extras.ibd,
            block_sync: extras.block_sync,
            block_announcer: extras.block_announcer,
            max_inbound: crate::service::P2pServiceConfig::default().max_inbound(),
            local_services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            user_agent: bitcoin_rs_primitives::USER_AGENT.to_owned(),
            v2_transport: false,
            relay_offers: RelayOffers::default(),
            overlay: Arc::new(crate::overlay::OverlayTransport::new(Arc::default())),
            shared_outbound: Arc::new(crate::connection::SharedOutboundBudget::new()),
            block_memory: Arc::default(),
            dial_routes: crate::DialRoutes::default(),
        }
    }

    ///   `sendpackages` carrying both BIP331 version bits during the
    ///   BIP332 with [`RelayOffers::stale_tip_prefers_blocks`] as the
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

    /// Records the BIP332 `prefers_blocks` byte `peer` announced back.
    ///   stale-tip relay and `peer` announced BIP332; otherwise nothing.
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

    fn check_destination(&self, addr: PeerEndpoint, manual: bool) -> Result<(), crate::PeerError> {
        if !self.overlay.config.allows(addr.address().network()) {
            return Err(crate::PeerError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination network disabled",
            )));
        }
        if self.banned.is_banned(addr.address(), SystemTime::now()) {
            return Err(crate::PeerError::BannedDestination(addr.address()));
        }
        if !manual && self.banned.is_discouraged(addr.address()) {
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

    fn announce_block(&self, source: crate::PeerSource, hash: bitcoin_rs_primitives::Hash256) {
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
        self.session_cancel.load()
    }

    /// Retain the whole response under backpressure. Never wait while holding
    /// the peer-table, scheduler, or chain transition lock; a cancelled
    /// connection/session releases the wait at the next send timeout.
    fn send_headers(
        &self,
        lease: &crate::PeerLease,
        source: crate::PeerSource,
        headers: Vec<bitcoin_rs_primitives::Header>,
        wire_response: bool,
    ) {
        if self.is_session_cancelled() || lease.is_cancelled() {
            return;
        }
        if wire_response && let Some(sync) = &self.block_sync {
            sync.note_header_response_received(source);
        }
        let mut inbound = crate::InboundHeaders {
            headers,
            source: Some(source),
            wire_response,
        };
        loop {
            if self.is_session_cancelled() || lease.is_cancelled() {
                return;
            }
            match self.headers_tx.send_timeout(inbound, POLL_INTERVAL) {
                Ok(()) => {
                    wake_sync(self.wake_tx.as_ref());
                    return;
                }
                Err(SendTimeoutError::Timeout(returned)) => inbound = returned,
                Err(SendTimeoutError::Disconnected(_)) => {
                    tracing::warn!(peer_addr = ?source.endpoint, "p2p inbound headers channel disconnected");
                    return;
                }
            }
        }
    }

    fn send_block(
        &self,
        lease: &crate::PeerLease,
        peer_addr: impl Into<crate::PeerRemote>,
        payload: bitcoin_rs_primitives::BlockPayload,
        memory_credit: Option<crate::inbound::block_memory::BlockMemoryCredit>,
    ) {
        let peer_addr = peer_addr.into();
        let source = lease.source(peer_addr.endpoint());
        let header = payload.block().header;
        let hash = bitcoin_rs_primitives::Hash256::from(header.compute_hash());
        let requested = self
            .block_sync
            .as_ref()
            .is_some_and(|sync| sync.owns_body_fetch(source, hash));
        let Some(credit) = lease.admit_block_forward(source, hash, requested) else {
            metrics::counter!("node.sync.dropped_unsolicited_blocks").increment(1);
            return;
        };
        if self.forward_block(payload, source, Some(credit), memory_credit) {
            self.send_headers(lease, source, vec![header], false);
        }
    }

    fn forward_block(
        &self,
        payload: bitcoin_rs_primitives::BlockPayload,
        source: crate::PeerSource,
        forward_credit: Option<crate::connection::BlockForwardCredit>,
        memory_credit: Option<crate::inbound::block_memory::BlockMemoryCredit>,
    ) -> bool {
        let mut inbound = crate::InboundBlock::new(payload, Some(source), forward_credit);
        inbound.memory_credit = memory_credit;
        loop {
            if self.is_session_cancelled() {
                tracing::debug!(
                    peer_addr = ?source.endpoint,
                    "dropping inbound block: session cancelled"
                );
                return false;
            }
            match self.blocks_tx.send_timeout(inbound, POLL_INTERVAL) {
                Ok(()) => {
                    wake_sync(self.wake_tx.as_ref());
                    return true;
                }
                Err(SendTimeoutError::Timeout(returned)) => inbound = returned,
                Err(SendTimeoutError::Disconnected(_)) => {
                    tracing::warn!(
                        peer_addr = ?source.endpoint,
                        "p2p inbound blocks channel disconnected"
                    );
                    return false;
                }
            }
        }
    }

    fn update_transaction_requests(&self, source: crate::PeerSource, message: &crate::Message) {
        let Some(inventory) = &self.tx_inventory else {
            return;
        };
        match message {
            crate::Message::NotFound(items) => {
                self.peer_table
                    .transaction_not_found(source, items, inventory.as_ref());
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
                self.peer_table
                    .poll_transaction_requests(inventory.as_ref());
            }
            _ => {}
        }
    }

    fn send_tx(&self, source: crate::PeerSource, tx: bitcoin_rs_primitives::Tx) {
        let body = crate::InboundBody::from(crate::InboundTx::new(tx, source));
        let dropped = if let Some(channel) = &self.inbound_tx {
            if self.is_session_cancelled() {
                Some(body)
            } else {
                match channel.try_send(body) {
                    Ok(()) => None,
                    Err(crossbeam_channel::TrySendError::Full(body)) => Some(body),
                    Err(crossbeam_channel::TrySendError::Disconnected(body)) => {
                        tracing::warn!(peer_addr = ?source.endpoint, "p2p inbound tx channel disconnected");
                        Some(body)
                    }
                }
            }
        } else {
            Some(body)
        };
        if let Some(crate::InboundBody::Tx(inbound)) = dropped {
            tracing::debug!(peer_addr = ?source.endpoint, "p2p transaction ingress unavailable; dropping body");
            self.peer_table.transaction_response_completed(
                source,
                inbound.tx.txid(),
                inbound.tx.wtxid(),
            );
            if let Some(inventory) = &self.tx_inventory {
                self.peer_table.poll_transaction_response(
                    inventory.as_ref(),
                    inbound.tx.txid(),
                    inbound.tx.wtxid(),
                );
            }
        }
    }
}

impl ConnectionShared {
    fn send_package(
        &self,
        source: crate::PeerSource,
        payload: bytes::Bytes,
    ) -> Result<(), crate::wire::PeerError> {
        let (Some(channel), Some(capacity), Some(inventory)) =
            (&self.inbound_tx, &self.package_capacity, &self.tx_inventory)
        else {
            tracing::debug!(peer_addr = ?source.endpoint, "p2p package ingress unavailable; dropping body");
            return Ok(());
        };
        let package = match self.peer_table.admit_package(
            capacity,
            inventory.as_ref(),
            source,
            payload,
        ) {
            Ok(package) => package,
            Err(refusal) if refusal.is_peer_fault() => {
                return Err(crate::wire::PeerError::Protocol(
                    "malformed package in violation of protocol",
                ));
            }
            Err(refusal) => {
                tracing::debug!(peer_addr = ?source.endpoint, %refusal, "p2p package not accepted");
                return Ok(());
            }
        };
        let body = crate::InboundBody::from(package);
        let refused = if self.is_session_cancelled() {
            Some(body)
        } else {
            match channel.try_send(body) {
                Ok(()) => None,
                Err(crossbeam_channel::TrySendError::Full(body)) => Some(body),
                Err(crossbeam_channel::TrySendError::Disconnected(body)) => {
                    tracing::warn!(peer_addr = ?source.endpoint, "p2p inbound package channel disconnected");
                    Some(body)
                }
            }
        };
        if let Some(crate::InboundBody::Package(package)) = refused {
            tracing::debug!(peer_addr = ?source.endpoint, "p2p package ingress unavailable; dropping body");
            self.peer_table
                .package_response_rejected(package.into_token(), inventory.as_ref());
        }
        Ok(())
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
    listener
        .set_nonblocking(true)
        .map_err(|source| ListenerError::Bind { addr, source })?;
    Ok(listener)
}

/// # Errors
/// Returns [`ListenerError::Accept`] when the listener cannot report its
pub fn serve(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    shared: ConnectionShared,
) -> Result<(), ListenerError> {
    let addr = listener.local_addr()?;
    accept_connections(addr, &listener, &shutdown, &shared);
    Ok(())
}

fn accept_connections(
    addr: std::net::SocketAddr,
    listener: &TcpListener,
    shutdown: &AtomicBool,
    shared: &ConnectionShared,
) {
    let mut accept_backoff = POLL_INTERVAL;
    while !shutdown.load(Ordering::Relaxed) && !shared.is_session_cancelled() {
        #[cfg(test)]
        if ACCEPT_ERROR_INJECT.swap(false, Ordering::Relaxed) {
            tracing::warn!(addr = %addr, "test-injected accept error; backing off");
            std::thread::sleep(POLL_INTERVAL);
            continue;
        }
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                let peer_addr = PeerEndpoint::from(peer_addr);
                accept_backoff = POLL_INTERVAL;
                admit_inbound(stream, peer_addr, shared);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => {
                tracing::warn!(
                    addr = %addr,
                    %error,
                    backoff_ms = accept_backoff.as_millis(),
                    "p2p accept error; backing off and continuing",
                );
                std::thread::sleep(accept_backoff);
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
        |endpoint| shared.check_destination(endpoint, false).is_err(),
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
    spawn_dial(addr, shared, role, false, false)
}

#[must_use]
pub(crate) fn spawn_pinned_outbound_connection(
    addr: PeerEndpoint,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_dial(addr, shared, role, true, false)
}

pub(crate) fn spawn_dial(
    addr: PeerEndpoint,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
    pinned: bool,
    count_failure: bool,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let thread_name = format!("bitcoin-rs-p2p-outbound-{addr}");
    let result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || run_outbound_connection(addr, &shared, role, pinned, count_failure));

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
    manual: bool,
    count_failure: bool,
) -> Result<(), crate::wire::PeerError> {
    shared.check_destination(addr, manual)?;
    if !shared.activity.is_active() {
        return Err(crate::wire::PeerError::Protocol("network inactive"));
    }
    if shared.is_session_cancelled() {
        return Err(crate::wire::PeerError::Protocol("p2p startup cancelled"));
    }

    if !manual && !shared.feeler {
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
        && (manual
            || shared
                .address_book
                .as_ref()
                .is_some_and(|book| book.advertises(addr, ServiceFlags::P2P_V2)));
    match dial(addr, shared, role, manual, count_failure, try_v2)? {
        Dialed::Done => Ok(()),
        Dialed::V1Retry => {
            tracing::debug!(
                peer_addr = %addr,
                "p2p v2 handshake unanswered; retrying with v1 transport protocol"
            );
            dial(addr, shared, role, manual, false, false).map(|_| ())
        }
    }
}

enum Dialed {
    Done,
    V1Retry,
}

/// BIP324 handshake when `try_v2` is set.
fn dial(
    addr: PeerEndpoint,
    shared: &ConnectionShared,
    role: crate::peer_info::PeerRole,
    manual: bool,
    count_failure: bool,
    try_v2: bool,
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
            book.attempted(addr, count_failure && !manual, crate::addrman::now());
        }
    }
    let connected = connection.map_err(crate::wire::PeerError::Io)?;
    let stream = connected.stream;
    configure_peer_stream(&stream).map_err(crate::wire::PeerError::Io)?;
    shared.check_destination(addr, manual)?;
    if shared.is_session_cancelled() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol("p2p startup cancelled"));
    }

    let counters = std::sync::Arc::new(crate::PeerCounters::default());
    let stream = crate::CountingStream::from_connected(stream, counters)
        .map_err(crate::wire::PeerError::Io)?;

    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::QueuedFrame>();
    let lease = match (role, manual) {
        (crate::peer_info::PeerRole::FullRelay, false) => crate::PeerLease::new(outbound_tx),
        (crate::peer_info::PeerRole::BlockRelayOnly, false) => {
            crate::PeerLease::new_block_relay(outbound_tx)
        }
        (_, true) => crate::PeerLease::new_manual(outbound_tx, role),
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
    let stream = stream
        .stop_reading_when(lease.clone())
        .recording_send_activity(lease.send_activity());
    if let Err(error) = shared.check_destination(addr, manual) {
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
    let negotiated = if try_v2 {
        let mut handshake = crate::bip324::Handshake::initiator(
            shared.magic,
            &mut bitcoin::secp256k1::rand::thread_rng(),
        );
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

    let nonce = generate_nonce(addr);

    let addr_bind = stream.local_addr().map_err(crate::wire::PeerError::Io)?;
    let counters = std::sync::Arc::clone(stream.counters());
    let mut peer = Peer::with_transport(stream, shared.magic, negotiated);
    peer.account_message_bytes(std::sync::Arc::clone(&counters));
    peer.attach_net_trace(crate::net_trace::NetTrace::outbound(
        lease.node_id(),
        addr.into(),
        role,
        manual,
    ));
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

fn run_outbound_handshake<S: std::io::Read + std::io::Write>(
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

/// The transport an inbound connection speaks: BIP324 when this node speaks
fn negotiate_inbound(
    stream: &mut crate::CountingStream<TcpStream>,
    shared: &ConnectionShared,
    lease: &crate::PeerLease,
    deadline: Instant,
) -> Result<crate::transport::Negotiated, crate::wire::PeerError> {
    if !shared.v2_transport {
        return Ok(crate::transport::Negotiated::v1(shared.magic));
    }
    let mut handshake = crate::bip324::Handshake::responder(
        shared.magic,
        &mut bitcoin::secp256k1::rand::thread_rng(),
    );
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
    if let Some(endpoint) = endpoint
        && let Err(error) = shared.check_destination(endpoint, lease.is_manual())
    {
        shared.peer_table.remove_current(peer_addr, &lease);
        return Err(error);
    }
    if let Err(error) = configure_peer_stream(&stream).map_err(crate::wire::PeerError::Io) {
        shared.remove_session(peer_addr.endpoint(), &lease);
        lease.cancel();
        return Err(error);
    }

    let counters = std::sync::Arc::new(crate::PeerCounters::default());
    let stream = match crate::CountingStream::from_connected(stream, counters)
        .map(|stream| stream.stop_reading_when(lease.clone()))
        .map(|stream| stream.recording_send_activity(lease.send_activity()))
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
        info.network = bitcoin_rs_primitives::NetworkLabel::Onion;
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

    let loop_result = run_message_loop(peer, peer_addr, &lease, shared, shared.ibd.as_ref());

    let source = lease.source(peer_addr.endpoint());
    if let Err(error) = &loop_result {
        shared.note_misbehavior(peer_addr, &lease, error);
    }
    shared.remove_session(peer_addr.endpoint(), &lease);
    if let Some(inventory) = &shared.tx_inventory {
        shared
            .peer_table
            .transaction_peer_disconnected(source, inventory.as_ref());
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

#[derive(Debug, PartialEq, Eq)]
enum KeepaliveAction {
    Idle,
    Ping,
    Expired,
}

struct Keepalive {
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
        Self {
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
        let receive_expired =
            receive_silence_expires && now.saturating_duration_since(last_recv) > TIMEOUT_INTERVAL;
        let send_expired = now.saturating_duration_since(last_send) > TIMEOUT_INTERVAL;
        if receive_expired || send_expired {
            return KeepaliveAction::Expired;
        }
        let idle = now.saturating_duration_since(last_recv) >= PING_INTERVAL
            || now.saturating_duration_since(last_send) >= PING_INTERVAL;
        let probe_owed = self
            .last_ping
            .is_none_or(|last| now.saturating_duration_since(last) >= PING_INTERVAL);
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
            keepalive.next_action(t0 + PING_INTERVAL)
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

struct ProductionSink<'a> {
    lease: &'a crate::PeerLease,
    production: std::cell::Cell<Option<crate::connection::OutboundCredit>>,
    reply: std::cell::Cell<Option<crate::connection::OutboundCredit>>,
    refused: std::cell::Cell<Option<crate::connection::Refusal>>,
}

impl<'a> ProductionSink<'a> {
    fn new(lease: &'a crate::PeerLease, reply: Option<crate::connection::OutboundCredit>) -> Self {
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

fn reply_bound(message: &crate::Message, getaddr_answerable: bool) -> Option<usize> {
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
                budget.wait_for(STREAM_POLL_INTERVAL, may_reserve);
                DeferredStep::Waiting
            } else {
                lease.cancel();
                DeferredStep::Ended
            }
        }
        Err(refusal) => {
            keepalive.note_refusal(refusal);
            peer.deferred_inbound = Some(message);
            budget.wait_for(STREAM_POLL_INTERVAL, may_reserve);
            DeferredStep::Waiting
        }
    }
}

fn run_message_loop<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    peer_addr: impl Into<crate::PeerRemote>,
    lease: &crate::PeerLease,
    shared: &ConnectionShared,
    ibd: Option<&(Arc<bitcoin_rs_chain::InitialBlockDownload>, Network)>,
) -> Result<(), crate::wire::PeerError> {
    use crate::peer::PeerState;
    use std::time::Instant;
    let peer_addr = peer_addr.into();
    let endpoint = peer_addr.endpoint();

    let tx_relay_open =
        || ibd.is_none_or(|(latch, network)| !latch.is_active(unix_time_secs(), *network));

    let mut keepalive = Keepalive::starting_message_loop(Instant::now(), lease.last_send());
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
            DeferredStep::NoneHeld => {
                step_parked_getdata(peer, shared, lease, &mut keepalive, &mut parked_since)?
            }
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

        let (message, _raw, reply, memory_credit) = if let Some((message, reply)) = resumed {
            (message, bytes::Bytes::new(), reply, None)
        } else {
            let read_result = peer.read_message_bounded(&shared.block_memory, || {
                lease.is_cancelled() || shared.is_session_cancelled()
            });
            if lease.is_cancelled() {
                tracing::debug!(
                    peer_addr = %peer_addr,
                    "p2p peer lease revoked during read; closing"
                );
                return Ok(());
            }
            match read_result {
                Ok(None) => continue,
                Ok(Some((message, raw, memory_credit))) => {
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
                    (message, raw, reply, memory_credit)
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
            shared
                .peer_table
                .note_transaction_inventory(lease.source(peer_addr.endpoint()), items);
        }
        let sink = ProductionSink::new(lease, reply);
        let dispatched = crate::dispatch::dispatch_inbound_full(
            peer,
            &message,
            shared.chain_query.as_deref(),
            shared.tx_inventory.as_deref(),
            &tx_relay_open,
            &|| sink.headroom(),
            &mut |response| sink.send(response),
            &mut |hash| shared.announce_block(lease.source(peer_addr.endpoint()), hash),
            &mut |items| {
                shared
                    .peer_table
                    .announce_transactions(lease.source(peer_addr.endpoint()), &items);
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
                shared.peer_table.request_package_transactions(
                    lease.source(peer_addr.endpoint()),
                    request.subject,
                    request.wtxids,
                );
            } else if let Some(inventory) = shared.tx_inventory.as_deref() {
                shared.peer_table.release_package_info(
                    lease.source(peer_addr.endpoint()),
                    request.subject,
                    inventory,
                );
            }
        } else if let crate::Message::AncPkgInfo(info) = &message
            && let (Some(subject), Some(inventory)) =
                (info.subject(), shared.tx_inventory.as_deref())
        {
            shared.peer_table.release_package_info(
                lease.source(peer_addr.endpoint()),
                subject,
                inventory,
            );
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
            crate::Message::FeeFilter(rate) => shared
                .peer_table
                .receive_fee_filter(lease.source(peer_addr.endpoint()), *rate),
            crate::Message::Tx(tx) => {
                use bitcoin::hashes::Hash as _;
                shared.peer_table.note_transaction_inventory(
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
                shared.send_headers(lease, lease.source(peer_addr.endpoint()), headers, true);
            }
            crate::Message::NotFound(items) => {
                shared.block_not_found(lease.source(peer_addr.endpoint()), &items);
            }
            crate::Message::StaleTip(announcement) => {
                let negotiated = peer.remote_feature(crate::feature::BIP332_ID).is_some();
                let ibd_active =
                    ibd.is_some_and(|(latch, network)| latch.is_active(unix_time_secs(), *network));
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
                            let tip_hash =
                                bitcoin_rs_primitives::Hash256::from(tip_header.compute_hash());
                            let source = lease.source(peer_addr.endpoint());
                            if let Some(sync) = &shared.block_sync {
                                sync.stale_tips().note_heard(source, tip_hash);
                            }
                            shared.send_headers(lease, source, headers, false);
                        }
                    }
                }
            }
            crate::Message::Block(payload) => {
                shared.send_block(lease, peer_addr, payload, memory_credit);
            }
            crate::Message::Tx(tx) => forward_tx_if_relay_open(
                shared,
                lease.source(peer_addr.endpoint()),
                tx,
                peer_addr,
                tx_relay_open(),
            ),
            crate::Message::PkgTxnsPayload(payload) => {
                if peer.package_relay_versions() & crate::packages::PKG_RELAY_PKGTXNS == 0 {
                    return Err(crate::wire::PeerError::Protocol(
                        "pkgtxns without negotiated package relay",
                    ));
                }
                if tx_relay_open()
                    && let Err(error) =
                        shared.send_package(lease.source(peer_addr.endpoint()), payload)
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
                budget.wait_for(STREAM_POLL_INTERVAL, || {
                    budget.may_charge(crate::wire::HEADER_LEN)
                });
                Ok(ParkedStep::StillParked)
            }
        };
    }
    match advance_parked_getdata(peer, shared, lease, keepalive, &budget) {
        Err(_) if lease.is_cancelled() => Ok(ParkedStep::Ended),
        advanced => advanced.map(|()| ParkedStep::StillParked),
    }
}

fn advance_parked_getdata<S>(
    peer: &mut Peer<S>,
    shared: &ConnectionShared,
    lease: &crate::PeerLease,
    keepalive: &mut Keepalive,
    budget: &Arc<crate::connection::OutboundBudget>,
) -> Result<(), crate::wire::PeerError> {
    if !report_parked_misses(peer, lease, keepalive, budget)? {
        return Ok(());
    }
    resume_parked_getdata(peer, shared, lease, keepalive, budget)
}

fn notfound_wire_bound(items: usize) -> usize {
    let count = u64::try_from(items).unwrap_or(u64::MAX);
    crate::wire::HEADER_LEN + bitcoin_rs_primitives::varint::encode(count).len() + 36 * items
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
            budget.wait_for(STREAM_POLL_INTERVAL, || budget.may_charge(bound));
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
        budget.wait_for(STREAM_POLL_INTERVAL, || budget.may_reserve_production());
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

fn process_compact_wire_message(
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
        shared.send_headers(
            lease,
            lease.source(peer_addr.endpoint()),
            vec![header],
            false,
        );
        return;
    }

    let identity_version = local_compact_version.unwrap_or(crate::peer::COMPACT_BLOCK_VERSION);
    let outcome = process_compact_message(
        compact_reconstruction,
        message,
        identity_version,
        compact_hints,
        Instant::now(),
    );
    let announced_header = if let crate::Message::CmpctBlock(cmpct) = message
        && !matches!(outcome, crate::compact_blocks::Outcome::Complete(_))
    {
        crate::compact_blocks::native_header(&cmpct.compact_block.header)
    } else {
        None
    };
    let source = lease.source(peer_addr.endpoint());
    if let Some((hash, follow_up)) = handle_compact_outcome(outcome, sink, peer_addr, shared)
        && let Some(sync) = shared.block_sync.as_ref()
    {
        sync.enqueue_owned_body_fetch(source, hash, || sink.send(follow_up).is_ok());
    }
    if let Some(header) = announced_header {
        shared.send_headers(lease, source, vec![header], false);
    }
}

/// Applies one BIP152 receive-side outcome: a finished block enters the
fn handle_compact_outcome(
    outcome: crate::compact_blocks::Outcome,
    sink: &ProductionSink<'_>,
    peer_addr: impl Into<crate::PeerRemote>,
    shared: &ConnectionShared,
) -> Option<(bitcoin_rs_primitives::Hash256, crate::Message)> {
    let peer_addr = peer_addr.into();
    let lease = sink.lease;
    match outcome {
        crate::compact_blocks::Outcome::Complete(block) => {
            tracing::info!(peer_addr = %peer_addr, hash = %block.block_hash(), "p2p compact block reconstructed");
            shared.send_block(
                lease,
                peer_addr,
                bitcoin_rs_primitives::BlockPayload::from_local(block),
                None,
            );
            None
        }
        crate::compact_blocks::Outcome::RequestMissing(request) => {
            tracing::info!(peer_addr = %peer_addr, "p2p compact reconstruction missing");
            let hash = bitcoin_rs_primitives::Hash256::from(crate::inv::native_block_hash(
                request.txs_request.block_hash,
            ));
            Some((hash, crate::Message::GetBlockTxn(request)))
        }
        crate::compact_blocks::Outcome::Fallback(hash) => {
            tracing::info!(peer_addr = %peer_addr, "p2p compact reconstruction fallback");
            Some((
                bitcoin_rs_primitives::Hash256::from(hash),
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

/// Feeds one receive-side BIP152 message into the loop's reconstruction
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

fn forward_tx_if_relay_open(
    shared: &ConnectionShared,
    source: crate::PeerSource,
    tx: bitcoin_rs_primitives::Tx,
    peer_addr: impl Into<crate::PeerRemote>,
    relay_open: bool,
) {
    let peer_addr = peer_addr.into();
    if relay_open {
        shared.send_tx(source, tx);
    } else {
        tracing::debug!(peer_addr = %peer_addr, "tx dropped: initial block download");
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

#[cfg(test)]
fn test_shared(
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
        bitcoin_rs_chain::LatchReader::new(Arc::new(AtomicBool::new(false))),
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
    use bitcoin_rs_primitives::USER_AGENT;
    use std::sync::atomic::AtomicUsize;

    struct InventoryReads(AtomicUsize);
    impl crate::TxInventory for InventoryReads {
        fn have_tx(&self, _: bitcoin_rs_primitives::Hash256, _: bool) -> bool {
            self.0.fetch_add(1, Ordering::Relaxed);
            false
        }
        fn get_tx(&self, _: bitcoin_rs_primitives::Txid) -> Option<bitcoin_rs_primitives::Tx> {
            None
        }
        fn get_tx_by_wtxid(
            &self,
            _: bitcoin_rs_primitives::Wtxid,
        ) -> Option<bitcoin_rs_primitives::Tx> {
            None
        }
        fn resident_ancestor_package(
            &self,
            _: bitcoin_rs_primitives::Wtxid,
        ) -> Option<Vec<bitcoin_rs_primitives::Wtxid>> {
            None
        }
        fn resident_package(
            &self,
            _: &[bitcoin_rs_primitives::Wtxid],
        ) -> Option<Vec<Arc<bitcoin_rs_primitives::Tx>>> {
            None
        }
    }

    #[test]
    fn ping_and_nontransaction_messages_do_not_poll_gateway_inventory() {
        let table = Arc::new(crate::PeerTable::new());
        let (sender, receiver) = crossbeam_channel::bounded(4);
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
        table.announce_transactions(source, &[item]);
        let (headers, _) = crossbeam_channel::bounded(1);
        let (blocks, _) = crossbeam_channel::bounded(1);
        let mut shared = test_shared(table, headers, blocks);
        let inventory = Arc::new(InventoryReads(AtomicUsize::new(0)));
        shared.tx_inventory = Some(inventory.clone());
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
        assert!(receiver.try_recv().is_err());
        shared.update_transaction_requests(source, &crate::Message::Inv(vec![item]));
        assert_eq!(
            inventory.0.load(Ordering::Relaxed),
            2,
            "one background and one pre-send identity check"
        );
        assert!(matches!(
            receiver.try_recv().map(crate::QueuedFrame::into_message),
            Ok(crate::Message::GetData(_))
        ));
    }
}

#[cfg(test)]
mod outbound_tests {
    use bitcoin_rs_primitives::PeerEndpoint;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::Arc;

    use super::{spawn_outbound_connection, spawn_pinned_outbound_connection, test_shared};
    use crate::PeerTable;
    use crate::peer_info::PeerRole;

    #[test]
    fn spawn_outbound_connection_to_closed_port_fails_quickly()
    -> Result<(), Box<dyn std::error::Error>> {
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
    use bitcoin_rs_primitives::PeerEndpoint;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    use super::{HANDSHAKE_TIMEOUT, STREAM_POLL_INTERVAL, configure_peer_stream};

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
            Some(STREAM_POLL_INTERVAL)
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
    use bitcoin_rs_primitives::PeerEndpoint;
    use std::net::{Ipv4Addr, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
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

        let shutdown = Arc::new(AtomicBool::new(false));
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);

        ACCEPT_ERROR_INJECT.store(true, Ordering::Relaxed);

        let thread_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || serve(listener, thread_shutdown, shared));

        std::thread::sleep(Duration::from_millis(300));

        let _client = TcpStream::connect(addr).expect("listener should still accept");

        shutdown.store(true, Ordering::Relaxed);
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
    use bitcoin_rs_primitives::PeerEndpoint;
    use std::io::Read;
    use std::net::{Ipv4Addr, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::{bind_listener, serve, test_shared};
    use crate::PeerTable;

    #[test]
    fn inbound_admission_over_cap_drops_stream() -> Result<(), Box<dyn std::error::Error>> {
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

        let shutdown = Arc::new(AtomicBool::new(false));
        let serve_shutdown = Arc::clone(&shutdown);
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

        shutdown.store(true, Ordering::Relaxed);
        handle.join().expect("listener thread panicked")?;
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod writer_setup_cleanup_tests {
    use bitcoin_rs_primitives::PeerEndpoint;
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
mod writer_shutdown_tests;

#[cfg(test)]
mod ready_notify_tests {
    use bitcoin_rs_primitives::PeerEndpoint;
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
        let token: bitcoin_rs_mempool::PeerToken = source.into();
        let snapshot = shared.peer_table.package_relay_versions(token);
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
#[expect(clippy::expect_used)]
mod block_forward_tests;

#[cfg(test)]
#[expect(clippy::expect_used)]
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
            shared.session_cancel.store(cancelled);
            assert!(
                run_outbound_connection(
                    target.into(),
                    &shared,
                    crate::PeerRole::FullRelay,
                    false,
                    false
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
    use bitcoin_rs_primitives::USER_AGENT;
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
mod discouragement_tests;

#[cfg(test)]
mod v2_transport_tests;

#[cfg(test)]
mod getdata_pause_tests;

#[cfg(test)]
mod header_ingress_tests;

#[cfg(test)]
mod aggregate_budget_tests;

#[cfg(test)]
mod aggregate_filter_tests;

#[cfg(test)]
mod loopback_serving_tests;

#[cfg(test)]
#[expect(clippy::expect_used)]
mod anonymous_inbound_tests;
