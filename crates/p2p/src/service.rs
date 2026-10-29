//! Runtime owner for the Bitcoin P2P subsystem.

use bitcoin_rs_primitives::PeerEndpoint;
use std::collections::VecDeque;
use std::io;
#[cfg(test)]
use std::net::SocketAddr;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use bitcoin::secp256k1::rand::RngCore as _;
use crossbeam_channel::{Receiver, Sender, TrySendError};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use thiserror::Error;

mod pinned;

use crate::listener::ListenerError;

const DEFAULT_OUTBOUND_FULL_RELAY_SLOTS: usize = 8;

const DEFAULT_OUTBOUND_BLOCK_RELAY_SLOTS: usize = 2;

const DEFAULT_OUTBOUND_QUEUE_LIMIT: usize = DEFAULT_OUTBOUND_FULL_RELAY_SLOTS;

const EXTRA_PEER_CHECK_INTERVAL: Duration = Duration::from_secs(45);

#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::as_conversions,
    clippy::suboptimal_flops,
    reason = "53-bit input is exact and finite delay fits u64; preserve Core multiply-then-add rounding without FMA"
)]
fn feeler_delay(uniform: u64) -> Duration {
    let fraction = (uniform >> 11) as f64 * (1.0 / 9_007_199_254_740_992.0);
    let micros = (-(-fraction).ln_1p() * 120_000_000.0 + 0.5) as u64;
    Duration::from_micros(micros)
}

const DEFAULT_INBOUND_BLOCK_QUEUE_LIMIT: usize = 256;

/// At most 64 protocol-bounded batches (2,000 headers each) await sync.
/// Full ingress backpressures the connection, rather than losing a response.
const INBOUND_HEADER_QUEUE_LIMIT: usize = 64;

const DEFAULT_MAX_PEER_CONNECTIONS: usize = 200;

const MAX_PARKED_DIALS: usize = 64;

#[derive(Clone, Debug)]
pub struct P2pServiceConfig {
    pub listen_addrs: Vec<std::net::SocketAddr>,

    pub magic: Magic,
    pub address_book_path: Option<std::path::PathBuf>,
    pub asmap_path: Option<std::path::PathBuf>,
    pub allow_local_addresses: bool,
    pub dns_seeds_enabled: bool,
    pub dns_seeds: Vec<String>,
    pub dns_port: u16,
    pub fixed_peers: Vec<String>,
    pub noban_subnets: Vec<crate::IpSubnet>,
    pub max_peer_connections: usize,
    pub outbound_full_relay_slots: usize,
    pub local_services: ServiceFlags,
    /// Whether connections try BIP324 v2 (see [`ConnectionShared::v2_transport`]).
    pub v2_transport: bool,
    /// The opt-in relay capabilities connections offer: BIP331 ancestor package relay
    /// and BIP332 stale-tip relay.
    ///
    /// Both are off by default; a peer relays packages or stale tips only after both
    /// sides negotiate it.
    pub relay_offers: crate::RelayOffers,
    pub outbound_block_relay_slots: usize,
    pub outbound_queue_limit: usize,
    pub inbound_block_queue_limit: usize,
    pub overlay: crate::overlay::OverlayConfig,
}

impl Default for P2pServiceConfig {
    fn default() -> Self {
        Self {
            listen_addrs: Vec::new(),
            magic: Magic::from_bytes([0; 4]),
            address_book_path: None,
            asmap_path: None,
            allow_local_addresses: false,
            dns_seeds_enabled: false,
            dns_seeds: Vec::new(),
            dns_port: 0,
            fixed_peers: Vec::new(),
            noban_subnets: Vec::new(),
            max_peer_connections: DEFAULT_MAX_PEER_CONNECTIONS,
            outbound_full_relay_slots: DEFAULT_OUTBOUND_FULL_RELAY_SLOTS,
            outbound_block_relay_slots: DEFAULT_OUTBOUND_BLOCK_RELAY_SLOTS,
            outbound_queue_limit: DEFAULT_OUTBOUND_QUEUE_LIMIT,
            inbound_block_queue_limit: DEFAULT_INBOUND_BLOCK_QUEUE_LIMIT,
            local_services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            v2_transport: false,
            relay_offers: crate::RelayOffers::default(),
            overlay: crate::overlay::OverlayConfig::default(),
        }
    }
}

impl P2pServiceConfig {
    /// INVARIANT: manual peers do not consume these slots; the two slot
    ///   counts are the only automatic outbound population knobs.
    #[must_use]
    fn total_outbound_active_limit(&self) -> usize {
        self.outbound_full_relay_slots
            .saturating_add(self.outbound_block_relay_slots)
    }

    /// INVARIANT: this is the only inbound capacity derivation; at the result
    ///   an inbound newcomer evicts an inbound connection or is refused
    ///   (`PeerTable::try_register_inbound`).
    #[must_use]
    pub(crate) fn max_inbound(&self) -> usize {
        self.max_peer_connections
            .saturating_sub(self.outbound_full_relay_slots)
            .saturating_sub(self.outbound_block_relay_slots)
    }

    /// INVARIANT: this is the only place the service configuration reaches
    ///   these `ConnectionShared` fields, and each switch maps to exactly its
    ///   own field.
    fn apply_to(&self, shared: &mut crate::listener::ConnectionShared) {
        shared.max_inbound = self.max_inbound();
        shared.local_services = self.local_services;
        shared.v2_transport = self.v2_transport;
        shared.relay_offers = self.relay_offers;
        shared.dial_routes = self.overlay.dial_routes();
    }
}

#[derive(Debug, Error)]
pub enum P2pServiceError {
    #[error("p2p service is already started")]
    AlreadyStarted,
    #[error("spawn p2p worker: {0}")]
    Spawn(#[from] io::Error),
    #[error(transparent)]
    Listener(#[from] ListenerError),
    #[error("p2p overlay setup: {0}")]
    Overlay(io::Error),
}

#[derive(Debug, Error)]
pub enum P2pJoinError {
    #[error(transparent)]
    Listener(#[from] ListenerError),
    #[error("p2p listener panicked")]
    ListenerPanic,
    #[error("p2p outbound drain panicked")]
    OutboundPanic,
    #[error("p2p bootstrap worker panicked")]
    BootstrapPanic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum P2pControlError {
    #[error("destination network disabled")]
    NetworkDisabled,
    #[error("destination is banned")]
    Banned,
    #[error("p2p outbound queue is full")]
    QueueFull,
    #[error("p2p outbound queue is closed")]
    Closed,
}

struct Workers {
    shutdown: Arc<AtomicBool>,
    session_cancel: Arc<AtomicBool>,
    listeners: Vec<JoinHandle<Result<(), ListenerError>>>,
    outbound: Option<JoinHandle<()>>,
    bootstrap: Option<JoinHandle<()>>,
    overlay_threads: Vec<JoinHandle<()>>,
    sam_session: Option<Arc<crate::sam::SamSession>>,
}

impl Default for Workers {
    fn default() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            session_cancel: Arc::new(AtomicBool::new(false)),
            listeners: Vec::new(),
            outbound: None,
            bootstrap: None,
            overlay_threads: Vec::new(),
            sam_session: None,
        }
    }
}

impl Workers {
    fn new(shutdown: Arc<AtomicBool>, session_cancel: Arc<AtomicBool>) -> Self {
        Self {
            shutdown,
            session_cancel,
            listeners: Vec::new(),
            outbound: None,
            bootstrap: None,
            overlay_threads: Vec::new(),
            sam_session: None,
        }
    }

    fn cancel(&self, peer_table: &crate::PeerTable, addresses: &Mutex<Vec<crate::PeerEndpoint>>) {
        self.session_cancel.store(true, Ordering::Release);
        self.shutdown.store(true, Ordering::Release);
        peer_table.cancel_all();
        if let Some(session) = &self.sam_session {
            session.close();
        }
        addresses.lock().clear();
    }

    fn join_all(&mut self) {
        for handle in self.overlay_threads.drain(..) {
            let _ = handle.join();
        }
        for handle in self.listeners.drain(..) {
            let _ = handle.join();
        }
        if let Some(handle) = self.outbound.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.bootstrap.take() {
            let _ = handle.join();
        }
    }

    fn teardown(
        &mut self,
        peer_table: &crate::PeerTable,
        addresses: &Mutex<Vec<crate::PeerEndpoint>>,
    ) {
        self.cancel(peer_table, addresses);
        self.join_all();
    }
}

/// INVARIANT: the origin travels with the request to the lease.
///
/// Core's `ConnectionType::MANUAL` is exempt from the chain-sync timeout and the
/// extra-peer retirement (`net_processing.cpp:5502`, `net_processing.cpp:5558-5604`),
/// and the queue is the only place that still knows which dials were asked for by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundDial {
    pub addr: PeerEndpoint,
    pub manual: bool,
    purpose: DialPurpose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DialPurpose {
    Regular,
    Feeler,
    Anchor,
}

impl OutboundDial {
    #[must_use]
    pub const fn auto(addr: PeerEndpoint) -> Self {
        Self {
            addr,
            manual: false,
            purpose: DialPurpose::Regular,
        }
    }

    #[must_use]
    pub const fn pinned(addr: PeerEndpoint) -> Self {
        Self {
            addr,
            manual: true,
            purpose: DialPurpose::Regular,
        }
    }
}

#[derive(Clone, Copy)]
struct ActiveOutbound {
    feeler: bool,

    role: crate::peer_info::PeerRole,
    manual: bool,
}

#[derive(Clone, Debug)]
pub struct BannedReader {
    inner: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    discouraged: Arc<Mutex<crate::discouragement::DiscouragedPeers>>,
    protected: Arc<[crate::IpSubnet]>,
    routing: Arc<crate::overlay::OverlayConfig>,
}

impl BannedReader {
    #[must_use]
    pub fn new(inner: Arc<RwLock<Vec<crate::BannedSubnet>>>) -> Self {
        Self::with_protection(inner, Vec::new())
    }

    fn with_protection(
        inner: Arc<RwLock<Vec<crate::BannedSubnet>>>,
        protected: Vec<crate::IpSubnet>,
    ) -> Self {
        Self {
            inner,
            discouraged: Arc::new(Mutex::new(
                crate::discouragement::DiscouragedPeers::default(),
            )),
            protected: protected.into(),
            routing: Arc::new(crate::overlay::OverlayConfig::default()),
        }
    }

    #[must_use]
    pub fn automatic_snapshot(
        &self,
        now: SystemTime,
    ) -> crate::discouragement::AutomaticPeerPolicy {
        let banned = self.inner.read().clone();
        let discouraged = self.discouraged.lock().snapshot(Instant::now());
        crate::discouragement::AutomaticPeerPolicy {
            banned,
            discouraged,
            protected: Arc::clone(&self.protected),
            now,
            routing: Arc::clone(&self.routing),
        }
    }

    #[must_use]
    pub fn is_noban(&self, ip: impl Into<crate::PeerAddress>) -> bool {
        ip.into()
            .ip()
            .is_some_and(|ip| self.protected.iter().any(|subnet| subnet.contains(ip)))
    }

    #[must_use]
    pub fn is_discouraged(&self, ip: impl Into<crate::PeerAddress>) -> bool {
        {
            let ip = ip.into();
            !self.is_noban(ip) && self.discouraged.lock().contains(ip, Instant::now())
        }
    }

    pub(crate) fn discourage(&self, ip: impl Into<crate::PeerAddress>) -> bool {
        self.discouraged.lock().insert(ip, Instant::now())
    }

    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, Vec<crate::BannedSubnet>> {
        self.inner.read()
    }

    #[must_use]
    pub fn is_banned(&self, ip: impl Into<crate::PeerAddress>, now: SystemTime) -> bool {
        ip.into()
            .ip()
            .is_some_and(|ip| crate::subnet::is_banned(&self.inner.read(), ip, now))
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn fixture_empty() -> Self {
        Self::new(Arc::new(RwLock::new(Vec::new())))
    }
}

impl From<Arc<RwLock<Vec<crate::BannedSubnet>>>> for BannedReader {
    fn from(inner: Arc<RwLock<Vec<crate::BannedSubnet>>>) -> Self {
        Self::new(inner)
    }
}

pub struct P2pService {
    overlay: Arc<crate::overlay::OverlayTransport>,
    config: P2pServiceConfig,
    shutdown: bitcoin_rs_chain::LatchReader,
    worker_shutdown: Mutex<Arc<AtomicBool>>,
    network_active: Arc<AtomicBool>,
    peer_table: Arc<crate::PeerTable>,
    banned: BannedReader,
    address_book: Arc<crate::addrman::AddressBook>,
    added_nodes: Arc<RwLock<Vec<PeerEndpoint>>>,
    fixed_destinations: Arc<RwLock<Vec<PeerEndpoint>>>,
    outbound_tx: Sender<OutboundDial>,
    outbound_rx: Arc<Mutex<Receiver<OutboundDial>>>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_headers_rx: Mutex<Option<Receiver<crate::InboundHeaders>>>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    inbound_blocks_rx: Mutex<Option<Receiver<crate::InboundBlock>>>,
    workers: Mutex<Option<Workers>>,
    session_cancel: Mutex<Arc<AtomicBool>>,
    shared_outbound: Arc<crate::connection::SharedOutboundBudget>,
    overlay_addresses: Arc<Mutex<Vec<crate::PeerEndpoint>>>,
}

impl std::fmt::Debug for P2pService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pService")
            .field("config", &self.config)
            .field("network_active", &self.network_active())
            .finish_non_exhaustive()
    }
}

impl P2pService {
    #[must_use]
    pub fn new(
        config: P2pServiceConfig,
        shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
    ) -> Self {
        let (outbound_tx, outbound_rx) = crossbeam_channel::bounded(config.outbound_queue_limit);
        let (inbound_headers_tx, inbound_headers_rx) =
            crossbeam_channel::bounded(INBOUND_HEADER_QUEUE_LIMIT);
        let (inbound_blocks_tx, inbound_blocks_rx) =
            crossbeam_channel::bounded(config.inbound_block_queue_limit);
        let address_book = crate::addrman::AddressBook::open(
            config.address_book_path.clone(),
            config.magic.to_bytes(),
            config.allow_local_addresses,
            config.asmap_path.as_deref(),
        );
        let overlay = Arc::new(crate::overlay::OverlayTransport::new(Arc::new(
            config.overlay.clone(),
        )));
        let mut banned = BannedReader::with_protection(
            Arc::new(RwLock::new(Vec::new())),
            config.noban_subnets.clone(),
        );
        banned.routing = Arc::clone(&overlay.config);
        Self {
            overlay,
            config,
            address_book,
            shutdown: shutdown.into(),
            worker_shutdown: Mutex::new(Arc::new(AtomicBool::new(false))),
            network_active: Arc::new(AtomicBool::new(true)),
            peer_table: Arc::new(crate::PeerTable::new()),
            session_cancel: Mutex::new(Arc::new(AtomicBool::new(false))),
            banned,
            added_nodes: Arc::new(RwLock::new(Vec::new())),
            fixed_destinations: Arc::new(RwLock::new(Vec::new())),
            outbound_tx,
            outbound_rx: Arc::new(Mutex::new(outbound_rx)),
            inbound_headers_tx,
            inbound_headers_rx: Mutex::new(Some(inbound_headers_rx)),
            inbound_blocks_tx,
            inbound_blocks_rx: Mutex::new(Some(inbound_blocks_rx)),
            workers: Mutex::new(None),
            shared_outbound: Arc::new(crate::connection::SharedOutboundBudget::new()),
            overlay_addresses: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[must_use]
    pub fn overlay_addresses(&self) -> Vec<crate::PeerEndpoint> {
        self.overlay_addresses.lock().clone()
    }

    pub fn proxy_randomize_credentials(&self) -> bool {
        self.config.overlay.randomize_credentials
    }

    pub fn network_states(&self) -> Vec<crate::OverlayNetworkState> {
        self.overlay.states(&self.peer_table)
    }

    pub fn resolve_peer(&self, endpoint: &str) -> io::Result<Vec<PeerEndpoint>> {
        self.overlay
            .resolve(endpoint, &|| self.shutdown.is_triggered())
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn shared_outbound_budget(&self) -> Arc<crate::connection::SharedOutboundBudget> {
        Arc::clone(&self.shared_outbound)
    }

    pub fn start(
        &self,
        chain_query: Option<&Arc<dyn crate::ChainQuery + 'static>>,
        sync_wake_tx: Option<&Sender<()>>,
        peer_ready: &Arc<dyn Fn(crate::PeerSource) + Send + Sync>,
        extras: crate::listener::ListenerExtras,
    ) -> Result<(), P2pServiceError> {
        let mut slot = self.workers.lock();
        if slot.is_some() {
            return Err(P2pServiceError::AlreadyStarted);
        }

        let epoch_shutdown = Arc::new(AtomicBool::new(false));
        let session_cancel = Arc::new(AtomicBool::new(false));
        *self.session_cancel.lock() = Arc::clone(&session_cancel);
        *self.worker_shutdown.lock() = Arc::clone(&epoch_shutdown);

        let mut workers = Workers::new(Arc::clone(&epoch_shutdown), Arc::clone(&session_cancel));

        match self.start_workers(&mut workers, chain_query, sync_wake_tx, peer_ready, extras) {
            Ok(()) => {
                *slot = Some(workers);
                Ok(())
            }
            Err(error) => {
                workers.teardown(&self.peer_table, &self.overlay_addresses);
                Err(error)
            }
        }
    }

    fn start_workers(
        &self,
        workers: &mut Workers,
        chain_query: Option<&Arc<dyn crate::ChainQuery + 'static>>,
        sync_wake_tx: Option<&Sender<()>>,
        peer_ready: &Arc<dyn Fn(crate::PeerSource) + Send + Sync>,
        extras: crate::listener::ListenerExtras,
    ) -> Result<(), P2pServiceError> {
        self.config.overlay.validate()?;
        let mut bound_listeners = Vec::with_capacity(self.config.listen_addrs.len());
        for addr in &self.config.listen_addrs {
            if !self
                .config
                .overlay
                .allows(PeerEndpoint::from(*addr).address().network())
            {
                continue;
            }
            let listener = crate::listener::bind_listener(*addr)?;
            tracing::info!(addr = %addr, "p2p listener bound");
            bound_listeners.push((*addr, listener));
        }

        let mut shared = crate::listener::ConnectionShared::new(
            Arc::clone(&self.peer_table),
            self.banned_reader(),
            Arc::new(crate::NetworkActivity::from_shared(Arc::clone(
                &self.network_active,
            ))),
            Arc::clone(&workers.session_cancel),
            Some(Arc::clone(peer_ready)),
            self.config.magic,
            self.inbound_headers_tx.clone(),
            self.inbound_blocks_tx.clone(),
            chain_query.cloned(),
            sync_wake_tx.cloned(),
            extras,
        );
        self.config.apply_to(&mut shared);
        shared.overlay = Arc::clone(&self.overlay);
        shared.address_book = Some(Arc::clone(&self.address_book));
        self.address_book.set_addrv2_gossip(
            self.config.overlay.tor_configured(),
            self.config.overlay.i2p_configured(),
        );
        shared = shared.with_shared_outbound(&self.shared_outbound);

        let worker_shutdown = self.worker_shutdown.lock().clone();
        workers
            .listeners
            .extend(self.overlay.start(&shared, &worker_shutdown)?);
        for (listener_addr, listener) in bound_listeners {
            let shutdown = Arc::clone(&workers.shutdown);
            let shared = shared.clone();
            let handle = thread::Builder::new()
                .name(format!("bitcoin-rs-p2p-{listener_addr}"))
                .spawn(move || crate::listener::serve(listener, shutdown, shared))?;
            workers.listeners.push(handle);
        }

        let routes = crate::RouteTable::from_routes(&shared.dial_routes);
        let dial_allowance = shared.block_sync.clone();
        let outbound = self.spawn_outbound_worker(shared, &workers.shutdown)?;
        workers.outbound = Some(outbound);

        let bootstrap = self.spawn_bootstrap_worker(
            dial_allowance,
            chain_query.cloned(),
            &workers.shutdown,
            routes,
        )?;
        workers.bootstrap = bootstrap;

        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "One drain loop owns active handles, parked admission, and teardown in one epoch"
    )]
    fn spawn_outbound_worker(
        &self,
        shared: crate::listener::ConnectionShared,
        shutdown: &Arc<AtomicBool>,
    ) -> Result<JoinHandle<()>, io::Error> {
        let address_book = Arc::clone(&self.address_book);
        let manual_nodes = Arc::clone(&self.added_nodes);
        let fixed_destinations = Arc::clone(&self.fixed_destinations);
        let outbound_rx = Arc::clone(&self.outbound_rx);
        let peer_table = Arc::clone(&self.peer_table);
        let shutdown = Arc::clone(shutdown);
        let process_shutdown = self.shutdown.clone();
        let full_relay_slots = self.config.outbound_full_relay_slots;
        let block_relay_slots = self.config.outbound_block_relay_slots;
        let active_limit = self.config.total_outbound_active_limit();
        let max_peer_connections = self.config.max_peer_connections;
        let allow_feelers = self.config.fixed_peers.is_empty() && active_limit > 0;
        thread::Builder::new()
            .name("bitcoin-rs-p2p-outbound-drain".to_owned())
            .spawn(move || {
                let mut active: HashMap<PeerEndpoint, ActiveOutbound> = HashMap::new();
                let mut parked: VecDeque<OutboundDial> = VecDeque::new();
                let mut handles = Vec::new();
                let mut pinned = pinned::PinnedPeers::default();
                let mut next_extra_peer_check = Instant::now() + EXTRA_PEER_CHECK_INTERVAL;
                let mut next_feeler = Instant::now() + feeler_delay(bitcoin::secp256k1::rand::thread_rng().next_u64());
                while !shutdown.load(Ordering::Acquire)
                    && !shared.session_cancel.load()
                    && !process_shutdown.is_triggered()
                {
                    let now = Instant::now();
                    for endpoint in reap_finished_outbound_connections(&mut active, &mut handles, &address_book) {
                        pinned.finished(endpoint, now);
                    }
                    if now >= next_extra_peer_check {
                        next_extra_peer_check = now + EXTRA_PEER_CHECK_INTERVAL;
                        retire_extra_full_relay_connection(
                            &peer_table,
                            shared.block_sync.as_deref(),
                            full_relay_slots,
                            now,
                        );
                    }
                    if !shared.activity.is_active() {
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    let extra_dial = shared
                        .block_sync
                        .as_ref()
                        .is_some_and(|sync| sync.allow_extra_full_relay_dial());
                    for _ in 0..parked.len() {
                        let Some(dial) = parked.pop_front() else { break; };
                        if !dial_has_capacity(&dial, &active, active_limit, block_relay_slots, extra_dial) {
                            parked.push_back(dial);
                            continue;
                        }
                        let manual = manual_nodes.read();
                        if !dial.manual && is_manual_endpoint(&manual, dial.addr) {
                            defer_rejected_dial(&dial, &address_book, &active);
                            continue;
                        }
                        spawn_outbound_dial(
                            &dial,
                            &shared,
                            &mut active,
                            &mut handles,
                            full_relay_slots,
                            block_relay_slots,
                            extra_dial,
                            max_peer_connections,
                        );
                    }
                    if allow_feelers && now >= next_feeler {
                        next_feeler = now + feeler_delay(bitcoin::secp256k1::rand::thread_rng().next_u64());
                        let manual = manual_nodes.read();
                        spawn_feeler(&shared, &address_book, &manual, &mut active, &mut handles, max_peer_connections);
                    }
                    {
                        let manual = manual_nodes.read();
                        let fixed = fixed_destinations.read();
                        let mut configured = manual.clone();
                        configured.extend_from_slice(&fixed);
                        for endpoint in pinned.due(&configured, &active, &peer_table, now) {
                            spawn_outbound_dial(&OutboundDial::pinned(endpoint), &shared, &mut active, &mut handles,
                                full_relay_slots, block_relay_slots, extra_dial, max_peer_connections);
                            if !active.contains_key(&endpoint) { pinned.finished(endpoint, now); }
                        }
                    }
                    let received = outbound_rx.lock().recv_timeout(Duration::from_secs(1));
                    let Ok(dial) = received else {
                        if matches!(
                            received,
                            Err(crossbeam_channel::RecvTimeoutError::Disconnected)
                        ) {
                            break;
                        }
                        continue;
                    };
                    if !dial.manual
                        && !dial_has_capacity(&dial, &active, active_limit, block_relay_slots, extra_dial)
                    {
                        if !park_automatic_dial(&mut parked, dial, &address_book, &active) {
                            tracing::warn!(
                                peer_addr = %dial.addr,
                                "p2p outbound request shed: parked automatic queue full; address claim released"
                            );
                        }
                        continue;
                    }
                    let manual = manual_nodes.read();
                    let fixed = fixed_destinations.read();
                    if dial.manual && (is_manual_endpoint(&manual, dial.addr) || is_manual_endpoint(&fixed, dial.addr)) { continue; }
                    if !dial.manual && is_manual_endpoint(&manual, dial.addr) {
                        defer_rejected_dial(&dial, &address_book, &active);
                        continue;
                    }
                    spawn_outbound_dial(
                        &dial,
                        &shared,
                        &mut active,
                        &mut handles,
                        full_relay_slots,
                        block_relay_slots,
                        extra_dial,
                        max_peer_connections,
                    );
                }
                finish_outbound_epoch(parked, &active, handles, &address_book);
            })
    }

    fn spawn_bootstrap_worker(
        &self,
        block_sync: Option<Arc<crate::sync::BlockSync>>,
        chain_query: Option<Arc<dyn crate::ChainQuery>>,
        shutdown: &Arc<AtomicBool>,
        routes: crate::RouteTable,
    ) -> Result<Option<JoinHandle<()>>, io::Error> {
        if !self.config.fixed_peers.is_empty() {
            let shutdown = Arc::clone(shutdown);
            let network_active = Arc::clone(&self.network_active);
            let destinations = Arc::clone(&self.fixed_destinations);
            let endpoints = self.config.fixed_peers.clone();
            let overlay = Arc::clone(&self.overlay);
            return thread::Builder::new()
                .name("bitcoin-rs-fixed-peer-bootstrap".to_owned())
                .spawn(move || {
                    run_fixed_peer_resolution(
                        shutdown,
                        network_active,
                        destinations,
                        endpoints,
                        overlay,
                    );
                })
                .map(Some);
        }
        let shutdown = Arc::clone(shutdown);
        let network_active = Arc::clone(&self.network_active);
        let peer_table = Arc::clone(&self.peer_table);
        let outbound_tx = self.outbound_tx.clone();
        let port = self.config.dns_port;
        let seeds = if self.config.dns_seeds_enabled && self.config.overlay.local_dns_allowed() {
            self.config.dns_seeds.clone()
        } else {
            Vec::new()
        };
        let target = self.config.total_outbound_active_limit();
        let maintenance = AddressMaintenance {
            shutdown,
            network_active,
            peer_table,
            outbound_tx,
            port,
            seeds,
            target,
            block_slots: self.config.outbound_block_relay_slots,
            block_sync,
            chain_query,
            address_book: Arc::clone(&self.address_book),
            banned: self.banned_reader(),
            manual_nodes: Arc::clone(&self.added_nodes),
            routes,
        };
        thread::Builder::new()
            .name("bitcoin-rs-address-maintenance".to_owned())
            .spawn(move || run_address_maintenance(&maintenance))
            .map(Some)
    }

    pub fn shutdown(&self) {
        let demonstrated = anchor_peers(&self.peer_table, &self.address_book);
        if let Some(workers) = self.workers.lock().as_mut() {
            workers.cancel(&self.peer_table, &self.overlay_addresses);
        }
        self.worker_shutdown.lock().store(true, Ordering::Release);
        self.session_cancel.lock().store(true, Ordering::Release);
        self.overlay_addresses.lock().clear();
        if !demonstrated.is_empty() {
            self.address_book
                .remember_anchors(&demonstrated, crate::addrman::now());
        }

        self.peer_table
            .set_network_active(&self.network_active, false);
        self.address_book
            .return_restart_anchors(crate::addrman::now());
        self.address_book.save();
    }

    #[must_use]
    pub fn shutdown_reader(&self) -> &bitcoin_rs_chain::LatchReader {
        &self.shutdown
    }

    pub fn join_core_workers(&self) -> Result<(), P2pJoinError> {
        let (listeners, outbound, overlay_threads) = {
            let mut slot = self.workers.lock();
            let Some(workers) = slot.as_mut() else {
                return Ok(());
            };
            let listeners = std::mem::take(&mut workers.listeners);
            let outbound = workers.outbound.take();
            let overlay_threads = std::mem::take(&mut workers.overlay_threads);
            if workers.bootstrap.is_none() {
                *slot = None;
            }
            (listeners, outbound, overlay_threads)
        };
        for handle in overlay_threads {
            if handle.join().is_err() {
                tracing::error!("p2p overlay worker panicked");
            }
        }
        let mut first_error = None;
        for handle in listeners {
            match handle.join() {
                Ok(Ok(())) => tracing::info!("p2p listener exited cleanly"),
                Ok(Err(error)) => {
                    tracing::warn!(%error, "p2p listener exited with error");
                    if first_error.is_none() {
                        first_error = Some(P2pJoinError::Listener(error));
                    }
                }
                Err(_) => {
                    tracing::error!("p2p listener panicked");
                    if first_error.is_none() {
                        first_error = Some(P2pJoinError::ListenerPanic);
                    }
                }
            }
        }
        if let Some(handle) = outbound
            && handle.join().is_err()
        {
            tracing::error!("p2p outbound drain panicked");
            if first_error.is_none() {
                first_error = Some(P2pJoinError::OutboundPanic);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub fn join_bootstrap_worker(&self) -> Result<(), P2pJoinError> {
        let bootstrap = {
            let mut slot = self.workers.lock();
            let Some(workers) = slot.as_mut() else {
                return Ok(());
            };
            let bootstrap = workers.bootstrap.take();
            if workers.listeners.is_empty() && workers.outbound.is_none() {
                *slot = None;
            }
            bootstrap
        };
        if let Some(handle) = bootstrap
            && handle.join().is_err()
        {
            tracing::error!("p2p bootstrap worker panicked");
            return Err(P2pJoinError::BootstrapPanic);
        }
        self.address_book.save();
        Ok(())
    }

    pub fn join(&self) -> Result<(), P2pJoinError> {
        let core = self.join_core_workers();
        let bootstrap = self.join_bootstrap_worker();
        core.and(bootstrap)
    }

    #[cfg(feature = "test-seam")]
    #[doc(hidden)]
    pub fn test_install_outbound_worker(&self, handle: JoinHandle<()>) {
        self.workers
            .lock()
            .get_or_insert_with(Workers::default)
            .outbound = Some(handle);
    }

    #[cfg(feature = "test-seam")]
    #[doc(hidden)]
    pub fn test_install_bootstrap_worker(&self, handle: JoinHandle<()>) {
        self.workers
            .lock()
            .get_or_insert_with(Workers::default)
            .bootstrap = Some(handle);
    }

    #[must_use]
    pub fn table(&self) -> Arc<crate::PeerTable> {
        Arc::clone(&self.peer_table)
    }

    #[must_use]
    pub fn overlay_config(&self) -> &crate::overlay::OverlayConfig {
        &self.config.overlay
    }

    #[must_use]
    pub fn local_services(&self) -> bitcoin::p2p::ServiceFlags {
        self.config.local_services
    }

    #[must_use]
    pub fn network_active(&self) -> bool {
        self.network_active.load(Ordering::Acquire)
    }

    pub fn set_network_active(&self, active: bool) {
        self.peer_table
            .set_network_active(&self.network_active, active);
    }

    pub fn set_ban(&self, entry: crate::BannedSubnet) {
        let mut banned = self.banned.inner.write();
        banned.retain(|current| current.subnet != entry.subnet);
        banned.push(entry);
    }

    pub fn remove_ban(&self, subnet: crate::IpSubnet) {
        self.banned
            .inner
            .write()
            .retain(|entry| entry.subnet != subnet);
    }

    pub fn clear_banned(&self) {
        self.banned.inner.write().clear();
    }

    #[must_use]
    pub fn banned_reader(&self) -> BannedReader {
        self.banned.clone()
    }

    #[must_use]
    pub fn banned(&self) -> Vec<crate::BannedSubnet> {
        self.banned.read().clone()
    }

    #[must_use]
    pub fn added_nodes(&self) -> Vec<PeerEndpoint> {
        self.added_nodes.read().clone()
    }

    pub fn add_node(&self, addr: PeerEndpoint, persist: bool) -> Result<(), P2pControlError> {
        if !self.overlay.config.allows(addr.address().network()) {
            return Err(P2pControlError::NetworkDisabled);
        }
        if self.banned.is_banned(addr.address(), SystemTime::now()) {
            return Err(P2pControlError::Banned);
        }
        if persist {
            let mut added = self.added_nodes.write();
            if !added.contains(&addr) {
                added.push(addr);
            }
        }
        if !self.network_active() {
            return Ok(());
        }
        match self.outbound_tx.try_send(OutboundDial::pinned(addr)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) if persist => Ok(()),
            Err(TrySendError::Full(_)) => Err(P2pControlError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(P2pControlError::Closed),
        }
    }

    pub fn remove_node(&self, addr: PeerEndpoint) {
        self.added_nodes.write().retain(|current| *current != addr);
    }

    pub fn disconnect(&self, addr: impl Into<crate::PeerRemote>) -> bool {
        self.peer_table.disconnect(addr)
    }

    pub fn disconnect_ready(&self, addr: impl Into<crate::PeerRemote>) -> bool {
        self.peer_table.disconnect_ready(addr)
    }

    pub fn disconnect_ready_node_id(&self, node_id: u64) -> bool {
        self.peer_table.disconnect_ready_node_id(node_id)
    }

    pub fn disconnect_ready_node_id_at(
        &self,
        addr: impl Into<crate::PeerRemote>,
        node_id: u64,
    ) -> bool {
        self.peer_table.disconnect_ready_node_id_at(addr, node_id)
    }

    #[cfg(test)]
    pub(crate) fn test_queue_automatic_dial(
        &self,
        addr: PeerEndpoint,
    ) -> Result<(), crossbeam_channel::SendError<OutboundDial>> {
        self.outbound_tx.send(OutboundDial::auto(addr))
    }

    pub fn take_inbound_headers_receiver(&self) -> Option<Receiver<crate::InboundHeaders>> {
        self.inbound_headers_rx.lock().take()
    }

    pub fn take_inbound_blocks_receiver(&self) -> Option<Receiver<crate::InboundBlock>> {
        self.inbound_blocks_rx.lock().take()
    }

    #[must_use]
    pub fn inbound_blocks_sender(&self) -> Sender<crate::InboundBlock> {
        self.inbound_blocks_tx.clone()
    }
}

fn defer_rejected_dial(
    dial: &OutboundDial,
    book: &crate::addrman::AddressBook,
    active: &HashMap<PeerEndpoint, ActiveOutbound>,
) {
    if dial.manual
        || active.iter().any(|(addr, running)| {
            !running.manual
                && crate::addrman::canonical(*addr) == crate::addrman::canonical(dial.addr)
        })
    {
        return;
    }
    if dial.purpose == DialPurpose::Anchor {
        book.defer_anchor(dial.addr);
    } else {
        book.reject_queued(dial.addr, dial.purpose == DialPurpose::Feeler);
    }
}

fn finish_outbound_epoch(
    parked: VecDeque<OutboundDial>,
    active: &HashMap<PeerEndpoint, ActiveOutbound>,
    handles: Vec<(PeerEndpoint, JoinHandle<Result<(), crate::PeerError>>)>,
    book: &crate::addrman::AddressBook,
) {
    for dial in parked {
        defer_rejected_dial(&dial, book, active);
    }
    for (addr, handle) in handles {
        let _ = handle.join();
        if active.get(&addr).is_some_and(|dial| !dial.manual) {
            book.unqueue(addr);
        }
    }
    book.return_restart_anchors(crate::addrman::now());
}

fn reap_finished_outbound_connections(
    active: &mut HashMap<PeerEndpoint, ActiveOutbound>,
    handles: &mut Vec<(PeerEndpoint, JoinHandle<Result<(), crate::PeerError>>)>,
    book: &crate::addrman::AddressBook,
) -> Vec<PeerEndpoint> {
    let mut finished = Vec::new();
    let mut index = 0;
    while index < handles.len() {
        if !handles[index].1.is_finished() {
            index += 1;
            continue;
        }
        let (addr, handle) = handles.swap_remove(index);
        if let Some(dial) = active.remove(&addr) {
            if dial.manual {
                finished.push(addr);
            } else {
                book.unqueue(addr);
            }
        }
        match handle.join() {
            Ok(Ok(())) => tracing::debug!(addr = %addr, "p2p outbound connection exited cleanly"),
            Ok(Err(error)) => {
                tracing::warn!(addr = %addr, %error, "p2p outbound connection exited with error");
            }
            Err(_) => tracing::warn!(addr = %addr, "p2p outbound connection panicked"),
        }
    }
    finished
}

fn spawn_feeler(
    shared: &crate::listener::ConnectionShared,
    book: &crate::addrman::AddressBook,
    manual: &[PeerEndpoint],
    active: &mut HashMap<PeerEndpoint, ActiveOutbound>,
    handles: &mut Vec<(PeerEndpoint, JoinHandle<Result<(), crate::PeerError>>)>,
    max_peer_connections: usize,
) {
    if active.values().any(|entry| entry.feeler)
        || !shared.activity.is_active()
        || shared.session_cancel.load()
    {
        return;
    }
    let connected: Vec<_> = shared
        .peer_table
        .sessions()
        .into_iter()
        .filter(|session| !session.lease.is_cancelled())
        .filter_map(|session| session.addr.endpoint())
        .collect();
    let mut addresses: Vec<_> = active.keys().copied().collect();
    addresses.extend_from_slice(&connected);
    let policy = shared.banned.automatic_snapshot(SystemTime::now());
    let routes = crate::RouteTable::from_routes(&shared.dial_routes);
    let Some(addr) = book.feeler(&addresses, &connected, crate::addrman::now(), |addr| {
        !is_manual_endpoint(manual, addr)
            && policy.allows(addr.address())
            && routes.denial(&addr).is_none()
    }) else {
        return;
    };
    if !book.queued_feeler(addr) {
        return;
    }
    spawn_outbound_dial(
        &OutboundDial {
            addr,
            manual: false,
            purpose: DialPurpose::Feeler,
        },
        shared,
        active,
        handles,
        0,
        0,
        false,
        max_peer_connections,
    );
}

fn is_manual_endpoint(manual: &[PeerEndpoint], addr: PeerEndpoint) -> bool {
    let addr = crate::addrman::canonical(addr);
    manual
        .iter()
        .any(|pin| crate::addrman::canonical(*pin) == addr)
}

fn wait_for_shutdown(shutdown: &AtomicBool, delay: Duration) -> bool {
    let deadline = Instant::now() + delay;
    while !shutdown.load(Ordering::Acquire) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
    true
}

#[cfg(test)]
fn bootstrap_fixed_peer_endpoints<R, I>(
    network_active: &AtomicBool,
    peer_table: &crate::PeerTable,
    outbound_tx: &Sender<OutboundDial>,
    endpoints: &[String],
    mut resolve: R,
) where
    R: FnMut(&str) -> io::Result<I>,
    I: IntoIterator<Item = SocketAddr>,
{
    'endpoints: for endpoint in endpoints {
        if !network_active.load(Ordering::Acquire) {
            break 'endpoints;
        }
        match crate::endpoint::classify_endpoint(endpoint) {
            crate::endpoint::ClassifiedEndpoint::Valid(parsed) => {
                if peer_table.is_connected(parsed) || !network_active.load(Ordering::Acquire) {
                    continue;
                }
                if outbound_tx.try_send(OutboundDial::pinned(parsed)).is_err() {
                    break 'endpoints;
                }
            }
            crate::endpoint::ClassifiedEndpoint::InvalidOverlay => {
                tracing::warn!(
                    endpoint,
                    "fixed peer rejected: invalid overlay name must not resolve via DNS"
                );
            }
            crate::endpoint::ClassifiedEndpoint::NonOverlay => {
                let addresses = match resolve(endpoint.as_str()) {
                    Ok(addresses) => addresses,
                    Err(error) => {
                        tracing::warn!(endpoint, %error, "fixed peer resolution failed");
                        continue;
                    }
                };
                for addr in addresses {
                    if peer_table.is_connected(crate::PeerEndpoint::Ip(addr))
                        || !network_active.load(Ordering::Acquire)
                    {
                        continue;
                    }
                    if outbound_tx
                        .try_send(OutboundDial::pinned(crate::PeerEndpoint::Ip(addr)))
                        .is_err()
                    {
                        break 'endpoints;
                    }
                }
            }
        }
    }
}

#[expect(clippy::needless_pass_by_value)]
fn run_fixed_peer_resolution(
    shutdown: Arc<AtomicBool>,
    network_active: Arc<AtomicBool>,
    destinations: Arc<RwLock<Vec<PeerEndpoint>>>,
    endpoints: Vec<String>,
    overlay: Arc<crate::overlay::OverlayTransport>,
) {
    while !shutdown.load(Ordering::Acquire) {
        if !network_active.load(Ordering::Acquire) {
            if wait_for_shutdown(&shutdown, Duration::from_millis(100)) {
                break;
            }
            continue;
        }
        let mut resolved = Vec::new();
        for endpoint in &endpoints {
            match overlay.resolve(endpoint, &|| {
                shutdown.load(Ordering::Acquire) || !network_active.load(Ordering::Acquire)
            }) {
                Ok(addresses) => resolved.extend(addresses),
                Err(error) => tracing::warn!(endpoint, %error, "fixed peer resolution failed"),
            }
        }
        *destinations.write() = resolved;
        if wait_for_shutdown(&shutdown, Duration::from_secs(2)) {
            break;
        }
    }
}
/// INVARIANT: an operator pin (`--connect`/`addnode`) asks for full relay because
/// Core's `ConnectionType::MANUAL` peers relay transactions.
///
/// Feeding the pin through the slot chooser could hand it `BlockRelayOnly`, which
/// advertises `relay = false` and ends the connection on the first transaction the
/// operator's peer sends; the chooser only orders the dials the scheduler started
/// itself.
fn dial_outbound_role(
    dial: &OutboundDial,
    peer_table: &crate::PeerTable,
    pending: &HashMap<PeerEndpoint, ActiveOutbound>,
    full_relay_slots: usize,
    block_relay_slots: usize,
    extra_full_relay: bool,
) -> crate::peer_info::PeerRole {
    if dial.manual {
        return crate::peer_info::PeerRole::FullRelay;
    }
    if dial.purpose == DialPurpose::Feeler {
        return crate::peer_info::PeerRole::BlockRelayOnly;
    }
    if dial.purpose == DialPurpose::Anchor {
        return crate::PeerRole::BlockRelayOnly;
    }
    next_outbound_role(
        peer_table,
        pending,
        full_relay_slots,
        block_relay_slots,
        extra_full_relay,
    )
}

fn count_address_failure(
    peer_table: &crate::PeerTable,
    maximum: usize,
    book: &crate::addrman::AddressBook,
) -> bool {
    let outbound: Vec<_> = peer_table
        .sessions()
        .into_iter()
        .filter(|session| {
            !session.lease.is_inbound()
                && !session.lease.is_cancelled()
                && !session
                    .addr
                    .endpoint()
                    .is_some_and(|addr| book.is_feeler(addr))
        })
        .filter_map(|session| session.addr.endpoint())
        .collect();
    book.count_failure(&outbound, maximum)
}

fn spawn_outbound_dial(
    dial: &OutboundDial,
    shared: &crate::listener::ConnectionShared,
    active: &mut HashMap<PeerEndpoint, ActiveOutbound>,
    handles: &mut Vec<(PeerEndpoint, JoinHandle<Result<(), crate::PeerError>>)>,
    full_relay_slots: usize,
    block_relay_slots: usize,
    extra_dial: bool,
    max_peer_connections: usize,
) {
    let dial = OutboundDial {
        addr: crate::addrman::canonical(dial.addr),
        ..*dial
    };
    let services_allowed = dial.manual
        || dial.purpose == DialPurpose::Feeler
        || shared.address_book.as_ref().is_none_or(|book| {
            let depth =
                crate::listener::approximate_best_block_depth(shared.chain_query.as_deref());
            book.ordinary_services_eligible(dial.addr, depth)
        });
    let allowed = if dial.manual {
        !shared
            .banned
            .is_banned(dial.addr.address(), SystemTime::now())
    } else {
        shared
            .banned
            .automatic_snapshot(SystemTime::now())
            .allows(dial.addr.address())
    };
    if !shared.activity.is_active() || shared.session_cancel.load() || !services_allowed || !allowed
    {
        if let Some(book) = &shared.address_book {
            defer_rejected_dial(&dial, book, active);
        }
        return;
    }
    let peer_table = shared.peer_table.as_ref();
    if active
        .keys()
        .any(|addr| crate::addrman::canonical(*addr) == dial.addr)
        || peer_table.sessions().iter().any(|session| {
            !session.lease.is_cancelled()
                && session.addr.endpoint().map(crate::addrman::canonical) == Some(dial.addr)
        })
    {
        if !dial.manual && active.get(&dial.addr).is_none_or(|running| running.manual) {
            if let Some(book) = &shared.address_book {
                defer_rejected_dial(&dial, book, active);
            }
        }
        tracing::debug!(
            addr = %dial.addr,
            "p2p outbound request skipped: already active"
        );
        return;
    }
    let role = dial_outbound_role(
        &dial,
        peer_table,
        active,
        full_relay_slots,
        block_relay_slots,
        extra_dial,
    );
    let count_failure = !dial.manual
        && shared
            .address_book
            .as_ref()
            .is_some_and(|book| count_address_failure(peer_table, max_peer_connections, book));
    if !dial.manual {
        if let Some(book) = &shared.address_book {
            match dial.purpose {
                DialPurpose::Regular => {
                    if !book.queued(dial.addr) {
                        return;
                    }
                }
                DialPurpose::Feeler => {}
                DialPurpose::Anchor => {
                    if !book.anchor_dispatched(dial.addr) {
                        return;
                    }
                }
            }
        } else if dial.purpose == DialPurpose::Anchor {
            return;
        }
    }
    let mut shared = shared.clone();
    shared.feeler = dial.purpose == DialPurpose::Feeler;
    let handle = if dial.manual {
        crate::listener::spawn_pinned_outbound_connection(dial.addr, shared, role)
    } else {
        crate::listener::spawn_dial(dial.addr, shared, role, false, count_failure)
    };
    active.insert(
        dial.addr,
        ActiveOutbound {
            feeler: dial.purpose == DialPurpose::Feeler,
            role,
            manual: dial.manual,
        },
    );
    handles.push((dial.addr, handle));
}

/// INVARIANT: only automatic connections count, once in their own class.
fn next_outbound_role(
    peer_table: &crate::PeerTable,
    pending: &HashMap<PeerEndpoint, ActiveOutbound>,
    full_relay_slots: usize,
    block_relay_slots: usize,
    extra_full_relay: bool,
) -> crate::peer_info::PeerRole {
    use crate::peer_info::PeerRole;
    let sessions = peer_table.sessions();
    let census: Vec<&crate::peer_table::PeerSession> = sessions
        .iter()
        .filter(|session| {
            !session.lease.is_inbound()
                && !session.lease.is_cancelled()
                && !session.lease.is_manual()
                && !session
                    .addr
                    .endpoint()
                    .and_then(|addr| pending.get(&addr))
                    .is_some_and(|entry| entry.feeler)
        })
        .collect();
    let connected_full = census
        .iter()
        .filter(|session| session.lease.role() == PeerRole::FullRelay)
        .count();
    let connected_block = census
        .iter()
        .filter(|session| session.lease.role() == PeerRole::BlockRelayOnly)
        .count();
    let in_flight = |want: PeerRole| {
        pending
            .iter()
            .filter(|(addr, outbound)| {
                !outbound.manual
                    && !outbound.feeler
                    && outbound.role == want
                    && !census
                        .iter()
                        .any(|session| session.addr.endpoint() == Some(**addr))
            })
            .count()
    };
    let dialed_full = connected_full + in_flight(PeerRole::FullRelay);
    let dialed_block = connected_block + in_flight(PeerRole::BlockRelayOnly);
    if dialed_full < full_relay_slots + usize::from(extra_full_relay) {
        PeerRole::FullRelay
    } else if dialed_block < block_relay_slots {
        PeerRole::BlockRelayOnly
    } else {
        PeerRole::FullRelay
    }
}

/// INVARIANT: the extra connection exists to find a better chain, so it leaves as soon
/// as the chain moves.
///
/// Core retires one per check (`EvictExtraOutboundPeers`,
/// `net_processing.cpp:5604-5668`) and passes over a peer with blocks in flight or a
/// peer below the minimum age.
fn retire_extra_full_relay_connection(
    peer_table: &crate::PeerTable,
    sync: Option<&crate::sync::BlockSync>,
    slots: usize,
    now: Instant,
) {
    let Some(sync) = sync else {
        return;
    };
    if sync.allow_extra_full_relay_dial() {
        return;
    }
    let Some(session) = newest_excess_full_relay(peer_table, slots, now, |source| {
        sync.is_downloading_bodies(source)
    }) else {
        return;
    };
    if session.endpoint.is_some_and(|endpoint| {
        peer_table.disconnect_connection(endpoint, session.lease.connection_id())
    }) {
        tracing::info!(
            peer_addr = ?session.endpoint,
            "p2p retiring the extra full-relay connection: the tip is moving again"
        );
    }
}

/// INVARIANT: the census and the victim set hold automatic connections only:
///   a hand-pinned full-relay connection counts in neither, as Core's
///   `IsFullOutboundConn()` excludes `ConnectionType::MANUAL`
fn newest_excess_full_relay(
    peer_table: &crate::PeerTable,
    slots: usize,
    now: Instant,
    is_downloading: impl Fn(crate::PeerSource) -> bool,
) -> Option<crate::peer_table::PeerSession> {
    let sessions: Vec<crate::peer_table::PeerSession> = peer_table
        .sessions()
        .into_iter()
        .filter(|session| {
            !session.lease.is_inbound()
                && !session.lease.is_cancelled()
                && !session.lease.is_manual()
                && session.lease.role() == crate::peer_info::PeerRole::FullRelay
        })
        .collect();
    let excess = sessions.len().saturating_sub(slots);
    if excess == 0 {
        return None;
    }
    sessions
        .iter()
        .rev()
        .take(excess)
        .find(|session| {
            now.saturating_duration_since(session.lease.connected_at())
                >= crate::download_window::MINIMUM_CONNECT_TIME
                && !is_downloading(session.lease.source(session.endpoint))
        })
        .cloned()
}

fn dial_has_capacity(
    dial: &OutboundDial,
    active: &HashMap<PeerEndpoint, ActiveOutbound>,
    total: usize,
    blocks: usize,
    extra: bool,
) -> bool {
    has_automatic_outbound_capacity(active, total, extra)
        && (dial.purpose != DialPurpose::Anchor
            || active
                .values()
                .filter(|entry| {
                    !entry.manual && !entry.feeler && entry.role == crate::PeerRole::BlockRelayOnly
                })
                .count()
                < blocks)
}

fn has_automatic_outbound_capacity(
    active: &HashMap<PeerEndpoint, ActiveOutbound>,
    active_limit: usize,
    extra_dial: bool,
) -> bool {
    let count = active
        .values()
        .filter(|outbound| !outbound.manual && !outbound.feeler)
        .count();
    count < active_limit + usize::from(extra_dial)
}

struct AddressMaintenance {
    shutdown: Arc<AtomicBool>,
    network_active: Arc<AtomicBool>,
    peer_table: Arc<crate::PeerTable>,
    outbound_tx: Sender<OutboundDial>,
    port: u16,
    seeds: Vec<String>,
    target: usize,
    block_slots: usize,
    block_sync: Option<Arc<crate::sync::BlockSync>>,
    chain_query: Option<Arc<dyn crate::ChainQuery>>,
    address_book: Arc<crate::addrman::AddressBook>,
    banned: BannedReader,
    manual_nodes: Arc<RwLock<Vec<crate::PeerEndpoint>>>,
    routes: crate::RouteTable,
}

fn park_automatic_dial(
    parked: &mut VecDeque<OutboundDial>,
    dial: OutboundDial,
    book: &crate::addrman::AddressBook,
    active: &HashMap<PeerEndpoint, ActiveOutbound>,
) -> bool {
    if parked.len() >= MAX_PARKED_DIALS {
        defer_rejected_dial(&dial, book, active);
        return false;
    }
    parked.push_back(dial);
    true
}

fn ready_address_count(peer_table: &crate::PeerTable, book: &crate::addrman::AddressBook) -> usize {
    peer_table
        .sessions()
        .into_iter()
        .filter(|session| {
            !session.lease.is_inbound()
                && !session.lease.is_manual()
                && !session.lease.is_cancelled()
                && session.info.is_some()
                && !session
                    .addr
                    .endpoint()
                    .is_some_and(|addr| book.is_feeler(addr))
        })
        .count()
}

fn anchor_peers(table: &crate::PeerTable, book: &crate::addrman::AddressBook) -> Vec<PeerEndpoint> {
    table
        .sessions()
        .into_iter()
        .filter(|session| {
            !session.lease.is_cancelled()
                && !session.lease.is_inbound()
                && !session.lease.is_manual()
                && session.lease.role() == crate::PeerRole::BlockRelayOnly
                && session.info.is_some()
                && !session.demonstrated_tips.is_empty()
                && !session
                    .addr
                    .endpoint()
                    .is_some_and(|addr| book.is_feeler(addr))
        })
        .filter_map(|session| session.addr.endpoint())
        .collect()
}

fn queue_restart_anchors(
    maintenance: &AddressMaintenance,
    anchors: &mut VecDeque<PeerEndpoint>,
    attempting: &mut Option<PeerEndpoint>,
    active: &mut Vec<PeerEndpoint>,
    now: u64,
) -> usize {
    if maintenance.shutdown.load(Ordering::Acquire)
        || !maintenance.network_active.load(Ordering::Acquire)
    {
        return 0;
    }
    let sessions = maintenance.peer_table.sessions();
    let ready_blocks: Vec<_> = sessions
        .iter()
        .filter(|session| {
            !session.lease.is_cancelled()
                && !session.lease.is_inbound()
                && !session.lease.is_manual()
                && session.lease.role() == crate::PeerRole::BlockRelayOnly
                && session.info.is_some()
                && !session
                    .addr
                    .endpoint()
                    .is_some_and(|addr| maintenance.address_book.is_feeler(addr))
        })
        .filter_map(|session| session.addr.endpoint())
        .collect();
    if let Some(addr) = *attempting
        && maintenance.address_book.anchor_eligible(addr, &[], now)
    {
        anchors.push_front(addr);
        *attempting = None;
    }
    if let Some(addr) = *attempting
        && maintenance.address_book.is_pending(addr)
        && !maintenance.address_book.is_feeler(addr)
        && !ready_blocks.contains(&addr)
    {
        return anchors.len().min(
            maintenance
                .block_slots
                .saturating_sub(ready_blocks.len() + 1),
        );
    }
    *attempting = None;
    if ready_blocks.len() >= maintenance.block_slots {
        anchors.clear();
        maintenance.address_book.return_restart_anchors(now);
        return 0;
    }
    let depth = crate::listener::approximate_best_block_depth(maintenance.chain_query.as_deref());
    let policy = maintenance.banned.automatic_snapshot(SystemTime::now());
    let manual = maintenance.manual_nodes.read();
    while let Some(addr) = anchors.pop_front() {
        if is_manual_endpoint(&manual, addr)
            || !maintenance.address_book.anchor_eligible(addr, active, now)
            || !maintenance
                .address_book
                .ordinary_services_eligible(addr, depth)
            || !policy.allows(addr.address())
            || maintenance.routes.denial(&addr).is_some()
        {
            maintenance.address_book.return_restart_anchor(addr, now);
            continue;
        }
        if !maintenance.address_book.queue_anchor(addr) {
            continue;
        }
        if maintenance
            .outbound_tx
            .try_send(OutboundDial {
                addr,
                manual: false,
                purpose: DialPurpose::Anchor,
            })
            .is_err()
        {
            maintenance.address_book.defer_anchor(addr);
            anchors.push_front(addr);
            break;
        }
        *attempting = Some(addr);
        active.push(addr);
        break;
    }
    anchors.len().min(
        maintenance
            .block_slots
            .saturating_sub(ready_blocks.len() + usize::from(attempting.is_some())),
    )
}

fn run_address_maintenance(maintenance: &AddressMaintenance) {
    let resolver = crate::peer::SystemDnsResolver::new(maintenance.port);
    let mut next_dns = Instant::now()
        + if maintenance.address_book.len() < 64 {
            Duration::ZERO
        } else {
            Duration::from_secs(60)
        };
    let mut next_save = Instant::now() + Duration::from_mins(15);
    let mut anchors = VecDeque::new();
    let mut anchors_taken = false;
    let mut anchor_attempt = None;
    while !maintenance.shutdown.load(Ordering::Acquire) {
        let tick_time = SystemTime::now();
        let now = tick_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let ready_count = ready_address_count(&maintenance.peer_table, &maintenance.address_book);
        if maintenance.network_active.load(Ordering::Acquire) {
            if !anchors_taken && maintenance.block_slots > 0 {
                anchors = maintenance.address_book.take_restart_anchors(now).into();
                anchors_taken = true;
            }
            if maintenance.shutdown.load(Ordering::Acquire)
                || !maintenance.network_active.load(Ordering::Acquire)
            {
                continue;
            }
            let connected: Vec<_> = maintenance
                .peer_table
                .sessions()
                .into_iter()
                .filter(|session| !session.lease.is_cancelled())
                .filter_map(|session| session.addr.endpoint())
                .collect();
            let policy = maintenance.banned.automatic_snapshot(tick_time);
            {
                let manual = maintenance.manual_nodes.read();
                if maintenance.shutdown.load(Ordering::Acquire)
                    || !maintenance.network_active.load(Ordering::Acquire)
                {
                    continue;
                }
                maintenance
                    .address_book
                    .resolve_collisions(&connected, now, |addr| {
                        !is_manual_endpoint(&manual, addr) && policy.allows(addr.address())
                    });
            }
            if dns_recovery_due(
                maintenance.address_book.len(),
                ready_count,
                maintenance.target,
                Instant::now(),
                &mut next_dns,
            ) {
                for seed in &maintenance.seeds {
                    match crate::peer::DnsResolver::resolve(&resolver, seed) {
                        Ok(addresses) => maintenance.address_book.learn_dns(seed, &addresses, now),
                        Err(error) => tracing::warn!(seed, %error, "DNS bootstrap unavailable"),
                    }
                }
            }
            let mut active: Vec<_> = maintenance
                .peer_table
                .sessions()
                .into_iter()
                .filter(|session| {
                    !session.lease.is_cancelled()
                        && !session.lease.is_inbound()
                        && !session
                            .addr
                            .endpoint()
                            .is_some_and(|addr| maintenance.address_book.is_feeler(addr))
                })
                .filter_map(|session| session.addr.endpoint())
                .collect();
            let reserved = queue_restart_anchors(
                maintenance,
                &mut anchors,
                &mut anchor_attempt,
                &mut active,
                now,
            );
            queue_address_candidates(maintenance, now, tick_time, reserved);
        }
        let demonstrated = anchor_peers(&maintenance.peer_table, &maintenance.address_book);
        if !demonstrated.is_empty() {
            maintenance
                .address_book
                .remember_anchors(&demonstrated, now);
        }
        save_address_book_if_due(&maintenance.address_book, Instant::now(), &mut next_save);
        if wait_for_shutdown(&maintenance.shutdown, Duration::from_secs(1)) {
            break;
        }
    }
    maintenance
        .address_book
        .return_restart_anchors(crate::addrman::now());
    maintenance.address_book.save();
}

fn dns_recovery_due(
    book_len: usize,
    ready: usize,
    target: usize,
    tick: Instant,
    next: &mut Instant,
) -> bool {
    if tick < *next || (book_len >= 64 && ready >= target) {
        return false;
    }
    *next = tick + Duration::from_secs(60);
    true
}

fn save_address_book_if_due(book: &crate::addrman::AddressBook, tick: Instant, next: &mut Instant) {
    if tick >= *next {
        *next = tick + Duration::from_mins(15);
        book.save();
    }
}

fn queue_address_candidates(
    maintenance: &AddressMaintenance,
    now: u64,
    tick_time: SystemTime,
    reserved_anchors: usize,
) {
    let extra = usize::from(
        maintenance
            .block_sync
            .as_ref()
            .is_some_and(|sync| sync.allow_extra_full_relay_dial()),
    );
    let sessions = maintenance.peer_table.sessions();
    let mut active: Vec<_> = sessions
        .iter()
        .filter(|session| !session.lease.is_cancelled())
        .filter_map(|session| session.addr.endpoint())
        .collect();
    let grouped: Vec<_> = sessions
        .iter()
        .filter(|session| {
            !session.lease.is_cancelled()
                && !session.lease.is_inbound()
                && !session
                    .addr
                    .endpoint()
                    .is_some_and(|addr| maintenance.address_book.is_feeler(addr))
        })
        .filter_map(|session| session.addr.endpoint())
        .collect();
    let automatic: Vec<_> = sessions
        .iter()
        .filter(|session| {
            !session.lease.is_cancelled()
                && !session.lease.is_inbound()
                && !session.lease.is_manual()
                && !session
                    .addr
                    .endpoint()
                    .is_some_and(|addr| maintenance.address_book.is_feeler(addr))
        })
        .filter_map(|session| session.addr.endpoint())
        .collect();
    let occupied = automatic.len() + maintenance.address_book.pending_count_excluding(&automatic);
    let needed = (maintenance.target + extra).saturating_sub(occupied + reserved_anchors);
    let policy = maintenance.banned.automatic_snapshot(tick_time);
    let depth = crate::listener::approximate_best_block_depth(maintenance.chain_query.as_deref());
    let manual = maintenance.manual_nodes.read();
    for _ in 0..needed {
        if maintenance.shutdown.load(Ordering::Acquire)
            || !maintenance.network_active.load(Ordering::Acquire)
        {
            break;
        }
        let Some(addr) = maintenance
            .address_book
            .select(&active, &grouped, now, depth, |addr| {
                !is_manual_endpoint(&manual, addr)
                    && policy.allows(addr.address())
                    && maintenance.routes.denial(&addr).is_none()
            })
        else {
            break;
        };
        if !maintenance.address_book.queued(addr) {
            continue;
        }
        if maintenance
            .outbound_tx
            .try_send(OutboundDial::auto(addr))
            .is_err()
        {
            maintenance.address_book.reject_queued(addr, false);
            break;
        }
        active.push(addr);
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::PeerSource;
    use bitcoin_rs_primitives::PeerEndpoint;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};

    #[test]
    fn feeler_poisson_delay_matches_actual_core_uniform_vectors() {
        let data: sonic_rs::Value =
            sonic_rs::from_str(include_str!("../tests/data/core-poisson-v31.1.json"))
                .expect("actual Core sampling fixture");
        for row in data["rows"].as_array().expect("rows") {
            assert_eq!(
                feeler_delay(row["uniform"].as_u64().expect("uniform")).as_micros(),
                u128::from(row["delay_us"].as_u64().expect("microseconds")),
                "{row}"
            );
        }
    }

    fn idle_ready() -> Arc<dyn Fn(PeerSource) + Send + Sync> {
        Arc::new(|_source: PeerSource| {})
    }

    #[test]
    fn relay_feature_switches_default_off_and_reach_connections_independently() {
        let (headers, _) = crossbeam_channel::bounded(1);
        let (blocks, _) = crossbeam_channel::bounded(1);
        let mut shared = crate::listener::ConnectionShared::new(
            Arc::new(crate::PeerTable::new()),
            BannedReader::fixture_empty(),
            Arc::new(crate::NetworkActivity::from_shared(Arc::new(
                AtomicBool::new(true),
            ))),
            Arc::new(AtomicBool::new(false)),
            None,
            Magic::REGTEST,
            headers,
            blocks,
            None,
            None,
            crate::listener::ListenerExtras::default(),
        );
        P2pServiceConfig::default().apply_to(&mut shared);
        assert_eq!(shared.relay_offers, crate::RelayOffers::default());

        for offers in [
            crate::RelayOffers {
                package_relay: true,
                ..crate::RelayOffers::default()
            },
            crate::RelayOffers {
                stale_tip_relay: true,
                ..crate::RelayOffers::default()
            },
            crate::RelayOffers {
                stale_tip_relay: true,
                stale_tip_prefers_blocks: true,
                ..crate::RelayOffers::default()
            },
            crate::RelayOffers::default(),
        ] {
            P2pServiceConfig {
                relay_offers: offers,
                ..P2pServiceConfig::default()
            }
            .apply_to(&mut shared);
            assert_eq!(shared.relay_offers, offers);
        }
    }

    #[test]
    fn start_fails_when_listener_cannot_bind() {
        let occupied = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )
        .expect("occupy port");
        let addr = occupied.local_addr().expect("local_addr");
        let service = P2pService::new(
            P2pServiceConfig {
                listen_addrs: vec![addr],
                ..P2pServiceConfig::default()
            },
            Arc::new(AtomicBool::new(false)),
        );
        let error = service
            .start(
                None,
                None,
                &idle_ready(),
                crate::listener::ListenerExtras::default(),
            )
            .expect_err("occupied listen addr must fail start");
        assert!(
            matches!(error, P2pServiceError::Listener(ListenerError::Bind { .. })),
            "start must surface the bind failure, got {error:?}"
        );
        service.shutdown();
        service
            .join()
            .expect("failed start must leave the service joinable");
        drop(occupied);
    }

    #[test]
    fn independent_services_own_independent_aggregate_budgets() {
        let first = P2pService::new(
            P2pServiceConfig::default(),
            Arc::new(AtomicBool::new(false)),
        );
        let second = P2pService::new(
            P2pServiceConfig::default(),
            Arc::new(AtomicBool::new(false)),
        );
        let a = first.shared_outbound_budget();
        let b = second.shared_outbound_budget();
        assert!(!Arc::ptr_eq(&a, &b), "services must not share an aggregate");
        let (queue, _receiver) = crate::test_support::message_channel();
        let lease = crate::PeerLease::new(queue).with_shared_budget(&a);
        assert!(lease.send(crate::Message::Ping(1)).is_ok());
        assert!(a.pending() > 0, "the send counts against its service");
        assert_eq!(b.pending(), 0, "the other service is unaffected");
    }

    #[test]
    fn start_and_join_succeed_without_listeners() {
        let service = P2pService::new(
            P2pServiceConfig::default(),
            Arc::new(AtomicBool::new(false)),
        );
        service
            .start(
                None,
                None,
                &idle_ready(),
                crate::listener::ListenerExtras::default(),
            )
            .expect("empty listen set starts");
        service.shutdown();
        service.join().expect("clean join");
    }

    #[test]
    fn overlay_workers_are_retained_for_join_and_rollback() {
        let dir = tempfile::tempdir().expect("identity dir");
        let mut config = P2pServiceConfig::default();
        config.overlay.onion_proxy = Some(SocketAddr::from(([127, 0, 0, 1], 19051)));
        config.overlay.tor_control = Some(SocketAddr::from(([127, 0, 0, 1], 19052)));
        config.overlay.identity_dir = dir.path().to_path_buf();
        let service = P2pService::new(config, Arc::new(AtomicBool::new(false)));
        service
            .start(
                None,
                None,
                &idle_ready(),
                crate::listener::ListenerExtras::default(),
            )
            .expect("overlay start succeeds");
        {
            let workers = service.workers.lock();
            let workers = workers.as_ref().expect("workers installed");
            assert_eq!(
                workers.listeners.len(),
                1,
                "overlay.start handles must be retained for rollback and join"
            );
        }
        service.shutdown();
        service.join().expect("join waits for overlay teardown");
    }

    #[test]
    fn network_activity_transition_cancels_leases_only_when_disabled() {
        let table = crate::PeerTable::new();
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        table.register(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333)),
            lease.clone(),
        );
        let flag = AtomicBool::new(true);

        table.set_network_active(&flag, true);
        assert!(flag.load(Ordering::Acquire));
        assert!(!lease.is_cancelled());

        table.set_network_active(&flag, false);
        assert!(!flag.load(Ordering::Acquire));
        assert!(lease.is_cancelled());
    }

    #[test]
    fn manual_connection_does_not_fill_automatic_full_relay_slot() {
        use crate::connection::PeerLease;
        use crate::peer_info::PeerRole;

        let table = crate::PeerTable::new();
        let (manual_tx, _manual_rx) = crossbeam_channel::unbounded();
        table.register(
            PeerEndpoint::from(([127, 0, 0, 1], 1)),
            PeerLease::new_manual(manual_tx, PeerRole::FullRelay),
        );
        let mut pending = HashMap::from([(
            PeerEndpoint::from(([127, 0, 0, 1], 2)),
            ActiveOutbound {
                feeler: false,

                role: PeerRole::FullRelay,
                manual: true,
            },
        )]);
        let automatic_dial = OutboundDial::auto(PeerEndpoint::from(([127, 0, 0, 1], 3)));

        assert_eq!(
            dial_outbound_role(&automatic_dial, &table, &pending, 1, 1, false),
            PeerRole::FullRelay,
            "manual peers and dials must not fill automatic slots"
        );
        assert!(
            has_automatic_outbound_capacity(&pending, 1, false),
            "a pending manual dial must not use automatic capacity"
        );

        pending.insert(
            PeerEndpoint::from(([127, 0, 0, 1], 4)),
            ActiveOutbound {
                feeler: false,

                role: PeerRole::FullRelay,
                manual: false,
            },
        );
        assert!(
            !has_automatic_outbound_capacity(&pending, 1, false),
            "a pending automatic dial must use automatic capacity"
        );
    }

    #[test]
    fn next_outbound_role_fills_full_relay_slots_first() {
        use crate::connection::PeerLease;
        let table = crate::PeerTable::new();
        assert!(
            matches!(
                next_outbound_role(&table, &HashMap::new(), 1, 1, false),
                crate::peer_info::PeerRole::FullRelay
            ),
            "an empty table takes the full-relay slot first"
        );

        let (full_tx, _full_rx) = crossbeam_channel::unbounded();
        table.register(
            PeerEndpoint::from(([127, 0, 0, 1], 1)),
            PeerLease::new(full_tx),
        );
        assert!(
            matches!(
                next_outbound_role(&table, &HashMap::new(), 1, 1, false),
                crate::peer_info::PeerRole::BlockRelayOnly
            ),
            "the full-relay slot is held, so the next dial is block-relay"
        );
        assert!(
            matches!(
                next_outbound_role(&table, &HashMap::new(), 1, 1, true),
                crate::peer_info::PeerRole::FullRelay
            ),
            "a stale tip raises the full-relay target by one"
        );

        let (block_tx, _block_rx) = crossbeam_channel::unbounded();
        table.register(
            PeerEndpoint::from(([127, 0, 0, 1], 2)),
            PeerLease::new_block_relay(block_tx),
        );
        assert!(
            matches!(
                next_outbound_role(&table, &HashMap::new(), 1, 1, false),
                crate::peer_info::PeerRole::FullRelay
            ),
            "with both classes full, a requested dial stays full relay"
        );
    }

    #[test]
    fn in_flight_dials_hold_their_class() {
        use crate::peer_info::PeerRole;

        let table = crate::PeerTable::new();
        let mut pending: HashMap<PeerEndpoint, ActiveOutbound> = HashMap::new();
        for port in 1..=8_u16 {
            pending.insert(
                PeerEndpoint::from(([127, 0, 0, 1], port)),
                ActiveOutbound {
                    feeler: false,

                    role: PeerRole::FullRelay,
                    manual: false,
                },
            );
        }
        assert!(
            matches!(
                next_outbound_role(&table, &pending, 8, 2, false),
                PeerRole::BlockRelayOnly
            ),
            "eight unregistered full-relay dials already fill the full-relay slots"
        );
        for port in 9..=10_u16 {
            pending.insert(
                PeerEndpoint::from(([127, 0, 0, 1], port)),
                ActiveOutbound {
                    feeler: false,

                    role: PeerRole::BlockRelayOnly,
                    manual: false,
                },
            );
        }
        assert!(
            matches!(
                next_outbound_role(&table, &pending, 8, 2, false),
                PeerRole::FullRelay
            ),
            "with both classes dialled full, a requested dial stays full relay"
        );
    }

    #[test]
    fn a_registered_dial_counts_once() {
        use crate::connection::PeerLease;
        use crate::peer_info::PeerRole;

        let table = crate::PeerTable::new();
        let mut pending: HashMap<PeerEndpoint, ActiveOutbound> = HashMap::new();
        for port in 1..=5_u16 {
            let addr = PeerEndpoint::from(([127, 0, 0, 1], port));
            let (tx, _rx) = crossbeam_channel::unbounded();
            table.register(addr, PeerLease::new(tx));
            pending.insert(
                addr,
                ActiveOutbound {
                    feeler: false,

                    role: PeerRole::FullRelay,
                    manual: false,
                },
            );
        }
        assert!(
            matches!(
                next_outbound_role(&table, &pending, 8, 2, false),
                PeerRole::FullRelay
            ),
            "five connected full-relay peers hold five of eight slots, not ten"
        );
    }

    #[test]
    fn newest_excess_full_relay_picks_the_newest_aged_connection() {
        use crate::connection::PeerLease;
        use crate::download_window::MINIMUM_CONNECT_TIME;
        use crate::peer_info::PeerRole;

        fn addr(port: u16) -> PeerEndpoint {
            PeerEndpoint::from(([127, 0, 0, 1], port))
        }

        let now = Instant::now();
        let aged = now
            .checked_sub(MINIMUM_CONNECT_TIME)
            .expect("test clock is past the minimum connect time");
        let table = crate::PeerTable::new();
        for port in 1..=2_u16 {
            let (tx, _rx) = crossbeam_channel::unbounded();
            let mut lease = PeerLease::new(tx);
            lease.backdate_for_test(aged);
            table.register(addr(port), lease);
        }
        let (block_tx, _block_rx) = crossbeam_channel::unbounded();
        let mut block_lease = PeerLease::new_block_relay(block_tx);
        block_lease.backdate_for_test(aged);
        table.register(addr(3), block_lease);
        let (inbound_tx, _inbound_rx) = crossbeam_channel::unbounded();
        let mut inbound_lease = PeerLease::new_inbound(inbound_tx);
        inbound_lease.backdate_for_test(aged);
        table.register(addr(4), inbound_lease);

        assert!(
            newest_excess_full_relay(&table, 2, now, |_| false).is_none(),
            "two full-relay connections fill two slots, and neither a              block-relay nor an inbound connection counts as one"
        );

        let (young_tx, _young_rx) = crossbeam_channel::unbounded();
        let young_lease = PeerLease::new(young_tx);
        table.register(addr(5), young_lease);
        let (third_tx, _third_rx) = crossbeam_channel::unbounded();
        let mut third_lease = PeerLease::new(third_tx);
        third_lease.backdate_for_test(aged);
        table.register(addr(6), third_lease);

        let excess = newest_excess_full_relay(&table, 2, now, |_| false)
            .expect("three full-relay peers are one extra");
        assert_eq!(
            excess.addr,
            crate::PeerRemote::Endpoint(addr(6)),
            "the newest aged connection is the one"
        );
        assert_eq!(excess.lease.role(), PeerRole::FullRelay);

        let (pinned_tx, _pinned_rx) = crossbeam_channel::unbounded();
        let mut pinned_lease = PeerLease::new_manual(pinned_tx, PeerRole::FullRelay);
        pinned_lease.backdate_for_test(aged);
        table.register(addr(7), pinned_lease);
        assert_eq!(
            newest_excess_full_relay(&table, 2, now, |_| false)
                .expect("the pinned connection is not a candidate")
                .endpoint
                .expect("identified excess peer"),
            excess.endpoint.expect("identified excess peer"),
            "the newest automatic connection stays the victim while a pinned one is newer"
        );
    }

    #[test]
    fn a_pinned_dial_takes_full_relay_whatever_the_slots_hold() {
        use crate::connection::PeerLease;
        use crate::peer_info::PeerRole;

        let table = crate::PeerTable::new();
        let addr = PeerEndpoint::from(([127, 0, 0, 1], 1));
        let (tx, _rx) = crossbeam_channel::unbounded();
        table.register(addr, PeerLease::new(tx));

        assert!(
            matches!(
                next_outbound_role(&table, &HashMap::new(), 1, 1, false),
                PeerRole::BlockRelayOnly
            ),
            "premise: the automatic chooser answers a full slot with block relay"
        );
        assert!(
            matches!(
                dial_outbound_role(
                    &OutboundDial::pinned(PeerEndpoint::from(([127, 0, 0, 1], 2))),
                    &table,
                    &HashMap::new(),
                    1,
                    1,
                    false,
                ),
                PeerRole::FullRelay
            ),
            "the operator's pin is answered with full relay regardless"
        );
    }

    #[test]
    fn the_excess_victim_comes_from_the_excess_slice_only() {
        use crate::connection::PeerLease;
        use crate::download_window::MINIMUM_CONNECT_TIME;

        fn addr(port: u16) -> PeerEndpoint {
            PeerEndpoint::from(([127, 0, 0, 1], port))
        }

        let now = Instant::now();
        let aged = now
            .checked_sub(MINIMUM_CONNECT_TIME)
            .expect("test clock is past the minimum connect time");
        let table = crate::PeerTable::new();

        for port in 1..=2_u16 {
            let (tx, _rx) = crossbeam_channel::unbounded();
            let mut lease = PeerLease::new(tx);
            lease.backdate_for_test(aged);
            table.register(addr(port), lease);
        }
        let (young_tx, _young_rx) = crossbeam_channel::unbounded();
        table.register(addr(3), PeerLease::new(young_tx));

        assert!(
            newest_excess_full_relay(&table, 2, now, |_| false).is_none(),
            "the only excess candidate is too young, so nobody in the slots is retired"
        );

        let (aged_tx, _aged_rx) = crossbeam_channel::unbounded();
        let mut downloading = PeerLease::new(aged_tx);
        downloading.backdate_for_test(aged);
        table.register(addr(4), downloading);
        let source = table
            .lease(addr(4))
            .map(|lease| lease.source(Some(addr(4))))
            .expect("the downloading excess peer is registered");

        assert!(
            newest_excess_full_relay(&table, 2, now, |candidate| candidate == source).is_none(),
            "the downloading excess peer is passed over and nothing else is beyond the slots"
        );
        assert_eq!(
            newest_excess_full_relay(&table, 2, now, |_| false)
                .expect("the aged excess peer is eligible")
                .addr,
            crate::PeerRemote::Endpoint(addr(4)),
            "the same peer is the victim once its download completes"
        );
    }

    #[test]
    fn a_pinned_peer_beyond_a_full_set_creates_no_excess() {
        use crate::connection::PeerLease;
        use crate::download_window::MINIMUM_CONNECT_TIME;
        use crate::peer_info::PeerRole;

        fn addr(port: u16) -> PeerEndpoint {
            PeerEndpoint::from(([127, 0, 0, 1], port))
        }

        let now = Instant::now();
        let aged = now
            .checked_sub(MINIMUM_CONNECT_TIME)
            .expect("test clock is past the minimum connect time");
        let table = crate::PeerTable::new();

        for port in 1..=2_u16 {
            let (tx, _rx) = crossbeam_channel::unbounded();
            let mut lease = PeerLease::new(tx);
            lease.backdate_for_test(aged);
            table.register(addr(port), lease);
        }
        let (pinned_tx, _pinned_rx) = crossbeam_channel::unbounded();
        let mut pinned_lease = PeerLease::new_manual(pinned_tx, PeerRole::FullRelay);
        pinned_lease.backdate_for_test(aged);
        table.register(addr(3), pinned_lease);

        assert!(
            newest_excess_full_relay(&table, 2, now, |_| false).is_none(),
            "a full automatic set plus a pinned peer is still no connection over"
        );

        let (extra_tx, _extra_rx) = crossbeam_channel::unbounded();
        let mut extra_lease = PeerLease::new(extra_tx);
        extra_lease.backdate_for_test(aged);
        table.register(addr(4), extra_lease);

        assert_eq!(
            newest_excess_full_relay(&table, 2, now, |_| false)
                .expect("three automatic connections are one extra")
                .addr,
            crate::PeerRemote::Endpoint(addr(4)),
            "a real automatic excess still retires its newest aged peer"
        );
    }

    #[test]
    fn add_node_enqueues_and_respects_queue_capacity() {
        let service = P2pService::new(
            P2pServiceConfig {
                outbound_queue_limit: 1,
                ..P2pServiceConfig::default()
            },
            Arc::new(AtomicBool::new(false)),
        );
        let addr1: PeerEndpoint = "127.0.0.1:8333".parse().expect("addr");
        let addr2: PeerEndpoint = "127.0.0.2:8333".parse().expect("addr");

        assert!(service.add_node(addr1, true).is_ok());
        assert_eq!(service.added_nodes().as_slice(), &[addr1]);
        let dial = service.outbound_rx.lock().try_recv().expect("recv");
        assert_eq!(dial, OutboundDial::pinned(addr1));

        service
            .outbound_tx
            .try_send(OutboundDial::pinned(addr1))
            .expect("send");

        assert_eq!(
            service.add_node(addr2, false),
            Err(P2pControlError::QueueFull)
        );

        assert!(service.add_node(addr2, true).is_ok());
        assert_eq!(service.added_nodes().as_slice(), &[addr1, addr2]);
    }

    #[test]
    fn add_node_inactive_skips_queueing() {
        let service = P2pService::new(
            P2pServiceConfig::default(),
            Arc::new(AtomicBool::new(false)),
        );
        service.set_network_active(false);
        let addr: PeerEndpoint = "127.0.0.1:8333".parse().expect("addr");
        assert!(service.add_node(addr, true).is_ok());
        assert_eq!(service.added_nodes().as_slice(), &[addr]);
        assert!(service.outbound_rx.lock().try_recv().is_err());
    }

    #[test]
    fn add_node_rejects_banned_address() {
        let service = P2pService::new(
            P2pServiceConfig::default(),
            Arc::new(AtomicBool::new(false)),
        );
        let subnet: crate::IpSubnet = "127.0.0.0/24".parse().expect("subnet");
        service.set_ban(crate::BannedSubnet {
            subnet,
            ban_created: SystemTime::now(),
            banned_until: None,
            reason: String::new(),
        });
        let addr: PeerEndpoint = "127.0.0.1:8333".parse().expect("addr");
        assert_eq!(service.add_node(addr, true), Err(P2pControlError::Banned));
        assert_eq!(service.added_nodes().as_slice(), &[]);
        assert!(service.outbound_rx.lock().try_recv().is_err());
    }
    #[test]
    fn parked_overflow_releases_the_address_for_another_selection() {
        let address = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333));
        let book = crate::addrman::AddressBook::open(None, [1; 4], true, None);
        book.learn_dns("seed", &[address], 10_000);
        book.queued(address);
        assert_eq!(book.select(&[], &[], 10_000, u64::MAX, |_| true), None);
        let mut parked = VecDeque::from(vec![OutboundDial::auto(address); MAX_PARKED_DIALS]);
        assert!(!park_automatic_dial(
            &mut parked,
            OutboundDial::auto(address),
            &book,
            &HashMap::new()
        ));
        assert_eq!(
            book.select(&[], &[], 10_000, u64::MAX, |_| true),
            Some(address)
        );
    }
    fn maintenance_fixture(target: usize) -> (AddressMaintenance, Receiver<OutboundDial>) {
        let (tx, rx) = crossbeam_channel::bounded(16);
        let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
        for n in 1..100 {
            let addr = PeerEndpoint::from(([8, n, 1, 1], 8333));
            book.learn_dns("seed", &[addr], 10_000);
            book.learn_peer(
                crate::PeerRemote::Endpoint(addr),
                &[(addr, 9, 10_000)],
                10_000,
            );
        }
        (
            AddressMaintenance {
                block_slots: 2,
                manual_nodes: Arc::new(RwLock::new(Vec::new())),
                shutdown: Arc::new(AtomicBool::new(false)),
                network_active: Arc::new(AtomicBool::new(true)),
                peer_table: Arc::new(crate::PeerTable::new()),
                outbound_tx: tx,
                port: 8333,
                seeds: Vec::new(),
                target,
                block_sync: None,
                chain_query: None,
                address_book: book,
                banned: BannedReader::fixture_empty(),
                routes: crate::RouteTable::default(),
            },
            rx,
        )
    }

    #[test]
    fn fresh_unreachable_book_reseeds_on_a_bounded_cooldown() {
        let tick = Instant::now();
        let mut next = tick + Duration::from_secs(60);
        assert!(!dns_recovery_due(64, 0, 8, tick, &mut next));
        assert!(dns_recovery_due(
            64,
            0,
            8,
            tick + Duration::from_secs(60),
            &mut next
        ));
        assert!(!dns_recovery_due(
            64,
            0,
            8,
            tick + Duration::from_secs(61),
            &mut next
        ));
        assert!(!dns_recovery_due(
            64,
            8,
            8,
            tick + Duration::from_secs(120),
            &mut next
        ));
        assert!(dns_recovery_due(
            64,
            7,
            8,
            tick + Duration::from_secs(120),
            &mut next
        ));
        assert_eq!(next, tick + Duration::from_secs(180));
    }

    #[test]
    fn block_relay_readiness_counts_for_dns_without_refreshing_gossip_time() {
        let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
        let full = PeerEndpoint::from(([8, 1, 1, 1], 8333));
        book.learn_dns("seed", &[full], 5000);
        let block = (2..=255)
            .map(|n| PeerEndpoint::from(([8, n, 1, 1], 8333)))
            .find(|peer| {
                book.learn_dns("seed", &[*peer], 5000);
                book.len() == 2
            })
            .expect("distinct candidate slot");
        let table = crate::PeerTable::new();
        for (addr, block_only) in [(full, false), (block, true)] {
            let (tx, _) = crossbeam_channel::bounded(1);
            let lease = if block_only {
                crate::PeerLease::new_block_relay(tx)
            } else {
                crate::PeerLease::new(tx)
            };
            table.register(addr, lease.clone());
            let info = crate::PeerInfo {
                addr: crate::PeerRemote::Endpoint(addr),
                endpoint: Some(addr),
                network: addr.net(),
                version: 70016,
                wtxid_relay: false,
                relay_transactions: true,
                compact_block_relay: false,
                send_headers: false,
                services: 9,
                user_agent: String::new(),
                start_height: 0,
                best_known_height: 0,
                conn_time: 0,
                inbound: false,
                addr_bind: crate::TransportRemote::new(
                    addr.socket_addr()
                        .unwrap_or_else(|| panic!("expected IP fixture")),
                ),
                time_offset: 0,
                counters: Arc::new(crate::PeerCounters::default()),
                transport: crate::TransportProtocol::V1,
            };
            assert!(table.publish_info(addr, &lease, info));
        }
        assert_eq!(ready_address_count(&table, &book), 2);
        assert!(book.queued_feeler(block));
        assert_eq!(
            ready_address_count(&table, &book),
            1,
            "exclude ready feelers"
        );
        book.reject_queued(block, true);
        assert_eq!(ready_address_count(&table, &book), 2);
        let response = book.gossip(10_000);
        for (addr, expected) in [(full, 5000), (block, 5000)] {
            let timestamp = response
                .iter()
                .find(|advertised| {
                    advertised.socket_addr().ok().map(PeerEndpoint::from) == Some(addr)
                })
                .expect("advertised")
                .time;
            assert_eq!(
                timestamp, expected,
                "active connections never refresh gossip timestamp"
            );
        }
    }

    #[test]
    fn failure_accounting_uses_persistent_tcp_groups_including_manual_before_ready() {
        let table = crate::PeerTable::new();
        let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
        assert!(!count_address_failure(&table, 125, &book));
        assert!(count_address_failure(&table, 1, &book));
        let (tx, _) = crossbeam_channel::bounded(1);
        let automatic = crate::PeerLease::new(tx.clone());
        table.register(PeerEndpoint::from(([8, 1, 1, 1], 8333)), automatic);
        assert!(!count_address_failure(&table, 125, &book));
        assert!(count_address_failure(&table, 2, &book));
        let same_group = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
        table.register(PeerEndpoint::from(([8, 1, 2, 2], 8333)), same_group);
        assert!(!count_address_failure(&table, 125, &book));
        let manual = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
        table.register(PeerEndpoint::from(([8, 2, 1, 1], 8333)), manual.clone());
        assert!(
            table
                .sessions()
                .iter()
                .all(|session| session.info.is_none())
        );
        assert!(
            count_address_failure(&table, 125, &book),
            "Core counts established TCP sessions before handshake publication"
        );
        manual.cancel();
        let probe = PeerEndpoint::from(([9, 4, 1, 1], 8333));
        assert!(book.queued_feeler(probe));
        let probe_lease = register_ready_block_peer(&table, probe);
        assert!(!count_address_failure(&table, 125, &book));
        assert!(count_address_failure(&table, 2, &book));
        assert_eq!(ready_address_count(&table, &book), 0);
        assert_eq!(anchor_peers(&table, &book), Vec::<PeerEndpoint>::new());
        table.remove_current(probe, &probe_lease);
        book.unqueue(probe);
        table.register(
            PeerEndpoint::from(([8, 3, 1, 1], 8333)),
            crate::PeerLease::new_inbound(tx),
        );
        assert!(
            !count_address_failure(&table, 125, &book),
            "inbound and cancelled sessions do not certify connectivity"
        );
    }

    #[test]
    fn failure_census_uses_the_same_configured_asmap_for_persistent_tcp_sessions() {
        let directory = tempfile::tempdir().expect("directory");
        let map = directory.path().join("asmap.raw");
        std::fs::write(
            &map,
            include_bytes!("../tests/data/asmap-source-quota-core-v31.1.raw"),
        )
        .expect("Core map");
        let book = crate::addrman::AddressBook::open(None, [1; 4], false, Some(&map));
        let table = crate::PeerTable::new();
        let (tx, _) = crossbeam_channel::bounded(1);
        table.register(
            "8.8.0.1:8333".parse::<PeerEndpoint>().expect("peer"),
            crate::PeerLease::new(tx.clone()),
        );
        table.register(
            "9.9.0.1:8333".parse::<PeerEndpoint>().expect("same ASN"),
            crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay),
        );
        assert!(
            !count_address_failure(&table, 125, &book),
            "different prefixes in one ASN count once"
        );
        assert!(count_address_failure(&table, 2, &book));
        let independent = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
        table.register(
            "8.8.1.1:8333"
                .parse::<PeerEndpoint>()
                .expect("independent ASN"),
            independent.clone(),
        );
        assert!(
            table
                .sessions()
                .iter()
                .all(|session| session.info.is_none())
        );
        assert!(
            count_address_failure(&table, 125, &book),
            "independent ASN in same /16 establishes second group"
        );
        std::fs::remove_file(&map).expect("loaded map stays immutable");
        assert!(count_address_failure(&table, 125, &book));
        independent.cancel();
        table.register(
            "8.8.1.2:8333".parse::<PeerEndpoint>().expect("inbound"),
            crate::PeerLease::new_inbound(tx),
        );
        assert!(!count_address_failure(&table, 125, &book));
    }

    #[test]
    fn auxiliary_save_interval_retains_immediate_explicit_save() {
        let dir = tempfile::tempdir().expect("dir");
        let base = dir.path().join("peers.dat");
        let book = crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true, None);
        let addr = PeerEndpoint::from(([127, 0, 0, 1], 8333));
        book.learn_dns("seed", &[addr], 10_000);
        let tick = Instant::now();
        let mut next = tick + Duration::from_mins(15);
        save_address_book_if_due(&book, tick, &mut next);
        assert_eq!(
            crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true, None).len(),
            0
        );
        save_address_book_if_due(&book, tick + Duration::from_mins(15), &mut next);
        assert_eq!(
            crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true, None).len(),
            1
        );
        book.connected(addr, 20_000);
        save_address_book_if_due(&book, tick + Duration::from_secs(901), &mut next);
        assert_eq!(
            crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true, None)
                .gossip(20_000)[0]
                .time,
            10_000
        );
        book.save();
        assert_eq!(
            crate::addrman::AddressBook::open(Some(base), [1; 4], true, None).gossip(20_000)[0]
                .time,
            20_000,
            "shutdown and anchor-consumption barriers bypass the periodic throttle"
        );
    }

    #[test]
    fn automatic_policy_and_manual_bans_are_distinct() {
        let ip: std::net::IpAddr = "8.8.8.8".parse().expect("ip");
        let protected: crate::IpSubnet = "8.8.8.0/24".parse().expect("subnet");
        let service = P2pService::new(
            P2pServiceConfig {
                noban_subnets: vec![protected],
                ..Default::default()
            },
            Arc::new(AtomicBool::new(false)),
        );
        let reader = service.banned_reader();
        reader.discourage(ip);
        assert!(
            reader.is_noban(
                "::ffff:8.8.8.8"
                    .parse::<std::net::IpAddr>()
                    .expect("mapped ip")
            )
        );
        assert!(reader.automatic_snapshot(SystemTime::now()).allows(ip));
        service.set_ban(crate::BannedSubnet {
            subnet: protected,
            banned_until: None,
            ban_created: SystemTime::now(),
            reason: "manual".into(),
        });
        assert!(!reader.automatic_snapshot(SystemTime::now()).allows(ip));
        service.clear_banned();
        assert!(reader.automatic_snapshot(SystemTime::now()).allows(ip));
    }

    #[test]
    fn all_automatic_selection_classes_exclude_discouraged_addresses() {
        let (maintenance, queue) = maintenance_fixture(4);
        let now = crate::addrman::now();
        for n in 1..100 {
            let addr = PeerEndpoint::from(([8, n, 1, 1], 8333));
            maintenance.address_book.learn_dns("seed", &[addr], now);
            maintenance.address_book.learn_peer(
                crate::PeerRemote::Endpoint(addr),
                &[(addr, 9, now)],
                now,
            );
        }
        assert!(
            maintenance
                .address_book
                .select(&[], &[], now, u64::MAX, |_| true)
                .is_some()
        );
        assert!(
            maintenance
                .address_book
                .feeler(&[], &[], now, |_| true)
                .is_some()
        );
        for n in 1..100 {
            maintenance
                .banned
                .discourage(std::net::IpAddr::from([8, n, 1, 1]));
        }
        queue_address_candidates(&maintenance, now, SystemTime::now(), 0);
        assert!(
            queue.is_empty(),
            "regular selection must apply the policy snapshot"
        );
        let address = PeerEndpoint::from(([8, 1, 1, 1], 8333));
        maintenance.address_book.succeeded(address, 9, now);
        maintenance.address_book.remember_anchors(&[address], now);
        let mut anchors: VecDeque<_> = maintenance.address_book.take_restart_anchors(now).into();
        assert!(
            maintenance.address_book.anchor_eligible(address, &[], now),
            "anchor must otherwise be eligible"
        );
        queue_restart_anchors(&maintenance, &mut anchors, &mut None, &mut Vec::new(), now);
        assert!(
            !maintenance.address_book.is_pending(address),
            "a discouraged anchor must release its standby reservation"
        );
        assert!(
            queue.is_empty(),
            "restart anchors must apply the same policy"
        );
        let (headers, _) = crossbeam_channel::unbounded();
        let (blocks, _) = crossbeam_channel::unbounded();
        let shared = crate::listener::ConnectionShared::new(
            Arc::clone(&maintenance.peer_table),
            maintenance.banned.clone(),
            Arc::new(crate::NetworkActivity::from_shared(Arc::clone(
                &maintenance.network_active,
            ))),
            bitcoin_rs_chain::LatchReader::new(Arc::clone(&maintenance.shutdown)),
            None,
            Magic::BITCOIN,
            headers,
            blocks,
            None,
            None,
            crate::listener::ListenerExtras::default(),
        );
        let mut active = HashMap::new();
        let mut handles = Vec::new();
        spawn_feeler(
            &shared,
            &maintenance.address_book,
            &[],
            &mut active,
            &mut handles,
            DEFAULT_MAX_PEER_CONNECTIONS,
        );
        assert!(
            active.is_empty() && handles.is_empty(),
            "feeler selection must not start a discouraged dial"
        );
    }

    #[test]
    fn maintenance_counts_queued_parked_and_inflight_automatic_claims_once() {
        let (mut maintenance, rx) = maintenance_fixture(3);
        let tick = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        queue_address_candidates(&maintenance, 10_000, tick, 0);
        assert_eq!(rx.len(), 3);
        for _ in 0..4 {
            queue_address_candidates(&maintenance, 10_000, tick, 0);
        }
        assert_eq!(
            rx.len(),
            3,
            "ticks cannot keep filling a pending dial pipeline"
        );
        let parked = rx.try_recv().expect("queued");
        queue_address_candidates(&maintenance, 10_000, tick, 0);
        assert_eq!(rx.len(), 2, "parking keeps the claim occupied");
        maintenance
            .address_book
            .attempted(parked.addr, true, 10_001);
        queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100), 0);
        assert_eq!(
            rx.len(),
            2,
            "a slow connect keeps capacity occupied beyond retry backoff"
        );
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        maintenance.peer_table.register(parked.addr, lease.clone());
        maintenance.address_book.succeeded(parked.addr, 9, 10_100);
        maintenance.target = 4;
        queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100), 0);
        assert_eq!(rx.len(), 3, "the live session and its claim count once");
        let (tx, _rx) = crossbeam_channel::unbounded();
        maintenance.peer_table.register(
            PeerEndpoint::from(([9, 9, 1, 1], 8333)),
            crate::PeerLease::new_manual(tx, crate::PeerRole::FullRelay),
        );
        maintenance.target = 5;
        queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100), 0);
        assert_eq!(
            rx.len(),
            4,
            "manual sessions do not consume automatic slots"
        );
        lease.cancel();
        maintenance.address_book.unqueue(parked.addr);
        queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100), 0);
        assert_eq!(
            rx.len(),
            5,
            "finished cancelled automatic claims release their slot"
        );
    }

    #[test]
    fn selection_uses_one_ban_snapshot_at_the_tick_time() {
        let (maintenance, rx) = maintenance_fixture(1);
        let until = SystemTime::UNIX_EPOCH + Duration::from_secs(10_001);
        maintenance.banned.inner.write().push(crate::BannedSubnet {
            subnet: "8.0.0.0/8".parse().expect("subnet"),
            banned_until: Some(until),
            ban_created: SystemTime::UNIX_EPOCH,
            reason: String::new(),
        });
        queue_address_candidates(&maintenance, 10_000, until - Duration::from_secs(1), 0);
        assert_eq!(
            rx.len(),
            0,
            "the entire banned subnet is excluded before expiry"
        );
        queue_address_candidates(&maintenance, 10_001, until, 0);
        assert_eq!(
            rx.len(),
            1,
            "expiry uses the supplied tick, not a later wall clock read"
        );
    }

    #[test]
    fn shutdown_releases_parked_automatic_claims_before_restart() {
        let service = P2pService::new(
            P2pServiceConfig {
                outbound_full_relay_slots: 0,
                outbound_block_relay_slots: 0,
                allow_local_addresses: true,
                dns_seeds_enabled: false,
                ..P2pServiceConfig::default()
            },
            Arc::new(AtomicBool::new(false)),
        );
        let address = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333));
        let now = crate::addrman::now();
        service.address_book.learn_dns("seed", &[address], now);
        service.address_book.queued(address);
        service
            .outbound_tx
            .try_send(OutboundDial::auto(address))
            .expect("queue");
        service
            .start(
                None,
                None,
                &idle_ready(),
                crate::listener::ListenerExtras::default(),
            )
            .expect("start");
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if service
                .outbound_rx
                .try_lock()
                .is_some_and(|rx| rx.is_empty())
            {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            service.outbound_rx.lock().is_empty(),
            "worker must have parked the request"
        );
        assert_eq!(service.address_book.pending_count_excluding(&[]), 1);
        service.shutdown();
        service.join().expect("join");
        assert_eq!(service.address_book.pending_count_excluding(&[]), 0);
        assert_eq!(
            service
                .address_book
                .select(&[], &[], now, u64::MAX, |_| true),
            Some(address)
        );
        service.set_network_active(true);
        service
            .start(
                None,
                None,
                &idle_ready(),
                crate::listener::ListenerExtras::default(),
            )
            .expect("restart");
        service.shutdown();
        service.join().expect("restarted join");
    }

    #[test]
    fn manual_dial_cannot_release_an_automatic_claim_and_reaper_releases_only_its_owner() {
        let table = Arc::new(crate::PeerTable::new());
        let (headers, _) = crossbeam_channel::bounded(1);
        let (blocks, _) = crossbeam_channel::bounded(1);
        let mut shared = crate::listener::ConnectionShared::new(
            table,
            BannedReader::fixture_empty(),
            Arc::new(crate::NetworkActivity::from_shared(Arc::new(
                AtomicBool::new(true),
            ))),
            Arc::new(AtomicBool::new(false)),
            None,
            Magic::REGTEST,
            headers,
            blocks,
            None,
            None,
            crate::listener::ListenerExtras::default(),
        );
        let book = crate::addrman::AddressBook::open(None, [1; 4], true, None);
        shared.address_book = Some(book.clone());
        let address = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333));
        book.queued(address);
        let mut active = HashMap::from([(
            address,
            ActiveOutbound {
                feeler: false,

                role: crate::PeerRole::FullRelay,
                manual: true,
            },
        )]);
        let mut handles = Vec::new();
        spawn_outbound_dial(
            &OutboundDial::pinned(address),
            &shared,
            &mut active,
            &mut handles,
            1,
            0,
            false,
            DEFAULT_MAX_PEER_CONNECTIONS,
        );
        assert_eq!(
            book.pending_count_excluding(&[]),
            1,
            "manual duplicate must not clear the automatic owner"
        );
        for manual in [true, false] {
            active.insert(
                address,
                ActiveOutbound {
                    feeler: false,

                    role: crate::PeerRole::FullRelay,
                    manual,
                },
            );
            handles.push((address, thread::spawn(|| Ok(()))));
            let deadline = Instant::now() + Duration::from_secs(5);
            while !handles.is_empty() && Instant::now() < deadline {
                let _ = reap_finished_outbound_connections(&mut active, &mut handles, &book);
                thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(handles.len(), 0);
            assert_eq!(book.pending_count_excluding(&[]), usize::from(manual));
        }
    }

    #[test]
    fn anchors_require_automatic_block_relay_and_demonstrated_chain_evidence() {
        let book = crate::addrman::AddressBook::open(None, [1; 4], true, None);
        let table = crate::PeerTable::new();
        let mut leases = Vec::new();
        for port in 1..=4_u16 {
            let address = PeerEndpoint::from((Ipv4Addr::LOCALHOST, port));
            let (sender, _receiver) = crossbeam_channel::unbounded();
            let lease = match port {
                1 | 2 => crate::PeerLease::new_block_relay(sender),
                3 => crate::PeerLease::new_manual(sender, crate::PeerRole::BlockRelayOnly),
                _ => crate::PeerLease::new(sender),
            };
            let version = crate::handshake::version_message(
                1,
                1_000_000,
                crate::PeerRole::FullRelay,
                ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            );
            let info = crate::PeerInfo::outbound_from_version(
                address,
                address
                    .socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
                &version,
                10_000,
                10_000,
                Arc::new(crate::PeerCounters::default()),
            );
            table.register(address, lease.clone());
            assert!(table.publish_info(address, &lease, info));
            if port != 1 {
                assert!(table.note_announced_tip(
                    lease.source(Some(address)),
                    bitcoin_rs_primitives::Hash256::from_le_bytes(&[7; 32]),
                    Some(2)
                ));
            }
            leases.push(lease);
        }
        assert_eq!(
            anchor_peers(&table, &book),
            vec![PeerEndpoint::from((Ipv4Addr::LOCALHOST, 2))]
        );
        leases[1].cancel();
        assert_eq!(anchor_peers(&table, &book), Vec::<PeerEndpoint>::new());
    }

    #[test]
    fn anchor_dials_prefer_block_slots_without_displacing_manual_roles() {
        let table = crate::PeerTable::new();
        let address = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333));
        let anchor = OutboundDial {
            addr: address,
            manual: false,
            purpose: DialPurpose::Anchor,
        };
        assert_eq!(
            dial_outbound_role(&anchor, &table, &HashMap::new(), 8, 2, false),
            crate::PeerRole::BlockRelayOnly
        );
        assert_eq!(
            dial_outbound_role(
                &OutboundDial::pinned(address),
                &table,
                &HashMap::new(),
                8,
                2,
                false
            ),
            crate::PeerRole::FullRelay
        );
        let mut pending = HashMap::new();
        pending.insert(
            address,
            ActiveOutbound {
                feeler: true,

                manual: false,
                role: crate::PeerRole::BlockRelayOnly,
            },
        );
        assert!(
            has_automatic_outbound_capacity(&pending, 1, false),
            "a probe does not consume a steady slot"
        );
        assert_eq!(
            next_outbound_role(&table, &pending, 0, 1, false),
            crate::PeerRole::BlockRelayOnly
        );
    }

    #[test]
    fn anchor_queue_preserves_diversity_and_releases_a_saturated_attempt() {
        let (mut maintenance, _) = maintenance_fixture(2);
        let (sender, receiver) = crossbeam_channel::bounded(1);
        maintenance.outbound_tx = sender;
        let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
        maintenance.address_book = Arc::clone(&book);
        let first: PeerEndpoint = "8.1.1.1:8333".parse().expect("first");
        let other: PeerEndpoint = "9.2.1.1:8333".parse().expect("other");
        for addr in [first, other] {
            book.learn_dns("seed", &[addr], 10_000);
            book.succeeded(addr, 9, 10_001);
        }
        book.remember_anchors(&[first, other], 10_001);
        let mut anchors: VecDeque<_> = book.take_restart_anchors(10_002).into();
        let mut current = None;
        let mut active = Vec::new();
        maintenance
            .outbound_tx
            .try_send(OutboundDial::pinned(first))
            .expect("saturate");
        assert_eq!(
            queue_restart_anchors(
                &maintenance,
                &mut anchors,
                &mut current,
                &mut active,
                10_002
            ),
            2
        );
        assert!(book.anchor_eligible(first, &[], 10_002));
        assert!(receiver.try_recv().expect("drain").manual);
        queue_restart_anchors(
            &maintenance,
            &mut anchors,
            &mut current,
            &mut active,
            10_002,
        );
        assert_eq!(receiver.try_recv().expect("first").addr, first);
        assert!(book.anchor_dispatched(first));
        let _lease = register_ready_block_peer(&maintenance.peer_table, first);
        queue_restart_anchors(
            &maintenance,
            &mut anchors,
            &mut current,
            &mut active,
            10_003,
        );
        assert_eq!(receiver.try_recv().expect("diverse second").addr, other);
        assert_eq!(anchors, VecDeque::<PeerEndpoint>::new());
        book.defer_anchor(other);
        book.return_restart_anchors(10_004);
        assert_eq!(book.take_restart_anchors(10_004), vec![other]);
        maintenance.manual_nodes.write().push(other);
        let mut pinned = VecDeque::from(vec![other]);
        queue_restart_anchors(
            &maintenance,
            &mut pinned,
            &mut None,
            &mut Vec::new(),
            10_004,
        );
        assert!(receiver.try_recv().is_err());
        book.return_restart_anchors(10_004);
        assert!(!book.is_pending(other));
    }

    #[test]
    fn a_queued_or_registered_probe_never_occupies_a_steady_outbound_slot() {
        for registered in [false, true] {
            let (maintenance, receiver) = maintenance_fixture(1);
            let book = &maintenance.address_book;
            let probe = book
                .select(&[], &[], 10_000, u64::MAX, |_| true)
                .expect("probe candidate");
            assert!(book.queued_feeler(probe));
            book.attempted(probe, true, 10_000);
            assert_eq!(book.pending_count_excluding(&[]), 0);
            let (sender, _receiver) = crossbeam_channel::unbounded();
            let lease = crate::PeerLease::new_block_relay(sender);
            if registered {
                maintenance.peer_table.register(probe, lease.clone());
            }
            queue_address_candidates(
                &maintenance,
                10_001,
                SystemTime::UNIX_EPOCH + Duration::from_secs(10_001),
                0,
            );
            let regular = receiver
                .try_recv()
                .expect("the vacant steady slot is filled while probe is in flight");
            assert_ne!(regular.addr, probe);
            assert_eq!(regular.purpose, DialPurpose::Regular);
            queue_address_candidates(
                &maintenance,
                10_002,
                SystemTime::UNIX_EPOCH + Duration::from_secs(10_002),
                0,
            );
            assert!(
                receiver.try_recv().is_err(),
                "the steady claim itself still fills its slot"
            );
            maintenance.peer_table.remove_current(probe, &lease);
            book.unqueue(probe);
            queue_address_candidates(
                &maintenance,
                10_003,
                SystemTime::UNIX_EPOCH + Duration::from_secs(10_003),
                0,
            );
            assert!(receiver.try_recv().is_err());
        }
    }
    #[test]
    fn mapped_manual_pins_exclude_all_automatic_dial_classes_without_rewriting_configuration() {
        let (maintenance, queue) = maintenance_fixture(4);
        let now = crate::addrman::now();
        for n in 1..100 {
            maintenance.address_book.learn_dns(
                "seed",
                &[PeerEndpoint::from(([8, n, 1, 1], 8333))],
                now,
            );
        }
        let book = &maintenance.address_book;
        let anchor = book
            .select(&[], &[], now, u64::MAX, |_| true)
            .expect("eligible ordinary candidate");
        book.succeeded(anchor, 9, now);
        book.remember_anchors(&[anchor], now);
        assert_eq!(book.take_restart_anchors(now), vec![anchor]);
        assert!(
            book.anchor_eligible(anchor, &[], now),
            "the anchor would otherwise be selectable"
        );
        assert!(
            book.feeler(&[], &[], now, |_| true).is_some(),
            "unproven probe candidates exist"
        );
        for n in 1..100 {
            maintenance.manual_nodes.write().push(PeerEndpoint::new(
                std::net::IpAddr::V6(Ipv4Addr::new(8, n, 1, 1).to_ipv6_mapped()),
                8333,
            ));
        }
        queue_address_candidates(&maintenance, now, SystemTime::now(), 0);
        assert!(
            queue.try_recv().is_err(),
            "ordinary selection must honor a mapped spelling of a manual pin"
        );
        let mut anchors = VecDeque::from(vec![anchor]);
        queue_restart_anchors(&maintenance, &mut anchors, &mut None, &mut Vec::new(), now);
        assert!(
            queue.try_recv().is_err(),
            "anchor selection must honor mapped manual pins"
        );
        assert_eq!(anchors, VecDeque::<PeerEndpoint>::new());
        let (headers, _) = crossbeam_channel::bounded(1);
        let (blocks, _) = crossbeam_channel::bounded(1);
        let mut shared = crate::listener::ConnectionShared::new(
            Arc::clone(&maintenance.peer_table),
            maintenance.banned.clone(),
            Arc::new(crate::NetworkActivity::from_shared(Arc::new(
                AtomicBool::new(false),
            ))),
            Arc::new(AtomicBool::new(false)),
            None,
            Magic::REGTEST,
            headers,
            blocks,
            None,
            None,
            crate::listener::ListenerExtras::default(),
        );
        shared.address_book = Some(Arc::clone(book));
        let pins = maintenance.manual_nodes.read().clone();
        let mut active = HashMap::new();
        let mut handles = Vec::new();
        spawn_feeler(
            &shared,
            book,
            &pins,
            &mut active,
            &mut handles,
            DEFAULT_MAX_PEER_CONNECTIONS,
        );
        let spawned = handles.len();
        for (_, handle) in handles {
            let _ = handle.join();
        }
        assert_eq!(spawned, 0, "feeler selection must honor mapped manual pins");
        assert!(active.is_empty());
        assert!(
            maintenance
                .manual_nodes
                .read()
                .iter()
                .all(PeerEndpoint::is_ipv6),
            "operator spelling is retained"
        );
        assert!(
            !is_manual_endpoint(&pins, PeerEndpoint::new(anchor.address(), 8334)),
            "a different port is a different endpoint"
        );
    }
    #[test]
    fn onlynet_prefilter_selects_no_forbidden_network_dial() {
        let (mut maintenance, queue) = maintenance_fixture(4);
        maintenance.routes.onlynet = vec![crate::NetworkLabel::Onion];
        let now = 10_000;
        queue_address_candidates(&maintenance, now, SystemTime::now(), 0);
        assert!(
            queue.try_recv().is_err(),
            "an IP-heavy book under onlynet=onion must queue no ordinary dial"
        );
        let book = &maintenance.address_book;
        let anchor = book
            .select(&[], &[], now, u64::MAX, |_| true)
            .expect("eligible ordinary candidate");
        book.succeeded(anchor, 9, now);
        book.remember_anchors(&[anchor], now);
        assert_eq!(book.take_restart_anchors(now), vec![anchor]);
        assert!(
            book.anchor_eligible(anchor, &[], now),
            "the anchor would otherwise be selectable"
        );
        let mut anchors = VecDeque::from(vec![anchor]);
        queue_restart_anchors(&maintenance, &mut anchors, &mut None, &mut Vec::new(), now);
        assert!(
            queue.try_recv().is_err(),
            "anchor selection must honor the route prefilter"
        );
    }
    fn register_ready_block_peer(table: &crate::PeerTable, addr: PeerEndpoint) -> crate::PeerLease {
        let (sender, _receiver) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_block_relay(sender);
        let version = crate::handshake::version_message(
            1,
            0,
            crate::PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        );
        let info = crate::PeerInfo::outbound_from_version(
            addr,
            addr.socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
            &version,
            10_000,
            10_000,
            Arc::new(crate::PeerCounters::default()),
        );
        table.register(addr, lease.clone());
        assert!(table.publish_info(addr, &lease, info));
        assert!(table.note_announced_tip(
            lease.source(Some(addr)),
            bitcoin_rs_primitives::Hash256::from_le_bytes(&[7; 32]),
            Some(1)
        ));
        lease
    }

    #[test]
    fn failed_first_anchor_retains_the_second_for_a_single_block_slot() {
        for target in [1, 2] {
            let (mut maintenance, queue) = maintenance_fixture(target);
            maintenance.block_slots = 1;
            let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
            maintenance.address_book = Arc::clone(&book);
            let first: PeerEndpoint = "8.1.1.1:8333".parse().expect("first");
            let second: PeerEndpoint = "9.2.1.1:8333".parse().expect("second");
            let full: PeerEndpoint = "11.3.1.1:8333".parse().expect("ordinary full relay");
            for addr in [first, second, full] {
                book.learn_dns("seed", &[addr], 10_000);
            }
            for addr in [first, second] {
                book.succeeded(addr, 9, 10_001);
            }
            book.remember_anchors(&[first, second], 10_001);
            let mut anchors: VecDeque<_> = book.take_restart_anchors(10_002).into();
            assert_eq!(
                book.pending_count_excluding(&[]),
                0,
                "standby reservations consume no steady capacity"
            );
            let mut current = None;
            let reserved = queue_restart_anchors(
                &maintenance,
                &mut anchors,
                &mut current,
                &mut Vec::new(),
                10_002,
            );
            assert_eq!(queue.try_recv().expect("first anchor").addr, first);
            assert_eq!(
                book.pending_count_excluding(&[]),
                1,
                "only the queued first attempt consumes a slot"
            );
            assert!(book.anchor_dispatched(first));
            book.attempted(first, true, 10_002);
            queue_address_candidates(
                &maintenance,
                10_002,
                SystemTime::UNIX_EPOCH + Duration::from_secs(10_002),
                reserved,
            );
            if target == 2 {
                let ordinary = queue
                    .try_recv()
                    .expect("the free full-relay slot remains usable");
                assert_eq!(ordinary.addr, full);
                assert_eq!(ordinary.purpose, DialPurpose::Regular);
            }
            assert!(
                queue.try_recv().is_err(),
                "ordinary selection must not steal the second anchor"
            );
            assert!(
                !book.queued_feeler(second),
                "a racing feeler cannot claim a reserved anchor"
            );
            assert_eq!(anchors, VecDeque::from(vec![second]));
            book.unqueue(first);
            let reserved = queue_restart_anchors(
                &maintenance,
                &mut anchors,
                &mut current,
                &mut Vec::new(),
                10_003,
            );
            let fallback = queue.try_recv().expect("second persisted anchor");
            assert_eq!(fallback.addr, second);
            assert_eq!(fallback.purpose, DialPurpose::Anchor);
            assert_eq!(
                dial_outbound_role(
                    &fallback,
                    &maintenance.peer_table,
                    &HashMap::new(),
                    target - 1,
                    1,
                    false
                ),
                crate::PeerRole::BlockRelayOnly
            );
            queue_address_candidates(
                &maintenance,
                10_003,
                SystemTime::UNIX_EPOCH + Duration::from_secs(10_003),
                reserved,
            );
            assert!(queue.try_recv().is_err());
        }
    }

    #[test]
    fn a_queued_anchor_waits_for_its_block_slot_without_blocking_a_full_slot() {
        let first: PeerEndpoint = "8.1.1.1:8333".parse().expect("first");
        let second: PeerEndpoint = "9.2.1.1:8333".parse().expect("second");
        let busy = HashMap::from([(
            first,
            ActiveOutbound {
                role: crate::PeerRole::BlockRelayOnly,
                manual: false,
                feeler: false,
            },
        )]);
        assert!(
            !dial_has_capacity(
                &OutboundDial {
                    addr: second,
                    manual: false,
                    purpose: DialPurpose::Anchor
                },
                &busy,
                2,
                1,
                false
            ),
            "a queued anchor cannot oversubscribe a block slot"
        );
        assert!(dial_has_capacity(
            &OutboundDial::auto(second),
            &busy,
            2,
            1,
            false
        ));
    }

    #[test]
    fn shutdown_captures_anchors_before_cancelling_workers() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("peers.dat");
        let service = P2pService::new(
            P2pServiceConfig {
                address_book_path: Some(path.clone()),
                magic: Magic::REGTEST,
                allow_local_addresses: true,
                ..P2pServiceConfig::default()
            },
            Arc::new(AtomicBool::new(false)),
        );
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333));
        let now = crate::addrman::now();
        service.address_book.learn_dns("fixture", &[addr], now);
        service.address_book.succeeded(addr, 9, now);
        let lease = register_ready_block_peer(&service.peer_table, addr);
        *service.workers.lock() = Some(Workers::default());
        assert!(service.workers.lock().is_some());
        service.shutdown();
        assert!(lease.is_cancelled(), "shutdown must cancel live sessions");
        let restored =
            crate::addrman::AddressBook::open(Some(path), Magic::REGTEST.to_bytes(), true, None);
        assert_eq!(restored.take_restart_anchors(now), vec![addr]);
    }

    #[test]
    fn shutdown_captures_anchors_before_cancelling_worker_leases() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("peers.dat");
        let service = P2pService::new(
            P2pServiceConfig {
                address_book_path: Some(path.clone()),
                magic: Magic::REGTEST,
                allow_local_addresses: true,
                ..P2pServiceConfig::default()
            },
            Arc::new(AtomicBool::new(false)),
        );
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 8333)).into();
        let now = crate::addrman::now();
        service.address_book.learn_dns("fixture", &[addr], now);
        service.address_book.succeeded(addr, 9, now);
        let lease = register_ready_block_peer(&service.peer_table, addr);
        *service.workers.lock() = Some(Workers::default());
        service.shutdown();
        assert!(lease.is_cancelled(), "workers cancel every lease");
        let restored =
            crate::addrman::AddressBook::open(Some(path), Magic::REGTEST.to_bytes(), true, None);
        assert_eq!(restored.take_restart_anchors(now), vec![addr]);
    }
    fn saved_book(path: &std::path::Path) -> sonic_rs::Value {
        let bytes = std::fs::read(path).expect("saved book");
        sonic_rs::from_slice(&bytes[..bytes.len() - 32]).expect("book JSON")
    }

    #[test]
    fn rejected_duplicates_preserve_active_feeler_and_dispatched_anchor_claims_until_join() {
        for feeler in [false, true] {
            let address: PeerEndpoint = "127.0.0.1:8333".parse().expect("address");
            let book = crate::addrman::AddressBook::open(None, [1; 4], true, None);
            book.learn_dns("seed", &[address], 10_000);
            if feeler {
                assert!(book.queued_feeler(address));
                assert!(
                    !book.queued(address),
                    "regular cannot acquire a feeler claim"
                );
            } else {
                book.succeeded(address, 9, 10_000);
                book.remember_anchors(&[address], 10_000);
                assert_eq!(book.take_restart_anchors(10_001), vec![address]);
                assert!(book.queue_anchor(address));
                assert!(book.anchor_dispatched(address));
            }
            let mut active = HashMap::from([(
                address,
                ActiveOutbound {
                    manual: false,
                    feeler,
                    role: crate::PeerRole::BlockRelayOnly,
                },
            )]);
            let mut shared = crate::listener::ConnectionShared::new(
                Arc::new(crate::PeerTable::new()),
                BannedReader::fixture_empty(),
                Arc::new(crate::NetworkActivity::from_shared(Arc::new(
                    AtomicBool::new(false),
                ))),
                Arc::new(AtomicBool::new(false)),
                None,
                Magic::REGTEST,
                crossbeam_channel::bounded(1).0,
                crossbeam_channel::bounded(1).0,
                None,
                None,
                crate::listener::ListenerExtras::default(),
            );
            shared.address_book = Some(Arc::clone(&book));
            let mapped = PeerEndpoint::new(
                std::net::IpAddr::V6(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
                8333,
            );
            let duplicate = OutboundDial::auto(mapped);
            let mut handles = Vec::new();
            spawn_outbound_dial(
                &duplicate,
                &shared,
                &mut active,
                &mut handles,
                1,
                1,
                false,
                125,
            );
            assert!(handles.is_empty());
            assert!(
                book.is_pending(address),
                "inactive duplicate must preserve active owner"
            );
            assert!(is_manual_endpoint(&[mapped], address));
            defer_rejected_dial(&duplicate, &book, &active);
            assert!(
                book.is_pending(address),
                "manual-policy rejection preserves active owner"
            );
            let mut parked = VecDeque::from(vec![duplicate; MAX_PARKED_DIALS]);
            assert!(!park_automatic_dial(&mut parked, duplicate, &book, &active));
            assert!(book.is_pending(address), "overflow preserves active owner");
            assert_eq!(book.is_feeler(address), feeler);
            let worker_book = Arc::clone(&book);
            handles.push((
                address,
                thread::spawn(move || {
                    assert!(
                        worker_book.is_pending(address),
                        "claim remains through worker teardown"
                    );
                    Ok(())
                }),
            ));
            finish_outbound_epoch(parked, &active, handles, &book);
            assert!(!book.is_pending(address));
            assert!(
                book.take_restart_anchors(10_002).is_empty(),
                "dispatched anchor is never returned"
            );
        }
    }

    #[test]
    fn rejected_anchor_returns_original_metadata_and_releases_its_asmap_group() {
        let (mut maintenance, queue) = maintenance_fixture(1);
        let directory = tempfile::tempdir().expect("directory");
        let map = directory.path().join("asmap.raw");
        std::fs::write(
            &map,
            include_bytes!("../tests/data/asmap-source-quota-core-v31.1.raw"),
        )
        .expect("map");
        let base = directory.path().join("peers.dat");
        let path = directory.path().join("peers-01010101.dat");
        let book = crate::addrman::AddressBook::open(Some(base), [1; 4], false, Some(&map));
        maintenance.address_book = Arc::clone(&book);
        let anchor: PeerEndpoint = "8.8.0.1:8333".parse::<PeerEndpoint>().expect("anchor");
        let same_as: PeerEndpoint = "9.9.0.1:8333".parse::<PeerEndpoint>().expect("same ASN");
        book.learn_dns("seed", &[anchor], 10_000);
        book.succeeded(anchor, 9, 10_000);
        book.learn_dns("seed", &[same_as], 10_000);
        assert_eq!(
            book.select(&[], &[], 10_000, u64::MAX, |addr| addr == same_as),
            Some(same_as)
        );
        book.remember_anchors(&[anchor], 10_000);
        let mut anchors = book.take_restart_anchors(10_001).into();
        assert_eq!(
            book.select(&[], &[], 10_001, u64::MAX, |addr| addr == same_as),
            None
        );
        maintenance.banned = BannedReader::new(Arc::new(RwLock::new(vec![crate::BannedSubnet {
            subnet: "8.8.0.1/32".parse().expect("anchor ban"),
            banned_until: None,
            ban_created: SystemTime::now(),
            reason: String::new(),
        }])));
        queue_restart_anchors(
            &maintenance,
            &mut anchors,
            &mut None,
            &mut Vec::new(),
            10_002,
        );
        assert!(queue.try_recv().is_err());
        assert!(!book.is_pending(anchor));
        assert_eq!(
            book.select(&[], &[], 10_002, u64::MAX, |addr| addr == same_as),
            Some(same_as)
        );
        assert_eq!(saved_book(&path)["anchors"][0]["confirmed_at"], 10_000);
        assert_eq!(book.take_restart_anchors(10_003), vec![anchor]);
    }

    #[test]
    fn inactive_boot_preserves_anchors_and_shutdown_returns_queued_undispatched_payload() {
        let (mut maintenance, queue) = maintenance_fixture(1);
        let directory = tempfile::tempdir().expect("directory");
        let base = directory.path().join("peers.dat");
        let path = directory.path().join("peers-01010101.dat");
        let book = crate::addrman::AddressBook::open(Some(base), [1; 4], false, None);
        maintenance.address_book = Arc::clone(&book);
        maintenance.network_active.store(false, Ordering::Release);
        let address: PeerEndpoint = "8.8.8.8:8333".parse().expect("address");
        let now = crate::addrman::now();
        book.learn_dns("seed", &[address], now);
        book.succeeded(address, 9, now);
        book.remember_anchors(&[address], now);
        book.save();
        let original = std::fs::read(&path).expect("original");
        let maintenance = Arc::new(maintenance);
        let worker_maintenance = Arc::clone(&maintenance);
        let worker = thread::spawn(move || run_address_maintenance(&worker_maintenance));
        assert!(queue.recv_timeout(Duration::from_millis(250)).is_err());
        assert!(!book.is_pending(address));
        assert_eq!(std::fs::read(&path).expect("inactive book"), original);
        maintenance.network_active.store(true, Ordering::Release);
        let queued = queue
            .recv_timeout(Duration::from_secs(3))
            .expect("first active anchor");
        assert_eq!(queued.addr, address);
        assert_eq!(queued.purpose, DialPurpose::Anchor);
        assert!(book.is_pending(address));
        maintenance.shutdown.store(true, Ordering::Release);
        worker.join().expect("maintenance shutdown");
        assert!(!book.is_pending(address));
        assert!(
            !book.anchor_dispatched(address),
            "stale queued endpoint cannot dispatch after return"
        );
        assert_eq!(saved_book(&path)["anchors"][0]["confirmed_at"], now);
        assert_eq!(book.take_restart_anchors(now), vec![address]);
    }
    struct ServiceTip {
        time: std::sync::atomic::AtomicU32,
        pause: Mutex<Option<(Sender<()>, Receiver<()>)>>,
    }
    impl crate::ChainQuery for ServiceTip {
        fn stale_tip_announcement(
            &self,
            _: bitcoin_rs_primitives::Hash256,
            _: &[bitcoin_rs_primitives::Hash256],
        ) -> Option<crate::dispatch::StaleTipHeaders> {
            None
        }
        fn headers_after(
            &self,
            _: &[bitcoin_rs_primitives::BlockHash],
            _: bitcoin_rs_primitives::BlockHash,
            _: usize,
        ) -> Vec<bitcoin_rs_primitives::Header> {
            Vec::new()
        }
        fn serve_inventory_blocks(
            &self,
            _: &[bitcoin::p2p::message_blockdata::Inventory],
            _: Option<u64>,
            _: &dyn Fn() -> bool,
            _: &mut dyn FnMut(crate::Message) -> Result<(), crate::PeerError>,
        ) -> Result<crate::dispatch::InventoryServing, crate::PeerError> {
            Ok(crate::dispatch::InventoryServing::default())
        }
        fn block_transactions(
            &self,
            _: &bitcoin::bip152::BlockTransactionsRequest,
            _: Option<u64>,
            _: &dyn Fn() -> bool,
        ) -> Result<Option<crate::Message>, crate::PeerError> {
            Ok(None)
        }
        fn best_block_time(&self) -> Option<u32> {
            let pause = self.pause.lock().take();
            if let Some((entered, release)) = pause {
                entered.send(()).expect("query entered");
                release
                    .recv_timeout(Duration::from_secs(5))
                    .expect("release query");
            }
            Some(self.time.load(Ordering::Acquire))
        }
    }

    #[test]
    fn ordinary_queue_rechecks_services_and_tip_before_dispatch_and_tcp() {
        for tip_changes in [false, true] {
            let server = TcpListener::bind("127.0.0.1:0").expect("listener");
            server.set_nonblocking(true).expect("nonblocking");
            let address = server.local_addr().expect("address");
            let now = crate::addrman::now();
            let tip = Arc::new(ServiceTip {
                time: std::sync::atomic::AtomicU32::new(
                    u32::try_from(now - 143 * 600).expect("tip time"),
                ),
                pause: Mutex::new(None),
            });
            let query: Arc<dyn crate::ChainQuery> = tip.clone();
            let book = crate::addrman::AddressBook::open(None, [1; 4], true, None);
            book.learn_dns("seed", &[address.into()], now);
            book.succeeded(address.into(), if tip_changes { 1032 } else { 9 }, now);
            let (mut maintenance, queue) = maintenance_fixture(1);
            maintenance.address_book = Arc::clone(&book);
            maintenance.chain_query = Some(Arc::clone(&query));
            queue_address_candidates(&maintenance, now, SystemTime::now(), 0);
            let candidate = queue.try_recv().expect("eligible candidate is queued");
            let mut parked = VecDeque::new();
            assert!(park_automatic_dial(
                &mut parked,
                candidate,
                &book,
                &HashMap::new()
            ));
            if tip_changes {
                tip.time.store(
                    u32::try_from(now - 144 * 600).expect("older tip"),
                    Ordering::Release,
                );
            } else {
                book.set_services(address.into(), 1);
            }
            let mut shared = crate::listener::ConnectionShared::new(
                Arc::clone(&maintenance.peer_table),
                BannedReader::fixture_empty(),
                Arc::new(crate::NetworkActivity::from_shared(Arc::new(
                    AtomicBool::new(true),
                ))),
                Arc::new(AtomicBool::new(false)),
                None,
                Magic::REGTEST,
                crossbeam_channel::bounded(1).0,
                crossbeam_channel::bounded(1).0,
                Some(query),
                None,
                crate::listener::ListenerExtras::default(),
            );
            shared.address_book = Some(Arc::clone(&book));
            let mut active = HashMap::new();
            let mut handles = Vec::new();
            spawn_outbound_dial(
                &parked.pop_front().expect("parked dial"),
                &shared,
                &mut active,
                &mut handles,
                1,
                0,
                false,
                125,
            );
            assert_eq!(
                handles.len(),
                0,
                "stale parked metadata never starts a worker"
            );
            assert!(
                !book.is_pending(address.into()),
                "rejected ordinary claim is released"
            );
            let result = crate::listener::spawn_outbound_connection(
                address.into(),
                shared,
                crate::PeerRole::FullRelay,
            )
            .join()
            .expect("thread");
            assert!(
                matches!(
                    result,
                    Err(crate::PeerError::Protocol(
                        "outbound peer lacks desirable services"
                    ))
                ),
                "final listener admission must independently recheck"
            );
            assert!(
                matches!(server.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
                "no TCP connection reached the listener"
            );
        }
    }

    #[test]
    fn ordinary_selection_skips_known_incomplete_peer_and_anchor_return_preserves_age() {
        let (mut maintenance, queue) = maintenance_fixture(1);
        let directory = tempfile::tempdir().expect("directory");
        let book = crate::addrman::AddressBook::open(
            Some(directory.path().join("peers.dat")),
            [1; 4],
            false,
            None,
        );
        maintenance.address_book = Arc::clone(&book);
        let bad: PeerEndpoint = "8.8.8.8:8333".parse().expect("incomplete");
        let healthy: PeerEndpoint = "9.9.9.9:8333".parse().expect("healthy");
        book.learn_dns("seed", &[bad, healthy], 10_000);
        book.succeeded(bad, 9, 10_000);
        book.succeeded(healthy, 9, 10_000);
        book.remember_anchors(&[bad], 10_000);
        let mut anchors = book.take_restart_anchors(10_001).into();
        book.set_services(bad, 1);
        queue_restart_anchors(
            &maintenance,
            &mut anchors,
            &mut None,
            &mut Vec::new(),
            10_002,
        );
        assert!(queue.try_recv().is_err());
        assert!(!book.is_pending(bad));
        assert_eq!(
            saved_book(&directory.path().join("peers-01010101.dat"))["anchors"][0]["confirmed_at"],
            10_000
        );
        queue_address_candidates(
            &maintenance,
            10_002,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10_002),
            0,
        );
        assert_eq!(
            queue.try_recv().expect("healthy ordinary candidate").addr,
            healthy
        );
    }
    #[test]
    fn disable_during_outbound_tip_query_refuses_registration_before_handshake() {
        let directory = tempfile::tempdir().expect("directory");
        let service = Arc::new(P2pService::new(
            P2pServiceConfig {
                address_book_path: Some(directory.path().join("peers.dat")),
                allow_local_addresses: true,
                dns_seeds_enabled: false,
                magic: Magic::REGTEST,
                ..P2pServiceConfig::default()
            },
            Arc::new(AtomicBool::new(false)),
        ));
        let server = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = server.local_addr().expect("address");
        let now = crate::addrman::now();
        service
            .address_book
            .learn_dns("loopback", &[address.into()], now);
        service.address_book.set_services(address.into(), 9);
        let (entered, entered_rx) = crossbeam_channel::bounded(1);
        let (release, release_rx) = crossbeam_channel::bounded(1);
        let query: Arc<dyn crate::ChainQuery> = Arc::new(ServiceTip {
            time: std::sync::atomic::AtomicU32::new(u32::try_from(now).expect("tip time")),
            pause: Mutex::new(Some((entered, release_rx))),
        });
        let ready = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ready_count = Arc::clone(&ready);
        let mut shared = crate::listener::ConnectionShared::new(
            Arc::clone(&service.peer_table),
            service.banned_reader(),
            Arc::new(crate::NetworkActivity::from_shared(Arc::clone(
                &service.network_active,
            ))),
            Arc::clone(&service.session_cancel.lock()),
            Some(Arc::new(move |_| {
                ready_count.fetch_add(1, Ordering::Relaxed);
            })),
            Magic::REGTEST,
            crossbeam_channel::bounded(1).0,
            crossbeam_channel::bounded(1).0,
            Some(query),
            None,
            crate::listener::ListenerExtras::default(),
        );
        shared.address_book = Some(Arc::clone(&service.address_book));
        let worker = crate::listener::spawn_outbound_connection(
            address.into(),
            shared,
            crate::PeerRole::FullRelay,
        );
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("passed early activity check, paused before TCP");
        let disabling_service = Arc::clone(&service);
        let (disabled_tx, disabled_rx) = crossbeam_channel::bounded(1);
        let disable = thread::spawn(move || {
            disabling_service.set_network_active(false);
            disabled_tx.send(()).expect("disabled");
        });
        let disabled = disabled_rx.recv_timeout(Duration::from_secs(5));
        release.send(()).expect("release metadata query");
        disable.join().expect("disable worker");
        let (mut remote, _) = server.accept().expect("TCP can complete after disable");
        remote
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut byte = [0];
        let received = std::io::Read::read(&mut remote, &mut byte);
        let _ = remote.shutdown(std::net::Shutdown::Both);
        drop(remote);
        let result = worker.join().expect("outbound worker");
        disabled.expect("disable does not wait for socket I/O or metadata query");
        assert_eq!(received.expect("closed without handshake"), 0);
        assert!(
            matches!(
                result,
                Err(crate::PeerError::Protocol(
                    "transport or network unavailable"
                ))
            ),
            "unexpected outbound result: {result:?}"
        );
        assert_eq!(service.peer_table.sessions().len(), 0);
        assert_eq!(ready.load(Ordering::Relaxed), 0);
        service.address_book.save();
        let record = &saved_book(&directory.path().join("peers-fabfb5da.dat"))["records"][0];
        assert_eq!(record["last_success"], 0);
        assert_eq!(record["tried"], false);
    }

    #[test]
    fn workers_teardown_cleans_resources_and_cancels_sessions() {
        let peer_table = Arc::new(crate::PeerTable::new());
        let addresses = Mutex::new(vec![crate::PeerEndpoint::Ip(SocketAddr::from((
            [127, 0, 0, 1],
            8333,
        )))]);
        let shutdown = Arc::new(AtomicBool::new(false));
        let session_cancel = Arc::new(AtomicBool::new(false));
        let mut workers = Workers::new(Arc::clone(&shutdown), Arc::clone(&session_cancel));

        let thread_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            while !thread_shutdown.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        });
        workers.listeners.push(handle);

        assert!(!shutdown.load(Ordering::Acquire));
        assert!(!session_cancel.load(Ordering::Acquire));
        assert!(!addresses.lock().is_empty());

        workers.teardown(&peer_table, &addresses);

        assert!(shutdown.load(Ordering::Acquire));
        assert!(session_cancel.load(Ordering::Acquire));
        assert!(addresses.lock().is_empty());
        assert!(workers.listeners.is_empty());
    }

    #[test]
    fn bootstrap_fixed_peer_endpoints_valid_typed_endpoints_bypass_resolver() {
        let network_active = AtomicBool::new(true);
        let peer_table = crate::PeerTable::new();
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();

        let good_tor_payload = bitcoin_rs_primitives::endpoint::tor_v3_payload(&[7u8; 32]);
        let valid_onion = format!(
            "{}.onion:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&good_tor_payload)
        );
        let valid_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

        let mut resolve_calls = 0;
        let valid_overlay_targets = vec![valid_onion, valid_i2p];
        bootstrap_fixed_peer_endpoints(
            &network_active,
            &peer_table,
            &outbound_tx,
            &valid_overlay_targets,
            |_host| {
                resolve_calls += 1;
                Ok(vec![SocketAddr::from(([127, 0, 0, 1], 8333))])
            },
        );
        assert_eq!(
            resolve_calls, 0,
            "injected resolver must remain untouched for valid overlay targets"
        );
        assert!(matches!(
            outbound_rx.try_recv().expect("valid onion dial").addr,
            crate::PeerEndpoint::TorV3 { .. }
        ));
        assert!(matches!(
            outbound_rx.try_recv().expect("valid i2p dial").addr,
            crate::PeerEndpoint::I2p { .. }
        ));

        bootstrap_fixed_peer_endpoints(
            &network_active,
            &peer_table,
            &outbound_tx,
            &["127.0.0.1:8333".to_owned()],
            |_host| {
                resolve_calls += 1;
                Ok(vec![SocketAddr::from(([127, 0, 0, 1], 8333))])
            },
        );
        assert_eq!(
            resolve_calls, 0,
            "injected resolver must remain untouched for direct IP"
        );
        assert_eq!(
            outbound_rx.try_recv().expect("direct ip dial").addr,
            crate::PeerEndpoint::Ip(SocketAddr::from(([127, 0, 0, 1], 8333)))
        );
    }

    fn malformed_reserved_overlay_targets_testdata() -> Vec<String> {
        let good_tor_payload = bitcoin_rs_primitives::endpoint::tor_v3_payload(&[7u8; 32]);
        let valid_onion = format!(
            "{}.onion:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&good_tor_payload)
        );
        let valid_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

        let mut bad_payload = good_tor_payload;
        bad_payload[32] ^= 1;
        let invalid_checksum_onion = format!(
            "{}.onion:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&bad_payload)
        );
        let good_b32 = bitcoin_rs_primitives::endpoint::base32_encode(&good_tor_payload);

        vec![
            invalid_checksum_onion,
            "abc.onion:8333".to_owned(),
            format!("{}.b32.i2p:8333", "a".repeat(51)),
            format!("{}.b32.i2p:8333", "a".repeat(53)),
            format!("{good_b32}.onion:notaport"),
            format!("{good_b32}.onion:0"),
            format!("{good_b32}.onion:99999"),
            format!("{good_b32}.onion"),
            format!("{}.b32.i2p", "a".repeat(52)),
            valid_onion.to_uppercase(),
            valid_i2p.to_uppercase(),
            format!("{good_b32}.onion.:8333"),
            format!("{good_b32}.onion."),
            format!("{}.b32.i2p.:8333", "a".repeat(52)),
            format!("{}.b32.i2p.", "a".repeat(52)),
            "foo.i2p:8333".to_owned(),
            "foo.i2p".to_owned(),
            "FOO.I2P:8333".to_owned(),
            "foo.I2P:8333".to_owned(),
            "foo.i2p.:8333".to_owned(),
            "foo.i2p.".to_owned(),
            "b32.i2p:8333".to_owned(),
            "b32.i2p".to_owned(),
            "B32.I2P:8333".to_owned(),
            "b32.i2p.:8333".to_owned(),
            "b32.i2p.".to_owned(),
            "onion.:8333".to_owned(),
            "onion.".to_owned(),
            "ONION.:8333".to_owned(),
            "i2p.:8333".to_owned(),
            "i2p.".to_owned(),
            "I2P.:8333".to_owned(),
        ]
    }

    #[test]
    fn bootstrap_fixed_peer_endpoints_malformed_reserved_overlay_names_bypass_resolver() {
        let network_active = AtomicBool::new(true);
        let peer_table = crate::PeerTable::new();
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();

        let rejected_overlay_targets = malformed_reserved_overlay_targets_testdata();

        let mut resolve_calls = 0;
        bootstrap_fixed_peer_endpoints(
            &network_active,
            &peer_table,
            &outbound_tx,
            &rejected_overlay_targets,
            |_host| {
                resolve_calls += 1;
                Ok(vec![SocketAddr::from(([127, 0, 0, 1], 8333))])
            },
        );
        assert_eq!(
            resolve_calls, 0,
            "injected resolver must remain untouched for rejected overlay targets"
        );
        assert!(
            outbound_rx.try_recv().is_err(),
            "no dial should be generated for rejected overlay targets"
        );
    }

    #[test]
    fn bootstrap_fixed_peer_endpoints_ordinary_dns_and_lan_use_resolver() {
        let network_active = AtomicBool::new(true);
        let peer_table = crate::PeerTable::new();
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();

        let ordinary_hostnames = vec![
            "seed.bitcoin.sipa.be:8333".to_owned(),
            "fakeb32.i2p.org:8333".to_owned(),
            "onion:8333".to_owned(),
            "i2p:8333".to_owned(),
        ];
        let expected_addr = SocketAddr::from(([192, 0, 2, 42], 8333));
        let mut resolve_calls = 0;
        bootstrap_fixed_peer_endpoints(
            &network_active,
            &peer_table,
            &outbound_tx,
            &ordinary_hostnames,
            |_host| {
                resolve_calls += 1;
                Ok(vec![expected_addr])
            },
        );
        assert_eq!(
            resolve_calls, 4,
            "injected resolver must be called for ordinary DNS and LAN hostnames"
        );
        for _ in 0..4 {
            assert_eq!(
                outbound_rx.try_recv().expect("dns dial").addr,
                crate::PeerEndpoint::Ip(expected_addr)
            );
        }
    }

    #[test]
    fn bootstrap_fixed_peer_endpoints_queue_and_cancellation() {
        let peer_table = crate::PeerTable::new();

        let network_inactive = AtomicBool::new(false);
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let mut resolve_calls = 0;
        bootstrap_fixed_peer_endpoints(
            &network_inactive,
            &peer_table,
            &outbound_tx,
            &[
                "seed.bitcoin.sipa.be:8333".to_owned(),
                "127.0.0.1:8333".to_owned(),
            ],
            |_host| {
                resolve_calls += 1;
                Ok(vec![SocketAddr::from(([192, 0, 2, 42], 8333))])
            },
        );
        assert_eq!(resolve_calls, 0);
        assert!(outbound_rx.try_recv().is_err());

        let network_active = AtomicBool::new(true);
        let (bounded_tx, bounded_rx) = crossbeam_channel::bounded(1);
        bootstrap_fixed_peer_endpoints(
            &network_active,
            &peer_table,
            &bounded_tx,
            &["127.0.0.1:8333".to_owned(), "127.0.0.2:8333".to_owned()],
            |_host| Ok(vec![SocketAddr::from(([127, 0, 0, 1], 8333))]),
        );
        assert!(bounded_rx.try_recv().is_ok());
        assert!(bounded_rx.try_recv().is_err());
    }
}
