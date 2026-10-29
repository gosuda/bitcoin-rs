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
/// extra-peer retirement (`net_processing.cpp`),
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
        let (inbound_headers_tx, inbound_headers_rx) = crossbeam_channel::unbounded();
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
/// `net_processing.cpp`) and passes over a peer with blocks in flight or a
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
mod tests;
