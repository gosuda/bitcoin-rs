//! Runtime owner for the Bitcoin P2P subsystem.
//!
//! P2pService owns the mutable network control state and every worker that
//! acts on it. The node supplies chain read/query and inbound event sinks, but
//! does not construct listener, dial, DNS, or fixed-peer workers itself.

use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
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

use crate::listener::ListenerError;

/// Core's `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS` (`net.h:69`).
const DEFAULT_OUTBOUND_FULL_RELAY_SLOTS: usize = 8;

/// Core's `MAX_OUTBOUND_BLOCK_RELAY_CONNECTIONS` (`net.h:73`).
const DEFAULT_OUTBOUND_BLOCK_RELAY_SLOTS: usize = 2;

const DEFAULT_OUTBOUND_QUEUE_LIMIT: usize = DEFAULT_OUTBOUND_FULL_RELAY_SLOTS;

/// How often the connection manager looks for a full-relay connection that the
/// stale-tip allowance made extra.
const EXTRA_PEER_CHECK_INTERVAL: Duration = Duration::from_secs(45);

/// Core `random.cpp` `MakeExponentiallyDistributed` and `random.h` microsecond
/// rounding, for a mean of 120 seconds. The 53-bit fraction is strictly <1,
/// so the maximum delay is finite (4,408,416,068 microseconds), with zero allowed.
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

/// Core's automatic-connection maximum, `-maxconnections`
/// (`DEFAULT_MAX_PEER_CONNECTIONS`, `net.h:81`).
const DEFAULT_MAX_PEER_CONNECTIONS: usize = 200;

/// How many capacity-blocked automatic dials the drain worker holds for
/// retry. Comfortably above any reachable slot count, so a saturated cap
/// cannot let the parked backlog grow without limit.
const MAX_PARKED_DIALS: usize = 64;

/// Configuration needed by the P2P runtime, after node configuration has
/// resolved the consensus network and message-start bytes.
#[derive(Clone, Debug)]
pub struct P2pServiceConfig {
    /// Addresses on which inbound P2P connections are accepted.
    pub listen_addrs: Vec<SocketAddr>,
    /// Network message-start bytes.
    pub magic: Magic,
    /// Auxiliary peer-book base/legacy path. The owner adds the P2P magic to
    /// the filename and imports a valid matching legacy file without deleting
    /// it. None keeps discovery in memory.
    pub address_book_path: Option<std::path::PathBuf>,
    /// Optional Core `ASMap` file; invalid configured files preserve peer books read-only.
    pub asmap_path: Option<std::path::PathBuf>,
    /// Permit private/local peer addresses only on isolated regtest networks.
    pub allow_local_addresses: bool,
    /// Whether DNS seed maintenance is enabled.
    pub dns_seeds_enabled: bool,
    /// DNS seed host names. The service resolves them only in its worker.
    pub dns_seeds: Vec<String>,
    /// Port appended to DNS seed results.
    pub dns_port: u16,
    /// Fixed connect endpoints. Non-empty disables DNS maintenance.
    pub fixed_peers: Vec<String>,
    /// Total automatic peer connections, the Core maximum inbound and
    /// outbound admission is derived from.
    ///
    /// Core: `m_max_automatic_connections` (`net.h:1091`).
    pub max_peer_connections: usize,
    /// Outbound full-relay connection slots (transaction, address, block relay,
    /// and announcements).
    pub outbound_full_relay_slots: usize,
    /// The services this node advertises in every `version`.
    pub local_services: ServiceFlags,
    /// Outbound block-relay-only connection slots (blocks only, no `tx` or
    /// `addr`).
    pub outbound_block_relay_slots: usize,
    /// Outbound request queue capacity.
    pub outbound_queue_limit: usize,
    /// Inbound block queue capacity.
    pub inbound_block_queue_limit: usize,
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
            max_peer_connections: DEFAULT_MAX_PEER_CONNECTIONS,
            outbound_full_relay_slots: DEFAULT_OUTBOUND_FULL_RELAY_SLOTS,
            outbound_block_relay_slots: DEFAULT_OUTBOUND_BLOCK_RELAY_SLOTS,
            outbound_queue_limit: DEFAULT_OUTBOUND_QUEUE_LIMIT,
            inbound_block_queue_limit: DEFAULT_INBOUND_BLOCK_QUEUE_LIMIT,
            local_services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        }
    }
}

impl P2pServiceConfig {
    /// Total outbound connection slots.
    ///
    /// PRE: none.
    /// POST: returns the sum of the full-relay and block-relay slot counts,
    ///   which bounds the live automatic-outbound target and simultaneous
    ///   automatic attempts.
    /// INVARIANT: manual peers do not consume these slots; the two slot
    ///   counts are the only automatic outbound population knobs.
    #[must_use]
    fn total_outbound_active_limit(&self) -> usize {
        self.outbound_full_relay_slots
            .saturating_add(self.outbound_block_relay_slots)
    }

    /// Inbound connection capacity: what the automatic-connection maximum
    /// leaves after the outbound slot counts.
    ///
    /// PRE: none.
    /// POST: returns `max_peer_connections` minus both outbound slot counts,
    ///   clamped at zero.
    /// INVARIANT: this is the only inbound capacity derivation; the listener
    ///   refuses admission at the result, it never evicts.
    #[must_use]
    pub(crate) fn max_inbound(&self) -> usize {
        self.max_peer_connections
            .saturating_sub(self.outbound_full_relay_slots)
            .saturating_sub(self.outbound_block_relay_slots)
    }
}

/// Errors returned while starting P2P workers.
#[derive(Debug, Error)]
pub enum P2pServiceError {
    /// The service has already been started.
    #[error("p2p service is already started")]
    AlreadyStarted,
    /// A worker could not be spawned.
    #[error("spawn p2p worker: {0}")]
    Spawn(#[from] io::Error),
    /// A listener could not bind or run.
    #[error(transparent)]
    Listener(#[from] ListenerError),
}

/// Errors returned when joining P2P workers after shutdown.
#[derive(Debug, Error)]
pub enum P2pJoinError {
    /// A listener worker returned a bind or accept failure.
    #[error(transparent)]
    Listener(#[from] ListenerError),
    /// A listener worker panicked.
    #[error("p2p listener panicked")]
    ListenerPanic,
    /// The outbound drain worker panicked.
    #[error("p2p outbound drain panicked")]
    OutboundPanic,
    /// The bootstrap worker panicked.
    #[error("p2p bootstrap worker panicked")]
    BootstrapPanic,
}

/// Errors returned by RPC-facing P2P control operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum P2pControlError {
    /// The destination is covered by an active manual ban.
    #[error("destination is banned")]
    Banned,
    /// The bounded dial queue has no capacity.
    #[error("p2p outbound queue is full")]
    QueueFull,
    /// The P2P service has already shut down.
    #[error("p2p outbound queue is closed")]
    Closed,
}

#[derive(Default)]
struct Workers {
    listeners: Vec<JoinHandle<Result<(), ListenerError>>>,
    outbound: Option<JoinHandle<()>>,
    bootstrap: Option<JoinHandle<()>>,
}

/// One queued request to dial an outbound address, with the origin that
/// asked for it.
///
/// PRE: none.
/// POST: `manual` records whether the operator named this address.
/// INVARIANT: the origin travels with the request to the lease. Core's
///   `ConnectionType::MANUAL` is exempt from the chain-sync timeout and the
///   extra-peer retirement (`net_processing.cpp:5502`,
///   `net_processing.cpp:5558-5604`), and the queue is the only place that
///   still knows which dials were asked for by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundDial {
    /// The address to dial.
    pub addr: SocketAddr,
    /// Whether the operator asked for this address by name.
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
    /// A dial the seed list or the address book produced.
    #[must_use]
    pub const fn auto(addr: SocketAddr) -> Self {
        Self {
            addr,
            manual: false,
            purpose: DialPurpose::Regular,
        }
    }

    /// A dial the operator pinned with `--connect` or `addnode`.
    #[must_use]
    pub const fn pinned(addr: SocketAddr) -> Self {
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

/// Cloneable, read-only capability for querying the active manual ban list.
///
/// Ban mutations remain with the P2P service; connection workers only test
/// addresses against the active table.
#[derive(Clone, Debug)]
pub struct BannedReader {
    inner: Arc<RwLock<Vec<crate::BannedSubnet>>>,
}

impl BannedReader {
    /// Wraps the shared ban table in a read-only reader capability.
    #[must_use]
    pub const fn new(inner: Arc<RwLock<Vec<crate::BannedSubnet>>>) -> Self {
        Self { inner }
    }

    /// Acquires a shared read lock on the ban list.
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, Vec<crate::BannedSubnet>> {
        self.inner.read()
    }

    /// Returns whether the given IP is banned at the given time.
    #[must_use]
    pub fn is_banned(&self, ip: std::net::IpAddr, now: SystemTime) -> bool {
        crate::subnet::is_banned(&self.inner.read(), ip, now)
    }

    /// Returns an empty fixture reader for tests.
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

/// The sole runtime owner of P2P control state and workers.
pub struct P2pService {
    config: P2pServiceConfig,
    shutdown: bitcoin_rs_chain::LatchReader,
    worker_shutdown: Arc<AtomicBool>,
    network_active: Arc<AtomicBool>,
    peer_table: Arc<crate::PeerTable>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    address_book: Arc<crate::addrman::AddressBook>,
    added_nodes: Arc<RwLock<Vec<SocketAddr>>>,
    outbound_tx: Sender<OutboundDial>,
    outbound_rx: Arc<Mutex<Receiver<OutboundDial>>>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_headers_rx: Mutex<Option<Receiver<crate::InboundHeaders>>>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    inbound_blocks_rx: Mutex<Option<Receiver<crate::InboundBlock>>>,
    workers: Mutex<Option<Workers>>,
    /// Per-start cancellation observed by listener and connection threads.
    /// A failed start leaves this token asserted; the next start installs a
    /// fresh token so leftover workers cannot be un-cancelled.
    session_cancel: Mutex<Arc<AtomicBool>>,
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
    /// Creates an unstarted P2P service and allocates all P2P-owned state.
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
        Self {
            config,
            address_book,
            shutdown: shutdown.into(),
            worker_shutdown: Arc::new(AtomicBool::new(false)),
            network_active: Arc::new(AtomicBool::new(true)),
            peer_table: Arc::new(crate::PeerTable::new()),
            session_cancel: Mutex::new(Arc::new(AtomicBool::new(false))),
            banned: Arc::new(RwLock::new(Vec::new())),
            added_nodes: Arc::new(RwLock::new(Vec::new())),
            outbound_tx,
            outbound_rx: Arc::new(Mutex::new(outbound_rx)),
            inbound_headers_tx,
            inbound_headers_rx: Mutex::new(Some(inbound_headers_rx)),
            inbound_blocks_tx,
            inbound_blocks_rx: Mutex::new(Some(inbound_blocks_rx)),
            workers: Mutex::new(None),
        }
    }

    /// Starts listeners, outbound connection draining, and peer bootstrap.
    ///
    /// The node gives the service only read-only chain serving and event
    /// delivery hooks. Worker construction and teardown remain P2P-owned.
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

        let session_cancel = Arc::new(AtomicBool::new(false));
        *self.session_cancel.lock() = Arc::clone(&session_cancel);
        self.worker_shutdown.store(false, Ordering::Release);

        let mut bound_listeners = Vec::with_capacity(self.config.listen_addrs.len());
        for addr in &self.config.listen_addrs {
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
            session_cancel,
            Some(Arc::clone(peer_ready)),
            self.config.magic,
            self.inbound_headers_tx.clone(),
            self.inbound_blocks_tx.clone(),
            chain_query.cloned(),
            sync_wake_tx.cloned(),
            extras,
        );
        shared.max_inbound = self.config.max_inbound();
        shared.local_services = self.config.local_services;
        shared.address_book = Some(Arc::clone(&self.address_book));

        let mut listeners = Vec::with_capacity(bound_listeners.len());
        for (listener_addr, listener) in bound_listeners {
            let shutdown = Arc::clone(&self.worker_shutdown);
            let shared = shared.clone();
            let handle = match thread::Builder::new()
                .name(format!("bitcoin-rs-p2p-{listener_addr}"))
                .spawn(move || crate::listener::serve(listener, shutdown, shared))
            {
                Ok(handle) => handle,
                Err(error) => {
                    self.rollback_startup(listeners, None);
                    return Err(error.into());
                }
            };
            listeners.push(handle);
        }

        let dial_allowance = shared.block_sync.clone();
        let outbound = match self.spawn_outbound_worker(shared) {
            Ok(handle) => handle,
            Err(error) => {
                self.rollback_startup(listeners, None);
                return Err(error.into());
            }
        };
        let bootstrap = match self.spawn_bootstrap_worker(dial_allowance, chain_query.cloned()) {
            Ok(handle) => handle,
            Err(error) => {
                self.rollback_startup(listeners, Some(outbound));
                return Err(error.into());
            }
        };
        *slot = Some(Workers {
            listeners,
            outbound: Some(outbound),
            bootstrap,
        });
        Ok(())
    }

    fn rollback_startup(
        &self,
        listeners: Vec<JoinHandle<Result<(), ListenerError>>>,
        outbound: Option<JoinHandle<()>>,
    ) {
        // Leave the start-scoped token asserted. Retrying start installs a
        // new token; resetting this one would un-cancel leftover workers.
        self.session_cancel.lock().store(true, Ordering::Release);
        self.worker_shutdown.store(true, Ordering::Release);
        self.peer_table.cancel_all();
        for handle in listeners {
            let _ = handle.join();
        }
        if let Some(handle) = outbound {
            let _ = handle.join();
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "One drain loop owns active handles, parked admission, and teardown in one epoch"
    )]
    fn spawn_outbound_worker(
        &self,
        shared: crate::listener::ConnectionShared,
    ) -> Result<JoinHandle<()>, io::Error> {
        let address_book = Arc::clone(&self.address_book);
        let manual_nodes = Arc::clone(&self.added_nodes);
        let outbound_rx = Arc::clone(&self.outbound_rx);
        let peer_table = Arc::clone(&self.peer_table);
        let shutdown = Arc::clone(&self.worker_shutdown);
        let process_shutdown = self.shutdown.clone();
        let full_relay_slots = self.config.outbound_full_relay_slots;
        let block_relay_slots = self.config.outbound_block_relay_slots;
        let active_limit = self.config.total_outbound_active_limit();
        let max_peer_connections = self.config.max_peer_connections;
        let allow_feelers = self.config.fixed_peers.is_empty() && active_limit > 0;
        thread::Builder::new()
            .name("bitcoin-rs-p2p-outbound-drain".to_owned())
            .spawn(move || {
                let mut active: HashMap<SocketAddr, ActiveOutbound> = HashMap::new();
                // Automatic dials that arrived while the automatic cap was
                // full, retried in order once a slot opens.
                let mut parked: VecDeque<OutboundDial> = VecDeque::new();
                let mut handles = Vec::new();
                let mut next_extra_peer_check = Instant::now() + EXTRA_PEER_CHECK_INTERVAL;
                let mut next_feeler = Instant::now() + feeler_delay(bitcoin::secp256k1::rand::thread_rng().next_u64());
                while !shutdown.load(Ordering::Acquire)
                    && !shared.session_cancel.load()
                    && !process_shutdown.is_triggered()
                {
                    reap_finished_outbound_connections(&mut active, &mut handles, &address_book);
                    let now = Instant::now();
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
                    // Manual dials bypass admission and do not consume
                    // automatic slots. Automatic dials at capacity are
                    // parked and retried in order once a slot opens. When
                    // the parked queue is full, the request is shed and its
                    // Pending selection is cleared so the book can retry an
                    // address that was never dialed. A stale tip raises the
                    // automatic cap by one so an extra full-relay peer can
                    // form beside a full slot set.
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
    ) -> Result<Option<JoinHandle<()>>, io::Error> {
        if !self.config.fixed_peers.is_empty() {
            let shutdown = Arc::clone(&self.worker_shutdown);
            let network_active = Arc::clone(&self.network_active);
            let peer_table = Arc::clone(&self.peer_table);
            let outbound_tx = self.outbound_tx.clone();
            let endpoints = self.config.fixed_peers.clone();
            return thread::Builder::new()
                .name("bitcoin-rs-fixed-peer-bootstrap".to_owned())
                .spawn(move || {
                    run_fixed_peer_bootstrap(
                        shutdown,
                        network_active,
                        peer_table,
                        outbound_tx,
                        endpoints,
                    );
                })
                .map(Some);
        }
        let shutdown = Arc::clone(&self.worker_shutdown);
        let network_active = Arc::clone(&self.network_active);
        let peer_table = Arc::clone(&self.peer_table);
        let outbound_tx = self.outbound_tx.clone();
        let port = self.config.dns_port;
        let seeds = if self.config.dns_seeds_enabled {
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
        };
        thread::Builder::new()
            .name("bitcoin-rs-address-maintenance".to_owned())
            .spawn(move || run_address_maintenance(&maintenance))
            .map(Some)
    }

    /// Stops P2P workers and asks all current connection owners to tear down.
    pub fn shutdown(&self) {
        let demonstrated = anchor_peers(&self.peer_table, &self.address_book);
        if !demonstrated.is_empty() {
            self.address_book
                .remember_anchors(&demonstrated, crate::addrman::now());
        }
        self.session_cancel.lock().store(true, Ordering::Release);
        self.worker_shutdown.store(true, Ordering::Release);
        self.peer_table
            .set_network_active(&self.network_active, false);
        self.address_book
            .return_restart_anchors(crate::addrman::now());
        self.address_book.save();
    }

    /// Returns a reference to the process-wide shutdown reader.
    #[must_use]
    pub fn shutdown_reader(&self) -> &bitcoin_rs_chain::LatchReader {
        &self.shutdown
    }

    /// Joins listener and outbound workers. Bootstrap is joined separately so
    /// node teardown can keep that drain after the bounded subsystem wait.
    pub fn join_core_workers(&self) -> Result<(), P2pJoinError> {
        let (listeners, outbound) = {
            let mut slot = self.workers.lock();
            let Some(workers) = slot.as_mut() else {
                return Ok(());
            };
            let listeners = std::mem::take(&mut workers.listeners);
            let outbound = workers.outbound.take();
            if workers.bootstrap.is_none() {
                *slot = None;
            }
            (listeners, outbound)
        };
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

    /// Joins the bootstrap worker if one was started.
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

    /// Joins every worker owned by this service. Calling it more than once is
    /// harmless.
    pub fn join(&self) -> Result<(), P2pJoinError> {
        let core = self.join_core_workers();
        let bootstrap = self.join_bootstrap_worker();
        core.and(bootstrap)
    }

    /// Test seam for node teardown coverage: installs a caller-spawned
    /// handle as the outbound drain worker, so join-failure paths are
    /// reachable without a live peer.
    #[cfg(feature = "test-seam")]
    #[doc(hidden)]
    pub fn test_install_outbound_worker(&self, handle: JoinHandle<()>) {
        self.workers
            .lock()
            .get_or_insert_with(Workers::default)
            .outbound = Some(handle);
    }

    /// Test seam for node teardown coverage: installs a caller-spawned
    /// handle as the bootstrap worker.
    #[cfg(feature = "test-seam")]
    #[doc(hidden)]
    pub fn test_install_bootstrap_worker(&self, handle: JoinHandle<()>) {
        self.workers
            .lock()
            .get_or_insert_with(Workers::default)
            .bootstrap = Some(handle);
    }

    /// Returns the single session table owned by this service.
    #[must_use]
    pub fn table(&self) -> Arc<crate::PeerTable> {
        Arc::clone(&self.peer_table)
    }

    /// The service flags this node advertises in every `version` (Core
    /// `init.cpp:2022-2026`): what RPC reports as `localservices`.
    #[must_use]
    pub fn local_services(&self) -> bitcoin::p2p::ServiceFlags {
        self.config.local_services
    }

    /// Returns whether P2P network activity is enabled.
    #[must_use]
    pub fn network_active(&self) -> bool {
        self.network_active.load(Ordering::Acquire)
    }

    /// Enables or disables network activity. Disabling cancels current peers;
    /// their owners remove the leases during teardown.
    pub fn set_network_active(&self, active: bool) {
        self.peer_table
            .set_network_active(&self.network_active, active);
    }

    /// Adds or replaces one manual ban entry.
    pub fn set_ban(&self, entry: crate::BannedSubnet) {
        let mut banned = self.banned.write();
        banned.retain(|current| current.subnet != entry.subnet);
        banned.push(entry);
    }

    /// Removes one manual ban entry.
    pub fn remove_ban(&self, subnet: crate::IpSubnet) {
        self.banned.write().retain(|entry| entry.subnet != subnet);
    }

    /// Clears all manual bans.
    pub fn clear_banned(&self) {
        self.banned.write().clear();
    }

    /// Returns a read-only reader for the active manual bans.
    #[must_use]
    pub fn banned_reader(&self) -> BannedReader {
        BannedReader::new(Arc::clone(&self.banned))
    }

    /// Returns a snapshot of current manual bans.
    #[must_use]
    pub fn banned(&self) -> Vec<crate::BannedSubnet> {
        self.banned.read().clone()
    }

    /// Returns configured addnode add addresses.
    #[must_use]
    pub fn added_nodes(&self) -> Vec<SocketAddr> {
        self.added_nodes.read().clone()
    }

    /// Applies Core-like addnode state and requests a connection.
    pub fn add_node(&self, addr: SocketAddr, persist: bool) -> Result<(), P2pControlError> {
        if crate::subnet::is_banned(&self.banned.read(), addr.ip(), SystemTime::now()) {
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

    /// Removes one configured addnode add address.
    pub fn remove_node(&self, addr: SocketAddr) {
        self.added_nodes.write().retain(|current| *current != addr);
    }

    /// Disconnects any active connection with the given address.
    pub fn disconnect(&self, addr: SocketAddr) -> bool {
        self.peer_table.disconnect(addr)
    }

    /// Queues an automatic dial for the stale-tip slot-cap unit test.
    /// Local addnode requests are manual and cannot exercise that allowance.
    #[cfg(test)]
    pub(crate) fn test_queue_automatic_dial(
        &self,
        addr: SocketAddr,
    ) -> Result<(), crossbeam_channel::SendError<OutboundDial>> {
        self.outbound_tx.send(OutboundDial::auto(addr))
    }

    /// Takes the inbound headers receiver for the single coordinator.
    pub fn take_inbound_headers_receiver(&self) -> Option<Receiver<crate::InboundHeaders>> {
        self.inbound_headers_rx.lock().take()
    }

    /// Takes the inbound block receiver for the single coordinator.
    pub fn take_inbound_blocks_receiver(&self) -> Option<Receiver<crate::InboundBlock>> {
        self.inbound_blocks_rx.lock().take()
    }

    /// Returns a sender for inbound block notifications.
    #[must_use]
    pub fn inbound_blocks_sender(&self) -> Sender<crate::InboundBlock> {
        self.inbound_blocks_tx.clone()
    }
}

/// Tear down one start epoch without leaving parked or completed automatic
/// claims behind. Thread joins occur before releasing their lifetime claims.
fn defer_rejected_dial(
    dial: &OutboundDial,
    book: &crate::addrman::AddressBook,
    active: &HashMap<SocketAddr, ActiveOutbound>,
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
    active: &HashMap<SocketAddr, ActiveOutbound>,
    handles: Vec<(SocketAddr, JoinHandle<Result<(), crate::PeerError>>)>,
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
    active: &mut HashMap<SocketAddr, ActiveOutbound>,
    handles: &mut Vec<(SocketAddr, JoinHandle<Result<(), crate::PeerError>>)>,
    book: &crate::addrman::AddressBook,
) {
    let mut index = 0;
    while index < handles.len() {
        if !handles[index].1.is_finished() {
            index += 1;
            continue;
        }
        let (addr, handle) = handles.swap_remove(index);
        if active.remove(&addr).is_some_and(|dial| !dial.manual) {
            book.unqueue(addr);
        }
        match handle.join() {
            Ok(Ok(())) => tracing::debug!(addr = %addr, "p2p outbound connection exited cleanly"),
            Ok(Err(error)) => {
                tracing::warn!(addr = %addr, %error, "p2p outbound connection exited with error");
            }
            Err(_) => tracing::warn!(addr = %addr, "p2p outbound connection panicked"),
        }
    }
}

/// Use the existing outbound owner for one bounded probe; a feeler bypasses
/// the steady slot count but cannot coexist with another unfinished probe.
fn spawn_feeler(
    shared: &crate::listener::ConnectionShared,
    book: &crate::addrman::AddressBook,
    manual: &[SocketAddr],
    active: &mut HashMap<SocketAddr, ActiveOutbound>,
    handles: &mut Vec<(SocketAddr, JoinHandle<Result<(), crate::PeerError>>)>,
    max_peer_connections: usize,
) {
    if active.values().any(|entry| entry.feeler)
        || !shared.activity.is_active()
        || shared.session_cancel.load()
    {
        return;
    }
    // TCP presence is separate from queued/in-flight work. Core's
    // AlreadyConnectedToAddress may Good a TCP-present collision incumbent;
    // a pending dial must not manufacture that success evidence.
    let connected: Vec<_> = shared
        .peer_table
        .sessions()
        .into_iter()
        .filter(|session| !session.lease.is_cancelled())
        .map(|session| session.addr)
        .collect();
    let mut addresses: Vec<_> = active.keys().copied().collect();
    addresses.extend_from_slice(&connected);
    let banned = shared.banned.read().clone();
    let tick_time = SystemTime::now();
    let Some(addr) = book.feeler(&addresses, &connected, crate::addrman::now(), |addr| {
        !is_manual_endpoint(manual, addr)
            && !crate::subnet::is_banned(&banned, addr.ip(), tick_time)
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

/// Compare endpoint identities using the address book's canonical spelling.
/// Keep the configured spelling in the operator-owned list itself.
fn is_manual_endpoint(manual: &[SocketAddr], addr: SocketAddr) -> bool {
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

#[expect(clippy::needless_pass_by_value)]
fn run_fixed_peer_bootstrap(
    shutdown: Arc<AtomicBool>,
    network_active: Arc<AtomicBool>,
    peer_table: Arc<crate::PeerTable>,
    outbound_tx: Sender<OutboundDial>,
    endpoints: Vec<String>,
) {
    while !shutdown.load(Ordering::Acquire) {
        if !network_active.load(Ordering::Acquire) {
            if wait_for_shutdown(&shutdown, Duration::from_millis(100)) {
                break;
            }
            continue;
        }
        'endpoints: for endpoint in &endpoints {
            if !network_active.load(Ordering::Acquire) {
                break 'endpoints;
            }
            let addresses = match endpoint.as_str().to_socket_addrs() {
                Ok(addresses) => addresses,
                Err(error) => {
                    tracing::warn!(endpoint, %error, "fixed peer resolution failed");
                    continue;
                }
            };
            for addr in addresses {
                if peer_table.is_connected(addr) || !network_active.load(Ordering::Acquire) {
                    continue;
                }
                if outbound_tx.try_send(OutboundDial::pinned(addr)).is_err() {
                    break 'endpoints;
                }
            }
        }
        if wait_for_shutdown(&shutdown, Duration::from_secs(2)) {
            break;
        }
    }
}

/// Chooses the role of one dial, pinned or automatic.
///
/// PRE: `dial` is a dequeued outbound request; the remaining arguments are
///   the automatic chooser's, over the same table and pending set.
/// POST: a pinned dial is answered with full relay whatever the classes
///   hold; an automatic one is answered by [`next_outbound_role`].
/// INVARIANT: an operator pin (`--connect`/`addnode`) asks for full relay
///   because Core's `ConnectionType::MANUAL` peers relay transactions.
///   Feeding the pin through the slot chooser could hand it
///   `BlockRelayOnly`, which advertises `relay = false` and ends the
///   connection on the first transaction the operator's peer sends; the
///   chooser only orders the dials the scheduler started itself.
fn dial_outbound_role(
    dial: &OutboundDial,
    peer_table: &crate::PeerTable,
    pending: &HashMap<SocketAddr, ActiveOutbound>,
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

// PeerTable registers outbound leases only after TCP establishment. Like Core's
// CNode census, handshake-in-progress and manual persistent sessions count;
// queued/inflight dial work and inbound/cancelled sessions do not.
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
                && !book.is_feeler(session.addr)
        })
        .map(|session| session.addr)
        .collect();
    book.count_failure(&outbound, maximum)
}

/// Starts one accepted dial: skips addresses already running or connected,
/// picks the relay role, and records the in-flight attempt.
fn spawn_outbound_dial(
    dial: &OutboundDial,
    shared: &crate::listener::ConnectionShared,
    active: &mut HashMap<SocketAddr, ActiveOutbound>,
    handles: &mut Vec<(SocketAddr, JoinHandle<Result<(), crate::PeerError>>)>,
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
    if !shared.activity.is_active()
        || shared.session_cancel.load()
        || !services_allowed
        || shared.banned.is_banned(dial.addr.ip(), SystemTime::now())
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
            !session.lease.is_cancelled() && crate::addrman::canonical(session.addr) == dial.addr
        })
    {
        // A manual request cannot release a queued automatic request's claim.
        // A duplicate automatic request also cannot release a running automatic
        // thread's ownership; otherwise the next maintenance tick can reselect it.
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

/// Chooses the relay role of the next automatic outbound connection.
///
/// PRE: `peer_table` holds the live connections of the current epoch,
///   `pending` holds every dial the caller has started whose thread is still
///   running — connected ones included — keyed by address with its role and
///   origin, and `extra_full_relay` reports the scheduler's allowance.
/// POST: return `BlockRelayOnly` only while the automatic block-relay
///   population is below its slots, which happens once automatic full-relay
///   slots are filled.
/// INVARIANT: only automatic connections count, once in their own class.
///   The table and pending dials share one snapshot, so registration during a
///   census cannot drop a dial from both groups. Manual peers and dials never
///   consume automatic slots. Full-relay slots fill first, then block-relay
///   slots, as Core orders its dial priorities (`net.cpp:2780-2799`). A stale
///   tip raises the full-relay target by one, as Core's
///   `GetTryNewOutboundPeer` (`net.cpp:2471-2480`). When both classes are
///   satisfied the automatic dial is served as full relay. A pinned dial is
///   assigned full relay by the caller and never reaches this chooser.
fn next_outbound_role(
    peer_table: &crate::PeerTable,
    pending: &HashMap<SocketAddr, ActiveOutbound>,
    full_relay_slots: usize,
    block_relay_slots: usize,
    extra_full_relay: bool,
) -> crate::peer_info::PeerRole {
    use crate::peer_info::PeerRole;
    // One snapshot classifies every dial exactly once: a dial the table has
    // taken counts in its class here and not in flight, a dial it has not
    // taken counts in flight and not here. Reading the counts and the
    // liveness checks from separate table passes could drop a dial that
    // registers in between into neither population and over-dial its class.
    let sessions = peer_table.sessions();
    let census: Vec<&crate::peer_table::PeerSession> = sessions
        .iter()
        .filter(|session| {
            !session.lease.is_inbound()
                && !session.lease.is_cancelled()
                && !session.lease.is_manual()
                && !pending.get(&session.addr).is_some_and(|entry| entry.feeler)
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
    // A live connection stays in `pending` until its thread exits, so only a
    // dial the table has not taken yet adds to its class.
    let in_flight = |want: PeerRole| {
        pending
            .iter()
            .filter(|(addr, outbound)| {
                !outbound.manual
                    && !outbound.feeler
                    && outbound.role == want
                    && !census.iter().any(|session| session.addr == **addr)
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

/// Retires the newest full-relay outbound connection that the stale-tip
/// allowance made extra, once the tip has moved again.
///
/// PRE: `slots` is the configured full-relay count; `sync`, when the node
///   wired one, answers whether the tip still looks stale and who is
///   mid-download.
/// POST: at most one connection is disconnected, and none while the tip still
///   looks stale, while no connection is above `slots`, or while every
///   candidate is too young or mid-download.
/// INVARIANT: the extra connection exists to find a better chain, so it leaves
///   as soon as the chain moves. Core retires one per check
///   (`EvictExtraOutboundPeers`, `net_processing.cpp:5604-5668`) and passes
///   over a peer with blocks in flight or a peer below the minimum age.
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
    if peer_table.disconnect_connection(session.addr, session.lease.connection_id()) {
        tracing::info!(
            peer_addr = %session.addr,
            "p2p retiring the extra full-relay connection: the tip is moving again"
        );
    }
}

/// The newest automatic full-relay outbound connection beyond the configured
/// slots.
///
/// PRE: `slots` is the configured full-relay count, and `is_downloading`
///   answers whether a candidate's body download is in flight, read from the
///   same window the scheduler fetches with.
/// POST: return `None` while the table holds no more than `slots` such
///   connections; otherwise return the newest one among the newest `excess`
///   connections that is old enough to be judged and has no body download
///   in flight.
/// INVARIANT: the census and the victim set hold automatic connections only:
///   a hand-pinned full-relay connection counts in neither, as Core's
///   `IsFullOutboundConn()` excludes `ConnectionType::MANUAL`
///   (`net_processing.cpp:5558-5604`). An operator's peer therefore never
///   forces the retirement of an automatic one. A connection that never
///   finished its handshake still holds a slot, so it counts, while a
///   candidate with blocks in flight is passed over, as Core's rule does
///   (`net_processing.cpp:5604-5668`).
///   `PeerTable::sessions` is ordered by connection identity, which is dial
///   order, so the newest is last and the excess is taken from the tail.
fn newest_excess_full_relay(
    peer_table: &crate::PeerTable,
    slots: usize,
    now: Instant,
    is_downloading: impl Fn(crate::PeerSource) -> bool,
) -> Option<crate::peer_table::PeerSession> {
    // A hand-pinned full-relay connection is outside the census, as Core's
    // `IsFullOutboundConn()` excludes `ConnectionType::MANUAL`
    // (`net_processing.cpp:5558-5604`): it creates no excess and the victim
    // selection below only ever sees automatic connections.
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
                && !is_downloading(session.lease.source(session.addr))
        })
        .cloned()
}

fn dial_has_capacity(
    dial: &OutboundDial,
    active: &HashMap<SocketAddr, ActiveOutbound>,
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
    active: &HashMap<SocketAddr, ActiveOutbound>,
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
    manual_nodes: Arc<RwLock<Vec<SocketAddr>>>,
}

fn park_automatic_dial(
    parked: &mut VecDeque<OutboundDial>,
    dial: OutboundDial,
    book: &crate::addrman::AddressBook,
    active: &HashMap<SocketAddr, ActiveOutbound>,
) -> bool {
    if parked.len() >= MAX_PARKED_DIALS {
        defer_rejected_dial(&dial, book, active);
        return false;
    }
    parked.push_back(dial);
    true
}

// One census preserves all automatic ready roles for recovery. Active peer
// timestamps are not refreshed while connected to prevent topology leakage;
// only disconnect updates full-relay timestamps in the book.
fn ready_address_count(peer_table: &crate::PeerTable) -> usize {
    peer_table
        .sessions()
        .into_iter()
        .filter(|session| {
            !session.lease.is_inbound()
                && !session.lease.is_manual()
                && !session.lease.is_cancelled()
                && session.info.is_some()
                && !book.is_feeler(session.addr)
        })
        .count()
}

fn anchor_peers(table: &crate::PeerTable, book: &crate::addrman::AddressBook) -> Vec<SocketAddr> {
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
                && !book.is_feeler(session.addr)
        })
        .map(|session| session.addr)
        .collect()
}

/// Queue consumed restart anchors before ordinary candidates using the same
/// bounded channel and eligibility policy as automatic dialing.
fn queue_restart_anchors(
    maintenance: &AddressMaintenance,
    anchors: &mut VecDeque<SocketAddr>,
    attempting: &mut Option<SocketAddr>,
    active: &mut Vec<SocketAddr>,
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
                && !maintenance.address_book.is_feeler(session.addr)
        })
        .map(|session| session.addr)
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
    let manual = maintenance.manual_nodes.read();
    while let Some(addr) = anchors.pop_front() {
        if is_manual_endpoint(&manual, addr)
            || !maintenance.address_book.anchor_eligible(addr, active, now)
            || !maintenance
                .address_book
                .ordinary_services_eligible(addr, depth)
            || maintenance.banned.is_banned(addr.ip(), SystemTime::now())
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
    // Give a populated book one cooldown to establish a connection before
    // asking seeds for replacements. Pending/failed dials are not successes.
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
            .unwrap_or_default()
            .as_secs();
        let ready_count = ready_address_count(&maintenance.peer_table);
        if maintenance.network_active.load(Ordering::Acquire) {
            if !anchors_taken && maintenance.block_slots > 0 {
                anchors = maintenance.address_book.take_restart_anchors(now).into();
                anchors_taken = true;
            }
            // Durable anchor consumption can block; activity may change during I/O.
            if maintenance.shutdown.load(Ordering::Acquire)
                || !maintenance.network_active.load(Ordering::Acquire)
            {
                continue;
            }
            // Hold operator policy through the owner's timer mutation; callbacks
            // execute outside the address-book lock and use one ban snapshot.
            let connected: Vec<_> = maintenance
                .peer_table
                .sessions()
                .into_iter()
                .filter(|session| !session.lease.is_cancelled())
                .map(|session| session.addr)
                .collect();
            let banned = maintenance.banned.read().clone();
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
                        !is_manual_endpoint(&manual, addr)
                            && !crate::subnet::is_banned(&banned, addr.ip(), tick_time)
                    });
            }
            // A fresh but unreachable book must not permanently suppress seed
            // recovery. Retained candidates remain usable with DNS disabled.
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
                        && !maintenance.address_book.is_feeler(session.addr)
                })
                .map(|session| session.addr)
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

/// Fill the automatic deficit once. Address-book claims cover queued, parked,
/// connecting and live automatic threads; live sessions are counted only once.
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
    // Connected-endpoint exclusion covers every direction; group diversity
    // suppression counts outbound sessions only, so inbound peers cannot
    // shrink the candidate space.
    let mut active: Vec<_> = sessions
        .iter()
        .filter(|session| !session.lease.is_cancelled())
        .map(|session| session.addr)
        .collect();
    let grouped: Vec<_> = sessions
        .iter()
        .filter(|session| {
            !session.lease.is_cancelled()
                && !session.lease.is_inbound()
                && !maintenance.address_book.is_feeler(session.addr)
        })
        .map(|session| session.addr)
        .collect();
    let automatic: Vec<_> = sessions
        .iter()
        .filter(|session| {
            !session.lease.is_cancelled()
                && !session.lease.is_inbound()
                && !session.lease.is_manual()
                && !maintenance.address_book.is_feeler(session.addr)
        })
        .map(|session| session.addr)
        .collect();
    let occupied = automatic.len() + maintenance.address_book.pending_count_excluding(&automatic);
    let needed = (maintenance.target + extra).saturating_sub(occupied + reserved_anchors);
    // Snapshot the ban table before taking the address-book lock. All candidates
    // in this tick see the same expiry time and no nested ban lock per record.
    let banned = maintenance.banned.read().clone();
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
                    && !crate::subnet::is_banned(&banned, addr.ip(), tick_time)
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
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};

    #[test]
    fn feeler_poisson_delay_matches_actual_core_uniform_vectors() {
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/core-poisson-v31.1.json"))
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
    fn start_fails_when_listener_cannot_bind() {
        let occupied =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("occupy port");
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
    fn network_activity_transition_cancels_leases_only_when_disabled() {
        let table = crate::PeerTable::new();
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        table.register(SocketAddr::from((Ipv4Addr::LOCALHOST, 8333)), lease.clone());
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
            SocketAddr::from(([127, 0, 0, 1], 1)),
            PeerLease::new_manual(manual_tx, PeerRole::FullRelay),
        );
        let mut pending = HashMap::from([(
            SocketAddr::from(([127, 0, 0, 1], 2)),
            ActiveOutbound {
                feeler: false,

                role: PeerRole::FullRelay,
                manual: true,
            },
        )]);
        let automatic_dial = OutboundDial::auto(SocketAddr::from(([127, 0, 0, 1], 3)));

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
            SocketAddr::from(([127, 0, 0, 1], 4)),
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
            SocketAddr::from(([127, 0, 0, 1], 1)),
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
            SocketAddr::from(([127, 0, 0, 1], 2)),
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
        let mut pending: HashMap<SocketAddr, ActiveOutbound> = HashMap::new();
        for port in 1..=8_u16 {
            pending.insert(
                SocketAddr::from(([127, 0, 0, 1], port)),
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
                SocketAddr::from(([127, 0, 0, 1], port)),
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
        let mut pending: HashMap<SocketAddr, ActiveOutbound> = HashMap::new();
        for port in 1..=5_u16 {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
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

        fn addr(port: u16) -> SocketAddr {
            SocketAddr::from(([127, 0, 0, 1], port))
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
            addr(6),
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
                .addr,
            excess.addr,
            "the newest automatic connection stays the victim while a pinned one is newer"
        );
    }

    #[test]
    fn a_pinned_dial_takes_full_relay_whatever_the_slots_hold() {
        use crate::connection::PeerLease;
        use crate::peer_info::PeerRole;

        let table = crate::PeerTable::new();
        let addr = SocketAddr::from(([127, 0, 0, 1], 1));
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
                    &OutboundDial::pinned(SocketAddr::from(([127, 0, 0, 1], 2))),
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

        fn addr(port: u16) -> SocketAddr {
            SocketAddr::from(([127, 0, 0, 1], port))
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
            .map(|lease| lease.source(addr(4)))
            .expect("the downloading excess peer is registered");

        assert!(
            newest_excess_full_relay(&table, 2, now, |candidate| candidate == source).is_none(),
            "the downloading excess peer is passed over and nothing else is beyond the slots"
        );
        assert_eq!(
            newest_excess_full_relay(&table, 2, now, |_| false)
                .expect("the aged excess peer is eligible")
                .addr,
            addr(4),
            "the same peer is the victim once its download completes"
        );
    }

    #[test]
    fn a_pinned_peer_beyond_a_full_set_creates_no_excess() {
        use crate::connection::PeerLease;
        use crate::download_window::MINIMUM_CONNECT_TIME;
        use crate::peer_info::PeerRole;

        fn addr(port: u16) -> SocketAddr {
            SocketAddr::from(([127, 0, 0, 1], port))
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
            addr(4),
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
        let addr1: SocketAddr = "127.0.0.1:8333".parse().expect("addr");
        let addr2: SocketAddr = "127.0.0.2:8333".parse().expect("addr");

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
        let addr: SocketAddr = "127.0.0.1:8333".parse().expect("addr");
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
        let addr: SocketAddr = "127.0.0.1:8333".parse().expect("addr");
        assert_eq!(service.add_node(addr, true), Err(P2pControlError::Banned));
        assert_eq!(service.added_nodes().as_slice(), &[]);
        assert!(service.outbound_rx.lock().try_recv().is_err());
    }
    #[test]
    fn parked_overflow_releases_the_address_for_another_selection() {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 8333));
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
            let addr = SocketAddr::from(([8, n, 1, 1], 8333));
            book.learn_dns("seed", &[addr], 10_000);
            book.learn_peer(addr.ip(), &[(addr, 9, 10_000)], 10_000);
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
        let full = SocketAddr::from(([8, 1, 1, 1], 8333));
        book.learn_dns("seed", &[full], 5000);
        let block = (2..=255)
            .map(|n| SocketAddr::from(([8, n, 1, 1], 8333)))
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
                addr,
                version: 70016,
                wtxid_relay: false,
                compact_block_relay: false,
                send_headers: false,
                services: 9,
                user_agent: String::new(),
                start_height: 0,
                best_known_height: 0,
                conn_time: 0,
                inbound: false,
                addr_bind: addr,
                time_offset: 0,
                counters: Arc::new(crate::PeerCounters::default()),
            };
            assert!(table.publish_info(addr, &lease, info));
        }
        assert_eq!(ready_address_count(&table), 2);
        let response = book.gossip(10_000);
        for (addr, expected) in [(full, 5000), (block, 5000)] {
            let timestamp = response
                .iter()
                .find(|(_, advertised)| advertised.socket_addr().ok() == Some(addr))
                .expect("advertised")
                .0;
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
        table.register(SocketAddr::from(([8, 1, 1, 1], 8333)), automatic);
        assert!(!count_address_failure(&table, 125, &book));
        assert!(count_address_failure(&table, 2, &book));
        let same_group = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
        table.register(SocketAddr::from(([8, 1, 2, 2], 8333)), same_group);
        assert!(!count_address_failure(&table, 125, &book));
        let manual = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
        table.register(SocketAddr::from(([8, 2, 1, 1], 8333)), manual.clone());
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
        let probe = SocketAddr::from(([9, 4, 1, 1], 8333));
        assert!(book.queued_feeler(probe));
        let probe_lease = register_ready_block_peer(&table, probe);
        assert!(!count_address_failure(&table, 125, &book));
        assert!(count_address_failure(&table, 2, &book));
        assert_eq!(refresh_ready_addresses(&book, &table, 10_000), 0);
        assert_eq!(anchor_peers(&table, &book), Vec::<SocketAddr>::new());
        table.remove_current(probe, &probe_lease);
        book.unqueue(probe);
        table.register(
            SocketAddr::from(([8, 3, 1, 1], 8333)),
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
            "8.8.0.1:8333".parse().expect("peer"),
            crate::PeerLease::new(tx.clone()),
        );
        table.register(
            "9.9.0.1:8333".parse().expect("same ASN"),
            crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay),
        );
        assert!(
            !count_address_failure(&table, 125, &book),
            "different prefixes in one ASN count once"
        );
        assert!(count_address_failure(&table, 2, &book));
        let independent = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
        table.register(
            "8.8.1.1:8333".parse().expect("independent ASN"),
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
            "8.8.1.2:8333".parse().expect("inbound"),
            crate::PeerLease::new_inbound(tx),
        );
        assert!(!count_address_failure(&table, 125, &book));
    }

    #[test]
    fn auxiliary_save_interval_retains_immediate_explicit_save() {
        let dir = tempfile::tempdir().expect("dir");
        let base = dir.path().join("peers.dat");
        let book = crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true, None);
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
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
                .0,
            10_000
        );
        book.save();
        assert_eq!(
            crate::addrman::AddressBook::open(Some(base), [1; 4], true, None).gossip(20_000)[0].0,
            20_000,
            "shutdown and anchor-consumption barriers bypass the periodic throttle"
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
            SocketAddr::from(([9, 9, 1, 1], 8333)),
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
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 8333));
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
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 8333));
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
                reap_finished_outbound_connections(&mut active, &mut handles, &book);
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
            let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
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
                address,
                &version,
                10_000,
                10_000,
                Arc::new(crate::PeerCounters::default()),
            );
            table.register(address, lease.clone());
            assert!(table.publish_info(address, &lease, info));
            if port != 1 {
                assert!(table.note_announced_tip(
                    lease.source(address),
                    bitcoin_rs_primitives::Hash256::from_le_bytes(&[7; 32]),
                    Some(2)
                ));
            }
            leases.push(lease);
        }
        assert_eq!(
            anchor_peers(&table, &book),
            vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 2))]
        );
        leases[1].cancel();
        assert_eq!(anchor_peers(&table, &book), Vec::<SocketAddr>::new());
    }

    #[test]
    fn anchor_dials_prefer_block_slots_without_displacing_manual_roles() {
        let table = crate::PeerTable::new();
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 8333));
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
        let first: SocketAddr = "8.1.1.1:8333".parse().expect("first");
        let other: SocketAddr = "9.2.1.1:8333".parse().expect("other");
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
        assert_eq!(anchors, VecDeque::<SocketAddr>::new());
        // A queued but never accepted anchor is returned, not discarded.
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
                &[SocketAddr::from(([8, n, 1, 1], 8333))],
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
            maintenance.manual_nodes.write().push(SocketAddr::new(
                Ipv4Addr::new(8, n, 1, 1).to_ipv6_mapped().into(),
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
        assert_eq!(anchors, VecDeque::<SocketAddr>::new());
        let (headers, _) = crossbeam_channel::bounded(1);
        let (blocks, _) = crossbeam_channel::bounded(1);
        // An inactive transport makes a regression fail locally before any TCP
        // dial: this test never opens connections to its public-looking fixtures.
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
                .all(SocketAddr::is_ipv6),
            "operator spelling is retained"
        );
        assert!(
            !is_manual_endpoint(&pins, SocketAddr::new(anchor.ip(), 8334)),
            "a different port is a different endpoint"
        );
    }
    fn register_ready_block_peer(table: &crate::PeerTable, addr: SocketAddr) -> crate::PeerLease {
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
            addr,
            &version,
            10_000,
            10_000,
            Arc::new(crate::PeerCounters::default()),
        );
        table.register(addr, lease.clone());
        assert!(table.publish_info(addr, &lease, info));
        assert!(table.note_announced_tip(
            lease.source(addr),
            bitcoin_rs_primitives::Hash256::from_le_bytes(&[7; 32]),
            Some(1)
        ));
        lease
    }

    #[test]
    fn failed_first_anchor_retains_the_second_for_a_single_block_slot() {
        for target in [1, 2] {
            // block-only total1; then one full plus one block slot
            let (mut maintenance, queue) = maintenance_fixture(target);
            maintenance.block_slots = 1;
            let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
            maintenance.address_book = Arc::clone(&book);
            let first: SocketAddr = "8.1.1.1:8333".parse().expect("first");
            let second: SocketAddr = "9.2.1.1:8333".parse().expect("second");
            let full: SocketAddr = "11.3.1.1:8333".parse().expect("ordinary full relay");
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
            book.unqueue(first); // first attempt failed and its thread was reaped
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
        let first: SocketAddr = "8.1.1.1:8333".parse().expect("first");
        let second: SocketAddr = "9.2.1.1:8333".parse().expect("second");
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
    fn shutdown_publishes_captured_anchors_without_a_maintenance_worker_or_join() {
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
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 8333));
        let now = crate::addrman::now();
        service.address_book.learn_dns("fixture", &[addr], now);
        service.address_book.succeeded(addr, 9, now);
        let _lease = register_ready_block_peer(&service.peer_table, addr);
        assert!(service.workers.lock().is_none());
        service.shutdown();
        let restored =
            crate::addrman::AddressBook::open(Some(path), Magic::REGTEST.to_bytes(), true, None);
        assert_eq!(restored.take_restart_anchors(now), vec![addr]);
    }
    fn saved_book(path: &std::path::Path) -> serde_json::Value {
        let bytes = std::fs::read(path).expect("saved book");
        serde_json::from_slice(&bytes[..bytes.len() - 32]).expect("book JSON")
    }

    #[test]
    fn rejected_duplicates_preserve_active_feeler_and_dispatched_anchor_claims_until_join() {
        for feeler in [false, true] {
            let address: SocketAddr = "127.0.0.1:8333".parse().expect("address");
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
            let mapped =
                SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(), 8333);
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
        let anchor: SocketAddr = "8.8.0.1:8333".parse().expect("anchor");
        let same_as: SocketAddr = "9.9.0.1:8333".parse().expect("same ASN");
        book.learn_dns("seed", &[anchor, same_as], 10_000);
        book.succeeded(anchor, 9, 10_000);
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
        let address: SocketAddr = "8.8.8.8:8333".parse().expect("address");
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
            book.learn_dns("seed", &[address], now);
            book.succeeded(address, if tip_changes { 1032 } else { 9 }, now);
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
                book.set_services(address, 1);
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
                !book.is_pending(address),
                "rejected ordinary claim is released"
            );
            let result = crate::listener::spawn_outbound_connection(
                address,
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
        let bad: SocketAddr = "8.8.8.8:8333".parse().expect("incomplete");
        let healthy: SocketAddr = "9.9.9.9:8333".parse().expect("healthy");
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
        service.address_book.learn_dns("loopback", &[address], now);
        service.address_book.set_services(address, 9);
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
        let worker =
            crate::listener::spawn_outbound_connection(address, shared, crate::PeerRole::FullRelay);
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
        // Close before joining: the old unconditional registration would send a
        // VERSION and wait for a response. Its failure must be the leaked byte,
        // not a second fixture pause or the production handshake deadline.
        let _ = remote.shutdown(std::net::Shutdown::Both);
        drop(remote);
        let result = worker.join().expect("outbound worker");
        disabled.expect("disable does not wait for socket I/O or metadata query");
        assert_eq!(received.expect("closed without handshake"), 0);
        assert!(matches!(
            result,
            Err(crate::PeerError::Protocol("network inactive"))
        ));
        assert_eq!(service.peer_table.sessions().len(), 0);
        assert_eq!(ready.load(Ordering::Relaxed), 0);
        service.address_book.save();
        let record = &saved_book(&directory.path().join("peers-fabfb5da.dat"))["records"][0];
        assert_eq!(record["last_success"], 0);
        assert_eq!(record["tried"], false);
    }
}
