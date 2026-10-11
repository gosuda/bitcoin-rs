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
}

impl OutboundDial {
    /// A dial the seed list or the address book produced.
    #[must_use]
    pub const fn auto(addr: SocketAddr) -> Self {
        Self {
            addr,
            manual: false,
        }
    }

    /// A dial the operator pinned with `--connect` or `addnode`.
    #[must_use]
    pub const fn pinned(addr: SocketAddr) -> Self {
        Self { addr, manual: true }
    }
}

#[derive(Clone, Copy)]
struct ActiveOutbound {
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
        let bootstrap = match self.spawn_bootstrap_worker(dial_allowance) {
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

    fn spawn_outbound_worker(
        &self,
        shared: crate::listener::ConnectionShared,
    ) -> Result<JoinHandle<()>, io::Error> {
        let address_book = Arc::clone(&self.address_book);
        let outbound_rx = Arc::clone(&self.outbound_rx);
        let peer_table = Arc::clone(&self.peer_table);
        let shutdown = Arc::clone(&self.worker_shutdown);
        let process_shutdown = self.shutdown.clone();
        let full_relay_slots = self.config.outbound_full_relay_slots;
        let block_relay_slots = self.config.outbound_block_relay_slots;
        let active_limit = self.config.total_outbound_active_limit();
        let max_peer_connections = self.config.max_peer_connections;
        thread::Builder::new()
            .name("bitcoin-rs-p2p-outbound-drain".to_owned())
            .spawn(move || {
                let mut active: HashMap<SocketAddr, ActiveOutbound> = HashMap::new();
                // Automatic dials that arrived while the automatic cap was
                // full, retried in order once a slot opens.
                let mut parked: VecDeque<OutboundDial> = VecDeque::new();
                let mut handles = Vec::new();
                let mut next_extra_peer_check = Instant::now() + EXTRA_PEER_CHECK_INTERVAL;
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
                    while let Some(&dial) = parked.front() {
                        if !has_automatic_outbound_capacity(&active, active_limit, extra_dial) {
                            break;
                        }
                        parked.pop_front();
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
                        && !has_automatic_outbound_capacity(&active, active_limit, extra_dial)
                    {
                        if !park_automatic_dial(&mut parked, dial, &address_book) {
                            tracing::warn!(
                                peer_addr = %dial.addr,
                                "p2p outbound request shed: parked automatic queue full; address claim released"
                            );
                        }
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
                for dial in parked {
                    if !dial.manual { address_book.unqueue(dial.addr); }
                }
                for (addr, handle) in handles {
                    let _ = handle.join();
                    if active.get(&addr).is_some_and(|dial| !dial.manual) {
                        address_book.unqueue(addr);
                    }
                }
            })
    }

    fn spawn_bootstrap_worker(
        &self,
        block_sync: Option<Arc<crate::sync::BlockSync>>,
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
            block_sync,
            address_book: Arc::clone(&self.address_book),
            banned: self.banned_reader(),
        };
        thread::Builder::new()
            .name("bitcoin-rs-address-maintenance".to_owned())
            .spawn(move || run_address_maintenance(&maintenance))
            .map(Some)
    }

    /// Stops P2P workers and asks all current connection owners to tear down.
    pub fn shutdown(&self) {
        self.session_cancel.lock().store(true, Ordering::Release);
        self.worker_shutdown.store(true, Ordering::Release);
        apply_network_active(&self.network_active, &self.peer_table, false);
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
        apply_network_active(&self.network_active, &self.peer_table, active);
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

/// Applies the service-owned network-activity transition.
///
/// Disabling cancels current leases; connection owners remove their own
/// sessions during teardown.
fn apply_network_active(flag: &AtomicBool, table: &crate::PeerTable, active: bool) {
    flag.store(active, Ordering::Release);
    if !active {
        table.cancel_all();
    }
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
fn count_address_failure(peer_table: &crate::PeerTable, maximum: usize) -> bool {
    let groups: std::collections::HashSet<_> = peer_table
        .sessions()
        .into_iter()
        .filter(|session| !session.lease.is_inbound() && !session.lease.is_cancelled())
        .map(|session| crate::netgroup::group(session.addr.ip()))
        .collect();
    groups.len() >= maximum.saturating_sub(1).min(2)
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
    let peer_table = shared.peer_table.as_ref();
    if active.contains_key(&dial.addr) || peer_table.is_connected(dial.addr) {
        // A manual request cannot release a queued automatic request's claim.
        // A duplicate automatic request also cannot release a running automatic
        // thread's ownership; otherwise the next maintenance tick can reselect it.
        if !dial.manual && active.get(&dial.addr).is_none_or(|running| running.manual) {
            if let Some(book) = &shared.address_book {
                book.unqueue(dial.addr);
            }
        }
        tracing::debug!(
            addr = %dial.addr,
            "p2p outbound request skipped: already active"
        );
        return;
    }
    let role = dial_outbound_role(
        dial,
        peer_table,
        active,
        full_relay_slots,
        block_relay_slots,
        extra_dial,
    );
    let count_failure = !dial.manual && count_address_failure(peer_table, max_peer_connections);
    if !dial.manual {
        if let Some(book) = &shared.address_book {
            book.queued(dial.addr);
        }
    }
    let handle = if dial.manual {
        crate::listener::spawn_pinned_outbound_connection(dial.addr, shared.clone(), role)
    } else {
        crate::listener::spawn_dial(dial.addr, shared.clone(), role, false, count_failure)
    };
    active.insert(
        dial.addr,
        ActiveOutbound {
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

fn has_automatic_outbound_capacity(
    active: &HashMap<SocketAddr, ActiveOutbound>,
    active_limit: usize,
    extra_dial: bool,
) -> bool {
    let count = active.values().filter(|outbound| !outbound.manual).count();
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
    block_sync: Option<Arc<crate::sync::BlockSync>>,
    address_book: Arc<crate::addrman::AddressBook>,
    banned: BannedReader,
}

fn park_automatic_dial(
    parked: &mut VecDeque<OutboundDial>,
    dial: OutboundDial,
    book: &crate::addrman::AddressBook,
) -> bool {
    if parked.len() >= MAX_PARKED_DIALS {
        book.unqueue(dial.addr);
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
        })
        .count()
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
    while !maintenance.shutdown.load(Ordering::Acquire) {
        let tick_time = SystemTime::now();
        let now = tick_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ready_count = ready_address_count(&maintenance.peer_table);
        if maintenance.network_active.load(Ordering::Acquire) {
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
            queue_address_candidates(maintenance, now, tick_time);
        }
        save_address_book_if_due(&maintenance.address_book, Instant::now(), &mut next_save);
        if wait_for_shutdown(&maintenance.shutdown, Duration::from_secs(1)) {
            break;
        }
    }
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
fn queue_address_candidates(maintenance: &AddressMaintenance, now: u64, tick_time: SystemTime) {
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
        .filter(|session| !session.lease.is_cancelled() && !session.lease.is_inbound())
        .map(|session| session.addr)
        .collect();
    let automatic: Vec<_> = sessions
        .iter()
        .filter(|session| {
            !session.lease.is_cancelled()
                && !session.lease.is_inbound()
                && !session.lease.is_manual()
        })
        .map(|session| session.addr)
        .collect();
    let occupied = automatic.len() + maintenance.address_book.pending_count_excluding(&automatic);
    let needed = (maintenance.target + extra).saturating_sub(occupied);
    // Snapshot the ban table before taking the address-book lock. All candidates
    // in this tick see the same expiry time and no nested ban lock per record.
    let banned = maintenance.banned.read().clone();
    for _ in 0..needed {
        if maintenance.shutdown.load(Ordering::Acquire) {
            break;
        }
        let Some(addr) = maintenance
            .address_book
            .select(&active, &grouped, now, |addr| {
                !crate::subnet::is_banned(&banned, addr.ip(), tick_time)
            })
        else {
            break;
        };
        maintenance.address_book.queued(addr);
        if maintenance
            .outbound_tx
            .try_send(OutboundDial::auto(addr))
            .is_err()
        {
            maintenance.address_book.unqueue(addr);
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
    fn apply_network_active_cancels_leases_only_when_disabled() {
        let table = crate::PeerTable::new();
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        table.register(SocketAddr::from((Ipv4Addr::LOCALHOST, 8333)), lease.clone());
        let flag = AtomicBool::new(true);

        apply_network_active(&flag, &table, true);
        assert!(flag.load(Ordering::Acquire));
        assert!(!lease.is_cancelled());

        apply_network_active(&flag, &table, false);
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
        let book = crate::addrman::AddressBook::open(None, [1; 4], true);
        book.learn_dns("seed", &[address], 10_000);
        book.queued(address);
        assert_eq!(book.select(&[], &[], 10_000, |_| true), None);
        let mut parked = VecDeque::from(vec![OutboundDial::auto(address); MAX_PARKED_DIALS]);
        assert!(!park_automatic_dial(
            &mut parked,
            OutboundDial::auto(address),
            &book
        ));
        assert_eq!(book.select(&[], &[], 10_000, |_| true), Some(address));
    }
    fn maintenance_fixture(target: usize) -> (AddressMaintenance, Receiver<OutboundDial>) {
        let (tx, rx) = crossbeam_channel::bounded(16);
        let book = crate::addrman::AddressBook::open(None, [1; 4], false);
        for n in 1..100 {
            book.learn_dns("seed", &[SocketAddr::from(([8, n, 1, 1], 8333))], 10_000);
        }
        (
            AddressMaintenance {
                shutdown: Arc::new(AtomicBool::new(false)),
                network_active: Arc::new(AtomicBool::new(true)),
                peer_table: Arc::new(crate::PeerTable::new()),
                outbound_tx: tx,
                port: 8333,
                seeds: Vec::new(),
                target,
                block_sync: None,
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
        let book = crate::addrman::AddressBook::open(None, [1; 4], false);
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
        assert!(!count_address_failure(&table, 125));
        assert!(count_address_failure(&table, 1));
        let (tx, _) = crossbeam_channel::bounded(1);
        let automatic = crate::PeerLease::new(tx.clone());
        table.register(SocketAddr::from(([8, 1, 1, 1], 8333)), automatic);
        assert!(!count_address_failure(&table, 125));
        assert!(count_address_failure(&table, 2));
        let same_group = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
        table.register(SocketAddr::from(([8, 1, 2, 2], 8333)), same_group);
        assert!(!count_address_failure(&table, 125));
        let manual = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
        table.register(SocketAddr::from(([8, 2, 1, 1], 8333)), manual.clone());
        assert!(
            table
                .sessions()
                .iter()
                .all(|session| session.info.is_none())
        );
        assert!(
            count_address_failure(&table, 125),
            "Core counts established TCP sessions before handshake publication"
        );
        manual.cancel();
        table.register(
            SocketAddr::from(([8, 3, 1, 1], 8333)),
            crate::PeerLease::new_inbound(tx),
        );
        assert!(
            !count_address_failure(&table, 125),
            "inbound and cancelled sessions do not certify connectivity"
        );
    }

    #[test]
    fn auxiliary_save_interval_retains_immediate_explicit_save() {
        let dir = tempfile::tempdir().expect("dir");
        let base = dir.path().join("peers.dat");
        let book = crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true);
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        book.learn_dns("seed", &[addr], 10_000);
        let tick = Instant::now();
        let mut next = tick + Duration::from_mins(15);
        save_address_book_if_due(&book, tick, &mut next);
        assert_eq!(
            crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true).len(),
            0
        );
        save_address_book_if_due(&book, tick + Duration::from_mins(15), &mut next);
        assert_eq!(
            crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true).len(),
            1
        );
        book.connected(addr, 20_000);
        save_address_book_if_due(&book, tick + Duration::from_secs(901), &mut next);
        assert_eq!(
            crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true).gossip(20_000)[0].0,
            10_000
        );
        book.save();
        assert_eq!(
            crate::addrman::AddressBook::open(Some(base), [1; 4], true).gossip(20_000)[0].0,
            20_000,
            "shutdown and anchor-consumption barriers bypass the periodic throttle"
        );
    }

    #[test]
    fn maintenance_counts_queued_parked_and_inflight_automatic_claims_once() {
        let (mut maintenance, rx) = maintenance_fixture(3);
        let tick = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        queue_address_candidates(&maintenance, 10_000, tick);
        assert_eq!(rx.len(), 3);
        for _ in 0..4 {
            queue_address_candidates(&maintenance, 10_000, tick);
        }
        assert_eq!(
            rx.len(),
            3,
            "ticks cannot keep filling a pending dial pipeline"
        );
        let parked = rx.try_recv().expect("queued");
        queue_address_candidates(&maintenance, 10_000, tick);
        assert_eq!(rx.len(), 2, "parking keeps the claim occupied");
        maintenance
            .address_book
            .attempted(parked.addr, true, 10_001);
        queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100));
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
        queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100));
        assert_eq!(rx.len(), 3, "the live session and its claim count once");
        let (tx, _rx) = crossbeam_channel::unbounded();
        maintenance.peer_table.register(
            SocketAddr::from(([9, 9, 1, 1], 8333)),
            crate::PeerLease::new_manual(tx, crate::PeerRole::FullRelay),
        );
        maintenance.target = 5;
        queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100));
        assert_eq!(
            rx.len(),
            4,
            "manual sessions do not consume automatic slots"
        );
        lease.cancel();
        maintenance.address_book.unqueue(parked.addr);
        queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100));
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
        queue_address_candidates(&maintenance, 10_000, until - Duration::from_secs(1));
        assert_eq!(
            rx.len(),
            0,
            "the entire banned subnet is excluded before expiry"
        );
        queue_address_candidates(&maintenance, 10_001, until);
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
            service.address_book.select(&[], &[], now, |_| true),
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
        let book = crate::addrman::AddressBook::open(None, [1; 4], true);
        shared.address_book = Some(book.clone());
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 8333));
        book.queued(address);
        let mut active = HashMap::from([(
            address,
            ActiveOutbound {
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
}
