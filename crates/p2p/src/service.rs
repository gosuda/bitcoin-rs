//! Runtime owner for the Bitcoin P2P subsystem.
//!
//! P2pService owns the mutable network control state and every worker that
//! acts on it. The node supplies chain read/query and inbound event sinks, but
//! does not construct listener, dial, DNS, or fixed-peer workers itself.

use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::p2p::Magic;
use crossbeam_channel::{Receiver, Sender, TrySendError};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use thiserror::Error;

use crate::connection::{PeerLifecycle, PeerSource};
use crate::listener::ListenerError;

const DEFAULT_OUTBOUND_TARGET: usize = 8;
const DEFAULT_OUTBOUND_ACTIVE_LIMIT: usize = 8;
const DEFAULT_OUTBOUND_QUEUE_LIMIT: usize = 8;
const DEFAULT_INBOUND_BLOCK_QUEUE_LIMIT: usize = 256;
const FAILED_ADDR_BACKOFF: Duration = Duration::from_mins(1);
const DNS_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);
const DNS_BOOTSTRAP_REFILL_INTERVAL: Duration = Duration::from_secs(1);
const DNS_BOOTSTRAP_FAST_REFILL_LIMIT: u8 = 2;

/// Configuration needed by the P2P runtime, after node configuration has
/// resolved the consensus network and message-start bytes.
#[derive(Clone, Debug)]
pub struct P2pServiceConfig {
    /// Addresses on which inbound P2P connections are accepted.
    pub listen_addrs: Vec<SocketAddr>,
    /// Network message-start bytes.
    pub magic: Magic,
    /// Whether DNS seed maintenance is enabled.
    pub dns_seeds_enabled: bool,
    /// DNS seed host names. The service resolves them only in its worker.
    pub dns_seeds: Vec<String>,
    /// Port appended to DNS seed results.
    pub dns_port: u16,
    /// Fixed connect endpoints. Non-empty disables DNS maintenance.
    pub fixed_peers: Vec<String>,
    /// Maximum number of active outbound attempts.
    pub outbound_active_limit: usize,
    /// Desired number of live outbound peers in DNS mode.
    pub outbound_peer_target: usize,
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
            dns_seeds_enabled: false,
            dns_seeds: Vec::new(),
            dns_port: 0,
            fixed_peers: Vec::new(),
            outbound_active_limit: DEFAULT_OUTBOUND_ACTIVE_LIMIT,
            outbound_peer_target: DEFAULT_OUTBOUND_TARGET,
            outbound_queue_limit: DEFAULT_OUTBOUND_QUEUE_LIMIT,
            inbound_block_queue_limit: DEFAULT_INBOUND_BLOCK_QUEUE_LIMIT,
        }
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

struct Workers {
    listeners: Vec<JoinHandle<Result<(), ListenerError>>>,
    outbound: Option<JoinHandle<()>>,
    bootstrap: Option<JoinHandle<()>>,
}

/// The sole runtime owner of P2P control state and workers.
pub struct P2pService {
    config: P2pServiceConfig,
    shutdown: Arc<AtomicBool>,
    worker_shutdown: Arc<AtomicBool>,
    network_active: Arc<AtomicBool>,
    lifecycle: Arc<PeerLifecycle>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    added_nodes: Arc<RwLock<Vec<SocketAddr>>>,
    outbound_tx: Sender<SocketAddr>,
    outbound_rx: Arc<Mutex<Receiver<SocketAddr>>>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_headers_rx: Arc<Mutex<Receiver<crate::InboundHeaders>>>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    inbound_blocks_rx: Arc<Mutex<Receiver<crate::InboundBlock>>>,
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
    pub fn new(config: P2pServiceConfig, shutdown: Arc<AtomicBool>) -> Self {
        let (outbound_tx, outbound_rx) = crossbeam_channel::bounded(config.outbound_queue_limit);
        let (inbound_headers_tx, inbound_headers_rx) = crossbeam_channel::unbounded();
        let (inbound_blocks_tx, inbound_blocks_rx) =
            crossbeam_channel::bounded(config.inbound_block_queue_limit);
        Self {
            config,
            shutdown,
            worker_shutdown: Arc::new(AtomicBool::new(false)),
            network_active: Arc::new(AtomicBool::new(true)),
            lifecycle: Arc::new(PeerLifecycle::new()),
            session_cancel: Mutex::new(Arc::new(AtomicBool::new(false))),
            banned: Arc::new(RwLock::new(Vec::new())),
            added_nodes: Arc::new(RwLock::new(Vec::new())),
            outbound_tx,
            outbound_rx: Arc::new(Mutex::new(outbound_rx)),
            inbound_headers_tx,
            inbound_headers_rx: Arc::new(Mutex::new(inbound_headers_rx)),
            inbound_blocks_tx,
            inbound_blocks_rx: Arc::new(Mutex::new(inbound_blocks_rx)),
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
        let chain_query = chain_query.cloned();
        let sync_wake_tx = sync_wake_tx.cloned();
        let peer_ready = peer_ready.clone();
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

        let mut listeners = Vec::with_capacity(bound_listeners.len());
        for (listener_addr, listener) in bound_listeners {
            let shutdown = Arc::clone(&self.worker_shutdown);
            let network_active = Arc::clone(&self.network_active);
            let peer_table = self.lifecycle.table();
            let banned = Arc::clone(&self.banned);
            let headers_tx = self.inbound_headers_tx.clone();
            let blocks_tx = self.inbound_blocks_tx.clone();
            let chain_query = chain_query.clone();
            let sync_wake_tx = sync_wake_tx.clone();
            let session_cancel = Arc::clone(&session_cancel);
            let peer_ready = Arc::clone(&peer_ready);
            let extras = extras.clone();
            let magic = self.config.magic;
            let handle = match thread::Builder::new()
                .name(format!("bitcoin-rs-p2p-{listener_addr}"))
                .spawn(move || {
                    crate::listener::serve_bound_with_session_cancel(
                        listener_addr,
                        listener,
                        shutdown,
                        network_active,
                        magic,
                        peer_table,
                        headers_tx,
                        blocks_tx,
                        banned,
                        chain_query,
                        sync_wake_tx,
                        session_cancel,
                        peer_ready,
                        extras,
                    )
                }) {
                Ok(handle) => handle,
                Err(error) => {
                    self.rollback_startup(listeners, None);
                    return Err(error.into());
                }
            };
            listeners.push(handle);
        }

        let outbound = match self.spawn_outbound_worker(
            chain_query,
            sync_wake_tx,
            Arc::clone(&session_cancel),
            Arc::clone(&peer_ready),
            extras,
        ) {
            Ok(handle) => handle,
            Err(error) => {
                self.rollback_startup(listeners, None);
                return Err(error.into());
            }
        };
        let bootstrap = match self.spawn_bootstrap_worker() {
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
        self.lifecycle.cancel_all();
        for handle in listeners {
            let _ = handle.join();
        }
        if let Some(handle) = outbound {
            let _ = handle.join();
        }
    }

    fn spawn_outbound_worker(
        &self,
        chain_query: Option<Arc<dyn crate::ChainQuery + 'static>>,
        sync_wake_tx: Option<Sender<()>>,
        session_cancel: Arc<AtomicBool>,
        peer_ready: Arc<dyn Fn(crate::PeerSource) + Send + Sync>,
        extras: crate::listener::ListenerExtras,
    ) -> Result<JoinHandle<()>, io::Error> {
        let outbound_rx = Arc::clone(&self.outbound_rx);
        let lifecycle = Arc::clone(&self.lifecycle);
        let banned = Arc::clone(&self.banned);
        let headers_tx = self.inbound_headers_tx.clone();
        let blocks_tx = self.inbound_blocks_tx.clone();
        let network_active = Arc::clone(&self.network_active);
        let shutdown = Arc::clone(&self.worker_shutdown);
        let magic = self.config.magic;
        let active_limit = self.config.outbound_active_limit;
        thread::Builder::new()
            .name("bitcoin-rs-p2p-outbound-drain".to_owned())
            .spawn(move || {
                let mut active = HashSet::new();
                let mut handles = Vec::new();
                while !shutdown.load(Ordering::Acquire) && !session_cancel.load(Ordering::Acquire) {
                    reap_finished_outbound_connections(&mut active, &mut handles);
                    if !network_active.load(Ordering::Acquire) || active.len() >= active_limit {
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    let received = outbound_rx.lock().recv_timeout(Duration::from_secs(1));
                    let Ok(addr) = received else {
                        if matches!(
                            received,
                            Err(crossbeam_channel::RecvTimeoutError::Disconnected)
                        ) {
                            break;
                        }
                        continue;
                    };
                    if active.contains(&addr) || lifecycle.contains(addr) {
                        tracing::debug!(
                            addr = %addr,
                            "p2p outbound request skipped: already active"
                        );
                        continue;
                    }
                    let handle = crate::listener::spawn_outbound_connection_with_session_cancel(
                        addr,
                        magic,
                        lifecycle.table(),
                        headers_tx.clone(),
                        blocks_tx.clone(),
                        Arc::clone(&banned),
                        Arc::clone(&network_active),
                        chain_query.clone(),
                        sync_wake_tx.clone(),
                        Arc::clone(&session_cancel),
                        Arc::clone(&peer_ready),
                        extras.clone(),
                    );
                    active.insert(addr);
                    handles.push((addr, handle));
                }
                for (_, handle) in handles {
                    let _ = handle.join();
                }
            })
    }

    fn spawn_bootstrap_worker(&self) -> Result<Option<JoinHandle<()>>, io::Error> {
        if !self.config.fixed_peers.is_empty() {
            let shutdown = Arc::clone(&self.worker_shutdown);
            let network_active = Arc::clone(&self.network_active);
            let lifecycle = Arc::clone(&self.lifecycle);
            let outbound_tx = self.outbound_tx.clone();
            let endpoints = self.config.fixed_peers.clone();
            return thread::Builder::new()
                .name("bitcoin-rs-fixed-peer-bootstrap".to_owned())
                .spawn(move || {
                    run_fixed_peer_bootstrap(
                        shutdown,
                        network_active,
                        lifecycle,
                        outbound_tx,
                        endpoints,
                    );
                })
                .map(Some);
        }
        if !self.config.dns_seeds_enabled || self.config.dns_seeds.is_empty() {
            tracing::debug!("p2p peer bootstrap disabled");
            return Ok(None);
        }
        let shutdown = Arc::clone(&self.worker_shutdown);
        let network_active = Arc::clone(&self.network_active);
        let lifecycle = Arc::clone(&self.lifecycle);
        let outbound_tx = self.outbound_tx.clone();
        let port = self.config.dns_port;
        let seeds = self.config.dns_seeds.clone();
        let target = self.config.outbound_peer_target;
        thread::Builder::new()
            .name("bitcoin-rs-dns-maintenance".to_owned())
            .spawn(move || {
                run_dns_peer_maintenance(
                    shutdown,
                    network_active,
                    lifecycle,
                    outbound_tx,
                    port,
                    seeds,
                    target,
                );
            })
            .map(Some)
    }

    /// Stops P2P workers and asks all current connection owners to tear down.
    pub fn shutdown(&self) {
        self.session_cancel.lock().store(true, Ordering::Release);
        self.shutdown.store(true, Ordering::Release);
        self.worker_shutdown.store(true, Ordering::Release);
        self.network_active.store(false, Ordering::Release);
        self.lifecycle.cancel_all();
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
        Ok(())
    }

    /// Joins every worker owned by this service. Calling it more than once is
    /// harmless.
    pub fn join(&self) -> Result<(), P2pJoinError> {
        let core = self.join_core_workers();
        let bootstrap = self.join_bootstrap_worker();
        core.and(bootstrap)
    }

    /// Returns the shared connection lifecycle view used by sync and RPC reads.
    #[must_use]
    pub fn lifecycle(&self) -> Arc<PeerLifecycle> {
        Arc::clone(&self.lifecycle)
    }

    /// Returns the single session table owned by this service.
    #[must_use]
    pub fn table(&self) -> Arc<crate::PeerTable> {
        self.lifecycle.table()
    }

    /// Returns whether P2P network activity is enabled.
    #[must_use]
    pub fn network_active(&self) -> bool {
        self.network_active.load(Ordering::Acquire)
    }

    /// Enables or disables network activity. Disabling cancels current peers;
    /// their owners remove the leases during teardown.
    pub fn set_network_active(&self, active: bool) {
        apply_network_active(&self.network_active, &self.lifecycle.table(), active);
    }

    /// Returns the shared admission switch for compatibility with node
    /// orchestration code that passes the switch into worker constructors.
    #[must_use]
    pub fn network_active_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.network_active)
    }

    /// Returns a snapshot of manual bans.
    #[must_use]
    pub fn banned(&self) -> Vec<crate::BannedSubnet> {
        self.banned.read().clone()
    }

    /// Returns the service-owned manual ban list handle.
    #[must_use]
    pub fn banned_handle(&self) -> Arc<RwLock<Vec<crate::BannedSubnet>>> {
        Arc::clone(&self.banned)
    }

    /// Returns a sender for RPC addnode requests.
    #[must_use]
    pub fn outbound_sender(&self) -> Sender<SocketAddr> {
        self.outbound_tx.clone()
    }

    /// Returns the service-owned outbound request receiver.
    #[must_use]
    pub fn outbound_receiver(&self) -> Arc<Mutex<Receiver<SocketAddr>>> {
        Arc::clone(&self.outbound_rx)
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

    /// Returns configured addnode add addresses.
    #[must_use]
    pub fn added_nodes(&self) -> Vec<SocketAddr> {
        self.added_nodes.read().clone()
    }

    /// Returns the service-owned persistent addnode view.
    #[must_use]
    pub fn added_nodes_handle(&self) -> Arc<RwLock<Vec<SocketAddr>>> {
        Arc::clone(&self.added_nodes)
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
        match self.outbound_tx.try_send(addr) {
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

    /// Sends a message only to the connection identified by source.
    ///
    /// The message is returned when the source is stale or its writer has
    /// gone away, allowing callers to keep ownership of retry decisions.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, source: PeerSource, message: crate::Message) -> Result<(), crate::Message> {
        self.lifecycle.send(source, message)
    }

    /// Disconnects only the connection identified by source.
    pub fn disconnect(&self, source: PeerSource) -> bool {
        self.lifecycle.disconnect_source(source)
    }

    /// Returns a cloned inbound headers receiver for the node sync coordinator.
    #[must_use]
    pub fn inbound_headers_receiver(&self) -> Arc<Mutex<Receiver<crate::InboundHeaders>>> {
        Arc::clone(&self.inbound_headers_rx)
    }

    /// Returns a sender for inbound header notifications.
    #[must_use]
    pub fn inbound_headers_sender(&self) -> Sender<crate::InboundHeaders> {
        self.inbound_headers_tx.clone()
    }

    /// Returns a cloned inbound block receiver for the node sync coordinator.
    #[must_use]
    pub fn inbound_blocks_receiver(&self) -> Arc<Mutex<Receiver<crate::InboundBlock>>> {
        Arc::clone(&self.inbound_blocks_rx)
    }

    /// Returns a sender for inbound block notifications.
    #[must_use]
    pub fn inbound_blocks_sender(&self) -> Sender<crate::InboundBlock> {
        self.inbound_blocks_tx.clone()
    }
}

/// Applies the network-activity transition used by [`P2pService`] and RPC.
///
/// Disabling cancels current leases; connection owners remove their own
/// sessions during teardown.
pub fn apply_network_active(flag: &AtomicBool, table: &crate::PeerTable, active: bool) {
    flag.store(active, Ordering::Release);
    if !active {
        table.cancel_all();
    }
}

fn reap_finished_outbound_connections(
    active: &mut HashSet<SocketAddr>,
    handles: &mut Vec<(SocketAddr, JoinHandle<Result<(), crate::PeerError>>)>,
) {
    let mut index = 0;
    while index < handles.len() {
        if !handles[index].1.is_finished() {
            index += 1;
            continue;
        }
        let (addr, handle) = handles.swap_remove(index);
        active.remove(&addr);
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

#[allow(clippy::needless_pass_by_value)]
fn run_fixed_peer_bootstrap(
    shutdown: Arc<AtomicBool>,
    network_active: Arc<AtomicBool>,
    lifecycle: Arc<PeerLifecycle>,
    outbound_tx: Sender<SocketAddr>,
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
                if lifecycle.contains(addr) || !network_active.load(Ordering::Acquire) {
                    continue;
                }
                if outbound_tx.try_send(addr).is_err() {
                    break 'endpoints;
                }
            }
        }
        if wait_for_shutdown(&shutdown, Duration::from_secs(2)) {
            break;
        }
    }
}

fn live_outbound_count(lifecycle: &PeerLifecycle) -> usize {
    lifecycle
        .live_leases()
        .iter()
        .filter(|(_, lease)| !lease.is_inbound())
        .count()
}

#[allow(clippy::needless_pass_by_value)]
fn run_dns_peer_maintenance(
    shutdown: Arc<AtomicBool>,
    network_active: Arc<AtomicBool>,
    lifecycle: Arc<PeerLifecycle>,
    outbound_tx: Sender<SocketAddr>,
    port: u16,
    seeds: Vec<String>,
    target: usize,
) {
    let resolver = crate::SystemDnsResolver::new(port);
    let seeds: Vec<&str> = seeds.iter().map(String::as_str).collect();
    let mut failed_backoff = HashMap::new();
    let mut cursor = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            usize::try_from(duration.as_nanos()).unwrap_or(0)
        });
    let mut fast_refills = 0_u8;
    let mut queued = drain_dns_peer_deficit(
        &resolver,
        &seeds,
        &network_active,
        &lifecycle,
        &outbound_tx,
        &mut failed_backoff,
        cursor,
        target,
    );
    cursor = cursor.wrapping_add(1);
    tracing::info!(queued, "dns peer bootstrap queued initial addresses");

    while !shutdown.load(Ordering::Acquire) {
        let live = live_outbound_count(&lifecycle);
        let delay = if live == 0 && queued > 0 && fast_refills < DNS_BOOTSTRAP_FAST_REFILL_LIMIT {
            fast_refills = fast_refills.saturating_add(1);
            DNS_BOOTSTRAP_REFILL_INTERVAL
        } else {
            if live > 0 {
                fast_refills = 0;
            }
            DNS_MAINTENANCE_INTERVAL
        };
        if !network_active.load(Ordering::Acquire) {
            if wait_for_shutdown(&shutdown, Duration::from_millis(100)) {
                break;
            }
            continue;
        }
        if wait_for_shutdown(&shutdown, delay) {
            break;
        }
        let live = live_outbound_count(&lifecycle);
        if live >= target {
            continue;
        }
        let needed = target - live;
        queued = drain_dns_peer_deficit(
            &resolver,
            &seeds,
            &network_active,
            &lifecycle,
            &outbound_tx,
            &mut failed_backoff,
            cursor,
            needed,
        );
        cursor = cursor.wrapping_add(1);
        if queued > 0 {
            tracing::info!(
                live,
                queued,
                needed,
                "dns peer maintenance refilled outbound queue"
            );
        }
    }
}

fn drain_dns_peer_deficit<R>(
    resolver: &R,
    seeds: &[&str],
    network_active: &AtomicBool,
    lifecycle: &PeerLifecycle,
    outbound_tx: &Sender<SocketAddr>,
    recently_queued: &mut HashMap<SocketAddr, Instant>,
    cursor: usize,
    needed: usize,
) -> usize
where
    R: crate::DnsResolver + ?Sized,
{
    if !network_active.load(Ordering::Acquire) || needed == 0 || seeds.is_empty() {
        return 0;
    }
    let now = Instant::now();
    recently_queued.retain(|_, queued_at| now.duration_since(*queued_at) < FAILED_ADDR_BACKOFF);
    let mut queued = 0;
    let mut seen = HashSet::new();
    'seeds: for offset in 0..seeds.len() {
        if !network_active.load(Ordering::Acquire) {
            break;
        }
        let seed = seeds[(cursor.wrapping_add(offset)) % seeds.len()];
        let Ok(mut addresses) = resolver.resolve(seed) else {
            tracing::warn!(seed, "dns seed resolution failed");
            continue;
        };
        if !addresses.is_empty() {
            let offset = cursor % addresses.len();
            addresses.rotate_left(offset);
        }
        for addr in addresses {
            if !seen.insert(addr) || lifecycle.contains(addr) || recently_queued.contains_key(&addr)
            {
                continue;
            }
            match outbound_tx.try_send(addr) {
                Ok(()) => {
                    recently_queued.insert(addr, now);
                    queued += 1;
                    if queued >= needed {
                        break 'seeds;
                    }
                }
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => break 'seeds,
            }
        }
    }
    queued
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
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
}
