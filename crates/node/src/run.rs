//! Top-level orchestration: wire subsystems, spin the event loop, drain.

use crate as bitcoin_rs_node;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::{TrySendError, bounded};

use crate::config::{NodeConfig, RuntimeInputs};
use crate::event_loop::EventLoop;
use crate::state::NodeState;
use crate::{logging, shutdown};

// Test-only observation seam: records that `run` reached the
// bootstrap-worker join. Lets a regression that propagates a checkpoint
// error with `?` *before* joining the worker be caught by a test that
// actually spawns a bootstrap worker. Compiled out of non-test builds, so
// it adds no production API surface.
#[cfg(test)]
std::thread_local! {
    static BOOTSTRAP_DRAIN_REACHED: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn mark_bootstrap_drain_reached() {
    BOOTSTRAP_DRAIN_REACHED.with(|slot| slot.set(true));
}

#[cfg(not(test))]
const fn mark_bootstrap_drain_reached() {}

/// Test-only: returns and clears whether [`run`] reached the bootstrap-worker
/// join on the current thread since the last call.
#[cfg(test)]
fn bootstrap_drain_was_reached() -> bool {
    BOOTSTRAP_DRAIN_REACHED.with(std::cell::Cell::take)
}

pub(crate) const DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const RPC_MAX_CONNECTIONS: usize = 128;
const RPC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const P2P_OUTBOUND_ACTIVE_LIMIT: usize = crate::state::P2P_OUTBOUND_QUEUE_LIMIT;
const FAILED_ADDR_BACKOFF_SECS: u64 = 60;
/// How often the DNS peer maintenance loop wakes to check the live peer count.
const DNS_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);
/// Retry a connectionless bootstrap before normal DNS maintenance.
const DNS_BOOTSTRAP_REFILL_INTERVAL: Duration = Duration::from_secs(1);
/// Maximum fast refills before returning to the normal maintenance cadence.
const DNS_BOOTSTRAP_FAST_REFILL_LIMIT: u8 = 2;
/// Seconds one daemon signal-wait poll covers before re-checking. The
/// helper sleeps in 100 ms slices, so this only bounds the re-check count.
const DAEMON_SIGNAL_WAIT_SECS: u64 = 3_600;

type PeerTable = Arc<bitcoin_rs_p2p::PeerTable>;
type BannedSubnets = Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>;
type P2pChainQuery = Arc<dyn bitcoin_rs_p2p::ChainQuery>;
type OutboundConnectionHandle =
    std::thread::JoinHandle<core::result::Result<(), bitcoin_rs_p2p::PeerError>>;

#[derive(Clone)]
struct RpcChainControl {
    handles: crate::apply::ApplyHandles,
}

impl bitcoin_rs_rpc::context::ChainControl for RpcChainControl {
    fn invalidate_block(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> core::result::Result<(), bitcoin_rs_rpc::context::ChainControlError> {
        crate::reorg::invalidate_block(&self.handles, hash).map_err(|error| match error {
            crate::reorg::ReorgError::UnknownBlock(_) => {
                bitcoin_rs_rpc::context::ChainControlError::UnknownBlock
            }
            crate::reorg::ReorgError::CannotInvalidateGenesis => {
                bitcoin_rs_rpc::context::ChainControlError::Genesis
            }
            other => bitcoin_rs_rpc::context::ChainControlError::Failed(other.to_string()),
        })
    }
}

/// Bounds rapid DNS retries while the initial outbound pool is still empty.
#[derive(Default)]
struct DnsBootstrapRefill {
    fast_refills: u8,
}

impl DnsBootstrapRefill {
    fn next_delay(&mut self, live: usize, queued: usize) -> Duration {
        if live > 0 {
            self.fast_refills = 0;
            return DNS_MAINTENANCE_INTERVAL;
        }
        if queued == 0 || self.fast_refills >= DNS_BOOTSTRAP_FAST_REFILL_LIMIT {
            return DNS_MAINTENANCE_INTERVAL;
        }
        self.fast_refills = self.fast_refills.saturating_add(1);
        DNS_BOOTSTRAP_REFILL_INTERVAL
    }
}

fn wait_for_shutdown(shutdown: &AtomicBool, delay: Duration) -> bool {
    let deadline = std::time::Instant::now() + delay;
    while !shutdown.load(Ordering::Acquire) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(100)));
    }
    true
}

fn build_rpc_auth(node_auth: &crate::Auth) -> Result<bitcoin_rs_rpc::Auth> {
    match node_auth {
        crate::Auth::Basic { user, password } => {
            Ok(bitcoin_rs_rpc::Auth::basic(user.clone(), password))
        }
        crate::Auth::Cookie { path } => Ok(bitcoin_rs_rpc::Auth::cookie(path)?),
    }
}

/// Spawns one listener thread per configured bind address, registering each
/// join handle in `services` the moment its spawn succeeds so a later
/// failure rolls the whole graph back through the shared teardown instead
/// of leaving detached listener threads outliving a failed startup.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn spawn_p2p_listeners(
    config: &bitcoin_rs_node::NodeConfig,
    shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    network_active: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    peer_table: &PeerTable,
    banned: BannedSubnets,
    inbound_headers_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::InboundHeaders>,
    inbound_blocks_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>,
    sync_wake_tx: crossbeam_channel::Sender<()>,
    chain_query: P2pChainQuery,
    services: &mut NodeServices,
) -> anyhow::Result<()> {
    let magic = bitcoin::p2p::Magic::from_bytes(config.p2p_magic);
    for addr in &config.p2p_listen {
        let listener_addr = *addr;
        let listener_shutdown = std::sync::Arc::clone(shutdown);
        let listener_network_active = std::sync::Arc::clone(network_active);
        let listener_peer_table = Arc::clone(peer_table);
        let listener_banned = Arc::clone(&banned);
        let listener_inbound_headers_tx = inbound_headers_tx.clone();
        let listener_inbound_blocks_tx = inbound_blocks_tx.clone();
        let listener_sync_wake_tx = sync_wake_tx.clone();
        let listener_chain_query = Arc::clone(&chain_query);
        let handle = std::thread::Builder::new()
            .name(format!("bitcoin-rs-p2p-{listener_addr}"))
            .spawn(move || {
                bitcoin_rs_p2p::listener::serve_with_shutdown_with_chain_and_sync_wake(
                    listener_addr,
                    listener_shutdown,
                    listener_network_active,
                    magic,
                    listener_peer_table,
                    listener_inbound_headers_tx,
                    listener_inbound_blocks_tx,
                    listener_banned,
                    Some(listener_chain_query),
                    Some(listener_sync_wake_tx),
                )
            })
            .map_err(|error| -> anyhow::Error { error.into() })?;
        tracing::info!(addr = %listener_addr, "p2p listener bound");
        // Owned by the graph from this moment: a later failure rolls back
        // through the shared teardown, never through detached handles.
        services.p2p_threads.push(handle);
    }
    Ok(())
}

fn reap_finished_outbound_connections(
    active: &mut hashbrown::HashSet<SocketAddr>,
    handles: &mut Vec<(SocketAddr, OutboundConnectionHandle)>,
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

fn outbound_addr_available(
    addr: SocketAddr,
    active: &hashbrown::HashSet<SocketAddr>,
    peer_table: &PeerTable,
) -> bool {
    if active.contains(&addr) {
        return false;
    }
    !peer_table.is_connected(addr)
}

#[allow(clippy::needless_pass_by_value)]
fn spawn_p2p_outbound_drain(
    state: &NodeState,
    shutdown: &Arc<AtomicBool>,
    sync_wake_tx: crossbeam_channel::Sender<()>,
    chain_query: P2pChainQuery,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    let outbound_rx = state.p2p_outbound_receiver();
    let magic = bitcoin::p2p::Magic::from_bytes(state.config().p2p_magic);
    let outbound_peer_table = state.peer_table();
    let outbound_banned = state.banned_subnets();
    let outbound_headers_tx = state.inbound_headers_sender();
    let outbound_blocks_tx = state.inbound_blocks_sender();
    let outbound_sync_wake_tx = sync_wake_tx;
    let outbound_shutdown = Arc::clone(shutdown);
    let outbound_chain_query = Arc::clone(&chain_query);
    let outbound_network_active = state.network_active();
    Ok(std::thread::Builder::new()
        .name("bitcoin-rs-p2p-outbound-drain".to_owned())
        .spawn(move || {
            let mut active = hashbrown::HashSet::new();
            let mut handles = Vec::new();
            while !outbound_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                reap_finished_outbound_connections(&mut active, &mut handles);
                if !outbound_network_active.load(std::sync::atomic::Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                if active.len() >= P2P_OUTBOUND_ACTIVE_LIMIT {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }

                let recv = {
                    let guard = outbound_rx.lock();
                    guard.recv_timeout(Duration::from_secs(1))
                };
                match recv {
                    Ok(addr) => {
                        if !outbound_addr_available(
                            addr,
                            &active,
                            &outbound_peer_table,
                        ) {
                            continue;
                        }
                        let handle = bitcoin_rs_p2p::listener::spawn_outbound_connection_with_chain_and_sync_wake(
                            addr,
                            magic,
                            Arc::clone(&outbound_peer_table),
                            outbound_headers_tx.clone(),
                            outbound_blocks_tx.clone(),
                            Arc::clone(&outbound_banned),
                            Arc::clone(&outbound_network_active),
                            Some(Arc::clone(&outbound_chain_query)),
                            Some(outbound_sync_wake_tx.clone()),
                        );
                        active.insert(addr);
                        handles.push((addr, handle));
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })?)
}

/// Spawns a long-lived thread that continuously maintains outbound peer count under DNS mode.
///
/// The thread wakes every [`DNS_MAINTENANCE_INTERVAL`] and, when the number of live outbound
/// peers is below [`crate::sync::MIN_PEERS_FOR_FANOUT`], resolves DNS seeds and queues the deficit
/// count of addresses into `outbound_tx`.  Addresses that recently failed are suppressed for
/// [`FAILED_ADDR_BACKOFF_SECS`] seconds via an in-memory backoff map.
///
/// Returns `Ok(None)` when DNS bootstrap is disabled or the network is regtest (both cases
/// require no background refill).
fn spawn_dns_peer_maintenance(
    config: &NodeConfig,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    network_active: Arc<AtomicBool>,
    peer_table: PeerTable,
    outbound_tx: crossbeam_channel::Sender<SocketAddr>,
) -> anyhow::Result<Option<std::thread::JoinHandle<()>>> {
    if !config.dns_seeds_enabled {
        tracing::debug!("dns peer bootstrap disabled");
        return Ok(None);
    }
    if matches!(config.network, bitcoin_rs_primitives::Network::Regtest) {
        tracing::debug!("dns peer bootstrap skipped for regtest");
        return Ok(None);
    }

    // Extract all config-derived data before spawning so the closure is 'static.
    let p2p_port = config.network.default_p2p_port();
    let seeds: Vec<&'static str> = config.network.dns_seeds().to_vec();

    Ok(Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-dns-maintenance".to_owned())
            .spawn(move || {
                let resolver = bitcoin_rs_p2p::SystemDnsResolver::new(p2p_port);
                let mut failed_backoff: hashbrown::HashMap<SocketAddr, std::time::Instant> =
                    hashbrown::HashMap::new();
                let mut selection_cursor = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| {
                        usize::try_from(duration.as_nanos()).unwrap_or(0)
                    });

                // Initial bootstrap: queue up to the fan-out peer threshold immediately.
                let queued = drain_dns_peer_deficit(
                    &resolver,
                    seeds.as_slice(),
                    &network_active,
                    &peer_table,
                    &outbound_tx,
                    &mut failed_backoff,
                    selection_cursor,
                    crate::sync::MIN_PEERS_FOR_FANOUT,
                );
                selection_cursor = selection_cursor.wrapping_add(1);
                tracing::info!(queued, "dns peer bootstrap queued initial addresses");
                let mut bootstrap_refill = DnsBootstrapRefill::default();
                let mut maintenance_delay = bootstrap_refill.next_delay(0, queued);

                while !shutdown.load(std::sync::atomic::Ordering::Acquire) {
                    if !network_active.load(std::sync::atomic::Ordering::Acquire) {
                        maintenance_delay = Duration::ZERO;
                        if wait_for_shutdown(&shutdown, Duration::from_millis(100)) {
                            break;
                        }
                        continue;
                    }
                    if wait_for_shutdown(&shutdown, maintenance_delay) {
                        break;
                    }
                    if !network_active.load(std::sync::atomic::Ordering::Acquire) {
                        maintenance_delay = Duration::ZERO;
                        continue;
                    }

                    let live = peer_table.len();
                    if live >= crate::sync::MIN_PEERS_FOR_FANOUT {
                        maintenance_delay = bootstrap_refill.next_delay(live, 0);
                        continue;
                    }
                    let deficit = crate::sync::MIN_PEERS_FOR_FANOUT - live;
                    let queued = drain_dns_peer_deficit(
                        &resolver,
                        seeds.as_slice(),
                        &network_active,
                        &peer_table,
                        &outbound_tx,
                        &mut failed_backoff,
                        selection_cursor,
                        deficit,
                    );
                    selection_cursor = selection_cursor.wrapping_add(1);
                    maintenance_delay = bootstrap_refill.next_delay(live, queued);
                    if queued > 0 {
                        tracing::info!(
                            live,
                            queued,
                            deficit,
                            fast_refills = bootstrap_refill.fast_refills,
                            "dns peer maintenance refilled outbound queue"
                        );
                    }
                }
            })?,
    ))
}

/// Draws up to `needed` dial candidates from `seeds` (resolving via `resolver`) and
/// `try_send`s them into `outbound_tx`.
///
/// Dedup is applied against:
/// 1. Addresses already present in `peer_table`.
/// 2. Addresses in `recently_queued` whose cooldown window has not yet expired.
///
/// Successfully queued addresses are inserted into `recently_queued` with the current
/// timestamp so they are not re-queued on the next maintenance tick before the dial
/// attempt completes.
///
/// `selection_cursor` rotates both seed order and each resolved address list so a
/// fresh process does not repeatedly dial the same cached DNS prefix.
///
/// Addresses that cannot be sent because the channel is full are silently skipped — the
/// caller will retry on the next maintenance tick.  The channel being disconnected is
/// treated as a transient error and logged; the loop stops.
///
/// Returns the number of addresses successfully queued.
fn drain_dns_peer_deficit<R>(
    resolver: &R,
    seeds: &[&str],
    network_active: &AtomicBool,
    peer_table: &PeerTable,
    outbound_tx: &crossbeam_channel::Sender<SocketAddr>,
    recently_queued: &mut hashbrown::HashMap<SocketAddr, std::time::Instant>,
    selection_cursor: usize,
    needed: usize,
) -> usize
where
    R: bitcoin_rs_p2p::DnsResolver + ?Sized,
{
    if !network_active.load(std::sync::atomic::Ordering::Acquire) || needed == 0 {
        return 0;
    }

    let now = std::time::Instant::now();
    let cooldown = std::time::Duration::from_secs(FAILED_ADDR_BACKOFF_SECS);

    // Evict expired cooldown entries to keep the map bounded.
    recently_queued.retain(|_, queued_at| now.duration_since(*queued_at) < cooldown);

    let mut queued = 0usize;
    let mut seen: hashbrown::HashSet<SocketAddr> = hashbrown::HashSet::new();

    'outer: for seed_offset in 0..seeds.len() {
        if !network_active.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        let seed = seeds[selection_cursor.wrapping_add(seed_offset) % seeds.len()];
        let mut addresses = match resolver.resolve(seed) {
            Ok(addresses) => addresses,
            Err(error) => {
                tracing::warn!(seed = %seed, %error, "dns seed resolution failed");
                continue;
            }
        };
        if !addresses.is_empty() {
            let address_offset = selection_cursor % addresses.len();
            addresses.rotate_left(address_offset);
        }
        for addr in addresses {
            if !network_active.load(std::sync::atomic::Ordering::Acquire) {
                break 'outer;
            }
            if !seen.insert(addr) {
                continue;
            }
            if peer_table.is_connected(addr) {
                continue;
            }
            if recently_queued.contains_key(&addr) {
                continue;
            }
            match outbound_tx.try_send(addr) {
                Ok(()) => {
                    recently_queued.insert(addr, now);
                    queued += 1;
                    if queued >= needed {
                        break 'outer;
                    }
                }
                Err(TrySendError::Full(_)) => {
                    tracing::debug!("dns maintenance stopped: outbound queue full");
                    break 'outer;
                }
                Err(TrySendError::Disconnected(_)) => {
                    tracing::warn!("dns maintenance: outbound channel disconnected");
                    break 'outer;
                }
            }
        }
    }

    queued
}

/// Maintains outbound connections to the fixed peers from `--connect`.
///
/// When `connect` is configured, DNS bootstrap is disabled and the node dials
/// only these addresses, re-queueing any that are not currently connected so a
/// dropped link is re-established (Bitcoin Core `-connect` semantics).
fn spawn_fixed_peer_bootstrap(
    state: &NodeState,
    shutdown: &Arc<AtomicBool>,
) -> anyhow::Result<Option<std::thread::JoinHandle<()>>> {
    let connect = state.config().connect.clone();
    if connect.is_empty() {
        return Ok(None);
    }
    let outbound_tx = state.p2p_outbound_sender();
    let peer_table = state.peer_table();
    let bootstrap_shutdown = Arc::clone(shutdown);
    let network_active = state.network_active();
    Ok(Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-fixed-peer-bootstrap".to_owned())
            .spawn(move || {
                while !bootstrap_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    if !network_active.load(std::sync::atomic::Ordering::Acquire) {
                        if wait_for_shutdown(&bootstrap_shutdown, Duration::from_millis(100)) {
                            break;
                        }
                        continue;
                    }
                    'endpoints: for endpoint in &connect {
                        if !network_active.load(std::sync::atomic::Ordering::Acquire) {
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
                            if peer_table.is_connected(addr) {
                                continue;
                            }
                            if !network_active.load(std::sync::atomic::Ordering::Acquire) {
                                break 'endpoints;
                            }
                            if outbound_tx.try_send(addr).is_err() {
                                // Queue full or closed; retry on the next tick.
                                break 'endpoints;
                            }
                        }
                    }
                    if wait_for_shutdown(&bootstrap_shutdown, Duration::from_secs(2)) {
                        break;
                    }
                }
            })?,
    ))
}

/// How the one ordered teardown was reached.
///
/// The mode decides exactly one thing — whether the node may publish the
/// clean-shutdown chainstate checkpoint — and every other cleanup step is
/// identical in both modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TeardownMode {
    /// The node never finished starting (a later bootstrap step failed, or
    /// the partially built graph was dropped). No checkpoint: publishing a
    /// successful-run marker for a run being abandoned would let the next
    /// startup resume a state the node never confirmed.
    StartupAbort,
    /// The node ran and is being shut down deliberately. The checkpoint is
    /// published only after every service joined successfully; a join
    /// failure suppresses it, because a worker that died abnormally may
    /// have left state that a clean-run marker would mislabel.
    CleanShutdown,
}

/// Service graph spawned by [`start_node`] and stopped by exactly one
/// ordered teardown.
///
/// The daemon and the embedded [`crate::embed::Node`] share this graph, so
/// there is exactly one lifecycle implementation: this struct plus
/// [`NodeState`]. Every handle is an `Option` (or drained `Vec`) so the
/// teardown takes each by value exactly once — a second teardown call finds
/// an empty graph and is a no-op, which is what makes the
/// shutdown-then-Drop sequence and repeated lifecycles safe. The graph owns
/// the process-level signal handler from the moment it is installed: the
/// shared teardown closes and joins it, so no lifecycle leaks a signal
/// worker, and no joinable handle is ever dropped while joinable.
#[derive(Default)]
pub(crate) struct NodeServices {
    /// Event-loop thread; the teardown joins it unconditionally.
    event_loop: Option<std::thread::JoinHandle<anyhow::Result<()>>>,
    /// Producer side of the event loop's shutdown channel, retained when the
    /// node owns the channel (an injected test receiver leaves this `None`).
    /// Taken by the teardown so the producer end is dropped exactly once.
    event_loop_signal: Option<crossbeam_channel::Sender<()>>,
    /// Optional metrics scrape listener; its own `Drop` stops and joins it.
    metrics: Option<crate::metrics::MetricsServer>,
    /// JSON-RPC server thread.
    rpc_thread: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    /// P2P listener threads, one per configured bind address. Registered
    /// here the moment each spawn succeeds.
    p2p_threads: Vec<std::thread::JoinHandle<Result<(), bitcoin_rs_p2p::listener::ListenerError>>>,
    /// Outbound connection drain worker.
    outbound_worker: Option<std::thread::JoinHandle<()>>,
    /// DNS or fixed-peer bootstrap worker, absent in regtest-style configs.
    bootstrap_worker: Option<std::thread::JoinHandle<()>>,
    /// Periodic chainstate checkpoint worker; joined before the clean
    /// checkpoint publication so it does not race the final write.
    checkpoint_worker: Option<std::thread::JoinHandle<()>>,
    /// Process-level SIGINT/SIGTERM forwarding handler, owned by the graph
    /// so the shared teardown — never a leak — closes and joins it.
    signal_handler: Option<crate::signal::ShutdownHandler>,
    /// Prevents the owner’s explicit teardown from being repeated by `Drop`.
    teardown_started: bool,
}

impl NodeServices {
    /// The one ordered teardown behind explicit shutdown, `Drop`, and
    /// startup rollback.
    ///
    /// Order is fixed: raise the node shutdown flag → wake the event loop →
    /// join it → rpc join → p2p joins → metrics stop → outbound join →
    /// bounded subsystem drain → bootstrap join → signal-handler close and
    /// join → clean checkpoint. The first failure is remembered while every
    /// later cleanup stage still runs, except that a clean checkpoint is
    /// published only after every preceding stage succeeds. Taking each
    /// handle by value makes a second call a no-op by construction. The
    /// idempotence guard covers an explicit shutdown followed by `Drop`.
    pub(crate) fn teardown(
        &mut self,
        state: Option<&NodeState>,
        mode: TeardownMode,
    ) -> anyhow::Result<()> {
        if self.teardown_started {
            return Ok(());
        }
        self.teardown_started = true;
        // Test seam: counts one entry through the shared teardown per call;
        // a no-op marker in non-test builds.
        let _stage = shutdown::mark_shutdown_stage();
        // Request: every worker loop polls this flag; the event loop also
        // wakes immediately through its retained channel when it owns one.
        if let Some(state) = state {
            state.shutdown().store(true, Ordering::Release);
        }
        if let Some(tx) = self.event_loop_signal.take() {
            let _ = tx.send(());
        }

        let mut first_error: Option<anyhow::Error> = None;
        self.join_core_services(&mut first_error);

        if let Err(error) = shutdown::drain_and_shutdown(DRAIN_DEADLINE) {
            set_first_error(&mut first_error, error);
        }
        // Join every worker and signal owner before publishing the clean
        // checkpoint. Startup rollback has no clean state to record, and
        // any earlier cleanup failure suppresses checkpoint publication.
        self.join_bootstrap_and_signal_workers(&mut first_error);
        publish_clean_checkpoint_if_eligible(state, mode, &mut first_error);
        if let Some(error) = first_error {
            return Err(error);
        }
        tracing::info!("bitcoin-rs node exited cleanly");
        Ok(())
    }

    /// Joins the stages that run before the bounded subsystem drain: the
    /// event loop, the rpc listener, every p2p listener, the metrics
    /// listener, and the outbound drain worker. Every stage still runs when
    /// an earlier one fails; the first failure lands in `first_error`.
    fn join_core_services(&mut self, first_error: &mut Option<anyhow::Error>) {
        if let Some(handle) = self.event_loop.take() {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => set_first_error(first_error, error),
                Err(_) => {
                    set_first_error(first_error, anyhow::anyhow!("event loop thread panicked"));
                }
            }
        }
        if let Some(handle) = self.rpc_thread.take() {
            match handle.join() {
                Ok(Ok(())) => tracing::info!("rpc listener exited cleanly"),
                Ok(Err(error)) => {
                    tracing::warn!(%error, "rpc listener exited with i/o error");
                    set_first_error(first_error, anyhow::Error::new(error));
                }
                Err(_) => {
                    tracing::error!("rpc listener panicked");
                    set_first_error(first_error, anyhow::anyhow!("rpc listener thread panicked"));
                }
            }
        }
        for handle in self.p2p_threads.drain(..) {
            let thread_name = handle
                .thread()
                .name()
                .unwrap_or("bitcoin-rs-p2p")
                .to_owned();
            match handle.join() {
                Ok(Ok(())) => tracing::info!(thread = %thread_name, "p2p listener exited cleanly"),
                Ok(Err(error)) => {
                    tracing::warn!(thread = %thread_name, %error, "p2p listener exited with error");
                    set_first_error(first_error, anyhow::Error::new(error));
                }
                Err(_) => {
                    tracing::error!(thread = %thread_name, "p2p listener panicked");
                    set_first_error(
                        first_error,
                        anyhow::anyhow!("p2p listener {thread_name} panicked"),
                    );
                }
            }
        }
        // The metrics listener stops and joins in its own `Drop`.
        self.metrics.take();
        if let Some(handle) = self.outbound_worker.take() {
            if matches!(handle.join(), Ok(())) {
                tracing::info!("P2P outbound drain exited cleanly");
            } else {
                tracing::error!("P2P outbound drain panicked");
                set_first_error(first_error, anyhow::anyhow!("P2P outbound drain panicked"));
            }
        }
    }

    /// Joins the stages that must finish before any checkpoint is published:
    /// the p2p bootstrap worker and the process signal handler. The first
    /// failure lands in `first_error`.
    fn join_bootstrap_and_signal_workers(&mut self, first_error: &mut Option<anyhow::Error>) {
        if let Some(handle) = self.bootstrap_worker.take() {
            mark_bootstrap_drain_reached();
            let thread_name = handle
                .thread()
                .name()
                .unwrap_or("bitcoin-rs-p2p-bootstrap")
                .to_owned();
            if matches!(handle.join(), Ok(())) {
                tracing::info!(thread = %thread_name, "P2P bootstrap worker exited cleanly");
            } else {
                tracing::error!(thread = %thread_name, "P2P bootstrap worker panicked");
                set_first_error(
                    first_error,
                    anyhow::anyhow!("P2P bootstrap worker panicked"),
                );
            }
        }
        if let Some(handle) = self.checkpoint_worker.take() {
            if matches!(handle.join(), Ok(())) {
                tracing::info!("periodic checkpoint worker exited cleanly");
            } else {
                tracing::error!("periodic checkpoint worker panicked");
                set_first_error(
                    first_error,
                    anyhow::anyhow!("periodic checkpoint worker panicked"),
                );
            }
        }
        if let Some(mut handler) = self.signal_handler.take() {
            if let Err(error) = handler.close_and_join() {
                tracing::error!(%error, "signal forwarding thread did not shut down cleanly");
                set_first_error(first_error, error);
            }
        }
    }

    /// Deliberate shutdown of a completed run: the full ordered teardown in
    /// [`TeardownMode::CleanShutdown`].
    pub(crate) fn cleanup(&mut self, state: &NodeState) -> anyhow::Result<()> {
        self.teardown(Some(state), TeardownMode::CleanShutdown)
    }
}

/// Publishes the clean-shutdown chainstate checkpoint, but only for a
/// deliberate shutdown that reached this stage with node state and with no
/// preceding cleanup failure. Any other path logs the skip: startup rollback
/// has no clean state to record, and a worker that died abnormally may have
/// left state that a clean-run marker would mislabel.
fn publish_clean_checkpoint_if_eligible(
    state: Option<&NodeState>,
    mode: TeardownMode,
    first_error: &mut Option<anyhow::Error>,
) {
    if let (Some(state), TeardownMode::CleanShutdown, None) = (state, mode, first_error.as_ref()) {
        match state.write_clean_checkpoint() {
            Ok(crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip) => {
                tracing::info!("no applied tip; clean checkpoint publication skipped");
            }
            Ok(crate::checkpoint::CheckpointWrite::Published { generation }) => {
                tracing::info!(generation, "published clean chainstate checkpoint");
            }
            Err(error) => {
                tracing::error!(%error, "clean checkpoint publication failed");
                set_first_error(first_error, anyhow::Error::new(error));
            }
        }
    } else {
        tracing::info!("clean checkpoint publication skipped: the node did not shut down cleanly");
    }
}

/// Records `error` as the first failure unless one is already pending.
fn set_first_error(slot: &mut Option<anyhow::Error>, error: anyhow::Error) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

impl Drop for NodeServices {
    fn drop(&mut self) {
        // The node owner (daemon or embedder) normally runs the teardown
        // explicitly; this covers a graph dropped without shutdown. The
        // same ordered teardown runs in `StartupAbort` mode — no checkpoint
        // to publish — so even this path joins every service it can stop.
        if let Err(error) = self.teardown(None, TeardownMode::StartupAbort) {
            tracing::warn!(%error, "dropped node services; teardown reported an error");
        }
    }
}

/// Incremental startup guard for [`start_node`].
///
/// Every successfully created worker, socket owner, and channel end is
/// recorded in the guard's [`NodeServices`] as soon as it exists. On any
/// later startup error the guard's `Drop` runs the same shared ordered
/// teardown in [`TeardownMode::StartupAbort`] — raising the shutdown flag,
/// waking and joining every started service, closing the signal handler,
/// and never publishing a checkpoint — instead of returning the error with
/// detached workers. It disarms only once the complete service graph has
/// moved into a returned `NodeServices`.
struct StartupGuard {
    state: Option<NodeState>,
    services: NodeServices,
}

impl StartupGuard {
    /// Moves the fully assembled graph out, disarming the rollback drop.
    fn disarm(mut self) -> (NodeState, NodeServices) {
        let Some(state) = self.state.take() else {
            // `disarm` is the only path that takes the state, and it
            // consumes the guard, so a live guard always owns it here.
            panic!("completed startup owns state");
        };
        let services = core::mem::take(&mut self.services);
        // The moved-out graph owns the teardown from here. The placeholder
        // left behind owns nothing, so neither this guard's drop nor the
        // placeholder's own drop may run a second teardown pass.
        self.services.teardown_started = true;
        (state, services)
    }
}

impl Drop for StartupGuard {
    fn drop(&mut self) {
        // Roll back in one shared ordered teardown. Failures cannot be
        // returned from `Drop`; the first one is logged beside the startup
        // error that caused this.
        if let Err(error) = self
            .services
            .teardown(self.state.as_ref(), TeardownMode::StartupAbort)
        {
            tracing::warn!(%error, "startup rollback reported a cleanup failure");
        }
        self.state.take(); // NodeState's own Drop stops its index workers.
    }
}

/// Boots the node: validation, storage, crash recovery, and the service
/// graph. Shared by the daemon runner and [`crate::embed::Node::start`].
///
/// `install_signals` is the daemon's only fork in the road: an embedded
/// node must not take over process SIGINT/SIGTERM handling, so it starts
/// with the flag off and owns its shutdown through
/// [`crate::embed::Node::shutdown`] instead.
///
/// # Errors
///
/// Propagates configuration validation, storage open, crash recovery, and
/// service bind failures, in that order. A failure after any service spawned
/// rolls the graph back through [`StartupGuard`]: already-spawned workers are
/// stopped and joined before the error is returned, so no worker outlives a
/// failed startup and no joinable handle is dropped.
#[allow(clippy::too_many_lines)]
pub(crate) fn start_node(
    config: NodeConfig,
    runtime: RuntimeInputs,
    install_signals: bool,
) -> Result<(
    NodeState,
    NodeServices,
    Arc<bitcoin_rs_rpc::context::Context>,
)> {
    cap_global_thread_pool();

    let injected_shutdown = runtime.shutdown;
    let state = NodeState::open(config, runtime.mempool_observer.as_ref())?;
    let mut guard = StartupGuard {
        state: Some(state),
        services: NodeServices::default(),
    };
    {
        let Some(state) = guard.state.as_mut() else {
            // The guard was just built with `state: Some(state)` above.
            panic!("state recorded above");
        };
        state.start_index_workers()?;
    }
    let Some(state) = guard.state.as_ref() else {
        panic!("state recorded above");
    };
    // No V1 recovery-sidecar consultation happens here. `NodeState::open`
    // already restored the checkpoint and, when enabled, replayed the
    // journal's committed suffix before derived-index workers were started.

    tracing::info!(
        network = ?state.config().network,
        data_dir = %state.data_dir().display(),
        storage_backend = %state.config().storage_backend,
        "bitcoin-rs node booting"
    );

    let metrics = crate::metrics::start_metrics(state.config().metrics_bind, state.shutdown())?;
    guard.services.metrics = metrics;

    let shutdown = state.shutdown();
    let (shutdown_rx, event_loop_signal) = if let Some(rx) = injected_shutdown {
        (rx, None)
    } else {
        let (tx, rx) = bounded(1);
        if install_signals {
            // Forwards process signals into our channel; the service
            // graph owns the handler from this moment, and the shared
            // teardown closes and joins it.
            let handler = crate::signal::install_shutdown_handler(
                std::sync::Arc::clone(&shutdown),
                tx.clone(),
            )?;
            guard.services.signal_handler = Some(handler);
        }
        (rx, Some(tx))
    };
    guard.services.event_loop_signal = event_loop_signal;
    let banned = state.banned_subnets();
    let network_active = state.network_active();
    let block_body_source = state.block_body_source();
    let p2p_chain_query: P2pChainQuery = Arc::new(
        crate::NodeP2pChainQuery::new(state.block_tree())
            .with_block_body_source(Arc::clone(&block_body_source)),
    );
    let (sync_wake_tx, sync_wake_rx) = bounded(1);
    let sync = state.sync();
    let loop_handle = EventLoop::with_sync_wake(shutdown_rx, sync, sync_wake_rx);
    let mining_control: Arc<dyn bitcoin_rs_rpc::context::MiningControl> =
        Arc::new(crate::MiningCoordinator::new(
            state.config().network,
            state.applied_tip(),
            state.block_tree(),
            state.mempool(),
            state.apply_handles(),
            Vec::new(),
            Arc::clone(&shutdown),
        ));
    // From here on, every gateway mutation and every authoritative tip move
    // reaches the coordinator's long-poll waiters through the node's shared
    // generation signal. The signal holds a `Weak` so it never extends the
    // coordinator's lifetime: the RPC context owns the coordinator, and an
    // owned reference here would cycle through `apply_handles`.
    state.mining_generation_signal().attach(&mining_control);
    let rpc_auth = Arc::new(build_rpc_auth(&state.config().rpc_auth)?);
    let mut rpc_context =
        bitcoin_rs_rpc::context::Context::from_handles(bitcoin_rs_rpc::context::ContextHandles {
            chain: bitcoin_rs_rpc::context::ChainHandles {
                chain_tip: state.chain_tip(),
                applied_tip: state.applied_tip(),
                blocks: state.blocks(),
                transactions: state.transactions(),
                utxo: state.utxo(),
                coin_stats: state.coin_stats(),
                block_tree: state.block_tree(),
                chain_network: state.config().network,
            },
            mempool: bitcoin_rs_rpc::context::MempoolHandles {
                mempool: state.mempool_gateway(),
            },
            indexes: bitcoin_rs_rpc::context::IndexHandles {
                tx_index: state.tx_index_query(),
                script_index: state.script_index_query(),
            },
            network: bitcoin_rs_rpc::context::NetworkHandles {
                network: state.network(),
                network_active: Arc::clone(&network_active),
                peer_table: state.peer_table(),
                p2p_outbound_sender: Some(state.p2p_outbound_sender()),
                banned: Arc::clone(&banned),
                added_nodes: Arc::new(parking_lot::RwLock::new(Vec::new())),
            },
            mining: bitcoin_rs_rpc::context::MiningHandles {
                mining_control: Some(Arc::clone(&mining_control)),
            },
            capabilities: Some(state.capability_provider()),
        })
        .with_esplora_tx_index(state.esplora_tx_index_query());
    rpc_context = rpc_context.with_block_body_source(block_body_source);
    rpc_context =
        rpc_context.with_chain_transition(Arc::clone(&state.apply_handles().chain_transition));
    if let Some(prune_service) = state.prune_service() {
        rpc_context = rpc_context.with_prune_service(prune_service);
    }
    rpc_context = rpc_context.with_chain_control(Arc::new(RpcChainControl {
        handles: state.apply_handles(),
    }));
    rpc_context = rpc_context.with_zmq_notifications(state.active_zmq_notifications());
    rpc_context = rpc_context.with_debug_log_path(state.data_dir().join("debug.log"));
    rpc_context = rpc_context.with_rollback_warnings(state.warning_store());
    let context = Arc::new(rpc_context);
    let rpc_handler = Arc::new(bitcoin_rs_rpc::Handler::new(Arc::clone(&context)));
    let rpc_server = bitcoin_rs_rpc::RpcServer::bind(
        state.config().rpc_bind,
        rpc_auth,
        rpc_handler,
        RPC_MAX_CONNECTIONS,
        RPC_IDLE_TIMEOUT,
        state.config().rest,
    )?;
    let rpc_local_addr = rpc_server.local_addr()?;
    tracing::info!(addr = %rpc_local_addr, "rpc listener bound");
    let rpc_shutdown = Arc::clone(&shutdown);
    let rpc_thread = std::thread::Builder::new()
        .name("bitcoin-rs-rpc".into())
        .spawn(move || rpc_server.serve_with_shutdown(rpc_shutdown))?;
    guard.services.rpc_thread = Some(rpc_thread);
    let peer_table = state.peer_table();
    spawn_p2p_listeners(
        state.config(),
        &shutdown,
        &network_active,
        &peer_table,
        Arc::clone(&banned),
        state.inbound_headers_sender(),
        state.inbound_blocks_sender(),
        sync_wake_tx.clone(),
        Arc::clone(&p2p_chain_query),
        &mut guard.services,
    )?;
    let outbound_worker =
        spawn_p2p_outbound_drain(state, &shutdown, sync_wake_tx, Arc::clone(&p2p_chain_query))?;
    guard.services.outbound_worker = Some(outbound_worker);
    let bootstrap_worker = if state.config().connect.is_empty() {
        spawn_dns_peer_maintenance(
            state.config(),
            Arc::clone(&shutdown),
            Arc::clone(&network_active),
            Arc::clone(&peer_table),
            state.p2p_outbound_sender(),
        )?
    } else {
        spawn_fixed_peer_bootstrap(state, &shutdown)?
    };
    guard.services.bootstrap_worker = bootstrap_worker;
    // Periodic chainstate checkpoint worker: publishes a checkpoint every
    // CHECKPOINT_INTERVAL_BLOCKS or CHECKPOINT_INTERVAL_SECS so a node
    // killed mid-sync restarts from a recent anchor, not the last clean
    // shutdown. Joined before the clean-shutdown checkpoint publication.
    let checkpoint_worker = state.start_periodic_checkpoint(
        crate::checkpoint_worker::CHECKPOINT_INTERVAL_BLOCKS,
        Duration::from_secs(crate::checkpoint_worker::CHECKPOINT_INTERVAL_SECS),
    )?;
    guard.services.checkpoint_worker = Some(checkpoint_worker);
    // The event loop runs on its own thread so both the daemon (signal wait)
    // and an embedder (typed API calls) can share the process meanwhile.
    let event_loop = std::thread::Builder::new()
        .name("bitcoin-rs-event-loop".into())
        .spawn(move || loop_handle.spin(&shutdown))?;
    guard.services.event_loop = Some(event_loop);
    let (state, services) = guard.disarm();
    Ok((state, services, context))
}

/// Boots the node and runs until shutdown.
///
/// The daemon is the node crate's first embedder: this function is a thin
/// signal wrapper around the one lifecycle implementation.
///
/// Flow:
/// 1. Install JSON tracing on stderr.
/// 2. `start_node` — validate config, open state, recover, spawn services.
/// 3. Wait for a shutdown decision — the in-process receiver wired via
///    [`RuntimeInputs::shutdown`] (tests) or a fresh SIGINT/SIGTERM handler
///    (production) drives the event loop, which owns the decision.
/// 4. Service shutdown — the one ordered teardown in
///    [`TeardownMode::CleanShutdown`]: join every worker and the signal
///    handler, then publish one immutable clean-shutdown chainstate
///    checkpoint.
pub fn run(config: NodeConfig, runtime: RuntimeInputs) -> Result<()> {
    logging::install_tracing(&config.log_level)?;
    let (state, services, context) = start_node(config, runtime, true)?;
    let node = crate::embed::node_from_parts(state, services, context);
    let shutdown = node.state.shutdown();
    // The event loop owns the shutdown channel; the flag is its published
    // decision. Long-poll it the way the other long-lived waiters do.
    while !wait_for_shutdown(&shutdown, Duration::from_secs(DAEMON_SIGNAL_WAIT_SECS)) {}
    // Consuming shutdown: dropping the node here releases the RPC context,
    // whose mining coordinator owns the apply handles and storage clones —
    // the last strong refs keeping the data dir locked past teardown.
    let shutdown_result = node.shutdown_blocking();
    shutdown_result.map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Threads for the process-wide rayon pool.
///
/// rayon defaults the global pool to one worker per core. That pool only runs
/// the short coarse jobs in apply — block txid hashing and shard commits —
/// while script verification holds its own pool of up to
/// `MAX_SCRIPT_VERIFY_THREADS` and the node holds its own I/O threads besides.
/// On a many-core host the process therefore oversubscribes by a wide margin
/// and the global workers spend their time spinning for work that is not there.
///
/// Measured on a loopback P2P sync to height `150_000`, `taskset -c 0-31`, three
/// interleaved pairs:
///
/// | global pool | wall | CPU |
/// | one per core (32) | 75.6s | 314.4s |
/// | 4 | 64.4s | 162.4s |
///
/// Both axes improve together, so this is not a wall-for-CPU trade. The sweep
/// is flat from 2 to 8 and climbs above it. A full-verification replay of the
/// same window is insensitive at every width (84-88s) because script
/// verification dominates there and runs in its own pool, so this cap costs
/// that path nothing.
const GLOBAL_RAYON_THREADS: usize = 4;

/// Caps the global rayon pool before any parallel iterator runs.
///
/// Idempotent by necessity: `build_global` fails if a pool already exists, and
/// that is not an error worth aborting a node boot over — it means something
/// else already sized the pool, and the default is merely slower, not wrong.
fn cap_global_thread_pool() {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let threads = available.min(GLOBAL_RAYON_THREADS);
    if let Err(error) = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
    {
        tracing::debug!(%error, "global rayon pool already configured, keeping it");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anyhow::anyhow;

    use super::*;

    // ---------------------------------------------------------------------------
    // Shared mock resolvers
    // ---------------------------------------------------------------------------

    struct CountingResolver(AtomicUsize);

    impl bitcoin_rs_p2p::DnsResolver for CountingResolver {
        fn resolve(&self, _seed: &str) -> Result<Vec<SocketAddr>, bitcoin_rs_p2p::PeerError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(Vec::new())
        }
    }

    /// Returns 16 addresses for any seed query.
    struct ManyAddrResolver;

    impl bitcoin_rs_p2p::DnsResolver for ManyAddrResolver {
        fn resolve(&self, _seed: &str) -> Result<Vec<SocketAddr>, bitcoin_rs_p2p::PeerError> {
            Ok((0..16_u16)
                .map(|offset| SocketAddr::from(([127, 0, 0, 1], 10_000 + offset)))
                .collect())
        }
    }

    struct SeedAwareResolver;

    impl bitcoin_rs_p2p::DnsResolver for SeedAwareResolver {
        fn resolve(&self, seed: &str) -> Result<Vec<SocketAddr>, bitcoin_rs_p2p::PeerError> {
            let base: u16 = match seed {
                "seed-a" => 10_000,
                "seed-b" => 11_000,
                "seed-c" => 12_000,
                _ => return Ok(Vec::new()),
            };
            Ok((0..4_u16)
                .map(|offset| SocketAddr::from(([127, 0, 0, 1], base + offset)))
                .collect())
        }
    }

    // ---------------------------------------------------------------------------
    // Helper
    // ---------------------------------------------------------------------------

    fn empty_peer_table() -> PeerTable {
        Arc::new(bitcoin_rs_p2p::PeerTable::new())
    }

    fn signet_seeds() -> Vec<&'static str> {
        bitcoin_rs_primitives::Network::Signet.dns_seeds().to_vec()
    }

    #[test]
    fn disabled_zmq_still_seals_the_observer_slot() {
        // The state constructs the gateway with its observer at
        // `NodeState::open` time. Even without a ZMQ endpoint the
        // observer slot is occupied by the node's `NodeMutationObserver`
        // (mining-generation leg only). Verify the API contract:
        // `shared_with` produces a gateway whose observer is present.
        let pool = Arc::new(parking_lot::RwLock::new(bitcoin_rs_mempool::Mempool::new(
            bitcoin_rs_mempool::MempoolLimits::default(),
        )));
        let observer: Arc<dyn bitcoin_rs_mempool::MempoolObserver> =
            Arc::new(bitcoin_rs_mempool::CompositeObserver::new());
        let gateway = bitcoin_rs_mempool::MempoolGateway::shared_with(pool, observer);
        assert!(
            gateway.has_observer(),
            "startup must seal the observer slot even without a ZMQ endpoint"
        );
    }

    #[test]
    fn clean_shutdown_publishes_checkpoint_and_returns_success() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = temp.path().join("node-success");
        config.rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        config.rpc_auth = crate::Auth::basic("user", "password");
        config.script_index = crate::config::ScriptIndexMode::Disabled;
        config.p2p_listen.clear();
        config.metrics_bind = None;

        let state = crate::state::NodeState::open(config.clone(), None)?;
        state.apply_block(&bitcoin_rs_primitives::Network::Regtest.genesis_block())?;
        state.write_clean_checkpoint()?;
        drop(state);
        let current_path = config
            .data_dir
            .join("chainstate-checkpoints")
            .join("CURRENT");
        let previous_current = std::fs::read(&current_path)?;

        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        shutdown_tx.send(())?;
        let reopen_config = config.clone();
        run(config, RuntimeInputs::default().with_shutdown(shutdown_rx))?;
        assert_ne!(std::fs::read(current_path)?, previous_current);

        let resumed = crate::state::NodeState::open(reopen_config, None)?;
        assert_eq!(
            resumed.resume_source(),
            crate::state::ResumeSource::Checkpoint
        );
        Ok(())
    }

    #[test]
    fn shutdown_checkpoint_io_failure_is_returned_and_preserves_current() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = temp.path().join("node");
        config.rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        config.rpc_auth = crate::Auth::basic("user", "password");
        config.script_index = crate::config::ScriptIndexMode::Disabled;
        config.p2p_listen.clear();
        config.metrics_bind = None;
        // Force a bootstrap worker to spawn (fixed-peer path) so the drain
        // below is exercised — with an empty `connect`, `bootstrap_worker`
        // would be `None` and the cleanup-ordering assertion could not catch a
        // regression that moves `?` back onto `write_clean_checkpoint`.
        config.connect = vec!["127.0.0.1:1".to_owned()];

        let state = crate::state::NodeState::open(config.clone(), None)?;
        state.apply_block(&bitcoin_rs_primitives::Network::Regtest.genesis_block())?;
        state.write_clean_checkpoint()?;
        drop(state);

        let current_path = config
            .data_dir
            .join("chainstate-checkpoints")
            .join("CURRENT");
        let previous_current = std::fs::read(&current_path)?;
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        shutdown_tx.send(())?;

        crate::checkpoint::inject_next_checkpoint_failpoint(
            crate::checkpoint::CheckpointFailpoint::ManifestWrite,
        );

        assert!(run(config, RuntimeInputs::default().with_shutdown(shutdown_rx)).is_err());
        assert_eq!(std::fs::read(current_path)?, previous_current);
        assert!(
            bootstrap_drain_was_reached(),
            "checkpoint publication error must not bypass the bounded bootstrap-worker drain"
        );
        Ok(())
    }

    /// One failed join must not skip the later cleanup stages — the
    /// bootstrap drain, the signal close, the deferred error surfacing all
    /// still run (the stage seam counts exactly one shared-teardown entry) —
    /// and a run whose worker died abnormally must not publish the
    /// clean-shutdown checkpoint over the state a previous run recorded.
    #[test]
    fn teardown_join_failure_completes_cleanup_and_suppresses_checkpoint() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = temp.path().join("node-join-failure");
        config.rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        config.rpc_auth = crate::Auth::basic("user", "password");
        config.script_index = crate::config::ScriptIndexMode::Disabled;
        config.p2p_listen.clear();
        config.metrics_bind = None;

        let state = crate::state::NodeState::open(config.clone(), None)?;
        state.apply_block(&bitcoin_rs_primitives::Network::Regtest.genesis_block())?;
        state.write_clean_checkpoint()?;
        let current_path = config
            .data_dir
            .join("chainstate-checkpoints")
            .join("CURRENT");
        let seeded_current = std::fs::read(&current_path)?;

        let panicker = std::thread::Builder::new()
            .name("bitcoin-rs-outbound-drain".to_owned())
            .spawn(|| panic!("injected worker panic"))?;
        let mut services = NodeServices::default();
        services.outbound_worker = Some(panicker);

        let result = services.teardown(Some(&state), TeardownMode::CleanShutdown);
        assert!(result.is_err(), "the panicking worker's join must surface");
        assert_eq!(
            shutdown::take_shutdown_stages_reached(),
            1,
            "the shared teardown must have run exactly once"
        );
        assert_eq!(
            std::fs::read(&current_path)?,
            seeded_current,
            "a teardown with a failed join must not publish the clean checkpoint"
        );
        drop(services);
        drop(state);

        // The graph's storage was released by the same teardown.
        let resumed = crate::state::NodeState::open(config, None)?;
        assert_eq!(
            resumed.resume_source(),
            crate::state::ResumeSource::Checkpoint,
            "the seeded checkpoint survives the failed run untouched"
        );
        Ok(())
    }

    /// The teardown must join the bootstrap worker for as long as it
    /// takes: the worker outlives the former one-second abandon deadline,
    /// and the shutdown must not return — let alone publish a checkpoint
    /// — before the worker has fully exited. The worker's exit clock is a
    /// `recv_timeout` on a dropped-sender channel (twice the former
    /// deadline), so no test thread ever sleeps. A successful shutdown
    /// then publishes the clean checkpoint after that join, which the
    /// changed CURRENT proves.
    #[test]
    fn teardown_joins_bootstrap_worker_beyond_former_deadline() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = temp.path().join("node-slow-bootstrap");
        config.rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        config.rpc_auth = crate::Auth::basic("user", "password");
        config.script_index = crate::config::ScriptIndexMode::Disabled;
        config.p2p_listen.clear();
        config.metrics_bind = None;

        let state = crate::state::NodeState::open(config.clone(), None)?;
        state.apply_block(&bitcoin_rs_primitives::Network::Regtest.genesis_block())?;
        state.write_clean_checkpoint()?;
        let current_path = config
            .data_dir
            .join("chainstate-checkpoints")
            .join("CURRENT");
        let seeded_current = std::fs::read(&current_path)?;

        // The gate sender stays alive in this frame, so the worker parks
        // until the two-second timeout expires — twice the former
        // one-second abandon deadline.
        let (_gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let (exited_tx, exited_rx) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("bitcoin-rs-p2p-bootstrap".to_owned())
            .spawn(move || {
                let _ = gate_rx.recv_timeout(std::time::Duration::from_secs(2));
                let _ = exited_tx.send(());
            })?;
        let mut services = NodeServices::default();
        services.bootstrap_worker = Some(worker);

        let started = std::time::Instant::now();
        services
            .teardown(Some(&state), TeardownMode::CleanShutdown)
            .unwrap_or_else(|error| {
                panic!("a clean shutdown with a slow worker must still succeed: {error}")
            });
        let elapsed = started.elapsed();

        assert!(
            elapsed >= std::time::Duration::from_secs(2),
            "teardown returned after {elapsed:?}; it must join the worker \
             instead of abandoning it at the former one-second deadline"
        );
        assert!(
            exited_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .is_ok(),
            "the worker had already finished when teardown returned"
        );
        assert!(
            bootstrap_drain_was_reached(),
            "the bootstrap join must run inside the teardown"
        );
        assert_ne!(
            std::fs::read(&current_path)?,
            seeded_current,
            "the clean checkpoint must be published after the joins succeed"
        );
        drop(services);
        drop(state);
        Ok(())
    }

    /// A late bootstrap panic suppresses the clean checkpoint — CURRENT
    /// keeps the previous generation — and the checkpoint write is never
    /// even attempted during teardown: the injected failpoint is still
    /// armed afterwards, proving the write runs only after every join
    /// succeeded.
    #[test]
    fn late_bootstrap_panic_suppresses_checkpoint() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = temp.path().join("node-late-failure");
        config.rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        config.rpc_auth = crate::Auth::basic("user", "password");
        config.script_index = crate::config::ScriptIndexMode::Disabled;
        config.p2p_listen.clear();
        config.metrics_bind = None;

        let state = crate::state::NodeState::open(config.clone(), None)?;
        state.apply_block(&bitcoin_rs_primitives::Network::Regtest.genesis_block())?;
        state.write_clean_checkpoint()?;
        let current_path = config
            .data_dir
            .join("chainstate-checkpoints")
            .join("CURRENT");
        let seeded_current = std::fs::read(&current_path)?;

        let panicker = std::thread::Builder::new()
            .name("bitcoin-rs-p2p-bootstrap".to_owned())
            .spawn(|| panic!("injected bootstrap panic"))?;
        let mut services = NodeServices::default();
        services.bootstrap_worker = Some(panicker);

        crate::checkpoint::inject_next_checkpoint_failpoint(
            crate::checkpoint::CheckpointFailpoint::ManifestWrite,
        );
        let result = services.teardown(Some(&state), TeardownMode::CleanShutdown);
        assert!(result.is_err(), "the panicking worker's join must surface");
        assert!(
            bootstrap_drain_was_reached(),
            "the bootstrap join must run inside the teardown"
        );
        assert_eq!(
            std::fs::read(&current_path)?,
            seeded_current,
            "a teardown with a failed join must not publish the clean checkpoint"
        );
        // The failpoint survived teardown: the checkpoint write was never
        // attempted, because it runs only after every join succeeded.
        assert!(
            state.write_clean_checkpoint().is_err(),
            "the injected checkpoint failure must still be armed after teardown"
        );
        drop(services);
        drop(state);
        Ok(())
    }

    /// The daemon runner and the embedded node must reach the same one
    /// ordered teardown: each path counts exactly one teardown entry, and
    /// the daemon signal handler installed by `start_node` is closed again
    /// by that teardown — twice in a row, with no stale handler left from
    /// the first lifecycle.
    #[test]
    fn daemon_and_embedded_paths_share_one_teardown() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;

        // Daemon path: run() with an injected pre-sent shutdown receiver.
        let mut daemon_config = NodeConfig::default_for_network(crate::Network::Regtest);
        daemon_config.data_dir = temp.path().join("daemon");
        daemon_config.rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        daemon_config.rpc_auth = crate::Auth::basic("user", "password");
        daemon_config.script_index = crate::config::ScriptIndexMode::Disabled;
        daemon_config.p2p_listen.clear();
        daemon_config.metrics_bind = None;
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        shutdown_tx.send(())?;
        let stages_before = shutdown::take_shutdown_stages_reached();
        run(
            daemon_config,
            RuntimeInputs::default().with_shutdown(shutdown_rx),
        )?;
        assert_eq!(
            shutdown::take_shutdown_stages_reached(),
            stages_before + 1,
            "the daemon run must reach the shared teardown exactly once"
        );

        // Embedded path: start_node with real signal handling, stopped
        // through the same teardown the daemon uses.
        let mut embedded_config = NodeConfig::default_for_network(crate::Network::Regtest);
        embedded_config.data_dir = temp.path().join("embedded");
        embedded_config.rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        embedded_config.rpc_auth = crate::Auth::basic("user", "password");
        embedded_config.script_index = crate::config::ScriptIndexMode::Disabled;
        embedded_config.p2p_listen.clear();
        embedded_config.metrics_bind = None;
        let installed_before = crate::signal::testing::installed_total();
        let closed_before = crate::signal::testing::closed_total();
        let (state, services, context) =
            start_node(embedded_config, RuntimeInputs::default(), true)?;
        let node = crate::embed::node_from_parts(state, services, context);
        node.shutdown_blocking()?;
        assert_eq!(
            shutdown::take_shutdown_stages_reached(),
            1,
            "the embedded shutdown must reach the shared teardown exactly once"
        );
        assert_eq!(
            crate::signal::testing::installed_total(),
            installed_before + 1,
            "the embedded lifecycle installs exactly one signal handler"
        );
        assert_eq!(
            crate::signal::testing::closed_total(),
            closed_before + 1,
            "the shared teardown must close and join that handler"
        );

        // Second embedded lifecycle on the same datadir: no stale signal
        // handler from the first, and the clean checkpoint resumes.
        let mut reopen_config = NodeConfig::default_for_network(crate::Network::Regtest);
        reopen_config.data_dir = temp.path().join("embedded");
        reopen_config.rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        reopen_config.rpc_auth = crate::Auth::basic("user", "password");
        reopen_config.script_index = crate::config::ScriptIndexMode::Disabled;
        reopen_config.p2p_listen.clear();
        reopen_config.metrics_bind = None;
        let (state, services, context) = start_node(reopen_config, RuntimeInputs::default(), true)?;
        let node = crate::embed::node_from_parts(state, services, context);
        node.shutdown_blocking()?;
        assert_eq!(
            crate::signal::testing::installed_total(),
            installed_before + 2,
            "the second lifecycle installs its own handler"
        );
        assert_eq!(
            crate::signal::testing::closed_total(),
            closed_before + 2,
            "the second lifecycle closes its own handler"
        );
        Ok(())
    }

    #[test]
    fn connectionless_bootstrap_refills_are_fast_and_bounded() {
        let mut refill = DnsBootstrapRefill::default();

        assert_eq!(
            refill.next_delay(0, crate::sync::MIN_PEERS_FOR_FANOUT),
            DNS_BOOTSTRAP_REFILL_INTERVAL
        );
        assert_eq!(
            refill.next_delay(0, crate::sync::MIN_PEERS_FOR_FANOUT),
            DNS_BOOTSTRAP_REFILL_INTERVAL
        );
        assert_eq!(
            refill.next_delay(0, crate::sync::MIN_PEERS_FOR_FANOUT),
            DNS_MAINTENANCE_INTERVAL
        );
        assert_eq!(refill.next_delay(1, 0), DNS_MAINTENANCE_INTERVAL);
        assert_eq!(
            refill.next_delay(0, crate::sync::MIN_PEERS_FOR_FANOUT),
            DNS_BOOTSTRAP_REFILL_INTERVAL
        );
    }

    #[test]
    fn selection_cursor_rotates_seed_and_address_prefix() {
        let peer_table = empty_peer_table();
        let (dial_tx, dial_rx) = crossbeam_channel::unbounded();
        let mut recently_queued = hashbrown::HashMap::new();

        let queued = drain_dns_peer_deficit(
            &SeedAwareResolver,
            &["seed-a", "seed-b", "seed-c"],
            &AtomicBool::new(true),
            &peer_table,
            &dial_tx,
            &mut recently_queued,
            1,
            2,
        );

        assert_eq!(queued, 2);
        assert_eq!(
            dial_rx.try_iter().collect::<Vec<_>>(),
            [11_001_u16, 11_002].map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
        );
    }

    #[test]
    fn inactive_network_skips_dns_resolution() {
        let resolver = CountingResolver(AtomicUsize::new(0));
        let network_active = AtomicBool::new(false);
        let peer_table = empty_peer_table();
        let (dial_tx, dial_rx) = crossbeam_channel::unbounded();
        let mut recently_queued = hashbrown::HashMap::new();

        let queued = drain_dns_peer_deficit(
            &resolver,
            &["seed-a"],
            &network_active,
            &peer_table,
            &dial_tx,
            &mut recently_queued,
            0,
            1,
        );

        assert_eq!(queued, 0);
        assert_eq!(resolver.0.load(Ordering::Relaxed), 0);
        assert!(dial_rx.try_recv().is_err());
    }

    // ---------------------------------------------------------------------------
    // Scenario (a): 3 live entries → exactly 5 dials queued, dedup respected
    // ---------------------------------------------------------------------------

    /// Resolver that includes the three pre-populated live addresses in its output
    /// so that dedup is exercised on addresses that actually overlap.
    struct OverlapResolver;

    impl bitcoin_rs_p2p::DnsResolver for OverlapResolver {
        fn resolve(&self, _seed: &str) -> Result<Vec<SocketAddr>, bitcoin_rs_p2p::PeerError> {
            // Ports 10_000..10_002 match the live entries; 10_003..10_018 are fresh.
            Ok((10_000_u16..10_019)
                .map(|p| SocketAddr::from(([127, 0, 0, 1], p)))
                .collect())
        }
    }

    #[test]
    fn deficit_queues_exact_shortfall_and_respects_dedup() {
        let peer_table = empty_peer_table();
        // Pre-populate 3 live connections using addresses the resolver will also return.
        for port in 10_000_u16..10_003 {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            let (tx, _rx) = crossbeam_channel::unbounded();
            peer_table.register(addr, bitcoin_rs_p2p::PeerLease::new(tx));
        }

        let (dial_tx, dial_rx) = crossbeam_channel::unbounded();
        let seeds = signet_seeds();
        let mut recently_queued = hashbrown::HashMap::new();
        let needed = crate::sync::MIN_PEERS_FOR_FANOUT - peer_table.len(); // 5

        let queued = drain_dns_peer_deficit(
            &OverlapResolver,
            seeds.as_slice(),
            &AtomicBool::new(true),
            &peer_table,
            &dial_tx,
            &mut recently_queued,
            0,
            needed,
        );

        assert_eq!(queued, 5, "should queue exactly the deficit");
        let dialed: Vec<SocketAddr> = dial_rx.try_iter().collect();
        assert_eq!(dialed.len(), 5);
        // None of the dialed addresses must overlap with the already-live set.
        for port in 10_000_u16..10_003 {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            assert!(
                !dialed.contains(&addr),
                "live addr {addr} must not be re-queued"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // Scenario (b): queued addr enters cooldown, not re-queued within window
    // ---------------------------------------------------------------------------

    #[test]
    fn recently_queued_addr_suppressed_within_cooldown_window() -> anyhow::Result<()> {
        let peer_table = empty_peer_table();
        let (dial_tx, dial_rx) = crossbeam_channel::unbounded();
        let seeds = signet_seeds();
        let mut recently_queued: hashbrown::HashMap<SocketAddr, std::time::Instant> =
            hashbrown::HashMap::new();

        // First call: queue 1 address.
        let q1 = drain_dns_peer_deficit(
            &ManyAddrResolver,
            seeds.as_slice(),
            &AtomicBool::new(true),
            &peer_table,
            &dial_tx,
            &mut recently_queued,
            0,
            1,
        );
        assert_eq!(q1, 1);
        let first_addr = dial_rx.try_recv()?;

        // Second call with same resolver: the address is in recently_queued,
        // so a different address should be chosen (total unique queued = 2).
        let q2 = drain_dns_peer_deficit(
            &ManyAddrResolver,
            seeds.as_slice(),
            &AtomicBool::new(true),
            &peer_table,
            &dial_tx,
            &mut recently_queued,
            0,
            1,
        );
        assert_eq!(q2, 1);
        let second_addr = dial_rx.try_recv()?;
        assert_ne!(
            first_addr, second_addr,
            "cooldown must prevent re-queueing the same addr"
        );
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Scenario (c): full dial channel → no panic, retry next tick
    // ---------------------------------------------------------------------------

    #[test]
    fn full_dial_channel_does_not_panic_and_queues_what_fits() {
        let peer_table = empty_peer_table();
        // Channel capacity = 1 — only one address can be queued.
        let (dial_tx, dial_rx) = crossbeam_channel::bounded(1);
        let seeds = signet_seeds();
        let mut recently_queued = hashbrown::HashMap::new();

        let queued = drain_dns_peer_deficit(
            &ManyAddrResolver,
            seeds.as_slice(),
            &AtomicBool::new(true),
            &peer_table,
            &dial_tx,
            &mut recently_queued,
            0,
            8,
        );

        // Must not panic; exactly 1 address fits before the channel is full.
        assert_eq!(queued, 1);
        assert_eq!(dial_rx.try_iter().count(), 1);
    }

    // ---------------------------------------------------------------------------
    // Scenario (d): shutdown flag stops the maintenance loop
    // ---------------------------------------------------------------------------

    // NOTE: uses the real SystemDnsResolver so requires network access. In a
    // network-isolated environment the initial DNS call may block for up to the
    // OS resolver timeout; the 15 s deadline accommodates typical public-CI
    // latency. The shutdown signal is set before the loop body executes, so the
    // thread exits on the first loop condition check after the initial bootstrap.
    #[test]
    fn maintenance_loop_exits_on_shutdown() -> anyhow::Result<()> {
        let config = NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Signet);
        let shutdown = Arc::new(AtomicBool::new(false));
        let peer_table = empty_peer_table();
        let (dial_tx, _dial_rx) = crossbeam_channel::unbounded();

        let handle = spawn_dns_peer_maintenance(
            &config,
            Arc::clone(&shutdown),
            Arc::new(AtomicBool::new(true)),
            peer_table,
            dial_tx,
        )?
        .ok_or_else(|| anyhow!("signet must produce a maintenance handle"))?;

        // Signal shutdown and verify the thread exits within a generous deadline.
        shutdown.store(true, Ordering::Relaxed);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !handle.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "maintenance thread did not exit after shutdown"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        handle
            .join()
            .map_err(|_| anyhow!("maintenance thread panicked"))?;
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Scenario (e): --connect mode unaffected — spawn_fixed_peer_bootstrap unchanged
    // ---------------------------------------------------------------------------

    #[test]
    fn fixed_peer_bootstrap_does_not_spawn_for_empty_connect_list() -> anyhow::Result<()> {
        // NodeState is heavyweight; test the guard directly via spawn_fixed_peer_bootstrap's
        // early-return path by confirming it returns Ok(None) when connect is empty.
        // The function reads state.config().connect, so we verify the public contract
        // through the DNS path: spawn_dns_peer_maintenance returns Some when seeds exist.
        let config = NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Signet);
        assert!(
            config.connect.is_empty(),
            "default signet config must have no --connect peers"
        );
        // When connect is empty, spawn_dns_peer_maintenance is taken; its handle is Some.
        let shutdown = Arc::new(AtomicBool::new(true)); // pre-set: thread exits immediately
        let peer_table = empty_peer_table();
        let (dial_tx, _) = crossbeam_channel::unbounded();
        let handle = spawn_dns_peer_maintenance(
            &config,
            shutdown,
            Arc::new(AtomicBool::new(true)),
            peer_table,
            dial_tx,
        )?
        .ok_or_else(|| anyhow!("signet must produce a maintenance handle"))?;
        handle
            .join()
            .map_err(|_| anyhow!("maintenance thread panicked"))?;
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Scenario (f): empty seed list (regtest / dns-disabled) → loop never spawns
    // ---------------------------------------------------------------------------

    #[test]
    fn maintenance_does_not_spawn_for_regtest_or_disabled_dns() {
        let regtest = NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Regtest);
        let mut disabled = NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Signet);
        disabled.dns_seeds_enabled = false;

        for config in [regtest, disabled] {
            let shutdown = Arc::new(AtomicBool::new(false));
            let peer_table = empty_peer_table();
            let (dial_tx, _) = crossbeam_channel::unbounded();
            let handle = match spawn_dns_peer_maintenance(
                &config,
                shutdown,
                Arc::new(AtomicBool::new(true)),
                peer_table,
                dial_tx,
            ) {
                Ok(handle) => handle,
                Err(error) => panic!("spawn_dns_peer_maintenance returned error: {error}"),
            };
            assert!(
                handle.is_none(),
                "must return None for regtest / dns-disabled configs"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // Legacy outbound-drain helpers (unchanged behaviour)
    // ---------------------------------------------------------------------------

    #[test]
    fn outbound_addr_available_rejects_active_duplicate() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let mut active = hashbrown::HashSet::new();
        active.insert(addr);
        let peer_table: PeerTable = empty_peer_table();

        assert!(!outbound_addr_available(addr, &active, &peer_table));
    }

    #[test]
    fn outbound_addr_available_rejects_connected_duplicate() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let active = hashbrown::HashSet::new();
        let peer_table: PeerTable = empty_peer_table();
        let (tx, _rx) = crossbeam_channel::unbounded();
        peer_table.register(addr, bitcoin_rs_p2p::PeerLease::new(tx));

        assert!(!outbound_addr_available(addr, &active, &peer_table));
    }

    #[test]
    fn outbound_drain_reaps_finished_attempts() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let mut active = hashbrown::HashSet::new();
        active.insert(addr);
        let handle = std::thread::spawn(|| Ok::<(), bitcoin_rs_p2p::PeerError>(()));
        while !handle.is_finished() {
            std::thread::yield_now();
        }
        let mut handles = vec![(addr, handle)];

        reap_finished_outbound_connections(&mut active, &mut handles);

        assert!(active.is_empty());
        assert!(handles.is_empty());
    }
}
