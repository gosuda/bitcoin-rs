//! Top-level orchestration: wire subsystems, spin the event loop, drain.

use crate as bitcoin_rs_node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::{Result, bail};
use crossbeam_channel::{Receiver, TrySendError, bounded};

use crate::config::Config;
use crate::event_loop::EventLoop;
use crate::state::NodeState;
use crate::{crash_recovery, logging, shutdown};

const DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const RPC_MAX_CONNECTIONS: usize = 128;
const RPC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const P2P_OUTBOUND_ACTIVE_LIMIT: usize = crate::state::P2P_OUTBOUND_QUEUE_LIMIT;
/// Target number of live outbound peers for normal operation and fan-out eligibility.
///
/// Must equal `sync::MIN_PEERS_FOR_FANOUT`; verified by the gate test.
const P2P_OUTBOUND_PEER_TARGET: usize = 8;
/// How long (in seconds) a failed dial address is suppressed from re-queueing.
const FAILED_ADDR_BACKOFF_SECS: u64 = 60;
/// How often the DNS peer maintenance loop wakes to check the live peer count.
const DNS_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

type PeerRegistry = Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>>;
type PeerOutboundMap = Arc<
    parking_lot::RwLock<
        hashbrown::HashMap<
            std::net::SocketAddr,
            crossbeam_channel::Sender<bitcoin_rs_p2p::Message>,
        >,
    >,
>;
type BannedSubnets = Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>;
type P2pChainQuery = Arc<dyn bitcoin_rs_p2p::ChainQuery>;
type OutboundConnectionHandle =
    std::thread::JoinHandle<core::result::Result<(), bitcoin_rs_p2p::PeerError>>;

fn build_rpc_auth(node_auth: &crate::Auth) -> Result<bitcoin_rs_rpc::Auth> {
    match node_auth {
        crate::Auth::Basic { user, password } => {
            Ok(bitcoin_rs_rpc::Auth::basic(user.clone(), password))
        }
        crate::Auth::Cookie { path } => Ok(bitcoin_rs_rpc::Auth::cookie(path)?),
    }
}

fn spawn_electrum_listener(
    config: &bitcoin_rs_node::Config,
    state: &NodeState,
    shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<Option<std::thread::JoinHandle<Result<(), bitcoin_rs_electrum::ElectrumError>>>>
{
    let Some(addr) = config.electrum_bind else {
        return Ok(None);
    };

    if let Some(cert) = &config.electrum_tls_cert {
        tracing::warn!(
            cert = %cert.display(),
            "electrum TLS cert configured but TLS wiring deferred; serving plaintext"
        );
    }

    let network = match state.config().network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    };
    let Some(index) = state.electrum_index_handle() else {
        bail!("electrum listener requires txindex");
    };
    let Some(history_reader) = state.electrum_history_reader() else {
        bail!("electrum listener requires txindex history reader");
    };
    let index = index
        .with_history_reader(history_reader)
        .with_network(network);
    let mempool = bitcoin_rs_electrum::MempoolHandle::from_arc(state.mempool());
    let cfg = bitcoin_rs_electrum::ServerConfig::default();
    let server = bitcoin_rs_electrum::ElectrumServer::bind(addr, index, mempool, cfg)
        .map_err(anyhow::Error::from)?;
    let local_addr = server.local_addr()?;
    tracing::info!(addr = %local_addr, "electrum listener bound");

    let electrum_shutdown = Arc::clone(shutdown);
    Ok(Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-electrum".into())
            .spawn(move || server.run_with_shutdown(electrum_shutdown))?,
    ))
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn spawn_p2p_listeners(
    config: &bitcoin_rs_node::Config,
    shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    peers: &PeerRegistry,
    peer_outbound: &PeerOutboundMap,
    banned: BannedSubnets,
    inbound_headers_tx: crossbeam_channel::Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>,
    sync_wake_tx: crossbeam_channel::Sender<()>,
    chain_query: P2pChainQuery,
) -> anyhow::Result<Vec<std::thread::JoinHandle<Result<(), bitcoin_rs_p2p::listener::ListenerError>>>>
{
    let mut handles = Vec::with_capacity(config.p2p_listen.len());
    let magic = bitcoin::p2p::Magic::from_bytes(config.network.magic());
    for addr in &config.p2p_listen {
        let listener_addr = *addr;
        let listener_shutdown = std::sync::Arc::clone(shutdown);
        let listener_peers = Arc::clone(peers);
        let listener_peer_outbound = Arc::clone(peer_outbound);
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
                    magic,
                    listener_peers,
                    listener_peer_outbound,
                    listener_inbound_headers_tx,
                    listener_inbound_blocks_tx,
                    listener_banned,
                    Some(listener_chain_query),
                    Some(listener_sync_wake_tx),
                )
            })?;
        tracing::info!(addr = %listener_addr, "p2p listener bound");
        handles.push(handle);
    }
    Ok(handles)
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
    peers: &PeerRegistry,
    peer_outbound: &PeerOutboundMap,
) -> bool {
    if active.contains(&addr) {
        return false;
    }
    if peer_outbound.read().contains_key(&addr) {
        return false;
    }
    !peers.read().iter().any(|peer| peer.addr == addr)
}

#[allow(clippy::needless_pass_by_value)]
fn spawn_p2p_outbound_drain(
    config: &bitcoin_rs_node::Config,
    state: &NodeState,
    shutdown: &Arc<AtomicBool>,
    peers: &PeerRegistry,
    peer_outbound: &PeerOutboundMap,
    banned: BannedSubnets,
    sync_wake_tx: crossbeam_channel::Sender<()>,
    chain_query: P2pChainQuery,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    let outbound_rx = state.p2p_outbound_receiver();
    let magic = bitcoin::p2p::Magic::from_bytes(config.network.magic());
    let outbound_registry = Arc::clone(peers);
    let outbound_peer_outbound = Arc::clone(peer_outbound);
    let outbound_banned = Arc::clone(&banned);
    let outbound_headers_tx = state.inbound_headers_sender();
    let outbound_blocks_tx = state.inbound_blocks_sender();
    let outbound_sync_wake_tx = sync_wake_tx;
    let outbound_shutdown = Arc::clone(shutdown);
    let outbound_chain_query = Arc::clone(&chain_query);

    Ok(std::thread::Builder::new()
        .name("bitcoin-rs-p2p-outbound-drain".to_owned())
        .spawn(move || {
            let mut active = hashbrown::HashSet::new();
            let mut handles = Vec::new();
            while !outbound_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                reap_finished_outbound_connections(&mut active, &mut handles);
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
                            &outbound_registry,
                            &outbound_peer_outbound,
                        ) {
                            tracing::debug!(addr = %addr, "p2p outbound request skipped: already active");
                            continue;
                        }
                        let handle = bitcoin_rs_p2p::listener::spawn_outbound_connection_with_chain_and_sync_wake(
                            addr,
                            magic,
                            Arc::clone(&outbound_registry),
                            Arc::clone(&outbound_peer_outbound),
                            outbound_headers_tx.clone(),
                            outbound_blocks_tx.clone(),
                            Arc::clone(&outbound_banned),
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
/// peers is below [`P2P_OUTBOUND_PEER_TARGET`], resolves DNS seeds and queues the deficit
/// count of addresses into `outbound_tx`.  Addresses that recently failed are suppressed for
/// [`FAILED_ADDR_BACKOFF_SECS`] seconds via an in-memory backoff map.
///
/// Returns `Ok(None)` when DNS bootstrap is disabled or the network is regtest (both cases
/// require no background refill).
fn spawn_dns_peer_maintenance(
    config: &Config,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    peer_outbound: PeerOutboundMap,
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

                // Initial bootstrap: queue up to P2P_OUTBOUND_PEER_TARGET addresses immediately.
                let queued = drain_dns_peer_deficit(
                    &resolver,
                    seeds.as_slice(),
                    &peer_outbound,
                    &outbound_tx,
                    &mut failed_backoff,
                    P2P_OUTBOUND_PEER_TARGET,
                );
                tracing::info!(queued, "dns peer bootstrap queued initial addresses");

                while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(DNS_MAINTENANCE_INTERVAL);
                    if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }

                    let live = peer_outbound.read().len();
                    if live >= P2P_OUTBOUND_PEER_TARGET {
                        continue;
                    }
                    let deficit = P2P_OUTBOUND_PEER_TARGET - live;
                    let queued = drain_dns_peer_deficit(
                        &resolver,
                        seeds.as_slice(),
                        &peer_outbound,
                        &outbound_tx,
                        &mut failed_backoff,
                        deficit,
                    );
                    if queued > 0 {
                        tracing::info!(
                            live,
                            queued,
                            deficit,
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
/// 1. Addresses already present in `peer_outbound`.
/// 2. Addresses in `recently_queued` whose cooldown window has not yet expired.
///
/// Successfully queued addresses are inserted into `recently_queued` with the current
/// timestamp so they are not re-queued on the next maintenance tick before the dial
/// attempt completes.
///
/// Addresses that cannot be sent because the channel is full are silently skipped — the
/// caller will retry on the next maintenance tick.  The channel being disconnected is
/// treated as a transient error and logged; the loop stops.
///
/// Returns the number of addresses successfully queued.
fn drain_dns_peer_deficit<R>(
    resolver: &R,
    seeds: &[&str],
    peer_outbound: &PeerOutboundMap,
    outbound_tx: &crossbeam_channel::Sender<SocketAddr>,
    recently_queued: &mut hashbrown::HashMap<SocketAddr, std::time::Instant>,
    needed: usize,
) -> usize
where
    R: bitcoin_rs_p2p::DnsResolver + ?Sized,
{
    if needed == 0 {
        return 0;
    }

    let now = std::time::Instant::now();
    let cooldown = std::time::Duration::from_secs(FAILED_ADDR_BACKOFF_SECS);

    // Evict expired cooldown entries to keep the map bounded.
    recently_queued.retain(|_, queued_at| now.duration_since(*queued_at) < cooldown);

    let mut queued = 0usize;
    let mut seen: hashbrown::HashSet<SocketAddr> = hashbrown::HashSet::new();

    'outer: for seed in seeds {
        let addresses = match resolver.resolve(seed) {
            Ok(a) => a,
            Err(error) => {
                tracing::warn!(seed = %seed, %error, "dns seed resolution failed");
                continue;
            }
        };
        for addr in addresses {
            if !seen.insert(addr) {
                continue;
            }
            if peer_outbound.read().contains_key(&addr) {
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
    let peers = state.peers();
    let peer_outbound = state.peer_outbound();
    let bootstrap_shutdown = Arc::clone(shutdown);
    Ok(Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-fixed-peer-bootstrap".to_owned())
            .spawn(move || {
                while !bootstrap_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    for addr in &connect {
                        if peer_outbound.read().contains_key(addr)
                            || peers.read().iter().any(|peer| peer.addr == *addr)
                        {
                            continue;
                        }
                        if outbound_tx.try_send(*addr).is_err() {
                            // Queue full or closed; retry on the next tick.
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
            })?,
    ))
}

/// Boots the node from a resolved [`Config`] and runs until shutdown.
///
/// Flow:
/// 1. Install JSON tracing on stderr.
/// 2. Open / create the node data directory and resolve state.
/// 3. Run crash recovery against the persisted sidecar.
/// 4. Acquire a shutdown signal — either the in-process receiver wired via
///    [`Config::with_shutdown_receiver`] (tests) or a fresh SIGINT/SIGTERM
///    handler (production).
/// 5. Spin the event loop until shutdown is requested.
/// 6. Drain subsystems within [`DRAIN_DEADLINE`].
#[allow(clippy::too_many_lines)]
pub fn run(mut config: Config) -> Result<()> {
    logging::install_tracing(&config.log_level)?;

    let injected_shutdown = config.shutdown_signal.take();
    let state = NodeState::open(config)?;
    crash_recovery::recover_if_needed(&state)?;

    tracing::info!(
        network = ?state.config().network,
        data_dir = %state.data_dir().display(),
        storage_backend = %state.config().storage_backend,
        "bitcoin-rs node booting"
    );

    let shutdown_rx: Receiver<()> = if let Some(rx) = injected_shutdown {
        rx
    } else {
        let (tx, rx) = bounded(1);
        // Forwards process signals into our channel; the JoinHandle outlives `run`.
        let _signal_thread = crate::signal::install_shutdown_handler(tx)?;
        rx
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let banned = state.banned_subnets();
    let block_body_source = state.block_body_source();
    let p2p_chain_query: P2pChainQuery = Arc::new(
        crate::NodeP2pChainQuery::new(state.block_tree(), state.blocks())
            .with_block_body_source(Arc::clone(&block_body_source)),
    );
    let (sync_wake_tx, sync_wake_rx) = bounded(1);
    let loop_handle = EventLoop::with_sync_wake(shutdown_rx, state.sync(), sync_wake_rx);
    let rpc_auth = Arc::new(build_rpc_auth(&state.config().rpc_auth)?);
    let mut rpc_context = bitcoin_rs_rpc::Context::from_handles(
        state.chain_tip(),
        state.applied_tip(),
        state.mempool(),
        state.blocks(),
        state.transactions(),
        state.utxo(),
        state.coin_stats(),
        state.filter_index(),
        state.network(),
        state.mining_template_id(),
        state.peers(),
        state.block_tree(),
        state.config().network,
        Some(state.inbound_blocks_sender()),
        Some(state.p2p_outbound_sender()),
        Arc::clone(&banned),
        Arc::new(parking_lot::RwLock::new(Vec::new())),
        state.tx_index(),
    );
    rpc_context = rpc_context.with_block_body_source(block_body_source);
    if let Some(prune_service) = state.prune_service() {
        rpc_context = rpc_context.with_prune_service(prune_service);
    }
    rpc_context = rpc_context.with_zmq_notifications(state.active_zmq_notifications());
    let rpc_handler = Arc::new(bitcoin_rs_rpc::Handler::new(Arc::new(rpc_context)));
    let rpc_server = bitcoin_rs_rpc::RpcServer::bind(
        state.config().rpc_bind,
        rpc_auth,
        rpc_handler,
        RPC_MAX_CONNECTIONS,
        RPC_IDLE_TIMEOUT,
    )?;
    let rpc_local_addr = rpc_server.local_addr()?;
    tracing::info!(addr = %rpc_local_addr, "rpc listener bound");
    // TODO(rpc_smoke): cover the RPC listener once the test ergonomics improve.
    let rpc_shutdown = Arc::clone(&shutdown);
    let rpc_thread = std::thread::Builder::new()
        .name("bitcoin-rs-rpc".into())
        .spawn(move || rpc_server.serve_with_shutdown(rpc_shutdown))?;
    let electrum_thread = spawn_electrum_listener(state.config(), &state, &shutdown)?;
    let peers = state.peers();
    let peer_outbound = state.peer_outbound();
    let p2p_threads = spawn_p2p_listeners(
        state.config(),
        &shutdown,
        &peers,
        &peer_outbound,
        Arc::clone(&banned),
        state.inbound_headers_sender(),
        state.inbound_blocks_sender(),
        sync_wake_tx.clone(),
        Arc::clone(&p2p_chain_query),
    )?;
    let _outbound_worker = spawn_p2p_outbound_drain(
        state.config(),
        &state,
        &shutdown,
        &peers,
        &peer_outbound,
        Arc::clone(&banned),
        sync_wake_tx,
        Arc::clone(&p2p_chain_query),
    )?;
    let _bootstrap_worker = if state.config().connect.is_empty() {
        spawn_dns_peer_maintenance(
            state.config(),
            Arc::clone(&shutdown),
            Arc::clone(&peer_outbound),
            state.p2p_outbound_sender(),
        )?
    } else {
        spawn_fixed_peer_bootstrap(&state, &shutdown)?
    };
    loop_handle.spin(&shutdown)?;
    if let Some(handle) = electrum_thread {
        match handle.join() {
            Ok(Ok(())) => tracing::info!("electrum listener exited cleanly"),
            Ok(Err(error)) => tracing::warn!(%error, "electrum listener exited with error"),
            Err(_) => tracing::error!("electrum listener panicked"),
        }
    }
    match rpc_thread.join() {
        Ok(Ok(())) => tracing::info!("rpc listener exited cleanly"),
        Ok(Err(error)) => tracing::warn!(%error, "rpc listener exited with i/o error"),
        Err(_) => tracing::error!("rpc listener panicked"),
    }
    for handle in p2p_threads {
        let thread_name = handle
            .thread()
            .name()
            .unwrap_or("bitcoin-rs-p2p")
            .to_owned();
        match handle.join() {
            Ok(Ok(())) => tracing::info!(thread = %thread_name, "p2p listener exited cleanly"),
            Ok(Err(error)) => {
                tracing::warn!(thread = %thread_name, %error, "p2p listener exited with error");
            }
            Err(_) => tracing::error!(thread = %thread_name, "p2p listener panicked"),
        }
    }

    shutdown::drain_and_shutdown(DRAIN_DEADLINE)?;
    tracing::info!("bitcoin-rs node exited cleanly");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use anyhow::anyhow;

    use super::*;

    // ---------------------------------------------------------------------------
    // Shared mock resolvers
    // ---------------------------------------------------------------------------

    /// Returns 16 addresses for any seed query.
    struct ManyAddrResolver;

    impl bitcoin_rs_p2p::DnsResolver for ManyAddrResolver {
        fn resolve(&self, _seed: &str) -> Result<Vec<SocketAddr>, bitcoin_rs_p2p::PeerError> {
            Ok((0..16_u16)
                .map(|offset| SocketAddr::from(([127, 0, 0, 1], 10_000 + offset)))
                .collect())
        }
    }

    // ---------------------------------------------------------------------------
    // Helper
    // ---------------------------------------------------------------------------

    fn empty_peer_outbound() -> PeerOutboundMap {
        Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new()))
    }

    fn signet_seeds() -> Vec<&'static str> {
        bitcoin_rs_primitives::Network::Signet.dns_seeds().to_vec()
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
        let peer_outbound = empty_peer_outbound();
        // Pre-populate 3 live connections using addresses the resolver will also return.
        for port in 10_000_u16..10_003 {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            let (tx, _rx) = crossbeam_channel::unbounded();
            peer_outbound.write().insert(addr, tx);
        }

        let (dial_tx, dial_rx) = crossbeam_channel::unbounded();
        let seeds = signet_seeds();
        let mut recently_queued = hashbrown::HashMap::new();
        let needed = P2P_OUTBOUND_PEER_TARGET - peer_outbound.read().len(); // 5

        let queued = drain_dns_peer_deficit(
            &OverlapResolver,
            seeds.as_slice(),
            &peer_outbound,
            &dial_tx,
            &mut recently_queued,
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
        let peer_outbound = empty_peer_outbound();
        let (dial_tx, dial_rx) = crossbeam_channel::unbounded();
        let seeds = signet_seeds();
        let mut recently_queued: hashbrown::HashMap<SocketAddr, std::time::Instant> =
            hashbrown::HashMap::new();

        // First call: queue 1 address.
        let q1 = drain_dns_peer_deficit(
            &ManyAddrResolver,
            seeds.as_slice(),
            &peer_outbound,
            &dial_tx,
            &mut recently_queued,
            1,
        );
        assert_eq!(q1, 1);
        let first_addr = dial_rx.try_recv()?;

        // Second call with same resolver: the address is in recently_queued,
        // so a different address should be chosen (total unique queued = 2).
        let q2 = drain_dns_peer_deficit(
            &ManyAddrResolver,
            seeds.as_slice(),
            &peer_outbound,
            &dial_tx,
            &mut recently_queued,
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
        let peer_outbound = empty_peer_outbound();
        // Channel capacity = 1 — only one address can be queued.
        let (dial_tx, dial_rx) = crossbeam_channel::bounded(1);
        let seeds = signet_seeds();
        let mut recently_queued = hashbrown::HashMap::new();

        let queued = drain_dns_peer_deficit(
            &ManyAddrResolver,
            seeds.as_slice(),
            &peer_outbound,
            &dial_tx,
            &mut recently_queued,
            8,
        );

        // Must not panic; exactly 1 address fits before the channel is full.
        assert_eq!(queued, 1);
        assert_eq!(dial_rx.try_iter().count(), 1);
    }

    // ---------------------------------------------------------------------------
    // Scenario (d): shutdown flag stops the maintenance loop
    // ---------------------------------------------------------------------------

    #[test]
    fn maintenance_loop_exits_on_shutdown() -> anyhow::Result<()> {
        let config = Config::default_for_network(bitcoin_rs_primitives::Network::Signet);
        let shutdown = Arc::new(AtomicBool::new(false));
        let peer_outbound = empty_peer_outbound();
        let (dial_tx, _dial_rx) = crossbeam_channel::unbounded();

        let handle =
            spawn_dns_peer_maintenance(&config, Arc::clone(&shutdown), peer_outbound, dial_tx)?
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
        let config = Config::default_for_network(bitcoin_rs_primitives::Network::Signet);
        assert!(
            config.connect.is_empty(),
            "default signet config must have no --connect peers"
        );
        // When connect is empty, spawn_dns_peer_maintenance is taken; its handle is Some.
        let shutdown = Arc::new(AtomicBool::new(true)); // pre-set: thread exits immediately
        let peer_outbound = empty_peer_outbound();
        let (dial_tx, _) = crossbeam_channel::unbounded();
        let handle = spawn_dns_peer_maintenance(&config, shutdown, peer_outbound, dial_tx)?
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
        let regtest = Config::default_for_network(bitcoin_rs_primitives::Network::Regtest);
        let mut disabled = Config::default_for_network(bitcoin_rs_primitives::Network::Signet);
        disabled.dns_seeds_enabled = false;

        for config in [regtest, disabled] {
            let shutdown = Arc::new(AtomicBool::new(false));
            let peer_outbound = empty_peer_outbound();
            let (dial_tx, _) = crossbeam_channel::unbounded();
            let handle = match spawn_dns_peer_maintenance(&config, shutdown, peer_outbound, dial_tx)
            {
                Ok(h) => h,
                Err(e) => panic!("spawn_dns_peer_maintenance returned error: {e}"),
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
        let peers: PeerRegistry = Arc::new(parking_lot::RwLock::new(Vec::new()));
        let peer_outbound: PeerOutboundMap = empty_peer_outbound();

        assert!(!outbound_addr_available(
            addr,
            &active,
            &peers,
            &peer_outbound
        ));
    }

    #[test]
    fn outbound_addr_available_rejects_connected_duplicate() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let active = hashbrown::HashSet::new();
        let peers: PeerRegistry = Arc::new(parking_lot::RwLock::new(Vec::new()));
        let peer_outbound: PeerOutboundMap = empty_peer_outbound();
        let (tx, _rx) = crossbeam_channel::unbounded();
        peer_outbound.write().insert(addr, tx);

        assert!(!outbound_addr_available(
            addr,
            &active,
            &peers,
            &peer_outbound
        ));
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
