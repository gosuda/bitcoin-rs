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
const DNS_BOOTSTRAP_ADDR_LIMIT: usize = 8;
const P2P_OUTBOUND_ACTIVE_LIMIT: usize = crate::state::P2P_OUTBOUND_QUEUE_LIMIT;

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

fn spawn_dns_seed_bootstrap(
    config: Config,
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

    Ok(Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-dns-bootstrap".to_owned())
            .spawn(move || {
                let resolver =
                    bitcoin_rs_p2p::SystemDnsResolver::new(config.network.default_p2p_port());
                match queue_dns_seed_bootstrap(&config, &resolver, &outbound_tx) {
                    Ok(queued) => tracing::info!(queued, "dns peer bootstrap queued addresses"),
                    Err(error) => tracing::warn!(%error, "dns peer bootstrap failed"),
                }
            })?,
    ))
}

fn queue_dns_seed_bootstrap<R>(
    config: &Config,
    resolver: &R,
    outbound_tx: &crossbeam_channel::Sender<SocketAddr>,
) -> anyhow::Result<usize>
where
    R: bitcoin_rs_p2p::DnsResolver + ?Sized,
{
    if !config.dns_seeds_enabled
        || matches!(config.network, bitcoin_rs_primitives::Network::Regtest)
    {
        return Ok(0);
    }

    let mut queued = Vec::new();
    for seed in config.network.dns_seeds() {
        let addresses = match resolver.resolve(seed) {
            Ok(addresses) => addresses,
            Err(error) => {
                tracing::warn!(seed = %seed, %error, "dns seed resolution failed");
                continue;
            }
        };
        for addr in addresses {
            if queued.contains(&addr) {
                continue;
            }
            match outbound_tx.try_send(addr) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    tracing::info!("dns peer bootstrap stopped: outbound queue full");
                    return Ok(queued.len());
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(anyhow::anyhow!(
                        "p2p outbound channel closed during DNS bootstrap"
                    ));
                }
            }
            queued.push(addr);
            if queued.len() == DNS_BOOTSTRAP_ADDR_LIMIT {
                tracing::info!(
                    limit = DNS_BOOTSTRAP_ADDR_LIMIT,
                    "dns peer bootstrap limit reached"
                );
                return Ok(queued.len());
            }
        }
    }
    if queued.is_empty() {
        tracing::warn!("dns peer bootstrap yielded no addresses");
    }
    Ok(queued.len())
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
    let _bootstrap_worker =
        spawn_dns_seed_bootstrap(state.config().clone(), state.p2p_outbound_sender())?;
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
    use super::*;

    struct StaticResolver;

    impl bitcoin_rs_p2p::DnsResolver for StaticResolver {
        fn resolve(&self, seed: &str) -> Result<Vec<SocketAddr>, bitcoin_rs_p2p::PeerError> {
            let port = match seed {
                "seed.signet.bitcoin.sprovoost.nl." => 38333,
                "seed.signet.achownodes.xyz." => 38334,
                _ => return Ok(Vec::new()),
            };
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
        }
    }

    struct ManyAddressResolver;

    impl bitcoin_rs_p2p::DnsResolver for ManyAddressResolver {
        fn resolve(&self, _seed: &str) -> Result<Vec<SocketAddr>, bitcoin_rs_p2p::PeerError> {
            Ok((0..16)
                .map(|offset| SocketAddr::from(([127, 0, 0, 1], 10_000 + offset)))
                .collect())
        }
    }

    struct FailingResolver;

    impl bitcoin_rs_p2p::DnsResolver for FailingResolver {
        fn resolve(&self, _seed: &str) -> Result<Vec<SocketAddr>, bitcoin_rs_p2p::PeerError> {
            Err(bitcoin_rs_p2p::PeerError::Protocol("test resolver failure"))
        }
    }

    #[test]
    fn dns_seed_bootstrap_queues_resolved_public_seed_addresses() -> anyhow::Result<()> {
        let config = Config::default_for_network(bitcoin_rs_primitives::Network::Signet);
        let (tx, rx) = crossbeam_channel::unbounded();

        assert_eq!(queue_dns_seed_bootstrap(&config, &StaticResolver, &tx)?, 2);
        assert_eq!(rx.try_recv()?, SocketAddr::from(([127, 0, 0, 1], 38333)));
        assert_eq!(rx.try_recv()?, SocketAddr::from(([127, 0, 0, 1], 38334)));
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn dns_seed_bootstrap_caps_queued_addresses() -> anyhow::Result<()> {
        let config = Config::default_for_network(bitcoin_rs_primitives::Network::Signet);
        let (tx, rx) = crossbeam_channel::unbounded();

        assert_eq!(
            queue_dns_seed_bootstrap(&config, &ManyAddressResolver, &tx)?,
            DNS_BOOTSTRAP_ADDR_LIMIT
        );
        assert_eq!(rx.try_iter().count(), DNS_BOOTSTRAP_ADDR_LIMIT);
        Ok(())
    }

    #[test]
    fn dns_seed_bootstrap_stops_when_outbound_queue_is_full() -> anyhow::Result<()> {
        let config = Config::default_for_network(bitcoin_rs_primitives::Network::Signet);
        let (tx, rx) = crossbeam_channel::bounded(1);

        assert_eq!(
            queue_dns_seed_bootstrap(&config, &ManyAddressResolver, &tx)?,
            1
        );
        assert_eq!(rx.try_iter().count(), 1);
        Ok(())
    }

    #[test]
    fn dns_seed_bootstrap_reports_closed_outbound_queue() {
        let config = Config::default_for_network(bitcoin_rs_primitives::Network::Signet);
        let (tx, rx) = crossbeam_channel::bounded(1);
        drop(rx);

        assert!(queue_dns_seed_bootstrap(&config, &StaticResolver, &tx).is_err());
    }

    #[test]
    fn outbound_addr_available_rejects_active_duplicate() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let mut active = hashbrown::HashSet::new();
        active.insert(addr);
        let peers: PeerRegistry = Arc::new(parking_lot::RwLock::new(Vec::new()));
        let peer_outbound: PeerOutboundMap =
            Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new()));

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
        let peer_outbound: PeerOutboundMap =
            Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new()));
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

    #[test]
    fn dns_seed_bootstrap_skips_disabled_and_regtest_configs() -> anyhow::Result<()> {
        let mut disabled = Config::default_for_network(bitcoin_rs_primitives::Network::Signet);
        disabled.dns_seeds_enabled = false;
        let regtest = Config::default_for_network(bitcoin_rs_primitives::Network::Regtest);
        let (tx, rx) = crossbeam_channel::unbounded();

        assert_eq!(
            queue_dns_seed_bootstrap(&disabled, &FailingResolver, &tx)?,
            0
        );
        assert_eq!(
            queue_dns_seed_bootstrap(&regtest, &FailingResolver, &tx)?,
            0
        );
        assert!(rx.try_recv().is_err());
        Ok(())
    }
}
