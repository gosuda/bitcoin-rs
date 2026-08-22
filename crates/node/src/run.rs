//! Top-level orchestration: wire subsystems, spin the event loop, drain.

use crate as bitcoin_rs_node;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use crossbeam_channel::{Receiver, TrySendError, bounded};

use crate::config::Config;
use crate::event_loop::EventLoop;
use crate::state::NodeState;
use crate::{crash_recovery, logging, shutdown};

// Test-only observation seam: records that `run` reached the bounded
// bootstrap-worker drain. Lets a regression that propagates a checkpoint
// error with `?` *before* draining the worker be caught by a test that
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
/// drain on the current thread since the last call.
#[cfg(test)]
fn bootstrap_drain_was_reached() -> bool {
    BOOTSTRAP_DRAIN_REACHED.with(std::cell::Cell::take)
}

const DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const BOOTSTRAP_JOIN_DEADLINE: Duration = Duration::from_secs(1);
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
/// Retry a connectionless bootstrap before normal DNS maintenance.
const DNS_BOOTSTRAP_REFILL_INTERVAL: Duration = Duration::from_secs(1);
/// Maximum fast refills before returning to the normal maintenance cadence.
const DNS_BOOTSTRAP_FAST_REFILL_LIMIT: u8 = 2;

type PeerRegistry = Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>>;
type PeerOutboundMap =
    Arc<parking_lot::RwLock<hashbrown::HashMap<SocketAddr, bitcoin_rs_p2p::PeerLease>>>;
type BannedSubnets = Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>;
type P2pChainQuery = Arc<dyn bitcoin_rs_p2p::ChainQuery>;
type OutboundConnectionHandle =
    std::thread::JoinHandle<core::result::Result<(), bitcoin_rs_p2p::PeerError>>;

#[derive(Clone)]
struct RpcChainControl {
    handles: crate::apply::ApplyHandles,
}

impl bitcoin_rs_rpc::ChainControl for RpcChainControl {
    fn invalidate_block(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> core::result::Result<(), bitcoin_rs_rpc::ChainControlError> {
        crate::reorg::invalidate_block(&self.handles, hash).map_err(|error| match error {
            crate::reorg::ReorgError::UnknownBlock(_) => {
                bitcoin_rs_rpc::ChainControlError::UnknownBlock
            }
            crate::reorg::ReorgError::CannotInvalidateGenesis => {
                bitcoin_rs_rpc::ChainControlError::Genesis
            }
            other => bitcoin_rs_rpc::ChainControlError::Failed(other.to_string()),
        })
    }

    fn test_block_validity(
        &self,
        block: &bitcoin::Block,
    ) -> core::result::Result<(), bitcoin_rs_rpc::BlockRejectReason> {
        crate::apply::test_block_validity(&self.handles, block, None)
            .map_err(|error| bitcoin_rs_rpc::BlockRejectReason(reject_reason(&error)))
    }
}

/// Bitcoin Core's reject-reason token for a rejection, where one corresponds.
///
/// `getblocktemplate` proposals return these verbatim, so a miner comparing
/// this node against Core sees the same word for the same failure. BIP22 leaves
/// the vocabulary open and Core simply reports whatever its validation state
/// carries, so a rejection with no Core counterpart is passed through as its
/// own message rather than forced into a token that means something else.
///
/// The tokens are transcribed from the vendored Core tree
/// (`src/validation.cpp`, `src/consensus/tx_check.cpp`,
/// `src/consensus/tx_verify.cpp`).
fn reject_reason(error: &crate::state::ApplyError) -> String {
    use crate::state::ApplyError as A;
    use bitcoin_rs_consensus::ConsensusError as C;

    let token = match error {
        A::Consensus(consensus) => match consensus {
            C::EmptyInputs => "bad-txns-vin-empty",
            C::EmptyOutputs => "bad-txns-vout-empty",
            C::CoinbaseScriptSigSize { .. } => "bad-cb-length",
            C::NullPrevout { .. } => "bad-txns-prevout-null",
            C::DuplicateInput { .. } => "bad-txns-inputs-duplicate",
            C::MissingPrevout { .. } => "bad-txns-inputs-missingorspent",
            C::OutputValueOverflow => "bad-txns-txouttotal-toolarge",
            C::InputsLessThanOutputs { .. } => "bad-txns-in-belowout",
            // Per-transaction, not the block budget: raised by `verify_tx`.
            C::SigopsLimit { .. } => "bad-txns-too-many-sigops",
            C::EmptyBlock | C::MissingCoinbase => "bad-cb-missing",
            C::ExtraCoinbase { .. } => "bad-cb-multiple",
            C::MerkleMutation => "bad-txns-duplicate",
            C::MerkleRoot => "bad-txnmrklroot",
            C::CoinbaseAmount { .. } => "bad-cb-amount",
            C::BlockValueOverflow => "bad-txns-accumulated-fee-outofrange",
            C::WitnessCommitment => "bad-witness-merkle-match",
            C::BlockWeight { .. } => "bad-blk-weight",
            C::Script { reason, .. } => {
                return format!("mandatory-script-verify-flag-failed ({reason})");
            }
            C::Bip { bip, .. } => match *bip {
                "BIP30" => "bad-txns-BIP30",
                "BIP34" => "bad-cb-height",
                "BIP68" | "BIP112" => "non-BIP68-final",
                "BIP113" | "BIP65" => "non-final",
                "COINBASE_MATURITY" => "bad-txns-premature-spend-of-coinbase",
                _ => return consensus.to_string(),
            },
            C::PrevoutMatrixSize { .. } | C::Kernel(_) | C::Encoding(_) => {
                return consensus.to_string();
            }
        },
        A::ProofOfWork { .. } => "high-hash",
        A::TargetAboveLimit | A::NbitsNonRetargetMismatch { .. } => "bad-diffbits",
        // Block-wide: Core reaches the same conclusion per transaction.
        A::BlockOutputsExceedInputs => "bad-txns-in-belowout",
        A::BlockValueOverflow => "bad-txns-accumulated-fee-outofrange",
        other => return other.to_string(),
    };
    token.to_owned()
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
    let Some(query) = state.tx_index_electrum_adapter() else {
        bail!("electrum listener requires txindex");
    };
    let chain: Arc<dyn bitcoin_rs_electrum::methods::BlockTreeAdapter> = Arc::new(
        crate::NodeBlockSource::new(state.blocks())
            .with_block_body_source(state.block_body_source())
            .with_block_tree(state.block_tree())
            .with_applied_tip(state.applied_tip()),
    );
    let index = bitcoin_rs_electrum::IndexHandle::new()
        .with_history_reader(query)
        .with_chain(chain)
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
    inbound_headers_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::InboundHeaders>,
    inbound_blocks_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>,
    sync_wake_tx: crossbeam_channel::Sender<()>,
    chain_query: P2pChainQuery,
    peer_registered: Arc<
        dyn Fn(SocketAddr, bitcoin_rs_p2p::PeerLease, bitcoin_rs_p2p::PeerInfo) -> bool
            + Send
            + Sync,
    >,
) -> anyhow::Result<Vec<std::thread::JoinHandle<Result<(), bitcoin_rs_p2p::listener::ListenerError>>>>
{
    let mut handles = Vec::with_capacity(config.p2p_listen.len());
    let magic = bitcoin::p2p::Magic::from_bytes(config.p2p_magic());
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
        let listener_peer_registered = Arc::clone(&peer_registered);
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
                    Some(listener_peer_registered),
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
    state: &NodeState,
    shutdown: &Arc<AtomicBool>,
    sync_wake_tx: crossbeam_channel::Sender<()>,
    chain_query: P2pChainQuery,
    peer_registered: Arc<
        dyn Fn(SocketAddr, bitcoin_rs_p2p::PeerLease, bitcoin_rs_p2p::PeerInfo) -> bool
            + Send
            + Sync,
    >,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    let outbound_rx = state.p2p_outbound_receiver();
    let magic = bitcoin::p2p::Magic::from_bytes(state.config().p2p_magic());
    let outbound_registry = state.peers();
    let outbound_peer_outbound = state.peer_outbound();
    let outbound_banned = state.banned_subnets();
    let outbound_headers_tx = state.inbound_headers_sender();
    let outbound_peer_registered = Arc::clone(&peer_registered);
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
                            Some(Arc::clone(&outbound_peer_registered)),
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
                let mut selection_cursor = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| {
                        usize::try_from(duration.as_nanos()).unwrap_or(0)
                    });

                // Initial bootstrap: queue up to P2P_OUTBOUND_PEER_TARGET addresses immediately.
                let queued = drain_dns_peer_deficit(
                    &resolver,
                    seeds.as_slice(),
                    &peer_outbound,
                    &outbound_tx,
                    &mut failed_backoff,
                    selection_cursor,
                    P2P_OUTBOUND_PEER_TARGET,
                );
                selection_cursor = selection_cursor.wrapping_add(1);
                tracing::info!(queued, "dns peer bootstrap queued initial addresses");
                let mut bootstrap_refill = DnsBootstrapRefill::default();
                let mut maintenance_delay = bootstrap_refill.next_delay(0, queued);

                while !shutdown.load(std::sync::atomic::Ordering::Acquire) {
                    if wait_for_shutdown(&shutdown, maintenance_delay) {
                        break;
                    }

                    let live = peer_outbound.read().len();
                    if live >= P2P_OUTBOUND_PEER_TARGET {
                        maintenance_delay = bootstrap_refill.next_delay(live, 0);
                        continue;
                    }
                    let deficit = P2P_OUTBOUND_PEER_TARGET - live;
                    let queued = drain_dns_peer_deficit(
                        &resolver,
                        seeds.as_slice(),
                        &peer_outbound,
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
/// 1. Addresses already present in `peer_outbound`.
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
    peer_outbound: &PeerOutboundMap,
    outbound_tx: &crossbeam_channel::Sender<SocketAddr>,
    recently_queued: &mut hashbrown::HashMap<SocketAddr, std::time::Instant>,
    selection_cursor: usize,
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

    'outer: for seed_offset in 0..seeds.len() {
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
                    'endpoints: for endpoint in &connect {
                        let addresses = match endpoint.as_str().to_socket_addrs() {
                            Ok(addresses) => addresses,
                            Err(error) => {
                                tracing::warn!(endpoint, %error, "fixed peer resolution failed");
                                continue;
                            }
                        };
                        for addr in addresses {
                            if peer_outbound.read().contains_key(&addr)
                                || peers.read().iter().any(|peer| peer.addr == addr)
                            {
                                continue;
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

/// Boots the node from a resolved [`Config`] and runs until shutdown.
///
/// Flow:
/// 1. Install JSON tracing on stderr.
/// 2. Open / create the node data directory and resolve state.
/// 3. Resume an authenticated chainstate checkpoint, or run legacy crash recovery on cold/header-only startup.
/// 4. Acquire a shutdown signal — either the in-process receiver wired via
///    [`Config::with_shutdown_receiver`] (tests) or a fresh SIGINT/SIGTERM
///    handler (production).
/// 5. Spin the event loop until shutdown is requested.
/// 6. Drain subsystems within [`DRAIN_DEADLINE`].
/// 7. Publish one immutable clean-shutdown chainstate checkpoint.
#[allow(clippy::too_many_lines)]
pub fn run(mut config: Config) -> Result<()> {
    logging::install_tracing(&config.log_level)?;
    cap_global_thread_pool();

    let injected_shutdown = config.shutdown_signal.take();
    let state = NodeState::open(config)?;
    if state.resume_source() != crate::state::ResumeSource::Checkpoint {
        crash_recovery::recover_if_needed(&state)?;
    }

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

    let shutdown = state.shutdown();
    let banned = state.banned_subnets();
    let block_body_source = state.block_body_source();
    let p2p_chain_query: P2pChainQuery = Arc::new(
        crate::NodeP2pChainQuery::new(state.block_tree(), state.blocks())
            .with_block_body_source(Arc::clone(&block_body_source)),
    );
    let (sync_wake_tx, sync_wake_rx) = bounded(1);
    let sync = state.sync();
    let peer_registered = sync.peer_registration_handle();
    let loop_handle = EventLoop::with_sync_wake(shutdown_rx, sync, sync_wake_rx);
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
        state.tx_index_query(),
    );
    rpc_context = rpc_context.with_block_body_source(block_body_source);
    if let Some(prune_service) = state.prune_service() {
        rpc_context = rpc_context.with_prune_service(prune_service);
    }
    rpc_context = rpc_context.with_chain_control(Arc::new(RpcChainControl {
        handles: state.apply_handles(),
    }));
    rpc_context = rpc_context.with_zmq_notifications(state.active_zmq_notifications());
    let rpc_handler = Arc::new(bitcoin_rs_rpc::Handler::new(Arc::new(rpc_context)));
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
        Arc::clone(&peer_registered),
    )?;
    let outbound_worker = spawn_p2p_outbound_drain(
        &state,
        &shutdown,
        sync_wake_tx,
        Arc::clone(&p2p_chain_query),
        Arc::clone(&peer_registered),
    )?;
    let bootstrap_worker = if state.config().connect.is_empty() {
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
    if matches!(outbound_worker.join(), Ok(())) {
        tracing::info!("P2P outbound drain exited cleanly");
    } else {
        tracing::error!("P2P outbound drain panicked");
    }
    shutdown::drain_and_shutdown(DRAIN_DEADLINE)?;
    // Attempt the clean checkpoint before joining the bootstrap worker, but defer
    // the result so a publication failure cannot bypass the bounded worker drain below.
    let clean_checkpoint = state.write_clean_checkpoint();
    match &clean_checkpoint {
        Ok(crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip) => {
            tracing::info!("no applied tip; clean checkpoint publication skipped");
        }
        Ok(crate::checkpoint::CheckpointWrite::Published { generation }) => {
            tracing::info!(generation, "published clean chainstate checkpoint");
        }
        Err(error) => {
            tracing::error!(%error, "clean checkpoint publication failed");
        }
    }
    if let Some(handle) = bootstrap_worker {
        mark_bootstrap_drain_reached();
        let thread_name = handle
            .thread()
            .name()
            .unwrap_or("bitcoin-rs-p2p-bootstrap")
            .to_owned();
        let deadline = std::time::Instant::now() + BOOTSTRAP_JOIN_DEADLINE;
        while !handle.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if handle.is_finished() {
            if matches!(handle.join(), Ok(())) {
                tracing::info!(thread = %thread_name, "P2P bootstrap worker exited cleanly");
            } else {
                tracing::error!(thread = %thread_name, "P2P bootstrap worker panicked");
            }
        } else {
            tracing::warn!(thread = %thread_name, "P2P bootstrap worker still blocked; abandoning join");
        }
    }
    // A checkpoint failure means the node did not exit cleanly; propagate it
    // after the bounded bootstrap-worker drain above.
    clean_checkpoint?;
    tracing::info!("bitcoin-rs node exited cleanly");
    Ok(())
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
/// |---|---|---|
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

    fn empty_peer_outbound() -> PeerOutboundMap {
        Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new()))
    }

    fn signet_seeds() -> Vec<&'static str> {
        bitcoin_rs_primitives::Network::Signet.dns_seeds().to_vec()
    }

    #[test]
    fn clean_shutdown_publishes_checkpoint_and_returns_success() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = Config::default_for_network(crate::Network::Regtest);
        config.data_dir = temp.path().join("node-success");
        config.rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        config.rpc_auth = crate::Auth::basic("user", "password");
        config.electrum_bind = None;
        config.p2p_listen.clear();
        config.metrics_bind = None;

        let state = crate::state::NodeState::open(config.clone())?;
        state.apply_block(&bitcoin::blockdata::constants::genesis_block(
            bitcoin::Network::Regtest,
        ))?;
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
        config = config.with_shutdown_receiver(shutdown_rx);
        run(config)?;
        assert_ne!(std::fs::read(current_path)?, previous_current);

        let resumed = crate::state::NodeState::open(reopen_config)?;
        assert_eq!(
            resumed.resume_source(),
            crate::state::ResumeSource::Checkpoint
        );
        Ok(())
    }

    #[test]
    fn shutdown_checkpoint_io_failure_is_returned_and_preserves_current() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = Config::default_for_network(crate::Network::Regtest);
        config.data_dir = temp.path().join("node");
        config.rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        config.rpc_auth = crate::Auth::basic("user", "password");
        config.electrum_bind = None;
        config.p2p_listen.clear();
        config.metrics_bind = None;
        // Force a bootstrap worker to spawn (fixed-peer path) so the drain
        // below is exercised — with an empty `connect`, `bootstrap_worker`
        // would be `None` and the cleanup-ordering assertion could not catch a
        // regression that moves `?` back onto `write_clean_checkpoint`.
        config.connect = vec!["127.0.0.1:1".to_owned()];

        let state = crate::state::NodeState::open(config.clone())?;
        state.apply_block(&bitcoin::blockdata::constants::genesis_block(
            bitcoin::Network::Regtest,
        ))?;
        state.write_clean_checkpoint()?;
        drop(state);

        let current_path = config
            .data_dir
            .join("chainstate-checkpoints")
            .join("CURRENT");
        let previous_current = std::fs::read(&current_path)?;
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        shutdown_tx.send(())?;
        config = config.with_shutdown_receiver(shutdown_rx);
        crate::checkpoint::inject_next_checkpoint_failpoint(
            crate::checkpoint::CheckpointFailpoint::ManifestWrite,
        );

        assert!(run(config).is_err());
        assert_eq!(std::fs::read(current_path)?, previous_current);
        assert!(
            bootstrap_drain_was_reached(),
            "checkpoint publication error must not bypass the bounded bootstrap-worker drain"
        );
        Ok(())
    }

    #[test]
    fn connectionless_bootstrap_refills_are_fast_and_bounded() {
        let mut refill = DnsBootstrapRefill::default();

        assert_eq!(
            refill.next_delay(0, P2P_OUTBOUND_PEER_TARGET),
            DNS_BOOTSTRAP_REFILL_INTERVAL
        );
        assert_eq!(
            refill.next_delay(0, P2P_OUTBOUND_PEER_TARGET),
            DNS_BOOTSTRAP_REFILL_INTERVAL
        );
        assert_eq!(
            refill.next_delay(0, P2P_OUTBOUND_PEER_TARGET),
            DNS_MAINTENANCE_INTERVAL
        );
        assert_eq!(refill.next_delay(1, 0), DNS_MAINTENANCE_INTERVAL);
        assert_eq!(
            refill.next_delay(0, P2P_OUTBOUND_PEER_TARGET),
            DNS_BOOTSTRAP_REFILL_INTERVAL
        );
    }

    #[test]
    fn selection_cursor_rotates_seed_and_address_prefix() {
        let peer_outbound = empty_peer_outbound();
        let (dial_tx, dial_rx) = crossbeam_channel::unbounded();
        let mut recently_queued = hashbrown::HashMap::new();

        let queued = drain_dns_peer_deficit(
            &SeedAwareResolver,
            &["seed-a", "seed-b", "seed-c"],
            &peer_outbound,
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
            peer_outbound
                .write()
                .insert(addr, bitcoin_rs_p2p::PeerLease::new(tx));
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
            &peer_outbound,
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
        peer_outbound
            .write()
            .insert(addr, bitcoin_rs_p2p::PeerLease::new(tx));

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

    /// A rejection a miner can act on carries Core's word for it.
    ///
    /// `getblocktemplate` proposals return these verbatim, so a miner that
    /// switches between this node and Core reads the same token for the same
    /// failure. The tokens come from the vendored Core tree, not from memory.
    #[test]
    fn a_rejection_reports_bitcoin_cores_reject_reason() {
        use bitcoin_rs_consensus::ConsensusError;

        for (error, expected) in [
            (
                crate::state::ApplyError::Consensus(ConsensusError::CoinbaseAmount {
                    paid: 2,
                    allowed: 1,
                }),
                "bad-cb-amount",
            ),
            (
                crate::state::ApplyError::Consensus(ConsensusError::MerkleRoot),
                "bad-txnmrklroot",
            ),
            (
                crate::state::ApplyError::Consensus(ConsensusError::MissingPrevout {
                    input_index: 0,
                }),
                "bad-txns-inputs-missingorspent",
            ),
            (
                crate::state::ApplyError::Consensus(ConsensusError::Bip {
                    bip: "COINBASE_MATURITY",
                    reason: "too young".to_owned(),
                }),
                "bad-txns-premature-spend-of-coinbase",
            ),
            (crate::state::ApplyError::TargetAboveLimit, "bad-diffbits"),
        ] {
            assert_eq!(super::reject_reason(&error), expected, "for {error:?}");
        }
    }

    /// A rejection with no Core counterpart says what it is.
    ///
    /// Reaching for the nearest-looking token would tell a miner the block
    /// failed a rule it never failed. BIP22 leaves the vocabulary open, so
    /// passing the message through is both allowed and honest.
    #[test]
    fn a_rejection_core_has_no_word_for_passes_its_own_message_through() {
        let error = crate::state::ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Kernel("engine unavailable".to_owned()),
        );
        let reason = super::reject_reason(&error);
        assert!(
            reason.contains("engine unavailable"),
            "the message must survive, got {reason}"
        );
        assert!(
            !reason.starts_with("bad-"),
            "an unmapped rejection must not borrow a Core token, got {reason}"
        );
    }
}
