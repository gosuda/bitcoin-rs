//! Incremental service composition shared by the daemon and embedded node.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::bounded;

use super::rpc::bind_rpc;
use super::services::{NodeServices, StartupGuard};
use crate::config::{NodeConfig, RuntimeInputs};
use crate::event_loop::EventLoop;
use crate::state::NodeState;

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
/// stopped and joined before the error is returned.
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
            panic!("state recorded above");
        };
        state.start_index_workers()?;
    }
    let Some(state) = guard.state.as_ref() else {
        panic!("state recorded above");
    };
    // Recovery completes before derived-index workers or network services
    // start. The guard owns every successfully created worker from here.
    tracing::info!(config = ?state.config(), "bitcoin-rs node booting");
    guard.services.metrics = if let Some(bind) = state.config().observability.metrics_bind {
        let identity = crate::metrics::EvidenceIdentity::of_process(state.config())?;
        crate::metrics::start_metrics(Some(bind), state.shutdown(), &identity)?
    } else {
        None
    };

    let shutdown = state.shutdown();
    let (shutdown_rx, event_loop_signal) = if let Some(rx) = injected_shutdown {
        (rx, None)
    } else {
        let (tx, rx) = bounded(1);
        if install_signals {
            guard.services.signal_handler = Some(crate::signal::install_shutdown_handler(
                Arc::clone(&shutdown),
                tx.clone(),
            )?);
        }
        (rx, Some(tx))
    };
    guard.services.event_loop_signal = event_loop_signal;
    let block_body_source = state.block_body_source();
    let p2p_chain_query: Arc<dyn bitcoin_rs_p2p::ChainQuery> = Arc::new(
        bitcoin_rs_p2p::ActiveChainQuery::new(state.block_tree())
            .with_block_body_source(Arc::clone(&block_body_source)),
    );
    let (sync_wake_tx, sync_wake_rx) = bounded(1);
    let sync = state.sync();
    let peer_ready_sync = Arc::clone(&sync);
    let loop_handle = EventLoop::with_sync_wake(shutdown_rx, sync, sync_wake_rx);
    let mining_control: Arc<dyn bitcoin_rs_mining::MiningControl> =
        Arc::new(crate::MiningCoordinator::new(
            state.config().network,
            state.applied_tip(),
            state.block_tree(),
            state.mempool(),
            state.apply_handles(),
            state.chain_followers(),
            state.config().mining.payout_script.clone(),
            Arc::clone(&shutdown),
        ));
    // The signal stores a Weak reference; the RPC context owns the
    // coordinator, without cycling through its apply handles.
    state.mining_generation_signal().attach(&mining_control);
    let gateway = state.mempool_gateway();
    let tx_inventory: Arc<dyn bitcoin_rs_p2p::TxInventory> = gateway.clone();
    let listener_extras = bitcoin_rs_p2p::ListenerExtras {
        tx_inventory: Some(tx_inventory),
        inbound_tx: Some(state.inbound_tx_sender()),
    };
    let (relay_queue, relay_rx) =
        bitcoin_rs_p2p::TxRelayQueue::new(bitcoin_rs_p2p::DEFAULT_TX_RELAY_QUEUE_CAPACITY);
    guard.services.tx_relay = Some(bitcoin_rs_p2p::spawn_tx_relay_worker(
        bitcoin_rs_p2p::PeerRelaySink::new(state.peer_table()),
        relay_rx,
        Arc::clone(&shutdown),
    )?);
    guard.services.tx_ingress = Some(crate::tx_ingress::spawn_tx_ingress_consumer(
        state,
        Arc::clone(&gateway),
        Arc::clone(&mining_control),
        Arc::clone(&shutdown),
        state.inbound_tx_rx_handle(),
        relay_queue.clone(),
    )?);
    gateway
        .attach_observer_leg(
            "tx-relay",
            Arc::new(bitcoin_rs_p2p::LocalTxRelayObserver::new(
                relay_queue,
                Arc::downgrade(&gateway),
            )),
        )
        .map_err(anyhow::Error::msg)?;

    let (context, rpc_server) = bind_rpc(state, &mining_control, block_body_source)?;
    let rpc_local_addr = rpc_server.local_addr()?;
    tracing::info!(addr = %rpc_local_addr, "rpc listener bound");
    let rpc_shutdown = Arc::clone(&shutdown);
    guard.services.rpc_thread = Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-rpc".into())
            .spawn(move || rpc_server.serve_with_shutdown(rpc_shutdown))?,
    );
    let peer_ready: Arc<dyn Fn(bitcoin_rs_p2p::PeerSource) + Send + Sync> =
        Arc::new(move |source: bitcoin_rs_p2p::PeerSource| {
            peer_ready_sync.on_peer_ready(source);
        });
    state
        .p2p()
        .start(
            Some(&p2p_chain_query),
            Some(&sync_wake_tx),
            &peer_ready,
            listener_extras,
        )
        .map_err(anyhow::Error::from)?;
    guard.services.checkpoint_worker = Some(state.start_periodic_checkpoint(
        crate::checkpoint_worker::CHECKPOINT_INTERVAL_BLOCKS,
        Duration::from_secs(crate::checkpoint_worker::CHECKPOINT_INTERVAL_SECS),
    )?);
    guard.services.event_loop = Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-event-loop".into())
            .spawn(move || loop_handle.spin(&shutdown))?,
    );
    let (state, services) = guard.disarm();
    Ok((state, services, context))
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
