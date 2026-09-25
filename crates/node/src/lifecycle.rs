//! The single owner of node startup, rollback, and ordered service shutdown.
//!
//! Startup returns a fully owned `Node`, not detached state and worker handles.
//! The daemon and embedding surfaces both enter this lifecycle directly.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;

use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_rpc::{
    RpcServer,
    context::{
        ChainControl, ChainControlError, ChainHandles, Context, ContextHandles, IndexHandles,
        MempoolHandles, MiningHandles, NetworkHandles,
    },
};

use crossbeam_channel::bounded;

use crate::config::{NodeConfig, RuntimeInputs};
use crate::embed::Node;
use crate::event_loop::EventLoop;
use crate::shutdown;
use crate::state::NodeState;

pub(crate) const DRAIN_DEADLINE: Duration = Duration::from_secs(5);

const RPC_MAX_CONNECTIONS: usize = 128;
const RPC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct RpcChainControl {
    handles: Arc<bitcoin_rs_chainstate::Chainstate>,
    followers: crate::chain_effects::ChainFollowers,
    sync: Arc<crate::BlockSync>,
}

impl ChainControl for RpcChainControl {
    fn invalidate_block(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> core::result::Result<(), ChainControlError> {
        let invalidated = crate::reorg::invalidate_block(&self.handles, &self.followers, hash)
            .map_err(|error| match error {
                crate::reorg::ReorgError::UnknownBlock(_) => ChainControlError::UnknownBlock,
                crate::reorg::ReorgError::CannotInvalidateGenesis => ChainControlError::Genesis,
                other => ChainControlError::Failed(other.to_string()),
            })?;
        // The transition is already released; the invalid descendants must
        // not keep occupying bounded download staging.
        self.sync.purge_invalidated(&invalidated);
        Ok(())
    }
}

/// Binds the RPC listener without spawning a worker. Startup records the
/// worker immediately after spawning, so a later failure cannot detach it.
fn bind_rpc(
    state: &NodeState,
    mining_control: &Arc<dyn MiningControl>,
    block_body_source: Arc<dyn BlockBodySource>,
    ibd: &Arc<bitcoin_rs_chain::InitialBlockDownload>,
) -> Result<(Arc<Context>, RpcServer)> {
    let rpc_auth = Arc::new(state.config().rpc.auth.to_rpc_auth()?);
    let chainstate = state.chainstate();
    let context = Context::from_handles(ContextHandles {
        chain: ChainHandles {
            chain_tip: chainstate.chain_tip_handle(),
            applied_tip: chainstate.applied_tip_handle(),
            chain_tx_count: chainstate.chain_tx_count_handle(),
            ibd: Arc::clone(ibd),
            blocks: state.blocks(),
            transactions: state.transactions(),
            utxo: chainstate.utxo_handle(),
            coin_stats: chainstate.coin_stats_handle(),
            block_tree: chainstate.block_tree_handle(),
            chain_network: state.config().network,
            chain_transition: chainstate.read_fence(),
            block_body_source: Some(block_body_source),
            prune_service: state.prune_service(),
            chain_control: Some(Arc::new(RpcChainControl {
                handles: chainstate,
                followers: state.chain_followers(),
                sync: state.sync(),
            })),
            rollback_warnings: Some(state.recovery_reporter()),
        },
        mempool: MempoolHandles {
            gateway: state.mempool_gateway(),
        },
        indexes: IndexHandles {
            derived_index: state.derived_index_query(),
            script_index: state.script_index_query(),
            esplora_tx_index: state.esplora_derived_index_query(),
            derived_index_status: Some(state.derived_index_status()),
        },
        network: NetworkHandles {
            network: state.network(),
            network_active: state.network_active(),
            peer_table: state.peer_table(),
            p2p_outbound_sender: Some(state.p2p_outbound_sender()),
            banned: state.banned_subnets(),
            added_nodes: state.added_nodes(),
        },
        mining: MiningHandles {
            mining_control: Some(Arc::clone(mining_control)),
        },
        zmq_publisher: state.zmq_publisher(),
        debug_log_path: Some(state.data_dir().join("debug.log")),
    });
    let context = Arc::new(context);
    let handler = Arc::new(bitcoin_rs_rpc::Handler::new(Arc::clone(&context)));
    let server = RpcServer::bind(
        state.config().rpc.bind,
        rpc_auth,
        handler,
        RPC_MAX_CONNECTIONS,
        RPC_IDLE_TIMEOUT,
        state.config().rpc.rest,
    )?;
    Ok((context, server))
}

// Records that teardown reached the bootstrap join on the current thread.
// This seam never adds state or an API to production builds.
#[cfg(test)]
std::thread_local! {
    static BOOTSTRAP_DRAIN_REACHED: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static BEFORE_CLEAN_CHECKPOINT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn mark_bootstrap_drain_reached() {
    BOOTSTRAP_DRAIN_REACHED.with(|slot| slot.set(true));
}

#[cfg(not(test))]
const fn mark_bootstrap_drain_reached() {}

#[cfg(test)]
fn bootstrap_drain_was_reached() -> bool {
    BOOTSTRAP_DRAIN_REACHED.with(std::cell::Cell::take)
}

#[cfg(test)]
fn inject_before_clean_checkpoint(hook: impl FnOnce() + 'static) {
    BEFORE_CLEAN_CHECKPOINT.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_before_clean_checkpoint_hook() {
    BEFORE_CLEAN_CHECKPOINT.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
const fn run_before_clean_checkpoint_hook() {}

/// How the one ordered teardown was reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TeardownMode {
    /// Startup did not complete; never publish a successful-run marker.
    StartupAbort,
    /// Publish a checkpoint only after every service joined successfully.
    CleanShutdown,
}

/// Node-owned workers and socket owners. P2P workers are owned by
/// `P2pService`, whose joins participate in this graph's teardown.
///
/// Each handle is taken exactly once. The idempotence guard makes explicit
/// shutdown followed by Drop safe, and prevents repeated lifecycle work.
#[derive(Default)]
pub(crate) struct NodeServices {
    event_loop: Option<std::thread::JoinHandle<anyhow::Result<()>>>,
    event_loop_signal: Option<crossbeam_channel::Sender<()>>,
    /// Stops and joins its listener in Drop.
    metrics: Option<crate::metrics::MetricsServer>,
    rpc_thread: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    /// Chainstate idle maintenance (journal flush, retention); joined
    /// before the final clean checkpoint publication.
    maintenance_worker: Option<std::thread::JoinHandle<()>>,
    tx_ingress: Option<std::thread::JoinHandle<()>>,
    /// Publishes the capability readiness gauge until shutdown.
    readiness_sampler: Option<std::thread::JoinHandle<()>>,
    tx_relay: Option<std::thread::JoinHandle<()>>,
    signal_handler: Option<crate::signal::ShutdownHandler>,
    teardown_started: bool,
    /// Failure injection at the core-worker join boundary, not a P2P owner.
    #[cfg(test)]
    outbound_worker: Option<std::thread::JoinHandle<()>>,
    /// Failure/delay injection at the bootstrap join boundary.
    #[cfg(test)]
    bootstrap_worker: Option<std::thread::JoinHandle<()>>,
}

impl NodeServices {
    /// Raises shutdown, wakes and joins the event loop, joins core services,
    /// drains subsystems, joins bootstrap/maintenance/signal workers, and only
    /// then publishes a clean checkpoint. The first error is returned after
    /// all remaining cleanup stages run; any error suppresses the checkpoint.
    pub(crate) fn teardown(
        &mut self,
        state: Option<&NodeState>,
        mode: TeardownMode,
    ) -> anyhow::Result<()> {
        if self.teardown_started {
            return Ok(());
        }
        self.teardown_started = true;
        let _stage = shutdown::mark_shutdown_stage();
        if let Some(state) = state {
            state.shutdown().store(true, Ordering::Release);
            state.p2p().shutdown();
        }
        if let Some(tx) = self.event_loop_signal.take() {
            // A full bounded channel already carries a wake. Blocking here
            // could prevent teardown from reaching the worker joins.
            let _ = tx.try_send(());
        }

        let mut first_error = None;
        self.join_core_services(state, &mut first_error);
        // Drain wait is deadline-bounded and never fails; it only bounds how
        // long teardown parks before joining the remaining workers.
        shutdown::drain_and_shutdown(DRAIN_DEADLINE);
        self.join_bootstrap_and_signal_workers(state, &mut first_error);
        publish_clean_checkpoint_if_eligible(state, mode, &mut first_error);
        // Owner-local fee-estimator history: the event loop has drained, so
        // no further mempool mutations run and this snapshot is final.
        // docs/policies/db-migration.md — owner-local, degrade-not-fail.
        if let Some(state) = state {
            bitcoin_rs_mempool::fee_history::save(state.data_dir(), &state.mempool());
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        tracing::info!("bitcoin-rs node exited cleanly");
        Ok(())
    }

    fn join_core_services(
        &mut self,
        state: Option<&NodeState>,
        first_error: &mut Option<anyhow::Error>,
    ) {
        if let Some(handle) = self.event_loop.take() {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => set_first_error(first_error, error),
                // Event loop thread panic.
                Err(_) => {
                    set_first_error(first_error, anyhow::anyhow!("event loop thread panicked"));
                }
            }
        }
        if let Some(handle) = self.rpc_thread.take() {
            match handle.join() {
                Ok(Ok(())) => tracing::info!("rpc listener exited cleanly"),
                // RPC listener returned an I/O error.
                Ok(Err(error)) => {
                    tracing::warn!(%error, "rpc listener exited with i/o error");
                    set_first_error(first_error, anyhow::Error::new(error));
                }
                // RPC listener thread panic.
                Err(_) => {
                    tracing::error!("rpc listener panicked");
                    set_first_error(first_error, anyhow::anyhow!("rpc listener thread panicked"));
                }
            }
        }
        self.metrics.take();
        if let Some(handle) = self.readiness_sampler.take() {
            // Readiness sampler thread panic.
            if handle.join().is_err() {
                tracing::error!("readiness sampler panicked");
                set_first_error(first_error, anyhow::anyhow!("readiness sampler panicked"));
            }
        }
        #[cfg(test)]
        if let Some(handle) = self.outbound_worker.take() {
            // Injected outbound-drain worker outcome.
            if matches!(handle.join(), Ok(())) {
                tracing::info!("P2P outbound drain exited cleanly");
            } else {
                tracing::error!("P2P outbound drain panicked");
                set_first_error(first_error, anyhow::anyhow!("P2P outbound drain panicked"));
            }
        }
        if let Some(state) = state {
            // P2P core worker join failure.
            if let Err(error) = state.p2p().join_core_workers() {
                set_first_error(first_error, error.into());
            }
        }
        if let Some(handle) = self.tx_ingress.take() {
            // Tx ingress worker panic.
            if matches!(handle.join(), Ok(())) {
                tracing::info!("tx ingress consumer exited cleanly");
            } else {
                tracing::error!("tx ingress consumer panicked");
                set_first_error(first_error, anyhow::anyhow!("tx ingress consumer panicked"));
            }
        }
        if let Some(handle) = self.tx_relay.take() {
            // Tx relay worker panic.
            if matches!(handle.join(), Ok(())) {
                tracing::info!("tx relay worker exited cleanly");
            } else {
                tracing::error!("tx relay worker panicked");
                set_first_error(first_error, anyhow::anyhow!("tx relay worker panicked"));
            }
        }
    }

    fn join_bootstrap_and_signal_workers(
        &mut self,
        state: Option<&NodeState>,
        first_error: &mut Option<anyhow::Error>,
    ) {
        if let Some(state) = state {
            // P2P bootstrap worker join failure.
            if let Err(error) = state.p2p().join_bootstrap_worker() {
                set_first_error(first_error, anyhow::Error::new(error));
            }
            mark_bootstrap_drain_reached();
        }
        #[cfg(test)]
        if let Some(handle) = self.bootstrap_worker.take() {
            mark_bootstrap_drain_reached();
            let thread_name = handle
                .thread()
                .name()
                .unwrap_or("bitcoin-rs-p2p-bootstrap")
                .to_owned();
            // Injected bootstrap worker outcome.
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
        if let Some(handle) = self.maintenance_worker.take() {
            // Chainstate maintenance worker panic.
            if matches!(handle.join(), Ok(())) {
                tracing::info!("chainstate maintenance worker exited cleanly");
            } else {
                tracing::error!("chainstate maintenance worker panicked");
                set_first_error(
                    first_error,
                    anyhow::anyhow!("chainstate maintenance worker panicked"),
                );
            }
        }
        if let Some(mut handler) = self.signal_handler.take() {
            // Signal forwarding thread failed to close or join.
            if let Err(error) = handler.close_and_join() {
                tracing::error!(%error, "signal forwarding thread did not shut down cleanly");
                set_first_error(first_error, error);
            }
        }
    }
}

fn publish_clean_checkpoint_if_eligible(
    state: Option<&NodeState>,
    mode: TeardownMode,
    first_error: &mut Option<anyhow::Error>,
) {
    if let (Some(state), TeardownMode::CleanShutdown, None) = (state, mode, first_error.as_ref()) {
        run_before_clean_checkpoint_hook();
        match state.write_clean_checkpoint() {
            Ok(None) => {
                tracing::info!("no applied tip; clean checkpoint publication skipped");
            }
            Ok(Some(generation)) => {
                tracing::info!(generation, "published clean chainstate checkpoint");
            }
            // Checkpoint write failure suppresses the clean-shutdown report.
            Err(error) => {
                tracing::error!(%error, "clean checkpoint publication failed");
                set_first_error(first_error, error);
            }
        }
    } else {
        tracing::info!("clean checkpoint publication skipped: the node did not shut down cleanly");
    }
}

fn set_first_error(slot: &mut Option<anyhow::Error>, error: anyhow::Error) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

impl Drop for NodeServices {
    fn drop(&mut self) {
        // Abandoned services still run the shared teardown.
        if let Err(error) = self.teardown(None, TeardownMode::StartupAbort) {
            tracing::warn!(%error, "dropped node services; teardown reported an error");
        }
    }
}

/// Records each successfully created service immediately. Until finished,
/// Drop rolls back through the same teardown without publishing a checkpoint.
struct StartupGuard {
    state: Option<NodeState>,
    services: NodeServices,
}

impl StartupGuard {
    fn finish(mut self, context: Arc<bitcoin_rs_rpc::context::Context>) -> crate::embed::Node {
        let Some(state) = self.state.take() else {
            panic!("completed startup owns state");
        };
        let services = core::mem::take(&mut self.services);
        self.services.teardown_started = true;
        crate::embed::Node {
            state,
            services: Some(services),
            context,
        }
    }
}

impl Drop for StartupGuard {
    fn drop(&mut self) {
        // Startup failure rolls the partially built graph back.
        if let Err(error) = self
            .services
            .teardown(self.state.as_ref(), TeardownMode::StartupAbort)
        {
            tracing::warn!(%error, "startup rollback reported a cleanup failure");
        }
        self.state.take();
    }
}

/// Boots an owned node after validation, storage open, and crash recovery.
///
/// The returned node already owns every worker and the RPC context. No caller
/// receives detached startup parts or needs to reconstruct lifecycle ownership.
/// `install_signals` is the daemon's only difference from embedded startup.
/// A failure after any service starts rolls it back through `StartupGuard`.
#[allow(clippy::too_many_lines)]
pub(crate) fn start_node(
    config: NodeConfig,
    runtime: RuntimeInputs,
    install_signals: bool,
) -> Result<Node> {
    // Registers the Bitcoin Core-compatible USDT probes with the platform
    // tracer so consumers (bpftrace, BCC, DTrace) can discover them — shared
    // startup, so daemon (`run`) and embedded (`Node::start`) nodes are
    // equally discoverable. A no-op without the `usdt` feature.
    bitcoin_rs_trace::register_probes();
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
    tracing::info!(config = ?state.config(), "bitcoin-rs node booting");
    guard.services.metrics = if let Some(bind) = state.config().observability.metrics_bind {
        let identity = crate::metrics::EvidenceIdentity::of_process(state.config())?;
        crate::metrics::start_metrics(Some(bind), state.shutdown(), &identity)?
    } else {
        None
    };
    // The sampler only publishes to the metrics recorder: without a bound
    // server its writes go nowhere, so do not spend the thread (and its
    // join latency in every start_node test) when metrics are off.
    guard.services.readiness_sampler = if guard.services.metrics.is_some() {
        Some(crate::metrics::spawn_readiness_sampler(
            state.derived_index_status(),
            state.shutdown(),
        )?)
    } else {
        None
    };

    let shutdown = state.shutdown();
    let (shutdown_rx, event_loop_signal) = if let Some(rx) = injected_shutdown {
        (rx, None)
    } else {
        let (tx, rx) = bounded(1);
        if install_signals {
            guard.services.signal_handler = Some(crate::signal::ShutdownHandler::install(
                Arc::clone(&shutdown),
                tx.clone(),
            )?);
        }
        (rx, Some(tx))
    };
    guard.services.event_loop_signal = event_loop_signal;
    let block_body_source = state.block_body_source()?;
    let chainstate = state.chainstate();
    let p2p_chain_query: Arc<dyn bitcoin_rs_p2p::ChainQuery> = Arc::new(
        bitcoin_rs_p2p::ActiveChainQuery::new(chainstate.block_tree_reader())
            .with_block_body_source(Arc::clone(&block_body_source)),
    );
    let (sync_wake_tx, sync_wake_rx) = bounded(1);
    let sync = state.sync();
    let peer_ready_sync = Arc::clone(&sync);
    let loop_handle = EventLoop::with_sync_wake(shutdown_rx, sync, sync_wake_rx);
    let coordinator = Arc::new(crate::MiningCoordinator::new(
        state.mempool(),
        Arc::clone(&chainstate),
        state.chain_followers(),
        state.config().mining.payout_script.clone(),
    ));
    let sequence_wake: Arc<dyn bitcoin_rs_mining::MempoolSequenceWake> = coordinator.clone();
    let mining_control: Arc<dyn bitcoin_rs_mining::MiningControl> = coordinator;
    let signal = state.mining_generation_signal();
    // The signal holds a Weak reference; the RPC context owns the coordinator.
    signal.attach(&mining_control);
    signal.attach_sequence_wake(&sequence_wake);
    let gateway = state.mempool_gateway();
    // The node's one latch, built with the chainstate at open and already
    // held by the block-download executor: `initialblockdownload`, the
    // transaction-relay gate, and block-peer eligibility read one signal.
    let ibd = state.ibd();
    let tx_inventory: Arc<dyn bitcoin_rs_p2p::TxInventory> = gateway.clone();
    let compact_hints: Arc<dyn bitcoin_rs_p2p::CompactBlockHints> = gateway.clone();
    let listener_extras = bitcoin_rs_p2p::ListenerExtras {
        tx_inventory: Some(tx_inventory),
        compact_hints: Some(compact_hints),
        inbound_tx: Some(state.inbound_tx_sender()),
        ibd: Some((Arc::clone(&ibd), state.config().network)),
        // One orchestrator: the listener announces block inventory to the
        // same sync loop the event loop drives.
        block_sync: Some(Arc::clone(&peer_ready_sync)),
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

    let (context, rpc_server) = bind_rpc(state, &mining_control, block_body_source, &ibd)?;
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
    guard.services.maintenance_worker = Some(state.start_chainstate_maintenance()?);
    guard.services.event_loop = Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-event-loop".into())
            .spawn(move || loop_handle.spin(&shutdown))?,
    );
    Ok(guard.finish(context))
}

/// Threads for the process-wide rayon pool.
///
/// This pool runs coarse hashing and shard-commit jobs. Script verification
/// owns its separate pool; sizing both pools to the whole host oversubscribes
/// the process. The existing four-worker cap is unchanged by this owner cut.
const GLOBAL_RAYON_THREADS: usize = 4;

fn cap_global_thread_pool() {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let threads = available.min(GLOBAL_RAYON_THREADS);
    // A second node start in one process finds the pool already installed.
    if let Err(error) = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
    {
        tracing::debug!(%error, "global rayon pool already configured, keeping it");
    }
}

#[cfg(test)]
#[path = "../tests/unit/lifecycle/tests.rs"]
mod tests;
