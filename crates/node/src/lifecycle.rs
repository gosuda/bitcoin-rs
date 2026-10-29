use core::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};

use bitcoin_rs_chain::{BlockBodySource, LatchReader};
use bitcoin_rs_chainstate::verify::{
    CheckLevel, VerifyError, VerifyOutcome, VerifyRequest, verify_recent_blocks,
};
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_rpc::{
    RpcServer, RpcSurface,
    context::{
        ChainControl, ChainControlError, ChainHandles, Context, ContextHandles, IndexHandles,
        MempoolHandles, MiningHandles, NetworkHandles,
    },
};

use crossbeam_channel::bounded;

use crate::config::{NodeConfig, RuntimeInputs};
use crate::embed::Node;
use crate::event_loop::EventLoop;
use crate::state::NodeState;

mod shutdown {
    #[cfg(test)]
    thread_local! {
        static SHUTDOWN_STAGES_REACHED: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
    }

    #[cfg(test)]
    pub(super) fn mark_shutdown_stage() {
        SHUTDOWN_STAGES_REACHED.with(|slot| slot.set(slot.get().saturating_add(1)));
    }

    #[cfg(test)]
    pub(super) fn take_shutdown_stages_reached() -> u32 {
        SHUTDOWN_STAGES_REACHED.with(core::cell::Cell::take)
    }

    #[cfg(not(test))]
    pub(super) fn mark_shutdown_stage() {}
}

pub(crate) const DRAIN_DEADLINE: Duration = Duration::from_secs(5);

const RPC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct RpcChainControl {
    handles: Arc<bitcoin_rs_chainstate::Chainstate>,
    followers: crate::chain_effects::ChainFollowers,
    sync: Arc<crate::BlockSync>,
    snapshots: Arc<crate::snapshot::SnapshotControl>,
}

fn rpc_network_handles(state: &NodeState) -> NetworkHandles {
    NetworkHandles {
        peer_table: state.peer_table(),
        p2p: state.p2p(),
        local_services: state.p2p().local_services().to_u64(),
        overlay: state.p2p().overlay_config().clone(),
    }
}

impl ChainControl for RpcChainControl {
    fn load_txoutset(
        &self,
        path: &std::path::Path,
    ) -> core::result::Result<
        bitcoin_rs_rpc::context::SnapshotImport,
        bitcoin_rs_rpc::context::SnapshotControlError,
    > {
        self.snapshots.import(path).map_err(Into::into)
    }

    fn dump_txoutset(
        &self,
        path: &std::path::Path,
        cancellation: &LatchReader,
    ) -> core::result::Result<
        bitcoin_rs_rpc::context::SnapshotExport,
        bitcoin_rs_rpc::context::SnapshotControlError,
    > {
        self.snapshots
            .export(path, cancellation)
            .map_err(Into::into)
    }

    fn chainstates(
        &self,
    ) -> core::result::Result<
        bitcoin_rs_rpc::context::ChainstatesInfo,
        bitcoin_rs_rpc::context::SnapshotControlError,
    > {
        self.snapshots.chainstates()
    }

    fn invalidate_block(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> core::result::Result<(), ChainControlError> {
        let outcome = crate::reorg::invalidate_block(&self.handles, &self.followers, hash)
            .map_err(|error| match error {
                crate::reorg::ReorgError::UnknownBlock(_) => ChainControlError::UnknownBlock,
                crate::reorg::ReorgError::CannotInvalidateGenesis => ChainControlError::Genesis,
                other => ChainControlError::Failed(other.to_string()),
            })?;
        self.sync.purge_invalidated(&outcome.invalid);
        if let Some(demoted) = outcome.demoted_tip {
            self.sync.record_demoted_tip(demoted);
        }
        Ok(())
    }

    fn verify_chain(
        &self,
        check_level: u8,
        nblocks: u32,
        cancellation: &LatchReader,
    ) -> Result<bool, ChainControlError> {
        let mut request = verify_request(check_level, nblocks);
        request.cancellation = Some(cancellation.clone());
        match verify_recent_blocks(&self.handles, request) {
            Ok(VerifyOutcome::Passed { .. }) => Ok(true),
            Ok(VerifyOutcome::SkippedNoBlockData { height }) => {
                tracing::info!(
                    height,
                    "verifychain window reaches blocks this node does not hold"
                );
                Ok(false)
            }
            Err(VerifyError::Interrupted) => Err(ChainControlError::Interrupted),
            Err(VerifyError::ClosedForRecovery) => Err(ChainControlError::Unavailable),
            Err(error) => {
                tracing::warn!(%error, "verifychain could not verify a block");
                Ok(false)
            }
        }
    }
}

fn verify_request(check_level: u8, nblocks: u32) -> VerifyRequest {
    let level = match check_level {
        0 => CheckLevel::ReadBodies,
        1 => CheckLevel::CheckBodies,
        _ => CheckLevel::CheckUndo,
    };
    VerifyRequest {
        level,
        depth: NonZeroU32::new(nblocks),
        cancellation: None,
    }
}

struct RpcBindings {
    context: Arc<Context>,
    listeners: Vec<(RpcServer, RpcSurface)>,
}

#[cfg(test)]
fn bind_rpc(
    state: &NodeState,
    mining_control: &Arc<dyn MiningControl>,
    block_body_source: Arc<dyn BlockBodySource>,
) -> Result<RpcBindings> {
    bind_rpc_with_pool(
        state,
        mining_control,
        block_body_source,
        bitcoin_rs_rpc::context::PoolHandles::default(),
    )
}

fn bind_rpc_with_pool(
    state: &NodeState,
    mining_control: &Arc<dyn MiningControl>,
    block_body_source: Arc<dyn BlockBodySource>,
    pool: bitcoin_rs_rpc::context::PoolHandles,
) -> Result<RpcBindings> {
    let config = state.config();
    let rpc_auth = Arc::new(config.rpc.auth.to_rpc_auth(&config.data_dir)?);
    let chainstate = state.chainstate();
    let context = Context::from_handles(ContextHandles {
        silent_payments: config.rpc.silent_payments,
        compressed_transactions: config.rpc.compressed_transactions,
        chain: ChainHandles {
            chain_tip: chainstate.header_tip_reader(),
            applied_tip: chainstate.applied_tip_reader(),
            active_tip_wait: Some(chainstate.clone()),
            progress: chainstate.chain_progress_reader(),
            blocks: state.block_log_reader(),
            utxo: chainstate.utxo_reader(),
            coin_stats: chainstate.coin_stats_handle(),
            block_tree: chainstate.block_tree_reader(),
            chain_network: state.config().network,
            chain_transition: state.stable_read(),
            block_body_source: Some(block_body_source),
            block_undo_source: Some(chainstate.clone()),
            prune_service: state.prune_service(),
            closed_for_recovery: chainstate.closed_for_recovery_reader(),
            chain_control: Some(Arc::new(RpcChainControl {
                handles: chainstate,
                followers: state.chain_followers(),
                sync: state.sync(),
                snapshots: Arc::clone(&state.snapshots),
            })),
            rollback_warnings: Some(state.recovery_reporter()),
        },
        mempool: MempoolHandles {
            gateway: state.mempool_gateway(),
        },
        indexes: IndexHandles {
            derived_index: state.derived_index_query(),
            esplora_tx_index: None,
            script_index: state.script_index_query(),
            compact_filters: state.compact_filter_query(),
            derived_index_status: Some(state.derived_index_status()),
        },
        network: rpc_network_handles(state),
        mining: MiningHandles {
            mining_control: Some(Arc::clone(mining_control)),
        },
        pool,
        zmq_publisher: state.zmq_publisher(),
        debug_log_path: Some(state.data_dir().join("debug.log")),
    })
    .with_esplora_derived_index(state.esplora_derived_index_query());
    let context = Arc::new(context);
    let handler = Arc::new(bitcoin_rs_rpc::Handler::new(Arc::clone(&context)));
    let server = RpcServer::bind(
        state.config().rpc.bind,
        Arc::clone(&rpc_auth),
        Arc::clone(&handler),
        config.rpc.max_connections,
        RPC_IDLE_TIMEOUT,
        state.config().rpc.rest,
    )
    .with_context(|| format!("failed to bind RPC listener at {}", config.rpc.bind))?;
    let mut servers = Vec::with_capacity(2);
    if let Some(address) = config.rpc.public_bind {
        let public = RpcServer::bind(
            address,
            rpc_auth,
            handler,
            config.rpc.public_max_connections,
            RPC_IDLE_TIMEOUT,
            config.rpc.rest,
        )
        .with_context(|| format!("failed to bind public HTTP listener at {address}"))?;
        servers.push((server, RpcSurface::Management));
        servers.push((public, RpcSurface::Public));
    } else {
        servers.push((server, RpcSurface::Shared));
    }
    Ok(RpcBindings {
        context,
        listeners: servers,
    })
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TeardownMode {
    StartupAbort,
    CleanShutdown,
}

#[derive(Default)]
pub(crate) struct NodeServices {
    #[cfg(feature = "pool")]
    pool: Option<crate::pool::PoolService>,
    event_loop: Option<std::thread::JoinHandle<()>>,
    event_loop_signal: Option<crossbeam_channel::Sender<()>>,
    metrics: Option<crate::metrics::MetricsServer>,
    rpc_threads: Vec<std::thread::JoinHandle<std::io::Result<()>>>,
    maintenance_worker: Option<std::thread::JoinHandle<()>>,
    tx_ingress: Option<std::thread::JoinHandle<()>>,
    readiness_sampler: Option<std::thread::JoinHandle<()>>,
    tx_relay: Option<std::thread::JoinHandle<()>>,
    block_announce: Option<std::thread::JoinHandle<()>>,
    signal_handler: Option<crate::signal::ShutdownHandler>,
    teardown_started: bool,
}

impl NodeServices {
    pub(crate) fn teardown(
        &mut self,
        state: Option<&mut NodeState>,
        mode: TeardownMode,
    ) -> anyhow::Result<()> {
        if self.teardown_started {
            return Ok(());
        }
        self.teardown_started = true;
        let mut first_error = None;
        let state = state.map(|state| {
            if let Err(error) = state.bounded_index_shutdown(DRAIN_DEADLINE) {
                set_first_error(&mut first_error, error);
            }
            &*state
        });
        shutdown::mark_shutdown_stage();
        #[cfg(feature = "pool")]
        if let Some(mut pool) = self.pool.take() {
            if let Err(error) = pool.shutdown(std::time::Instant::now() + DRAIN_DEADLINE) {
                set_first_error(&mut first_error, error);
            }
        }
        if let Some(state) = state {
            state.request_shutdown();
            state.p2p().shutdown();
        }
        if let Some(tx) = self.event_loop_signal.take() {
            let _ = tx.try_send(());
        }

        self.join_core_services(state, &mut first_error);
        self.join_bootstrap_and_signal_workers(state, &mut first_error);
        publish_clean_checkpoint_if_eligible(state, mode, &mut first_error);
        if let Some(state) = state {
            let history = state.mempool_reader().read().estimator_history();
            bitcoin_rs_mempool::fee_history::save(state.data_dir(), &history);
            if state.config().persist_mempool
                && matches!(mode, TeardownMode::CleanShutdown)
                && first_error.is_none()
            {
                save_mempool_snapshot(state);
            }
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
            if handle.join().is_err() {
                set_first_error(first_error, anyhow::anyhow!("event loop thread panicked"));
            }
        }
        for handle in self.rpc_threads.drain(..) {
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
        if let Some(mut metrics) = self.metrics.take()
            && let Err(error) = metrics.stop_and_join()
        {
            set_first_error(first_error, error);
        }
        if let Some(handle) = self.readiness_sampler.take() {
            if handle.join().is_err() {
                tracing::error!("readiness sampler panicked");
                set_first_error(first_error, anyhow::anyhow!("readiness sampler panicked"));
            }
        }
        if let Some(state) = state {
            if let Err(error) = state.p2p().join_core_workers() {
                set_first_error(first_error, error.into());
            }
        }
        if let Some(handle) = self.tx_ingress.take() {
            if matches!(handle.join(), Ok(())) {
                tracing::info!("tx ingress consumer exited cleanly");
            } else {
                tracing::error!("tx ingress consumer panicked");
                set_first_error(first_error, anyhow::anyhow!("tx ingress consumer panicked"));
            }
        }
        if let Some(state) = state {
            let package_teardown = state
                .peer_table()
                .clear_package_claims(&state.package_capacity());
            if package_teardown.bytes_reserved != 0 || package_teardown.held != 0 {
                tracing::warn!(?package_teardown, "package ingress held bytes at teardown");
            } else {
                tracing::debug!(?package_teardown, "package ingress cleared at teardown");
            }
        }
        if let Some(handle) = self.tx_relay.take() {
            if matches!(handle.join(), Ok(())) {
                tracing::info!("tx relay worker exited cleanly");
            } else {
                tracing::error!("tx relay worker panicked");
                set_first_error(first_error, anyhow::anyhow!("tx relay worker panicked"));
            }
        }
        if let Some(handle) = self.block_announce.take() {
            if matches!(handle.join(), Ok(())) {
                tracing::info!("block announce worker exited cleanly");
            } else {
                tracing::error!("block announce worker panicked");
                set_first_error(
                    first_error,
                    anyhow::anyhow!("block announce worker panicked"),
                );
            }
        }
    }

    fn join_bootstrap_and_signal_workers(
        &mut self,
        state: Option<&NodeState>,
        first_error: &mut Option<anyhow::Error>,
    ) {
        if let Some(state) = state {
            if let Err(error) = state.p2p().join_bootstrap_worker() {
                set_first_error(first_error, anyhow::Error::new(error));
            }
            mark_bootstrap_drain_reached();
        }
        if let Some(handle) = self.maintenance_worker.take() {
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
            if let Err(error) = handler.close_and_join() {
                tracing::error!(%error, "signal forwarding thread did not shut down cleanly");
                set_first_error(first_error, error);
            }
        }
    }
}

fn save_mempool_snapshot(state: &NodeState) {
    let budget = Duration::from_secs(10);
    let deadline = std::time::Instant::now() + budget;
    let gateway = state.mempool_gateway();
    let data_dir = state.data_dir().to_path_buf();
    let network = state.config().network;
    let max_bytes = state.config().mempool_snapshot_max_bytes;
    let (sender, receiver) = crossbeam_channel::bounded(1);
    match std::thread::Builder::new()
        .name("mempool-snapshot".into())
        .spawn(move || {
            let result = bitcoin_rs_mempool::snapshot::prepare(
                &data_dir, &gateway, network, max_bytes, deadline,
            );
            let _ = sender.send(result);
        }) {
        Ok(_) => publish_mempool_snapshot(receiver, deadline),
        Err(error) => tracing::warn!(%error, "could not start mempool snapshot save"),
    }
}

fn publish_mempool_snapshot(
    receiver: crossbeam_channel::Receiver<
        std::io::Result<bitcoin_rs_mempool::snapshot::PreparedSnapshot>,
    >,
    deadline: std::time::Instant,
) {
    match receiver.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
        Ok(Ok(snapshot)) => {
            if let Err(error) = snapshot.publish() {
                tracing::warn!(%error, "mempool snapshot publication failed");
            }
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "mempool snapshot save failed; preserving the previous file");
        }
        Err(error) => {
            tracing::warn!(%error, "mempool snapshot save did not finish within the shutdown budget");
        }
    }
    drop(receiver);
}

fn publish_clean_checkpoint_if_eligible(
    state: Option<&NodeState>,
    mode: TeardownMode,
    first_error: &mut Option<anyhow::Error>,
) {
    if let (Some(state), TeardownMode::CleanShutdown, None) = (state, mode, first_error.as_ref()) {
        run_before_clean_checkpoint_hook();
        match state.publish_checkpoint() {
            Ok(None) => {
                tracing::info!("no applied tip; clean checkpoint publication skipped");
            }
            Ok(Some(generation)) => {
                tracing::info!(generation, "published clean chainstate checkpoint");
            }
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
        if let Err(error) = self.teardown(None, TeardownMode::StartupAbort) {
            tracing::warn!(%error, "dropped node services; teardown reported an error");
        }
    }
}

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
        if let Err(error) = self
            .services
            .teardown(self.state.as_mut(), TeardownMode::StartupAbort)
        {
            tracing::warn!(%error, "startup rollback reported a cleanup failure");
        }
        self.state.take();
    }
}

#[expect(clippy::too_many_lines)]
pub(crate) fn start_node(
    config: NodeConfig,
    runtime: RuntimeInputs,
    install_signals: bool,
) -> Result<Node> {
    config.validate()?;
    bitcoin_rs_consensus::trace::register_probes();
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
        crate::metrics::start_metrics(Some(bind), state.shutdown_reader(), &identity)?
    } else {
        None
    };
    guard.services.readiness_sampler = if guard.services.metrics.is_some() {
        Some(crate::metrics::spawn_readiness_sampler(
            state.derived_index_status(),
            state.shutdown_reader(),
        )?)
    } else {
        None
    };

    let (shutdown_rx, event_loop_signal) = if let Some(rx) = injected_shutdown {
        (rx, None)
    } else {
        let (tx, rx) = bounded(1);
        if install_signals {
            let chainstate_for_signal = state.chainstate();
            guard.services.signal_handler = Some(crate::signal::ShutdownHandler::install(
                move || chainstate_for_signal.request_shutdown(),
                tx.clone(),
            )?);
        }
        (rx, Some(tx))
    };
    guard.services.event_loop_signal = event_loop_signal;
    let block_body_source = state.block_body_source()?;
    let chainstate = state.chainstate();
    let recent_block = bitcoin_rs_p2p::RecentBlockSlot::default();
    let p2p_chain_query: Arc<dyn bitcoin_rs_p2p::ChainQuery> = Arc::new(
        bitcoin_rs_p2p::ActiveChainQuery::new(
            chainstate.block_tree_reader(),
            chainstate.applied_tip_reader(),
            state.config().network,
        )
        .with_block_body_source(Arc::clone(&block_body_source))
        .with_compact_filters(state.compact_filter_query())
        .with_recent_block(recent_block.clone()),
    );
    let (sync_wake_tx, sync_wake_rx) = bounded(1);
    let sync = state.sync();
    let peer_ready_sync = Arc::clone(&sync);
    let loop_handle = EventLoop::with_sync_wake(shutdown_rx, sync, sync_wake_rx);
    let coordinator = Arc::new(crate::MiningCoordinator::new(
        state.mempool_reader(),
        Arc::clone(&chainstate),
        state.stable_read(),
        state.chain_followers(),
        final_payout_script(state.config()),
    ));
    let sequence_wake: Arc<dyn bitcoin_rs_mining::MempoolSequenceWake> = coordinator.clone();
    let mining_control: Arc<dyn bitcoin_rs_mining::MiningControl> = coordinator;
    let signal = state.mining_generation_signal();
    signal.attach(&mining_control);
    signal.attach_sequence_wake(&sequence_wake);
    let gateway = state.mempool_gateway();
    let tx_inventory: Arc<dyn bitcoin_rs_p2p::TxInventory> = gateway.clone();
    let compact_hints: Arc<dyn bitcoin_rs_p2p::CompactBlockHints> = gateway.clone();
    let block_announcer = Arc::new(
        bitcoin_rs_p2p::BlockAnnouncer::new(
            state.peer_table(),
            Arc::clone(&p2p_chain_query),
            bitcoin_rs_p2p::BlockAnnounceConfig::default(),
        )
        .with_ibd(state.ibd(), state.config().network)
        .with_recent_block(recent_block)
        .with_stale_tips(peer_ready_sync.stale_tips(), chainstate.block_tree_reader()),
    );
    let announcer_for_hook = Arc::clone(&block_announcer);
    let pow_valid_hook: bitcoin_rs_chainstate::PowValidBlockHook =
        Arc::new(move |block, hash, height| {
            announcer_for_hook.announce_pow_valid(block, hash, height);
        });
    chainstate
        .set_pow_valid_block(pow_valid_hook)
        .map_err(|_| anyhow::anyhow!("pow-valid hook already installed"))?;
    if let Some(announce_rx) = state.take_block_announce_receiver() {
        guard.services.block_announce = Some(bitcoin_rs_p2p::spawn_block_announce_worker(
            Arc::clone(&block_announcer),
            announce_rx,
            state.shutdown_reader(),
        )?);
    }
    let listener_extras = bitcoin_rs_p2p::ListenerExtras {
        tx_inventory: Some(tx_inventory),
        compact_hints: Some(compact_hints),
        inbound_tx: Some(state.inbound_tx_sender()),
        package_capacity: Some(state.package_capacity()),
        ibd: Some((state.ibd(), state.config().network)),
        block_sync: Some(Arc::clone(&peer_ready_sync)),
        block_announcer: Some(block_announcer),
    };
    let (relay_queue, relay_rx) =
        bitcoin_rs_p2p::TxRelayQueue::new(bitcoin_rs_p2p::DEFAULT_TX_RELAY_QUEUE_CAPACITY);
    guard.services.tx_relay = Some(bitcoin_rs_p2p::spawn_tx_relay_worker(
        bitcoin_rs_p2p::PeerRelaySink::new(state.peer_table())
            .with_ibd(state.ibd(), state.config().network),
        relay_rx,
        Arc::downgrade(&gateway),
        state.shutdown_reader(),
    )?);
    let inbound_tx_rx = state
        .take_inbound_tx_receiver()
        .ok_or_else(|| anyhow::anyhow!("inbound tx receiver already taken"))?;
    guard.services.tx_ingress = Some(crate::tx_ingress::spawn_tx_ingress_consumer(
        state,
        Arc::clone(&gateway),
        Arc::clone(&mining_control),
        state.shutdown_reader(),
        inbound_tx_rx,
        relay_queue.clone(),
    )?);
    gateway
        .attach_observer_leg(
            "tx-relay",
            Arc::new(bitcoin_rs_p2p::LocalTxRelayObserver::new(
                relay_queue,
                Arc::downgrade(&gateway),
            )),
            bitcoin_rs_mempool::BodyInterest::Metadata,
        )
        .map_err(anyhow::Error::msg)?;

    crate::chain_effects::bootstrap_genesis(&chainstate, &state.chain_followers())
        .map_err(|error| anyhow::Error::new(error).context("failed to bootstrap genesis"))?;
    #[cfg(feature = "pool")]
    {
        guard.services.pool =
            crate::pool::PoolService::prepare(state, Arc::clone(&mining_control))?;
    }
    #[cfg(feature = "pool")]
    let pool_handles = guard.services.pool.as_ref().map_or_else(
        bitcoin_rs_rpc::context::PoolHandles::default,
        crate::pool::PoolService::handles,
    );
    #[cfg(not(feature = "pool"))]
    let pool_handles = bitcoin_rs_rpc::context::PoolHandles::default();
    let RpcBindings { context, listeners } =
        bind_rpc_with_pool(state, &mining_control, block_body_source, pool_handles)?;
    for (rpc_server, surface) in listeners {
        let rpc_local_addr = rpc_server.local_addr()?;
        tracing::info!(addr = %rpc_local_addr, ?surface, "rpc listener bound");
        let rpc_shutdown = state.shutdown_reader();
        let worker = std::thread::Builder::new()
            .name("bitcoin-rs-rpc".into())
            .spawn(move || {
                let result = rpc_server.serve_surface_with_shutdown(rpc_shutdown.clone(), surface);
                if !rpc_shutdown.is_triggered() {
                    tracing::error!(?surface, error = ?result.as_ref().err(), "rpc listener exited before shutdown");
                }
                result
            })?;
        guard.services.rpc_threads.push(worker);
    }
    #[cfg(feature = "pool")]
    if let Some(pool) = guard.services.pool.as_mut() {
        pool.start()?;
    }
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
    let loop_shutdown = state.shutdown_reader();
    let loop_chainstate = state.chainstate();
    guard.services.event_loop = Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-event-loop".into())
            .spawn(move || {
                loop_handle.spin(&loop_shutdown, move || loop_chainstate.request_shutdown());
            })?,
    );
    Ok(guard.finish(context))
}

fn final_payout_script(config: &NodeConfig) -> Vec<u8> {
    #[cfg(feature = "pool")]
    if let Some(pool) = config.pool.as_ref() {
        return pool.reward_script.clone();
    }
    config.mining.payout_script.clone()
}
const GLOBAL_RAYON_THREADS: usize = 4;

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
mod tests;
