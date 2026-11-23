use core::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use bitcoin_rs_chain::verify::{
    CheckLevel, VerifyError, VerifyOutcome, VerifyRequest, verify_recent_blocks,
};
use bitcoin_rs_consensus::latch::LatchReader;
use bitcoin_rs_storage::block_body::BlockBodySource;
use bitcoin_rs_wire::mining::MiningControl;
use bitcoin_rs_wire::{
    RpcServer, RpcSurface,
    context::{
        ChainControl, ChainControlError, ChainHandles, Context, ContextHandles, IndexHandles,
        MempoolHandles, MiningHandles, NetworkHandles,
    },
};

use crossbeam_channel::bounded;

use crate::config::{ConfigError, NodeConfig, RuntimeInputs};
use crate::embed::Node;
use crate::event_loop::EventLoop;
use crate::run::RunError;
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
    handles: Arc<bitcoin_rs_chain::Chainstate>,
    followers: crate::chain_effects::ChainFollowers,
    sync: Arc<crate::p2p::sync::BlockSync>,
    snapshots: Arc<crate::snapshot::SnapshotControl>,
}

fn rpc_network_handles(state: &NodeState) -> NetworkHandles {
    NetworkHandles {
        peer_table: state.peer_table(),
        p2p: state.p2p(),
        local_services: state.p2p().local_services().to_u64(),
        user_agent: state.p2p().user_agent().to_owned(),
        overlay: state.p2p().overlay_config().clone(),
        v2_transport: state.config().p2p.v2_transport,
    }
}

impl ChainControl for RpcChainControl {
    fn load_txoutset(
        &self,
        path: &std::path::Path,
    ) -> core::result::Result<
        bitcoin_rs_wire::context::SnapshotImport,
        bitcoin_rs_wire::context::SnapshotControlError,
    > {
        self.snapshots.import(path).map_err(Into::into)
    }

    fn dump_txoutset(
        &self,
        path: &std::path::Path,
        cancellation: &LatchReader,
    ) -> core::result::Result<
        bitcoin_rs_wire::context::SnapshotExport,
        bitcoin_rs_wire::context::SnapshotControlError,
    > {
        self.snapshots
            .export(path, cancellation)
            .map_err(Into::into)
    }

    fn chainstates(
        &self,
    ) -> core::result::Result<
        bitcoin_rs_wire::context::ChainstatesInfo,
        bitcoin_rs_wire::context::SnapshotControlError,
    > {
        self.snapshots.chainstates()
    }

    fn invalidate_block(
        &self,
        hash: bitcoin_rs_consensus::primitives::Hash256,
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
) -> Result<RpcBindings, RunError> {
    bind_rpc_with_pool(
        state,
        mining_control,
        block_body_source,
        bitcoin_rs_wire::context::PoolHandles::default(),
    )
}

fn rpc_context_handles(
    state: &NodeState,
    mining_control: &Arc<dyn MiningControl>,
    block_body_source: Arc<dyn BlockBodySource>,
    pool: bitcoin_rs_wire::context::PoolHandles,
) -> ContextHandles {
    let config = state.config();
    let chainstate = state.chainstate();
    let shutdown_request: Arc<dyn Fn() + Send + Sync> = {
        let chainstate = Arc::clone(&chainstate);
        Arc::new(move || chainstate.request_shutdown())
    };
    ContextHandles {
        silent_payments: config.rpc.silent_payments,
        compressed_transactions: config.rpc.compressed_transactions,
        shutdown_request: Some(shutdown_request),
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
    }
}

fn bind_rpc_with_pool(
    state: &NodeState,
    mining_control: &Arc<dyn MiningControl>,
    block_body_source: Arc<dyn BlockBodySource>,
    pool: bitcoin_rs_wire::context::PoolHandles,
) -> Result<RpcBindings, RunError> {
    let config = state.config();
    let rpc_auth = Arc::new(config.rpc.auth.to_rpc_auth(&config.data_dir)?);
    let handles = rpc_context_handles(state, mining_control, block_body_source, pool);
    let context = Context::from_handles(handles)
        .with_esplora_derived_index(state.esplora_derived_index_query())
        .with_esplora_query_limit(
            std::num::NonZeroUsize::new(config.rpc.esplora_max_queries)
                .ok_or(ConfigError::EsploraMaxQueries)?,
        );
    let context = Arc::new(context);
    let handler = Arc::new(bitcoin_rs_wire::Handler::new(Arc::clone(&context)));
    let server = RpcServer::bind(
        state.config().rpc.bind,
        Arc::clone(&rpc_auth),
        Arc::clone(&handler),
        config.rpc.max_connections,
        RPC_IDLE_TIMEOUT,
        state.config().rpc.rest,
    )
    .map_err(|source| RunError::RpcBind {
        address: config.rpc.bind,
        source,
    })?;
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
        .map_err(|source| RunError::PublicRpcBind { address, source })?;
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
    static BEFORE_RECOVERY_RECHECK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
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

#[cfg(test)]
fn inject_before_recovery_recheck(hook: impl FnOnce() + 'static) {
    BEFORE_RECOVERY_RECHECK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_before_recovery_recheck_hook() {
    BEFORE_RECOVERY_RECHECK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
const fn run_before_recovery_recheck_hook() {}

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
    shutdown_forwarder: Option<(
        std::thread::JoinHandle<()>,
        Arc<bitcoin_rs_consensus::latch::LatchWriter>,
    )>,
    metrics: Option<crate::metrics::MetricsServer>,
    rpc_threads: Vec<std::thread::JoinHandle<std::io::Result<()>>>,
    rpc_addresses: Vec<(RpcSurface, std::net::SocketAddr)>,
    maintenance_worker: Option<std::thread::JoinHandle<()>>,
    tx_ingress: Option<std::thread::JoinHandle<()>>,
    readiness_sampler: Option<std::thread::JoinHandle<()>>,
    tx_relay: Option<std::thread::JoinHandle<()>>,
    block_announce: Option<std::thread::JoinHandle<()>>,
    signal_handler: Option<crate::signal::ShutdownHandler>,
    teardown_started: bool,
}
impl NodeServices {
    #[cfg(test)]
    pub(crate) fn rpc_address(&self, surface: RpcSurface) -> Option<std::net::SocketAddr> {
        self.rpc_addresses
            .iter()
            .find(|(bound, _)| *bound == surface)
            .map(|(_, address)| *address)
    }

    pub(crate) fn teardown(
        &mut self,
        state: Option<&mut NodeState>,
        mode: TeardownMode,
    ) -> Result<(), RunError> {
        if self.teardown_started {
            return Ok(());
        }
        self.teardown_started = true;
        let mut first_error = None;
        let state = state.map(|state| {
            if let Err(error) = state.bounded_index_shutdown(DRAIN_DEADLINE) {
                set_first_error(&mut first_error, error.into());
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

        self.join_core_services(state, &mut first_error);
        self.join_bootstrap_and_signal_workers(state, &mut first_error);
        run_before_recovery_recheck_hook();
        let closed_for_recovery =
            state.is_some_and(|state| state.chainstate().is_closed_for_recovery());
        publish_clean_checkpoint_if_eligible(state, mode, closed_for_recovery, &mut first_error);
        if let Some(state) = state {
            let history = state.mempool_reader().read().estimator_history();
            bitcoin_rs_mempool::fee_history::save(state.data_dir(), &history);
            if state.config().persist_mempool
                && matches!(mode, TeardownMode::CleanShutdown)
                && first_error.is_none()
                && !closed_for_recovery
            {
                save_mempool_snapshot(state);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if closed_for_recovery {
            return Err(RunError::ClosedForRecovery);
        }
        tracing::info!("bitcoin-rs node exited cleanly");
        Ok(())
    }

    fn join_core_services(
        &mut self,
        state: Option<&NodeState>,
        first_error: &mut Option<RunError>,
    ) {
        if let Some(handle) = self.event_loop.take() {
            if handle.join().is_err() {
                set_first_error(first_error, RunError::EventLoopPanicked);
            }
        }
        for handle in self.rpc_threads.drain(..) {
            match handle.join() {
                Ok(Ok(())) => tracing::info!("rpc listener exited cleanly"),
                Ok(Err(error)) => {
                    tracing::warn!(%error, "rpc listener exited with i/o error");
                    set_first_error(first_error, error.into());
                }
                Err(_) => {
                    tracing::error!("rpc listener panicked");
                    set_first_error(first_error, RunError::RpcListenerPanicked);
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
                set_first_error(first_error, RunError::ReadinessSamplerPanicked);
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
                set_first_error(first_error, RunError::TxIngressPanicked);
            }
        }
        if let Some(state) = state {
            let package_teardown = state
                .tx_policy
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
                set_first_error(first_error, RunError::TxRelayPanicked);
            }
        }
        if let Some(handle) = self.block_announce.take() {
            if matches!(handle.join(), Ok(())) {
                tracing::info!("block announce worker exited cleanly");
            } else {
                tracing::error!("block announce worker panicked");
                set_first_error(first_error, RunError::BlockAnnouncePanicked);
            }
        }
    }

    fn join_bootstrap_and_signal_workers(
        &mut self,
        state: Option<&NodeState>,
        first_error: &mut Option<RunError>,
    ) {
        if let Some(state) = state {
            if let Err(error) = state.p2p().join_bootstrap_worker() {
                set_first_error(first_error, error.into());
            }
            mark_bootstrap_drain_reached();
        }
        if let Some(handle) = self.maintenance_worker.take() {
            if matches!(handle.join(), Ok(())) {
                tracing::info!("chainstate maintenance worker exited cleanly");
            } else {
                tracing::error!("chainstate maintenance worker panicked");
                set_first_error(first_error, RunError::MaintenanceWorkerPanicked);
            }
        }
        if let Some((handle, stop)) = self.shutdown_forwarder.take() {
            stop.trigger();
            if matches!(handle.join(), Ok(())) {
                tracing::info!("shutdown forwarder exited cleanly");
            } else {
                tracing::error!("shutdown forwarder panicked");
                set_first_error(first_error, RunError::ShutdownForwarderPanicked);
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
    closed_for_recovery: bool,
    first_error: &mut Option<RunError>,
) {
    if let (Some(state), TeardownMode::CleanShutdown, None) = (state, mode, first_error.as_ref())
        && !closed_for_recovery
    {
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
                set_first_error(first_error, error.into());
            }
        }
        return;
    }
    let reason = if first_error.is_some() {
        "an earlier shutdown error"
    } else if closed_for_recovery {
        "a chainstate closed for recovery"
    } else {
        "a startup abort or an unclean shutdown"
    };
    tracing::info!("clean checkpoint publication skipped: {reason}");
}

fn set_first_error(slot: &mut Option<RunError>, error: RunError) {
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
    fn finish(mut self, context: Arc<bitcoin_rs_wire::context::Context>) -> crate::embed::Node {
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

pub(crate) fn start_node(
    config: NodeConfig,
    runtime: RuntimeInputs,
    install_signals: bool,
) -> Result<Node, RunError> {
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
    init_metrics_services(state, &mut guard.services)?;

    let injected_shutdown_forwarder = if let Some(rx) = injected_shutdown {
        let state_shutdown = state.shutdown_writer();
        let chainstate_for_signal = state.chainstate();
        let forwarder_stop = Arc::new(state.shutdown_reader().child());
        let forwarder_stop_reader = forwarder_stop.reader();
        Some((
            std::thread::Builder::new()
                .name("bitcoin-rs-shutdown-forwarder".into())
                .spawn(move || {
                    crossbeam_channel::select! {
                        recv(rx) -> _ => {}
                        recv(forwarder_stop_reader.closed()) -> _ => {}
                    }
                    state_shutdown.trigger();
                    chainstate_for_signal.request_shutdown();
                })?,
            forwarder_stop,
        ))
    } else {
        if install_signals {
            let chainstate_for_signal = state.chainstate();
            let state_shutdown = state.shutdown_writer();
            guard.services.signal_handler =
                Some(crate::signal::ShutdownHandler::install(move || {
                    state_shutdown.trigger();
                    chainstate_for_signal.request_shutdown();
                })?);
        }
        None
    };
    guard.services.shutdown_forwarder = injected_shutdown_forwarder;
    let block_body_source = state.block_body_source()?;
    let chainstate = state.chainstate();
    let recent_block = crate::p2p::RecentBlockSlot::new(state.block_memory());
    let p2p_chain_query: Arc<dyn bitcoin_rs_p2p::ChainQuery> = Arc::new(
        crate::p2p::ActiveChainQuery::new(
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
    let loop_handle = EventLoop::with_sync_wake(sync, sync_wake_rx);
    let coordinator = Arc::new(crate::MiningCoordinator::new(
        state.mempool_reader(),
        Arc::clone(&chainstate),
        state.block_memory(),
        state.stable_read(),
        state.chain_followers(),
        final_payout_script(state.config()),
        state.config().mining.coinbase_reserve,
    ));
    let sequence_wake: Arc<dyn bitcoin_rs_wire::mining::MempoolSequenceWake> = coordinator.clone();
    let mining_control: Arc<dyn bitcoin_rs_wire::mining::MiningControl> = coordinator;
    let signal = state.mining_generation_signal();
    signal.attach(&mining_control);
    signal.attach_sequence_wake(&sequence_wake);
    let gateway = state.mempool_gateway();
    let node_tx_inv = Arc::new(crate::p2p::NodeTxInventory(gateway.clone()));
    let tx_inventory: Arc<dyn bitcoin_rs_p2p::TxInventory> =
        Arc::new(crate::p2p::NodeTxInventory(gateway.clone()));
    let compact_hints: Arc<dyn bitcoin_rs_p2p::CompactBlockHints> =
        Arc::new(crate::p2p::NodeTxInventory(gateway.clone()));
    let block_announcer = Arc::new(
        crate::p2p::BlockAnnouncer::new(
            state.peer_table(),
            Arc::clone(&p2p_chain_query),
            crate::p2p::BlockAnnounceConfig::default(),
        )
        .with_ibd(state.ibd(), state.config().network)
        .with_recent_block(recent_block)
        .with_stale_tips(peer_ready_sync.stale_tips(), chainstate.block_tree_reader()),
    );
    let announcer_for_hook = Arc::clone(&block_announcer);
    let pow_valid_hook: bitcoin_rs_chain::PowValidBlockHook =
        Arc::new(move |block, hash, height| {
            announcer_for_hook.announce_pow_valid(block, hash, height);
        });
    chainstate
        .set_pow_valid_block(pow_valid_hook)
        .map_err(|_| RunError::PowValidHookInstalled)?;
    if let Some(announce_rx) = state.take_block_announce_receiver() {
        guard.services.block_announce = Some(crate::p2p::spawn_block_announce_worker(
            Arc::clone(&block_announcer),
            announce_rx,
            state.shutdown_reader(),
        )?);
    }
    let tx_ingress: Arc<dyn bitcoin_rs_p2p::listener::TxIngressObserver> =
        Arc::new(crate::p2p::NodeTxIngress::new(
            state.inbound_tx_sender(),
            state.package_capacity(),
            Arc::clone(&state.tx_policy),
            Arc::clone(&node_tx_inv),
            state.shutdown_reader(),
        ));
    let tx_policy = unsize_tx_policy(Arc::clone(&state.tx_policy));
    let node_ibd: Arc<dyn bitcoin_rs_p2p::listener::IbdState> =
        Arc::new(crate::p2p::NodeIbd(state.ibd()));
    let block_sync_obs = unsize_block_sync(Arc::clone(&peer_ready_sync));
    let block_announcer_obs = unsize_block_announcer(Arc::clone(&block_announcer));
    let listener_extras = bitcoin_rs_p2p::ListenerExtras {
        tx_inventory: Some(tx_inventory),
        compact_hints: Some(compact_hints),
        tx_ingress: Some(tx_ingress),
        tx_policy: Some(tx_policy),
        ibd: Some((node_ibd, state.config().network)),
        block_sync: Some(block_sync_obs),
        block_announcer: Some(block_announcer_obs),
        block_memory: Some(state.block_memory()),
    };
    let (relay_queue, relay_rx) =
        crate::p2p::TxRelayQueue::new(crate::p2p::DEFAULT_TX_RELAY_QUEUE_CAPACITY);
    guard.services.tx_relay = Some(crate::p2p::spawn_tx_relay_worker(
        crate::p2p::PeerRelaySink::new(Arc::clone(&state.tx_policy))
            .with_ibd(state.ibd(), state.config().network),
        relay_rx,
        Arc::downgrade(&gateway),
        state.shutdown_reader(),
    )?);
    let inbound_tx_rx = state
        .take_inbound_tx_receiver()
        .ok_or(RunError::InboundTxReceiverTaken)?;
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
            Arc::new(crate::p2p::LocalTxRelayObserver::new(
                relay_queue,
                Arc::downgrade(&gateway),
            )),
            bitcoin_rs_mempool::BodyInterest::Metadata,
        )
        .map_err(RunError::GatewayObserverLeg)?;

    crate::chain_effects::bootstrap_genesis(&chainstate, &state.chain_followers()).map_err(
        |source| RunError::BootstrapGenesis {
            source: Box::new(source),
        },
    )?;
    #[cfg(feature = "pool")]
    {
        guard.services.pool = crate::pool::PoolService::prepare(state, &mining_control)?;
    }
    #[cfg(feature = "pool")]
    let pool_handles = guard.services.pool.as_ref().map_or_else(
        bitcoin_rs_wire::context::PoolHandles::default,
        crate::pool::PoolService::handles,
    );
    #[cfg(not(feature = "pool"))]
    let pool_handles = bitcoin_rs_wire::context::PoolHandles::default();
    let RpcBindings { context, listeners } =
        bind_rpc_with_pool(state, &mining_control, block_body_source, pool_handles)?;
    start_rpc_listeners(state, listeners, &mut guard.services)?;
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
        .map_err(RunError::P2pStart)?;
    guard.services.maintenance_worker = Some(state.start_chainstate_maintenance()?);
    let loop_shutdown = state.shutdown_reader();
    let loop_chainstate = state.chainstate();
    let state_shutdown = state.shutdown_writer();
    guard.services.event_loop = Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-event-loop".into())
            .spawn(move || {
                loop_handle.spin(&loop_shutdown, move || {
                    state_shutdown.trigger();
                    loop_chainstate.request_shutdown();
                });
            })?,
    );
    Ok(guard.finish(context))
}
fn init_metrics_services(state: &NodeState, services: &mut NodeServices) -> Result<(), RunError> {
    services.metrics = if let Some(bind) = state.config().observability.metrics_bind {
        let identity = crate::metrics::EvidenceIdentity::of_process(state.config())?;
        crate::metrics::start_metrics(Some(bind), state.shutdown_reader(), &identity)?
    } else {
        None
    };
    services.readiness_sampler = if services.metrics.is_some() {
        Some(crate::metrics::spawn_readiness_sampler(
            state.derived_index_status(),
            state.shutdown_reader(),
        )?)
    } else {
        None
    };
    Ok(())
}

fn start_rpc_listeners(
    state: &NodeState,
    listeners: Vec<(RpcServer, RpcSurface)>,
    services: &mut NodeServices,
) -> Result<(), RunError> {
    for (rpc_server, surface) in listeners {
        let rpc_local_addr = rpc_server.local_addr()?;
        services.rpc_addresses.push((surface, rpc_local_addr));
        tracing::info!(addr = %rpc_local_addr, ?surface, "rpc listener bound");
        let rpc_shutdown = state.shutdown_reader();
        let worker = std::thread::Builder::new()
            .name("bitcoin-rs-wire".into())
            .spawn(move || {
                let result = rpc_server.serve_surface_with_shutdown(rpc_shutdown.clone(), surface);
                if !rpc_shutdown.is_triggered() {
                    tracing::error!(?surface, error = ?result.as_ref().err(), "rpc listener exited before shutdown");
                }
                result
            })?;
        services.rpc_threads.push(worker);
    }
    Ok(())
}

fn final_payout_script(config: &NodeConfig) -> Vec<u8> {
    #[cfg(feature = "pool")]
    if let Some(pool) = config.pool.as_ref() {
        return pool.reward_script.clone();
    }
    config.mining.payout_script.clone()
}
const GLOBAL_RAYON_THREADS: usize = 4;

pub(crate) fn worker_shares() -> u32 {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    u32::try_from(available.min(GLOBAL_RAYON_THREADS)).unwrap_or(1)
}

fn cap_global_thread_pool() {
    let threads = worker_shares();
    if let Err(error) = rayon::ThreadPoolBuilder::new()
        .num_threads(usize::try_from(threads).unwrap_or(GLOBAL_RAYON_THREADS))
        .build_global()
    {
        tracing::debug!(%error, "global rayon pool already configured, keeping it");
    }
}

fn unsize_tx_policy(
    policy: Arc<crate::p2p::tx_policy::NodeTxPolicy>,
) -> Arc<dyn bitcoin_rs_p2p::listener::TxPolicyObserver> {
    policy
}

fn unsize_block_sync(
    sync: Arc<crate::p2p::sync::BlockSync>,
) -> Arc<dyn bitcoin_rs_p2p::listener::BlockSyncObserver> {
    sync
}

fn unsize_block_announcer(
    announcer: Arc<crate::p2p::BlockAnnouncer>,
) -> Arc<dyn bitcoin_rs_p2p::listener::BlockAnnounceObserver> {
    announcer
}
#[cfg(test)]
mod tests {
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_consensus::primitives::{BlockBodyMetadata, BlockImage, Hash256};
    use bitcoin_rs_storage::block_body::{BlockBodyReader, BlockBodyStore};
    use bitcoin_rs_storage::{BlockFilePosition, BodyExtent, BoundedReadError, StorageError};
    use std::io::{Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
    use std::sync::{Condvar, Mutex};
    use std::thread::{self, JoinHandle};

    use super::*;
    use crate::config::{NodeConfig, RuntimeInputs};
    use crate::lifecycle::start_node;
    use crate::run::{RunError, run};
    use crate::test_support::TestError;

    fn isolated_config(data_dir: &Path) -> NodeConfig {
        let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.to_owned();
        config.rpc.bind = SocketAddr::from(([127, 0, 0, 1], 0));
        config.rpc.auth = crate::Auth::basic("user", "password");
        config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
        config.p2p.listen.clear();
        config.observability.metrics_bind = None;
        config
    }

    #[test]
    fn split_rpc_listeners_start_and_join_through_node_services() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut config = isolated_config(dir.path());
        config.rpc.bind = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        config.rpc.public_bind = Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
        let node = start_node(config, RuntimeInputs::default(), false)?;
        let services = node
            .services
            .as_ref()
            .ok_or(TestError::Missing("node services"))?;
        assert_eq!(services.rpc_threads.len(), 2);
        let management_address = services
            .rpc_address(bitcoin_rs_wire::RpcSurface::Management)
            .ok_or(TestError::Missing("management address"))?;
        let public_address = services
            .rpc_address(bitcoin_rs_wire::RpcSurface::Public)
            .ok_or(TestError::Missing("public address"))?;
        for (address, request, expected) in [
            (
                public_address,
                "OPTIONS /api/tx HTTP/1.1\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 204 No Content",
            ),
            (
                management_address,
                "POST / HTTP/1.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 401 Unauthorized",
            ),
        ] {
            let mut stream = TcpStream::connect(address)?;
            stream.set_read_timeout(Some(WITNESS_BOUND))?;
            stream.write_all(request.as_bytes())?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            assert!(response.starts_with(expected), "{response}");
        }
        node.shutdown_blocking()?;
        Ok(())
    }

    // BUD-02, P2P-01
    #[test]
    fn startup_shares_recent_block_serving_and_ingress_memory() -> Result<(), TestError> {
        use bitcoin::hashes::Hash;
        use bitcoin::p2p::message_blockdata::Inventory;
        use bitcoin_rs_chain::chain::regtest_fixture;
        use bitcoin_rs_consensus::primitives::{Amount, Network, Script, TxOut, unix_time_secs};
        use bitcoin_rs_p2p::handshake::run_inbound_handshake;
        use bitcoin_rs_p2p::test_support::message_channel;
        use bitcoin_rs_p2p::wire::{read_message, write_message};
        use bitcoin_rs_p2p::{Message, Peer, PeerLease};
        use bitcoin_rs_storage::budget::BudgetOwner;

        fn read_reply(
            peer: &mut Peer<TcpStream>,
            accept: impl Fn(&Message) -> bool,
        ) -> Result<Message, TestError> {
            let deadline = std::time::Instant::now() + WITNESS_BOUND;
            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(TestError::Timeout("startup peer reply"));
                }
                peer.stream.set_read_timeout(Some(remaining))?;
                let (message, _) = read_message(&mut peer.stream, peer.magic)?;
                if accept(&message) {
                    return Ok(message);
                }
                match message {
                    Message::Ping(nonce) => {
                        peer.send(&Message::Pong(nonce))?;
                    }
                    Message::GetHeaders(_) => {
                        peer.send(&Message::Headers(Vec::new()))?;
                    }
                    Message::GetData(items) => {
                        peer.send(&Message::NotFound(items))?;
                    }
                    _ => {}
                }
            }
        }

        let dir = tempfile::tempdir()?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let mut config = isolated_config(dir.path());
        config.p2p.connect = vec![listener.local_addr()?.to_string()];
        config.p2p.dns_seeds_enabled = false;
        config.p2p.v2_transport = false;
        let magic = bitcoin::p2p::Magic::from_bytes(config.p2p.magic);
        let node = start_node(config, RuntimeInputs::default(), false)?;
        let deadline = std::time::Instant::now() + WITNESS_BOUND;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(TestError::Timeout("startup outbound peer"));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        };
        stream.set_read_timeout(Some(WITNESS_BOUND))?;
        stream.set_write_timeout(Some(WITNESS_BOUND))?;
        let mut peer = Peer::new(stream, magic);
        let (outbound, _outbound_rx) = message_channel();
        let lease = PeerLease::new_inbound(outbound);
        run_inbound_handshake(
            &mut peer,
            1,
            0,
            bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
            bitcoin_rs_consensus::primitives::USER_AGENT,
            &lease,
            std::time::Instant::now() + WITNESS_BOUND,
        )?;

        let now = u32::try_from(unix_time_secs())?;
        let first = BlockImage::from_local(regtest_fixture::mined_regtest_child_at_time(
            Network::Regtest.genesis_block().block_hash(),
            now,
            1,
        )?);
        node.state.apply_block(&first)?;
        assert!(
            !node
                .state
                .chainstate()
                .ibd_latch()
                .is_active(u64::from(now), Network::Regtest,)
        );
        let budget = node.state.budget();
        assert_eq!(budget.charged_bytes(BudgetOwner::StagedImages), 0);
        let second = BlockImage::from_local(regtest_fixture::mined_regtest_child_at_time(
            first.block_hash(),
            now + 1,
            2,
        )?);
        node.state.apply_block(&second)?;
        let second_charge = budget.charged_bytes(BudgetOwner::StagedImages);
        assert!(second_charge >= u64::try_from(second.retained_heap_bytes())?);
        let second_tx = second.tx(0).materialize();
        let second_item =
            Inventory::Transaction(bitcoin::Txid::from_byte_array(*second_tx.txid().as_bytes()));
        assert!(node.state.mempool_gateway().read().is_empty());
        peer.send(&Message::GetData(vec![second_item]))?;
        assert_eq!(
            read_reply(&mut peer, |message| matches!(
                message,
                Message::Tx(_) | Message::NotFound(_)
            ))?,
            Message::Tx(second_tx)
        );

        let mut third =
            regtest_fixture::mined_regtest_child_at_time(second.block_hash(), now + 2, 3)?;
        third.txs[0].outputs.extend((0..16).map(|_| TxOut {
            value: Amount::from_sat(0),
            script_pubkey: Script::new(),
        }));
        third.header.merkle_root = regtest_fixture::merkle_root(&third.txs)
            .ok_or(TestError::Missing("startup block merkle root"))?;
        third.header.nonce = 0;
        regtest_fixture::mine_block_to_declared_target(&mut third)?;
        let third = BlockImage::from_local(third);
        let heap_growth = third
            .retained_heap_bytes()
            .checked_sub(second.retained_heap_bytes())
            .ok_or(TestError::ExpectationFailed("larger retained block layout"))?;
        assert!(heap_growth > 0);
        node.state.apply_block(&third)?;
        let third_charge = budget.charged_bytes(BudgetOwner::StagedImages);
        assert_eq!(third_charge, second_charge + u64::try_from(heap_growth)?);
        let third_tx = third.tx(0).materialize();
        let third_item =
            Inventory::Transaction(bitcoin::Txid::from_byte_array(*third_tx.txid().as_bytes()));
        peer.send(&Message::GetData(vec![third_item]))?;
        assert_eq!(
            read_reply(&mut peer, |message| matches!(
                message,
                Message::Tx(_) | Message::NotFound(_)
            ))?,
            Message::Tx(third_tx)
        );
        peer.send(&Message::GetData(vec![second_item]))?;
        assert_eq!(
            read_reply(&mut peer, |message| matches!(
                message,
                Message::Tx(_) | Message::NotFound(_)
            ))?,
            Message::NotFound(vec![second_item])
        );
        assert!(node.state.mempool_gateway().read().is_empty());

        let mut frame = Vec::new();
        write_message(
            &mut frame,
            magic,
            &Message::BlockBytes(third.bytes().clone()),
        )?;
        let split = frame.len() - 1;
        peer.stream.write_all(&frame[..split])?;
        let partial_body = u64::try_from(third.bytes().len() - 1)?;
        let deadline = std::time::Instant::now() + WITNESS_BOUND;
        while budget.charged_bytes(BudgetOwner::PeerReceive) < partial_body {
            if std::time::Instant::now() >= deadline {
                return Err(TestError::Timeout("partial frame charged to node ingress"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            budget.charged_bytes(BudgetOwner::StagedImages),
            third_charge
        );
        peer.stream.write_all(&frame[split..])?;
        peer.send(&Message::Ping(0x0053_5441_5254_5550))?;
        assert_eq!(
            read_reply(&mut peer, |message| matches!(
                message,
                Message::Pong(0x0053_5441_5254_5550)
            ))?,
            Message::Pong(0x0053_5441_5254_5550)
        );
        let deadline = std::time::Instant::now() + WITNESS_BOUND;
        while budget.charged_bytes(BudgetOwner::PeerReceive) != 0
            || budget.charged_bytes(BudgetOwner::StagedImages) != third_charge
        {
            if std::time::Instant::now() >= deadline {
                return Err(TestError::Timeout("completed duplicate frame released"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        peer.stream.shutdown(Shutdown::Both)?;
        drop(peer);
        drop(lease);
        node.shutdown_blocking()?;
        assert_eq!(budget.charged_bytes(BudgetOwner::PeerReceive), 0);
        assert_eq!(budget.charged_bytes(BudgetOwner::StagedImages), 0);
        Ok(())
    }

    #[test]
    fn public_bind_failure_rolls_back_management_binding_and_node_state() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut config = isolated_config(dir.path());
        let public = std::net::TcpListener::bind("127.0.0.1:0")?;
        let public_address = public.local_addr()?;
        config.rpc.bind = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        config.rpc.public_bind = Some(public_address);
        let error = match start_node(config.clone(), RuntimeInputs::default(), false) {
            Ok(_) => {
                return Err(TestError::UnexpectedSuccess(
                    "occupied public bind succeeded",
                ));
            }
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            format!("failed to bind public HTTP listener at {public_address}")
        );
        let RunError::PublicRpcBind { source, .. } = &error else {
            panic!("expected RunError::PublicRpcBind, got: {error:?}");
        };
        assert_eq!(source.kind(), std::io::ErrorKind::AddrInUse);
        let _reopened = NodeState::open(config, None)?;
        Ok(())
    }

    #[test]
    fn timed_out_snapshot_worker_cannot_overwrite_the_next_runs_snapshot() -> Result<(), TestError>
    {
        use bitcoin_rs_consensus::primitives::{Hash256, Network, Txid};
        use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits, snapshot};
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir()?;
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(
                MempoolLimits::default(),
            ))),
            None,
            ValidationEngine::Native,
            None,
        ));
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
        let (release_tx, release_rx) = crossbeam_channel::bounded(1);
        let (result_tx, result_rx) = crossbeam_channel::bounded(1);
        let worker_gateway = Arc::clone(&gateway);
        let path = dir.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            let staged = snapshot::prepare(
                &path,
                &worker_gateway,
                Network::Regtest,
                snapshot::DEFAULT_MAX_BYTES,
                Instant::now() + Duration::from_secs(10),
            );
            let _ = ready_tx.send(staged.is_ok());
            let _ = release_rx.recv();
            let _ = result_tx.send(staged);
        });
        let prepared = ready_rx.recv_timeout(Duration::from_secs(10))?;
        publish_mempool_snapshot(result_rx, Instant::now() + Duration::from_millis(2));
        gateway.prioritise(Txid(Hash256::from_le_bytes(&[7; 32])), 50)?;
        snapshot::save(
            dir.path(),
            &gateway,
            Network::Regtest,
            snapshot::DEFAULT_MAX_BYTES,
            Instant::now() + Duration::from_secs(10),
        )?;
        let file = dir.path().join("mempool-snapshot.dat");
        let newer = std::fs::read(&file)?;
        let _ = release_tx.send(());
        worker.join().map_err(|_| TestError::ThreadPanicked)?;
        assert!(
            prepared,
            "the delayed worker must hold a valid old snapshot"
        );
        assert_eq!(std::fs::read(&file)?, newer);
        assert_eq!(std::fs::read_dir(dir.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn rpc_network_handles_borrow_p2p_service_state() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let state = NodeState::open(isolated_config(dir.path()), None)?;
        let p2p = state.p2p();
        let handles = rpc_network_handles(&state);

        assert!(Arc::ptr_eq(&handles.peer_table, &p2p.table()));
        assert!(Arc::ptr_eq(&handles.p2p, &p2p));
        assert_eq!(handles.local_services, p2p.local_services().to_u64());
        assert_eq!(handles.v2_transport, state.config().p2p.v2_transport);
        Ok(())
    }

    #[test]
    fn verifychain_arguments_select_the_check_core_asks_for() {
        for (check_level, level) in [
            (0, CheckLevel::ReadBodies),
            (1, CheckLevel::CheckBodies),
            (2, CheckLevel::CheckUndo),
            (3, CheckLevel::CheckUndo),
            (4, CheckLevel::CheckUndo),
        ] {
            let request = verify_request(check_level, 6);
            assert_eq!(request.level, level, "level {check_level}");
            assert_eq!(request.depth, NonZeroU32::new(6), "level {check_level}");
            assert!(
                request.cancellation.is_none(),
                "the latch travels with the call, not the mapping"
            );
        }
        assert_eq!(
            verify_request(3, 0).depth,
            None,
            "zero blocks is the whole chain"
        );
    }

    #[test]
    fn verify_chain_accepts_an_intact_applied_chain_at_every_level_and_depth()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let state = NodeState::open(isolated_config(dir.path()), None)?;
        let genesis = BlockImage::from_local(
            bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
        );
        state.apply_block(&genesis)?;
        let mut previous = genesis.block_hash();
        for height in 1..=3 {
            let block = BlockImage::from_local(
                bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_child_at(previous, height)?,
            );
            state.apply_block(&block)?;
            previous = block.block_hash();
        }
        let control = RpcChainControl {
            handles: state.chainstate(),
            followers: state.chain_followers(),
            sync: state.sync(),
            snapshots: Arc::clone(&state.snapshots),
        };
        let cancellation = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        for check_level in 0..=4 {
            for nblocks in [0, 2, 100] {
                assert!(
                    matches!(
                        control.verify_chain(check_level, nblocks, &cancellation),
                        Ok(true)
                    ),
                    "level {check_level}, {nblocks} blocks"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn verify_chain_over_applied_genesis_is_answered_by_the_real_verifier() -> Result<(), TestError>
    {
        use bitcoin_rs_wire::context::ChainControlError;

        let dir = tempfile::tempdir()?;
        let state = NodeState::open(isolated_config(dir.path()), None)?;
        state.apply_block(&BlockImage::from_local(
            bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
        ))?;
        assert_eq!(
            state
                .chainstate()
                .applied_tip_snapshot()
                .map(|tip| tip.height),
            Some(0),
            "the fixture must apply genesis and nothing above it"
        );
        let control = RpcChainControl {
            handles: state.chainstate(),
            followers: state.chain_followers(),
            sync: state.sync(),
            snapshots: Arc::clone(&state.snapshots),
        };
        let live = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        for check_level in 0..=4 {
            for nblocks in [0, 1, 6] {
                assert!(
                    matches!(control.verify_chain(check_level, nblocks, &live), Ok(true)),
                    "level {check_level}, {nblocks} blocks"
                );
            }
        }
        state.chainstate().fail_closed_for_recovery();
        assert!(matches!(
            control.verify_chain(3, 6, &live),
            Err(ChainControlError::Unavailable)
        ));
        Ok(())
    }

    #[test]
    fn verify_chain_reports_cancellation_and_recovery_closure() -> Result<(), TestError> {
        use bitcoin_rs_wire::context::ChainControlError;

        let dir = tempfile::tempdir()?;
        let state = NodeState::open(isolated_config(dir.path()), None)?;
        let control = RpcChainControl {
            handles: state.chainstate(),
            followers: state.chain_followers(),
            sync: state.sync(),
            snapshots: Arc::clone(&state.snapshots),
        };
        let live = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        assert!(
            matches!(control.verify_chain(3, 6, &live), Ok(true)),
            "an open chain must verify"
        );
        let fired = {
            let trigger = bitcoin_rs_consensus::latch::LatchWriter::new();
            trigger.trigger();
            trigger.reader()
        };
        assert!(
            matches!(
                control.verify_chain(3, 6, &fired),
                Err(ChainControlError::Interrupted)
            ),
            "a cancelled request must interrupt, not fail as damage"
        );
        state.chainstate().fail_closed_for_recovery();
        assert!(
            matches!(
                control.verify_chain(3, 6, &live),
                Err(ChainControlError::Unavailable)
            ),
            "a closed chain must be unavailable, not verified"
        );
        Ok(())
    }

    #[test]
    fn rpc_load_txoutset_follows_core_import_behavior_independent_of_filename()
    -> Result<(), TestError> {
        use bitcoin_rs_chain::manifest::{ARTIFACT_SLOTS, SnapshotManifest, UTXO_SLOT};
        use sha2::Digest;

        let pinned = bitcoin_rs_consensus::primitives::Network::Regtest
            .assume_utxo_for_height(200)
            .ok_or(TestError::Missing("regtest height-200 anchor"))?;
        let dir = tempfile::tempdir()?;
        let mut config = isolated_config(dir.path());
        config.data_dir = dir.path().join("node");
        let state = NodeState::open(config, None)?;
        state.apply_block(&BlockImage::from_local(
            bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
        ))?;
        let headers: Vec<bitcoin_rs_consensus::primitives::Header> =
            sonic_rs::from_str::<Vec<String>>(include_str!(
                "../../../testdata/storage/fixtures/core-v2/blocks200.json"
            ))?
            .iter()
            .map(|hex| {
                let block: bitcoin::Block = bitcoin::consensus::encode::deserialize_hex(hex)?;
                bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(
                    &block.header,
                ))
                .map_err(TestError::from)
            })
            .collect::<Result<_, _>>()?;
        state.chainstate().admit_headers(&headers)?;
        let core_bytes =
            include_bytes!("../../../testdata/storage/fixtures/core-v2/core200.dat").as_slice();

        let applied_tip = || {
            state
                .chainstate()
                .applied_tip_snapshot()
                .map(|tip| tip.height)
        };
        assert_eq!(applied_tip(), Some(0));

        let control = RpcChainControl {
            handles: state.chainstate(),
            followers: state.chain_followers(),
            sync: state.sync(),
            snapshots: Arc::clone(&state.snapshots),
        };

        let mut sizes = [0_u64; ARTIFACT_SLOTS];
        let mut hashes = [[0_u8; 32]; ARTIFACT_SLOTS];
        sizes[UTXO_SLOT] = u64::try_from(core_bytes.len()).map_err(std::io::Error::other)?;
        hashes[UTXO_SLOT] = sha2::Sha256::digest(core_bytes).into();
        let manifest = SnapshotManifest {
            manifest_version: 1,
            network: "regtest".to_string(),
            genesis: bitcoin_rs_consensus::primitives::Network::Regtest
                .genesis_block_hash()
                .to_le_bytes(),
            base_hash: pinned.block_hash.to_le_bytes(),
            base_height: pinned.height,
            schema: bitcoin_rs_index::index_format_version(),
            utxo_commitment: pinned.hash_serialized.to_le_bytes(),
            index_commitments: [None; 4],
            coverage: [None; 4],
            sizes,
            hashes,
            historical_verified_height: 0,
        };
        let manifest_path = dir.path().join("snapshot_manifest.json");
        std::fs::write(&manifest_path, sonic_rs::to_vec_pretty(&manifest)?)?;

        assert!(
            control.load_txoutset(&manifest_path).is_err(),
            "a valid manifest JSON must not activate through the RPC surface"
        );
        assert_eq!(
            applied_tip(),
            Some(0),
            "the refused manifest attempt must install nothing"
        );

        let renamed = dir.path().join("core200.json");
        std::fs::write(&renamed, core_bytes)?;
        let imported = control.load_txoutset(&renamed)?;
        assert_eq!(imported.base_height, 200);
        assert_eq!(
            applied_tip(),
            Some(200),
            "a Core binary named .json must follow the same Core import behavior as extensionless"
        );
        Ok(())
    }

    fn seed_checkpoint(state: &NodeState) -> Result<(PathBuf, Vec<u8>), TestError> {
        state.apply_block(&BlockImage::from_local(
            bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
        ))?;
        let _ = state.publish_checkpoint()?;
        let current = state
            .data_dir()
            .join("chainstate-checkpoints")
            .join("CURRENT");
        let previous = std::fs::read(&current)?;
        Ok((current, previous))
    }

    struct RestoreCheckpointRoot {
        root: PathBuf,
        displaced: PathBuf,
    }

    impl Drop for RestoreCheckpointRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.root);
            let _ = std::fs::rename(&self.displaced, &self.root);
        }
    }

    #[test]
    fn disabled_zmq_still_seals_the_observer_slot() {
        let pool = Arc::new(parking_lot::RwLock::new(bitcoin_rs_mempool::Mempool::new(
            bitcoin_rs_mempool::MempoolLimits::default(),
        )));
        let observer: Arc<dyn bitcoin_rs_mempool::MempoolObserver> =
            Arc::new(bitcoin_rs_mempool::CompositeObserver::new());
        let gateway = Arc::new(bitcoin_rs_mempool::MempoolGateway::new(
            pool,
            Some((observer, bitcoin_rs_mempool::BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ));
        assert!(
            gateway.has_observer(),
            "startup must seal the observer slot even without a ZMQ endpoint"
        );
    }

    #[test]
    fn clean_shutdown_publishes_checkpoint_and_returns_success() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let config = isolated_config(&temp.path().join("node-success"));
        let state = NodeState::open(config.clone(), None)?;
        let (current, previous) = seed_checkpoint(&state)?;
        drop(state);

        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        let _ = shutdown_tx.send(());
        run(
            config.clone(),
            RuntimeInputs::default().with_shutdown(shutdown_rx),
        )?;
        assert_ne!(std::fs::read(current)?, previous);
        let resumed = NodeState::open(config, None)?;
        assert_eq!(
            resumed.resume_source(),
            crate::state::ResumeSource::Checkpoint
        );
        Ok(())
    }

    #[test]
    fn shutdown_checkpoint_io_failure_is_returned_and_preserves_current() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let mut config = isolated_config(&temp.path().join("node-checkpoint-failure"));
        config.p2p.connect = vec!["127.0.0.1:1".to_owned()];
        let state = NodeState::open(config.clone(), None)?;
        let (current, previous) = seed_checkpoint(&state)?;
        drop(state);

        let checkpoint_root = current
            .parent()
            .ok_or(TestError::Missing("checkpoint parent directory"))?
            .to_path_buf();
        let displaced = checkpoint_root.with_extension("checkpoint-failure-backup");
        let restore = RestoreCheckpointRoot {
            root: checkpoint_root.clone(),
            displaced: displaced.clone(),
        };
        let injected = Arc::new(AtomicBool::new(false));
        inject_before_clean_checkpoint({
            let displaced = displaced.clone();
            let injected = Arc::clone(&injected);
            move || {
                injected.store(true, Ordering::Release);
                std::fs::rename(&checkpoint_root, &displaced)
                    .unwrap_or_else(|error| panic!("move checkpoint root aside: {error}"));
                std::fs::write(&checkpoint_root, b"not a directory")
                    .unwrap_or_else(|error| panic!("replace checkpoint root with file: {error}"));
            }
        });

        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        shutdown_tx
            .send(())
            .map_err(|_| TestError::ExpectationFailed("shutdown receiver is live"))?;
        let result = run(config, RuntimeInputs::default().with_shutdown(shutdown_rx));

        assert!(result.is_err());
        assert!(
            injected.load(Ordering::Acquire),
            "clean-checkpoint failure hook was not reached; run failed earlier: {result:?}"
        );
        assert_eq!(std::fs::read(displaced.join("CURRENT"))?, previous);
        assert!(
            bootstrap_drain_was_reached(),
            "checkpoint errors must not bypass the bootstrap-worker join"
        );
        drop(restore);
        Ok(())
    }

    // EMB-01
    #[test]
    fn teardown_join_failure_completes_cleanup_and_suppresses_checkpoint() -> Result<(), TestError>
    {
        let temp = tempfile::tempdir()?;
        let config = isolated_config(&temp.path().join("node-join-failure"));
        let mut state = NodeState::open(config.clone(), None)?;
        let (current, previous) = seed_checkpoint(&state)?;
        let panicker = std::thread::Builder::new()
            .name("bitcoin-rs-outbound-drain".to_owned())
            .spawn(|| panic!("injected worker panic"))?;
        let mut services = NodeServices::default();
        state.p2p().test_install_outbound_worker(panicker);

        assert!(
            services
                .teardown(Some(&mut state), TeardownMode::CleanShutdown)
                .is_err()
        );
        assert_eq!(shutdown::take_shutdown_stages_reached(), 1);
        assert_eq!(std::fs::read(current)?, previous);
        drop(services);
        drop(state);

        let resumed = NodeState::open(config, None)?;
        assert_eq!(
            resumed.resume_source(),
            crate::state::ResumeSource::Checkpoint
        );
        Ok(())
    }

    #[test]
    fn teardown_joins_bootstrap_worker_beyond_former_deadline() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let config = isolated_config(&temp.path().join("node-slow-bootstrap"));
        let mut state = NodeState::open(config, None)?;
        let (current, previous) = seed_checkpoint(&state)?;
        let (_gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let (exited_tx, exited_rx) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("bitcoin-rs-p2p-bootstrap".to_owned())
            .spawn(move || {
                let _ = gate_rx.recv_timeout(std::time::Duration::from_secs(2));
                let _ = exited_tx.send(());
            })?;
        let mut services = NodeServices::default();
        state.p2p().test_install_bootstrap_worker(worker);
        let started = std::time::Instant::now();
        services.teardown(Some(&mut state), TeardownMode::CleanShutdown)?;
        let elapsed = started.elapsed();
        assert!(elapsed >= std::time::Duration::from_secs(2));
        assert!(
            exited_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .is_ok()
        );
        assert!(bootstrap_drain_was_reached());
        assert_ne!(std::fs::read(current)?, previous);
        drop(services);
        drop(state);
        Ok(())
    }

    #[test]
    fn teardown_metrics_panic_reports_failure_and_preserves_checkpoint() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let mut state = NodeState::open(isolated_config(temp.path()), None)?;
        let (current, previous) = seed_checkpoint(&state)?;
        let worker = std::thread::Builder::new()
            .name("bitcoin-rs-metrics".to_owned())
            .spawn(|| panic!("injected scrape worker panic"))?;
        let mut services = NodeServices::default();
        services.metrics = Some(crate::metrics::MetricsServer::with_worker_for_test(worker));

        let Err(error) = services.teardown(Some(&mut state), TeardownMode::CleanShutdown) else {
            return Err(TestError::UnexpectedSuccess(
                "teardown with panicked metrics succeeded",
            ));
        };
        assert!(
            matches!(error, RunError::MetricsScrapeThreadPanicked),
            "{error:?}"
        );
        assert_eq!(shutdown::take_shutdown_stages_reached(), 1);
        assert!(bootstrap_drain_was_reached());
        assert_eq!(std::fs::read(&current)?, previous);
        assert!(services.metrics.is_none());
        services.teardown(Some(&mut state), TeardownMode::CleanShutdown)?;
        assert_eq!(shutdown::take_shutdown_stages_reached(), 0);
        assert_eq!(std::fs::read(current)?, previous);
        Ok(())
    }

    // EMB-01
    #[test]
    fn daemon_and_embedded_paths_share_one_teardown() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let daemon_config = isolated_config(&temp.path().join("daemon"));
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        let _ = shutdown_tx.send(());
        let stages_before = shutdown::take_shutdown_stages_reached();
        run(
            daemon_config,
            RuntimeInputs::default().with_shutdown(shutdown_rx),
        )?;
        assert_eq!(shutdown::take_shutdown_stages_reached(), stages_before + 1);

        let embedded_config = isolated_config(&temp.path().join("embedded"));
        let installed_before = crate::signal::testing::installed_total();
        let closed_before = crate::signal::testing::closed_total();
        let node = start_node(embedded_config, RuntimeInputs::default(), true)?;
        node.shutdown_blocking()?;
        assert_eq!(shutdown::take_shutdown_stages_reached(), 1);
        assert_eq!(
            crate::signal::testing::installed_total(),
            installed_before + 1
        );
        assert_eq!(crate::signal::testing::closed_total(), closed_before + 1);
        Ok(())
    }

    #[test]
    fn repeated_teardown_and_drop_join_workers_once() -> Result<(), TestError> {
        shutdown::take_shutdown_stages_reached();
        let joins = Arc::new(AtomicUsize::new(0));
        let worker_joins = Arc::clone(&joins);
        let mut services = NodeServices::default();
        services.tx_ingress = Some(std::thread::spawn(move || {
            worker_joins.fetch_add(1, Ordering::Release);
        }));
        services.teardown(None, TeardownMode::StartupAbort)?;
        services.teardown(None, TeardownMode::StartupAbort)?;
        drop(services);
        assert_eq!(joins.load(Ordering::Acquire), 1);
        assert_eq!(shutdown::take_shutdown_stages_reached(), 1);
        Ok(())
    }

    #[test]
    fn startup_rollback_joins_workers_and_preserves_checkpoint() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let config = isolated_config(&temp.path().join("startup-rollback"));
        let state = NodeState::open(config.clone(), None)?;
        let (current, previous) = seed_checkpoint(&state)?;
        let shutdown = state.chainstate().shutdown_reader();
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = Arc::clone(&exited);
        let worker = std::thread::spawn(move || {
            while !shutdown.is_triggered() {
                std::thread::yield_now();
            }
            worker_exited.store(true, Ordering::Release);
        });
        let mut guard = StartupGuard {
            state: Some(state),
            services: NodeServices::default(),
        };
        guard.services.tx_ingress = Some(worker);
        drop(guard);
        assert!(exited.load(Ordering::Acquire));
        assert_eq!(std::fs::read(current)?, previous);
        let resumed = NodeState::open(config, None)?;
        assert_eq!(
            resumed.resume_source(),
            crate::state::ResumeSource::Checkpoint
        );
        Ok(())
    }

    #[test]
    fn explicit_shutdown_joins_index_worker_before_clean_checkpoint() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let mut config = isolated_config(&temp.path().join("node-index-join"));
        config.indexes.txindex = true;
        let node = start_node(config, RuntimeInputs::default(), true)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while matches!(
            node.state.derived_index_status().capability().state,
            bitcoin_rs_index::CapabilityState::Opening
        ) {
            assert!(
                std::time::Instant::now() < deadline,
                "txindex lifecycle remained Opening"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let joined = node.state.index_worker_joined();
        let worker_joined_before_checkpoint = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&worker_joined_before_checkpoint);
        inject_before_clean_checkpoint(move || {
            flag.store(joined.load(Ordering::Acquire), Ordering::Release);
        });

        node.shutdown_blocking()?;

        assert!(
            worker_joined_before_checkpoint.load(Ordering::Acquire),
            "the derived-index worker must be stopped and joined before the \
         clean checkpoint publishes"
        );
        Ok(())
    }

    // EMB-09
    #[test]
    fn a_queued_shutdown_wake_does_not_block_teardown() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let config = isolated_config(&temp.path().join("node-forwarder"));
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        let node = start_node(
            config.clone(),
            RuntimeInputs::default().with_shutdown(shutdown_rx),
            false,
        )?;

        let _ = shutdown_tx.send(());
        node.shutdown_blocking()?;

        let reopened = NodeState::open(config, None)?;
        drop(reopened);
        drop(shutdown_tx);
        Ok(())
    }

    // EMB-01
    #[test]
    fn recovery_closure_stops_the_node_run_loop() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let config = isolated_config(&temp.path().join("node-recovery-exit"));
        let node = start_node(config, RuntimeInputs::default(), false)?;

        node.state.chainstate().fail_closed_for_recovery();

        let deadline = std::time::Instant::now() + WITNESS_BOUND;
        loop {
            let exited = node
                .services
                .as_ref()
                .and_then(|services| services.event_loop.as_ref())
                .is_some_and(|handle| handle.is_finished());
            if exited {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the event loop kept running after a chainstate recovery closure"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            node.state.shutdown_reader().is_triggered(),
            "a recovery closure must raise the node shutdown latch"
        );

        match node.shutdown_blocking() {
            Err(crate::embed::NodeError::ClosedForRecovery) => {}
            other => panic!("a recovery closure must not tear down as a clean shutdown: {other:?}"),
        }
        Ok(())
    }

    // SYNC-04
    #[test]
    fn fatal_settlement_teardown_skips_the_checkpoint_and_answers_an_error() -> Result<(), TestError>
    {
        type CloseChain = Box<dyn Fn(&bitcoin_rs_chain::Chainstate)>;
        let variants: Vec<(&str, CloseChain)> = vec![
            (
                "fatal-settlement",
                Box::new(|chain: &bitcoin_rs_chain::Chainstate| chain.fail_closed_for_recovery()),
            ),
            (
                "graceful-close",
                Box::new(|chain: &bitcoin_rs_chain::Chainstate| {
                    drop(chain.close());
                }),
            ),
        ];
        for (variant, close) in variants {
            let temp = tempfile::tempdir()?;
            let config = isolated_config(&temp.path().join(variant));
            let state = NodeState::open(config.clone(), None)?;
            let (current, previous) = seed_checkpoint(&state)?;
            drop(state);

            let node = start_node(config.clone(), RuntimeInputs::default(), false)?;
            let chain = node.state.chainstate();
            close(&chain);
            drop(chain);
            let deadline = std::time::Instant::now() + WITNESS_BOUND;
            loop {
                let exited = node
                    .services
                    .as_ref()
                    .and_then(|services| services.event_loop.as_ref())
                    .is_some_and(|handle| handle.is_finished());
                if exited {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the event loop kept running after the chainstate closure"
                );
                thread::sleep(Duration::from_millis(10));
            }

            match node.shutdown_blocking() {
                Err(crate::embed::NodeError::ClosedForRecovery) => {}
                other => {
                    panic!("a closed chainstate must not tear down as a clean shutdown: {other:?}")
                }
            }
            assert_eq!(
                std::fs::read(&current)?,
                previous,
                "the closed chainstate must not publish a fresh checkpoint"
            );
            let reopened = NodeState::open(config, None)?;
            assert_eq!(
                reopened.resume_source(),
                crate::state::ResumeSource::Checkpoint,
                "restart must replay from the checkpoint published before the closure"
            );
        }
        Ok(())
    }

    // SYNC-04
    #[test]
    fn recovery_closure_during_teardown_skips_the_checkpoint_and_answers_an_error()
    -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let config = isolated_config(&temp.path().join("node-recovery-recheck"));
        let state = NodeState::open(config.clone(), None)?;
        let (current, previous) = seed_checkpoint(&state)?;
        let snapshot = state.data_dir().join("mempool-snapshot.dat");
        assert!(
            !snapshot.exists(),
            "the fixture must not start from a stored mempool snapshot"
        );
        drop(state);

        let node = start_node(config, RuntimeInputs::default(), false)?;
        let chain = node.state.chainstate();
        inject_before_recovery_recheck(move || chain.fail_closed_for_recovery());

        match node.shutdown_blocking() {
            Err(crate::embed::NodeError::ClosedForRecovery) => {}
            other => panic!(
                "a chainstate closed while teardown joins its workers must not exit cleanly: {other:?}"
            ),
        }
        assert_eq!(
            std::fs::read(&current)?,
            previous,
            "a chainstate closed during teardown must not publish a fresh checkpoint"
        );
        assert!(
            !snapshot.exists(),
            "a chainstate closed during teardown must not save the mempool snapshot"
        );
        Ok(())
    }
    const WITNESS_BOUND: Duration = Duration::from_secs(10);
    const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

    struct BodyGateState {
        armed: bool,
        entered: bool,
        released: bool,
    }

    struct BodyGate {
        state: Mutex<BodyGateState>,
        cvar: Condvar,
    }

    impl BodyGate {
        fn new() -> Self {
            Self {
                state: Mutex::new(BodyGateState {
                    armed: false,
                    entered: false,
                    released: false,
                }),
                cvar: Condvar::new(),
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, BodyGateState> {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        fn arm(&self) {
            let mut state = self.lock();
            state.armed = true;
            state.entered = false;
            state.released = false;
        }

        fn hold(&self) {
            let mut state = self.lock();
            if !state.armed {
                return;
            }
            state.entered = true;
            self.cvar.notify_all();
            while !state.released {
                state = self
                    .cvar
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }

        fn wait_entered(&self, timeout: Duration) -> bool {
            let deadline = std::time::Instant::now() + timeout;
            let mut state = self.lock();
            while !state.entered {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let (next, _) = self
                    .cvar
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state = next;
            }
            state.entered
        }

        fn release(&self) {
            let mut state = self.lock();
            state.armed = false;
            state.released = true;
            self.cvar.notify_all();
        }
    }

    struct HoldingBodies {
        inner: Arc<dyn BlockBodyStore>,
        gate: Arc<BodyGate>,
    }

    impl BlockBodyStore for HoldingBodies {
        fn load_staged_body(
            &self,
            height: u32,
            hash: Hash256,
            position: Option<BlockFilePosition>,
        ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
            self.inner.load_staged_body(height, hash, position)
        }

        fn stage_block_body(
            &self,
            height: u32,
            hash: Hash256,
            body: &[u8],
        ) -> std::result::Result<Option<BlockFilePosition>, StorageError> {
            self.inner.stage_block_body(height, hash, body)
        }

        fn persist_block_body(
            &self,
            height: u32,
            hash: Hash256,
            body: &[u8],
        ) -> std::result::Result<(), StorageError> {
            self.inner.persist_block_body(height, hash, body)
        }

        fn persist_block_body_value(
            &self,
            height: u32,
            hash: Hash256,
            body: bytes::Bytes,
        ) -> std::result::Result<(), StorageError> {
            self.inner.persist_block_body_value(height, hash, body)
        }

        fn load_block_body(
            &self,
            height: u32,
            hash: Hash256,
        ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
            self.inner.load_block_body(height, hash)
        }

        fn load_block_body_for_verification(
            &self,
            height: u32,
            hash: Hash256,
        ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
            self.inner.load_block_body_for_verification(height, hash)
        }

        fn load_block_body_for_verification_bounded(
            &self,
            height: u32,
            hash: Hash256,
            max_bytes: usize,
        ) -> std::result::Result<Option<Vec<u8>>, BoundedReadError> {
            self.gate.hold();
            self.inner
                .load_block_body_for_verification_bounded(height, hash, max_bytes)
        }

        fn load_block_body_bounded(
            &self,
            height: u32,
            hash: Hash256,
            max_bytes: usize,
        ) -> std::result::Result<Option<Vec<u8>>, BoundedReadError> {
            self.inner.load_block_body_bounded(height, hash, max_bytes)
        }

        fn reader(&self) -> std::result::Result<Box<dyn BlockBodyReader + '_>, StorageError> {
            self.inner.reader()
        }

        fn undo_record(
            &self,
            height: u32,
            hash: Hash256,
        ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
            self.inner.undo_record(height, hash)
        }

        fn load_block_body_range(
            &self,
            height: u32,
            hash: Hash256,
            offset: u32,
            len: u32,
        ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
            self.inner.load_block_body_range(height, hash, offset, len)
        }

        fn block_body_metadata(
            &self,
            height: u32,
            hash: Hash256,
        ) -> std::result::Result<Option<BlockBodyMetadata>, StorageError> {
            self.inner.block_body_metadata(height, hash)
        }

        fn append_cursor(&self) -> Option<BodyExtent> {
            self.inner.append_cursor()
        }

        fn block_position(
            &self,
            height: u32,
            hash: Hash256,
        ) -> std::result::Result<Option<BlockFilePosition>, StorageError> {
            self.inner.block_position(height, hash)
        }

        fn disk_usage(&self) -> Option<u64> {
            self.inner.disk_usage()
        }

        fn sync(&self) -> std::result::Result<(), StorageError> {
            self.inner.sync()
        }

        fn flush_index(&self) -> std::result::Result<(), StorageError> {
            self.inner.flush_index()
        }
    }

    struct BoundedThread<T> {
        name: &'static str,
        handle: JoinHandle<T>,
        done: Receiver<()>,
    }

    impl<T: Send + 'static> BoundedThread<T> {
        fn spawn(
            name: &'static str,
            body: impl FnOnce() -> T + Send + 'static,
        ) -> Result<Self, TestError> {
            let (done_tx, done) = mpsc::channel();
            let handle = thread::Builder::new()
                .name(name.to_owned())
                .spawn(move || {
                    let output = body();
                    let _ = done_tx.send(());
                    output
                })?;
            Ok(Self { name, handle, done })
        }

        fn finish(self) -> Result<T, TestError> {
            let name = self.name;
            match self.done.recv_timeout(WITNESS_BOUND) {
                Err(RecvTimeoutError::Timeout) => Err(TestError::Timeout(name)),
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    self.handle.join().map_err(|_| TestError::ThreadPanicked)
                }
            }
        }
    }

    struct ServedWitness {
        stop: Box<dyn Fn() + Send>,
        gate: Option<Arc<BodyGate>>,
        server: Option<BoundedThread<std::io::Result<()>>>,
        client: Option<BoundedThread<Result<String, TestError>>>,
        client_socket: Option<TcpStream>,
    }

    impl ServedWitness {
        fn new(stop: impl Fn() + Send + 'static, gate: Option<Arc<BodyGate>>) -> Self {
            Self {
                stop: Box::new(stop),
                gate,
                server: None,
                client: None,
                client_socket: None,
            }
        }

        fn serve(
            &mut self,
            server: RpcServer,
            shutdown: bitcoin_rs_consensus::latch::LatchReader,
        ) -> Result<(), TestError> {
            self.server = Some(BoundedThread::spawn("verifychain-rpc-server", move || {
                server.serve_with_shutdown(shutdown)
            })?);
            Ok(())
        }

        fn send(&mut self, addr: SocketAddr) -> Result<(), TestError> {
            let socket = TcpStream::connect(addr)?;
            socket.set_read_timeout(Some(SOCKET_TIMEOUT))?;
            socket.set_write_timeout(Some(SOCKET_TIMEOUT))?;
            self.client_socket = Some(socket.try_clone()?);
            self.client = Some(BoundedThread::spawn("verifychain-client", move || {
                send_verifychain(socket)
            })?);
            Ok(())
        }

        fn finish_server(&mut self) -> Result<(), TestError> {
            let Some(server) = self.server.take() else {
                return Err(TestError::Missing("RPC server"));
            };
            server.finish()??;
            Ok(())
        }

        fn finish_client(&mut self) -> Result<String, TestError> {
            let Some(client) = self.client.take() else {
                return Err(TestError::Missing("verifychain request"));
            };
            client.finish()?
        }
    }

    impl Drop for ServedWitness {
        fn drop(&mut self) {
            (self.stop)();
            if let Some(server) = self.server.take() {
                let _ = server.finish();
            }
            if let Some(gate) = &self.gate {
                gate.release();
            }
            if let Some(socket) = &self.client_socket {
                let _ = socket.shutdown(Shutdown::Both);
            }
            if let Some(client) = self.client.take() {
                let _ = client.finish();
            }
        }
    }

    fn send_verifychain(mut socket: TcpStream) -> Result<String, TestError> {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"verifychain","params":[0,1]}"#;
        write!(
            socket,
            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        socket.shutdown(Shutdown::Write)?;
        let mut response = String::new();
        socket.read_to_string(&mut response)?;
        Ok(response)
    }

    fn assert_socket_error(response: &str, message: &str) -> Result<(), TestError> {
        use sonic_rs::JsonValueTrait;

        if !response.starts_with("HTTP/1.1 200 OK\r\n") {
            return Err(TestError::ExpectationFailed(
                "a JSON-RPC 2.0 error answers HTTP 200",
            ));
        }
        let (_, payload) = response
            .split_once("\r\n\r\n")
            .ok_or(TestError::Missing("HTTP response body"))?;
        let value: sonic_rs::Value = sonic_rs::from_str(payload)?;
        if value.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            return Err(TestError::ExpectationFailed(
                "the reply is not a JSON-RPC 2.0 envelope",
            ));
        }
        if value.get("id").and_then(JsonValueTrait::as_i64) != Some(1) {
            return Err(TestError::ExpectationFailed("the reply does not echo id 1"));
        }
        if value.get("result").is_some() {
            return Err(TestError::ExpectationFailed("the reply carries a result"));
        }
        let error = value
            .get("error")
            .ok_or(TestError::Missing("JSON-RPC error payload"))?;
        if error.get("code").and_then(JsonValueTrait::as_i64) != Some(-1) {
            return Err(TestError::ExpectationFailed(
                "the error is not Core's misc code -1",
            ));
        }
        if error.get("message").and_then(|v| v.as_str()) != Some(message) {
            return Err(TestError::ExpectationFailed(
                "the error message is not as expected",
            ));
        }
        Ok(())
    }

    fn apply_regtest_chain(state: &NodeState) -> Result<(), TestError> {
        let genesis = BlockImage::from_local(
            bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
        );
        state.apply_block(&genesis)?;
        let mut previous = genesis.block_hash();
        for height in 1..=3 {
            let block = BlockImage::from_local(
                bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_child_at(previous, height)?,
            );
            state.apply_block(&block)?;
            previous = block.block_hash();
        }
        Ok(())
    }

    fn bind_test_rpc(state: &NodeState) -> Result<RpcServer, TestError> {
        let coordinator = Arc::new(crate::MiningCoordinator::new(
            state.mempool_reader(),
            state.chainstate(),
            state.block_memory(),
            state.stable_read(),
            state.chain_followers(),
            super::final_payout_script(state.config()),
            state.config().mining.coinbase_reserve,
        ));
        let mining_control: Arc<dyn bitcoin_rs_wire::mining::MiningControl> = coordinator;
        let mut bindings = bind_rpc(state, &mining_control, state.block_body_source()?)?;
        assert_eq!(bindings.listeners.len(), 1);
        Ok(bindings.listeners.remove(0).0)
    }
    #[cfg(feature = "pool")]
    #[test]
    fn final_payout_script_prefers_pool_when_values_differ() {
        use crate::config::PoolConfig;

        let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
        config.mining.payout_script = vec![0x51];
        let pool = PoolConfig {
            datadir: std::path::PathBuf::from("/tmp/btcrs-pool-regression"),
            v1_bind: None,
            sv2_bind: None,
            sv2_authority_key: None,
            allow_non_loopback: false,
            max_connections: 1,
            max_connections_per_ip: 1,
            share_difficulty: String::from("1"),
            share_target: bitcoin_rs_wire::mining::pool::ShareTarget::from_pool_difficulty_decimal(
                "1",
            )
            .unwrap_or_else(|error| panic!("fixed test difficulty parses: {error}")),
            window_work: 1,
            fee_bps: 0,
            reward_script: vec![0x52],
            maturity: 100,
            payout_confirmations: 1,
            reorg_watch_depth: 100,
            min_payout_sat: 546,
            max_payout_outputs: 1,
        };
        config.pool = Some(pool);
        assert_eq!(super::final_payout_script(&config), vec![0x52]);
        config.pool = None;
        assert_eq!(super::final_payout_script(&config), vec![0x51]);
    }

    #[test]
    fn verifychain_socket_cancels_in_flight_walk_on_node_shutdown() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let gate = Arc::new(BodyGate::new());
        let state = NodeState::open_with_body_store(isolated_config(dir.path()), None, {
            let gate = Arc::clone(&gate);
            move |store| {
                let wrapped: Arc<dyn BlockBodyStore> =
                    Arc::new(HoldingBodies { inner: store, gate });
                wrapped
            }
        })?;
        apply_regtest_chain(&state)?;
        let server = bind_test_rpc(&state)?;
        let addr = server.local_addr()?;

        gate.arm();
        let chainstate = state.chainstate();
        let mut witness = ServedWitness::new(
            move || chainstate.request_shutdown(),
            Some(Arc::clone(&gate)),
        );
        witness.serve(server, state.shutdown_reader())?;
        witness.send(addr)?;

        if !gate.wait_entered(WITNESS_BOUND) {
            return Err(TestError::Timeout(
                "the verifier never reached the held body read",
            ));
        }
        state.request_shutdown();
        gate.release();
        witness.finish_server()?;
        let response = witness.finish_client()?;
        assert_socket_error(&response, "Block verification interrupted")
    }

    #[test]
    fn verifychain_socket_reports_recovery_closure() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let state = NodeState::open(isolated_config(dir.path()), None)?;
        apply_regtest_chain(&state)?;
        let server = bind_test_rpc(&state)?;
        let addr = server.local_addr()?;

        let stop = Arc::new(bitcoin_rs_consensus::latch::LatchWriter::new());
        let mut witness = ServedWitness::new(
            {
                let stop = Arc::clone(&stop);
                move || stop.trigger()
            },
            None,
        );
        witness.serve(server, stop.reader())?;
        state.chainstate().fail_closed_for_recovery();
        witness.send(addr)?;
        let response = witness.finish_client()?;
        stop.trigger();
        witness.finish_server()?;
        assert_socket_error(&response, "Chainstate is unavailable for verification")
    }
}
