//! Ownership of started services, startup rollback, and ordered teardown.
//!
//! A clean checkpoint is published only after every join succeeds. Startup
//! failure, explicit shutdown, and Drop all use the same teardown path.

use std::sync::atomic::Ordering;

use super::DRAIN_DEADLINE;
use crate::shutdown;
use crate::state::NodeState;

// Records that teardown reached the bootstrap join on the current thread.
// This seam never adds state or an API to production builds.
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

#[cfg(test)]
fn bootstrap_drain_was_reached() -> bool {
    BOOTSTRAP_DRAIN_REACHED.with(std::cell::Cell::take)
}

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
    pub(super) event_loop: Option<std::thread::JoinHandle<anyhow::Result<()>>>,
    pub(super) event_loop_signal: Option<crossbeam_channel::Sender<()>>,
    /// Stops and joins its listener in Drop.
    pub(super) metrics: Option<crate::metrics::MetricsServer>,
    pub(super) rpc_thread: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    /// Joined before the final clean checkpoint publication.
    pub(super) checkpoint_worker: Option<std::thread::JoinHandle<()>>,
    pub(super) tx_ingress: Option<std::thread::JoinHandle<()>>,
    pub(super) tx_relay: Option<std::thread::JoinHandle<()>>,
    pub(super) signal_handler: Option<crate::signal::ShutdownHandler>,
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
    /// drains subsystems, joins bootstrap/checkpoint/signal workers, and only
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
            let _ = tx.send(());
        }

        let mut first_error = None;
        self.join_core_services(state, &mut first_error);
        if let Err(error) = shutdown::drain_and_shutdown(DRAIN_DEADLINE) {
            set_first_error(&mut first_error, error);
        }
        self.join_bootstrap_and_signal_workers(state, &mut first_error);
        publish_clean_checkpoint_if_eligible(state, mode, &mut first_error);
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
        self.metrics.take();
        #[cfg(test)]
        if let Some(handle) = self.outbound_worker.take() {
            if matches!(handle.join(), Ok(())) {
                tracing::info!("P2P outbound drain exited cleanly");
            } else {
                tracing::error!("P2P outbound drain panicked");
                set_first_error(first_error, anyhow::anyhow!("P2P outbound drain panicked"));
            }
        }
        if let Some(state) = state {
            if let Err(error) = state.p2p().join_core_workers() {
                set_first_error(first_error, anyhow::Error::new(error));
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
        if let Some(handle) = self.tx_relay.take() {
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

    pub(crate) fn cleanup(&mut self, state: &NodeState) -> anyhow::Result<()> {
        self.teardown(Some(state), TeardownMode::CleanShutdown)
    }
}

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

/// Records each successfully created service immediately. Until disarmed,
/// Drop rolls back through the same teardown without publishing a checkpoint.
pub(super) struct StartupGuard {
    pub(super) state: Option<NodeState>,
    pub(super) services: NodeServices,
}

impl StartupGuard {
    pub(super) fn disarm(mut self) -> (NodeState, NodeServices) {
        let Some(state) = self.state.take() else {
            panic!("completed startup owns state");
        };
        let services = core::mem::take(&mut self.services);
        // Neither this guard nor the empty placeholder may tear down twice.
        self.services.teardown_started = true;
        (state, services)
    }
}

impl Drop for StartupGuard {
    fn drop(&mut self) {
        if let Err(error) = self
            .services
            .teardown(self.state.as_ref(), TeardownMode::StartupAbort)
        {
            tracing::warn!(%error, "startup rollback reported a cleanup failure");
        }
        self.state.take(); // NodeState's own Drop stops its index workers.
    }
}

#[cfg(test)]
mod tests;
