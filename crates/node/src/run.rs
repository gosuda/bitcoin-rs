//! Daemon entry point over the shared node lifecycle.
//!
//! `startup` composes the service graph, `rpc` builds its RPC boundary, and
//! `services` owns both startup rollback and ordered teardown. P2P workers
//! remain owned by `bitcoin_rs_p2p::P2pService`.

mod rpc;
mod services;
mod startup;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;

use crate::config::{NodeConfig, RuntimeInputs};
use crate::logging;

pub(crate) use services::{NodeServices, TeardownMode};
pub(crate) use startup::start_node;

pub(crate) const DRAIN_DEADLINE: Duration = Duration::from_secs(5);
/// Bounds each daemon wait; the helper checks shutdown every 100 ms.
const DAEMON_SIGNAL_WAIT_SECS: u64 = 3_600;

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
    logging::install_tracing(&config.observability.log_level)?;
    let (state, services, context) = start_node(config, runtime, true)?;
    let node = crate::embed::node_from_parts(state, services, context);
    let shutdown = node.state.shutdown();
    // The event loop owns the shutdown channel; the flag is its published
    // decision. Long-poll it the way the other long-lived waiters do.
    while !wait_for_shutdown(&shutdown, Duration::from_secs(DAEMON_SIGNAL_WAIT_SECS)) {}
    // Consuming shutdown releases the RPC context and its storage clones,
    // so the data directory is no longer locked when this function returns.
    node.shutdown_blocking()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}
