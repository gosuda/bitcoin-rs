//! Daemon signal wrapper over the node-owned lifecycle.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;

use crate::config::{NodeConfig, RuntimeInputs};
use crate::logging;

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
/// Startup, rollback, and worker ownership belong to the lifecycle module.
/// The event loop owns the shutdown decision; this daemon wrapper observes
/// that decision and consumes the node through its explicit shutdown path.
pub fn run(config: NodeConfig, runtime: RuntimeInputs) -> Result<()> {
    logging::install_tracing(&config.observability.log_level)?;
    let node = crate::lifecycle::startup::start_node(config, runtime, true)?;
    let shutdown = node.state.shutdown();
    while !wait_for_shutdown(&shutdown, Duration::from_secs(DAEMON_SIGNAL_WAIT_SECS)) {}
    node.shutdown_blocking()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}
