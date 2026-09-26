//! Daemon signal wrapper over the node-owned lifecycle.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;

use crate::config::{NodeConfig, RuntimeInputs};
use crate::logging;

/// PRE: the node lifecycle owns the shutdown flag and teardown runs on it.
/// POST: returns after an acquire read of the flag observes `true`.
/// INVARIANT: waits no longer than 100 ms between observations.
fn wait_for_shutdown(shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Boots the node and runs until shutdown.
///
/// Startup, rollback, and worker ownership belong to the lifecycle module.
/// The event loop owns the shutdown decision; this daemon wrapper observes
/// that decision and consumes the node through its explicit shutdown path.
pub fn run(config: NodeConfig, runtime: RuntimeInputs) -> Result<()> {
    logging::install_tracing(&config.observability.log_level);
    let node = crate::lifecycle::start_node(config, runtime, true)?;
    wait_for_shutdown(&node.state.shutdown());
    node.shutdown_blocking()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}
