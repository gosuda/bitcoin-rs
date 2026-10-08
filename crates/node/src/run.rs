//! Daemon signal wrapper over the node-owned lifecycle.

use std::io::IsTerminal as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::config::{NodeConfig, RuntimeInputs};

/// Default tracing filter directive when the user supplies only a bare level.
const DEFAULT_FILTER: &str = "info,fjall=warn,rocksdb=warn";

/// Installs process-wide tracing to stderr for the daemon entrypoint.
fn install_tracing(level: &str) {
    let filter_directive = build_filter_directive(level);
    let filter =
        EnvFilter::try_new(&filter_directive).unwrap_or_else(|_error| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry().with(filter);
    if std::io::stderr().is_terminal() {
        let subscriber = subscriber.with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(true),
        );
        let _already_installed = subscriber.try_init();
    } else {
        let subscriber = subscriber.with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::stderr),
        );
        let _already_installed = subscriber.try_init();
    }
}

/// Builds the tracing filter while capping noisy third-party storage targets.
fn build_filter_directive(level: &str) -> String {
    if level.is_empty() || level == "info" {
        DEFAULT_FILTER.to_owned()
    } else if level.contains(',') || level.contains('=') {
        level.to_owned()
    } else {
        format!("{level},fjall=warn,rocksdb=warn")
    }
}

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
    install_tracing(&config.observability.log_level);
    let node = crate::lifecycle::start_node(config, runtime, true)?;
    wait_for_shutdown(&node.state.shutdown());
    node.shutdown_blocking()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_directive_is_respected_as_is() {
        let level = "debug,bitcoin_rs_p2p=trace";
        let directive = build_filter_directive(level);
        assert_eq!(directive, level);
    }

    #[test]
    fn default_filter_parses_successfully() {
        EnvFilter::try_new(DEFAULT_FILTER).unwrap_or_else(|error| {
            panic!("DEFAULT_FILTER must parse as a valid EnvFilter directive: {error}")
        });
    }

    #[test]
    fn bare_levels_cap_storage_targets() {
        for (level, expected) in [
            ("", "info,fjall=warn,rocksdb=warn"),
            ("info", "info,fjall=warn,rocksdb=warn"),
            ("debug", "debug,fjall=warn,rocksdb=warn"),
            ("warn", "warn,fjall=warn,rocksdb=warn"),
            ("error", "error,fjall=warn,rocksdb=warn"),
            ("trace", "trace,fjall=warn,rocksdb=warn"),
            ("off", "off,fjall=warn,rocksdb=warn"),
        ] {
            let directive = build_filter_directive(level);
            assert_eq!(directive, expected, "bare level {level:?}");
            EnvFilter::try_new(&directive).unwrap_or_else(|error| {
                panic!("bare level {level:?} with per-target caps must parse: {error}")
            });
        }
    }
}
