use std::io::IsTerminal as _;

use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

/// Default tracing filter directive when the user supplies only a bare level
/// like `info` or `debug`.
///
/// Third-party storage engines (fjall, rocksdb) and noisy subsystem internals
/// are capped at `warn` so that a bare `info` does not flood the log with
/// journal-rotation and compaction lines that obscure real node progress.
/// The user's explicit level still applies to all `bitcoin_rs_*` targets and
/// other first-party crates.
const DEFAULT_FILTER: &str = "info,fjall=warn,rocksdb=warn";

/// Installs process-wide tracing to stderr.
///
/// When stderr is a TTY, a human-readable format is used for operator
/// readability. When stderr is piped (e.g. `docker logs`), JSON is used
/// so downstream log aggregation can parse structured fields.
pub(crate) fn install_tracing(level: &str) {
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

/// Builds the tracing filter directive string from a user-supplied level.
///
/// A bare level like `info` or `debug` gets per-target caps appended so
/// third-party storage engines (fjall, rocksdb) do not flood the log at
/// INFO. A full directive string (containing `,` or `=`) is respected
/// as-is, since the user is already expressing per-target preferences.
fn build_filter_directive(level: &str) -> String {
    if level.is_empty() || level == "info" {
        DEFAULT_FILTER.to_owned()
    } else if level.contains(',') || level.contains('=') {
        level.to_owned()
    } else {
        format!("{level},fjall=warn,rocksdb=warn")
    }
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
        // The default directive must be a valid EnvFilter parse. If a
        // typo or invalid target name were introduced, this would fail.
        EnvFilter::try_new(DEFAULT_FILTER).unwrap_or_else(|error| {
            panic!("DEFAULT_FILTER must parse as a valid EnvFilter directive: {error}")
        });
    }

    #[test]
    fn bare_debug_directive_parses_successfully() {
        let directive = build_filter_directive("debug");
        EnvFilter::try_new(&directive).unwrap_or_else(|error| {
            panic!("bare-debug directive with per-target caps must parse: {error}")
        });
    }
}
