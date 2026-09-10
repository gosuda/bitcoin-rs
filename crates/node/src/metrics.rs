//! Node observability and benchmark evidence.
//!
//! The scrape server owns its listener and process-global recorder; uptime
//! and warnings each retain a single authoritative owner. Evidence types are
//! independent of the HTTP transport and preserve the ledger wire format.

mod catalog;
mod evidence;
mod server;
mod uptime;
mod warnings;

pub use evidence::{
    Cell, CorpusIdentity, EvidenceError, EvidenceIdentity, Interval, IntervalKind, LEDGER_SCHEMA,
    Ledger, Sample, Sha256Hex,
};
pub use server::MetricsServer;
pub(crate) use server::start_metrics;
pub use uptime::{process_start, process_uptime, record_process_start};
pub use warnings::{WarningKind, Warnings, node_warnings};

#[cfg(test)]
pub(crate) fn test_recorder() -> metrics::NoopRecorder {
    metrics::NoopRecorder
}
