extern crate alloc;

mod evidence;
mod prometheus;
mod uptime;
mod warnings;

pub use evidence::{
    Cell, CorpusIdentity, EvidenceError, EvidenceIdentity, Interval, IntervalKind, LEDGER_SCHEMA,
    Ledger, Sample, Sha256Hex,
};
pub use prometheus::MetricsServer;
pub(crate) use prometheus::start_metrics;
pub use uptime::{process_start, process_uptime, record_process_start};
pub use warnings::{WarningKind, Warnings, node_warnings};

#[cfg(test)]
pub(crate) fn test_recorder() -> metrics::NoopRecorder {
    metrics::NoopRecorder
}

#[cfg(test)]
mod tests;
