use alloc::string::String;

use super::interval::Interval;

/// Why evidence was refused.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum EvidenceError {
    /// A digest was not 64 lowercase hex characters.
    #[error("digest {0:?} is not 64 lowercase hex characters")]
    MalformedDigest(String),
    /// The ledger text did not match the schema.
    #[error("ledger schema: {0}")]
    Schema(String),
    /// A product sample named no corpus.
    #[error("product sample carries no corpus identity")]
    MissingCorpus,
    /// An interval ended before it started.
    #[error("interval {0:?} ends before it starts")]
    InvertedInterval(Interval),
    /// The two samples were not taken under one treatment.
    #[error("samples differ in path, owner or identity")]
    MismatchedTreatment,
    /// The two intervals share instants.
    #[error("intervals {0:?} and {1:?} overlap; nested or concurrent work is not an addend")]
    OverlappingIntervals(Interval, Interval),
    /// A summed counter exceeded `u64`.
    #[error("summed measurement overflows u64")]
    Overflow,
    /// The cell is not declared in the ledger.
    #[error("cell {0:?} is not declared in the ledger")]
    UnknownCell(String),
}
