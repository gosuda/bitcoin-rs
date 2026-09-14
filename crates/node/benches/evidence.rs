//! Recorded evidence for sync-pipeline measurements.
//!
//! Moved verbatim from the former `crates/node/src/metrics/evidence/` so the
//! product-cell machinery lives with its only consumer; the shared identity
//! types stay in `bitcoin_rs_node::metrics`.
#![allow(dead_code, reason = "each consumer uses a different subset")]

use anyhow::Result;
use bitcoin_rs_node::metrics::EvidenceIdentity;

/// Where a timed interval sits relative to the measured product.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntervalKind {
    /// Inside the node process.
    Inside,
    /// Outside the node process, for example harness setup.
    Outside,
    /// A duration the domain defines without wall-clock placement.
    DomainDefined,
}

/// A half-open timed interval in nanoseconds on the run's clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interval {
    /// Placement of the interval.
    pub kind: IntervalKind,
    /// Start offset.
    pub start_ns: u64,
    /// End offset, never before the start.
    pub end_ns: u64,
}

impl Interval {
    fn check(self) -> Result<(), EvidenceError> {
        if self.end_ns < self.start_ns {
            return Err(EvidenceError::InvertedInterval(self));
        }
        Ok(())
    }

    /// True when the intervals share any instant, which covers both nesting
    /// and concurrency.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.start_ns < other.end_ns && other.start_ns < self.end_ns
    }
}

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

/// One measurement of one cell by one owner.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    /// Ledger path the interval measures, for example `cell.wall`.
    pub path: String,
    /// Component that owns the measured resources, for example `node`.
    pub owner: String,
    /// Identity the sample was taken under.
    pub identity: EvidenceIdentity,
    /// Timed interval the resources were consumed in.
    pub interval: Interval,
    /// CPU time consumed, when the owner measured it.
    pub cpu_ns: Option<u64>,
    /// Wall time consumed.
    pub elapsed_ns: u64,
    /// Peak resident set, when the owner measured it.
    pub rss_peak_bytes: Option<u64>,
    /// Bytes read plus written, when the owner measured it.
    pub io_bytes: Option<u64>,
    /// Physical storage held at the end of the interval, when measured.
    pub storage_bytes: Option<u64>,
}

/// Combines two optional measurements; an absent side cannot silently absorb
/// a present one, because that would collapse coverage into a number.
fn combine(
    left: Option<u64>,
    right: Option<u64>,
    join: impl Fn(u64, u64) -> Option<u64>,
) -> Result<Option<u64>, EvidenceError> {
    match (left, right) {
        (None, None) => Ok(None),
        (Some(left), Some(right)) => join(left, right).map(Some).ok_or(EvidenceError::Overflow),
        _ => Err(EvidenceError::MismatchedTreatment),
    }
}

impl Sample {
    fn check(&self) -> Result<(), EvidenceError> {
        if self.identity.corpus.is_none() {
            return Err(EvidenceError::MissingCorpus);
        }
        self.interval.check()
    }

    /// Adds two disjoint samples of the same owner and identity.
    ///
    /// Nested and concurrent intervals share instants, so their resources
    /// were consumed once and cannot be added; extrema take the maximum.
    pub fn sum(&self, other: &Self) -> Result<Self, EvidenceError> {
        if self.path != other.path || self.owner != other.owner || self.identity != other.identity {
            return Err(EvidenceError::MismatchedTreatment);
        }
        if self.interval.overlaps(other.interval) {
            return Err(EvidenceError::OverlappingIntervals(
                self.interval,
                other.interval,
            ));
        }
        Ok(Self {
            path: self.path.clone(),
            owner: self.owner.clone(),
            identity: self.identity.clone(),
            interval: Interval {
                kind: self.interval.kind,
                start_ns: self.interval.start_ns.min(other.interval.start_ns),
                end_ns: self.interval.end_ns.max(other.interval.end_ns),
            },
            cpu_ns: combine(self.cpu_ns, other.cpu_ns, u64::checked_add)?,
            elapsed_ns: self
                .elapsed_ns
                .checked_add(other.elapsed_ns)
                .ok_or(EvidenceError::Overflow)?,
            rss_peak_bytes: combine(self.rss_peak_bytes, other.rss_peak_bytes, |a, b| {
                Some(a.max(b))
            })?,
            io_bytes: combine(self.io_bytes, other.io_bytes, u64::checked_add)?,
            storage_bytes: combine(self.storage_bytes, other.storage_bytes, |a, b| {
                Some(a.max(b))
            })?,
        })
    }
}

/// One product cell and every sample ever recorded for it.
///
/// An empty history is the honest state of an unmeasured cell; it is kept,
/// never dropped or defaulted.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    /// Cell identifier from the ledger matrix.
    pub id: String,
    /// Append-only sample history.
    pub samples: Vec<Sample>,
}

/// Schema tag every ledger and evidence file must carry.
pub const LEDGER_SCHEMA: &str = "bitcoin-rs-hot-path-ledger-v2";

/// The cell histories of `docs/benchmarks/hot-path-ledger.toml`.
///
/// Other top-level tables of that file belong to the attribution contract and
/// pass through untouched; this type owns only what a run may append to.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Ledger {
    /// Must equal [`LEDGER_SCHEMA`].
    pub schema: String,
    /// Every declared cell, measured or not.
    pub cells: Vec<Cell>,
    /// Top-level attribution-contract tables owned outside the benchmark tool.
    #[serde(flatten)]
    pub contract: std::collections::BTreeMap<String, toml::Value>,
}

impl Ledger {
    /// Parses ledger TOML and rejects any sample that lacks a full identity.
    pub fn parse(text: &str) -> Result<Self, EvidenceError> {
        let ledger: Self =
            toml::from_str(text).map_err(|error| EvidenceError::Schema(error.to_string()))?;
        if ledger.schema != LEDGER_SCHEMA {
            return Err(EvidenceError::Schema(format!(
                "schema {} is not {LEDGER_SCHEMA}",
                ledger.schema
            )));
        }
        for cell in &ledger.cells {
            for sample in &cell.samples {
                sample.check()?;
            }
        }
        Ok(ledger)
    }

    /// Appends a sample to a declared cell. Repeats are kept: a second run is
    /// evidence, not a correction.
    pub fn record(&mut self, cell: &str, sample: Sample) -> Result<(), EvidenceError> {
        sample.check()?;
        let cell = self
            .cells
            .iter_mut()
            .find(|candidate| candidate.id == cell)
            .ok_or_else(|| EvidenceError::UnknownCell(cell.into()))?;
        cell.samples.push(sample);
        Ok(())
    }

    /// Renders the ledger as TOML.
    pub fn render(&self) -> Result<String, EvidenceError> {
        toml::to_string(self).map_err(|error| EvidenceError::Schema(error.to_string()))
    }
}
