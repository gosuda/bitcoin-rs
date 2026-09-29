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

#[cfg(test)]
#[expect(clippy::expect_used, reason = "benchmark evidence rejection tests")]
mod tests {
    use super::*;
    use bitcoin_rs_node::metrics::{CorpusIdentity, Sha256Hex};

    const LEDGER_TOML: &str = include_str!("../../docs/benchmarks/hot-path-ledger.toml");
    const CELL: &str = "offline.c150.x86_64.fjall";

    fn identity() -> EvidenceIdentity {
        EvidenceIdentity {
            binary_sha256: Sha256Hex([0x11; 32]),
            version: "0.4.0".into(),
            config_sha256: Sha256Hex([0x22; 32]),
            corpus: Some(CorpusIdentity {
                id: "C150".into(),
                manifest_sha256: Sha256Hex([0x33; 32]),
            }),
            backend: "fjall".into(),
            durability: "journal:500b/5s".into(),
            hardware: "test x1".into(),
        }
    }

    fn sample(start_ns: u64, end_ns: u64) -> Sample {
        Sample {
            path: "cell.wall".into(),
            owner: "node".into(),
            identity: identity(),
            interval: Interval {
                kind: IntervalKind::Inside,
                start_ns,
                end_ns,
            },
            cpu_ns: Some(end_ns - start_ns),
            elapsed_ns: end_ns - start_ns,
            rss_peak_bytes: Some(1 << 20),
            io_bytes: Some(4096),
            storage_bytes: Some(1 << 30),
        }
    }

    /// Renders one measured cell and drops the line that carries `field`.
    fn ledger_without(field: &str) -> String {
        let mut ledger = Ledger::parse(LEDGER_TOML).expect("checked-in ledger");
        ledger.record(CELL, sample(0, 10)).expect("record");
        let rendered = ledger.render().expect("render");
        let kept: Vec<&str> = rendered
            .lines()
            .filter(|line| !line.trim_start().starts_with(field))
            .collect();
        assert!(kept.len() < rendered.lines().count(), "{field} was present");
        kept.join("\n")
    }

    #[test]
    fn evidence_without_an_identity_is_refused() {
        for field in [
            "binary_sha256",
            "version",
            "config_sha256",
            "backend",
            "durability",
            "hardware",
            "manifest_sha256",
        ] {
            let error = Ledger::parse(&ledger_without(field)).expect_err(field);
            assert!(
                matches!(error, EvidenceError::Schema(_)),
                "{field}: {error}"
            );
        }
        // A corpus table is optional to the type and mandatory to the ledger.
        let error = Ledger::parse(&ledger_without("[cells.samples.identity.corpus]"))
            .expect_err("corpus-less sample");
        assert!(
            matches!(
                error,
                EvidenceError::Schema(_) | EvidenceError::MissingCorpus
            ),
            "{error}"
        );
        let mut ledger = Ledger::parse(LEDGER_TOML).expect("checked-in ledger");
        let mut headless = sample(0, 10);
        headless.identity.corpus = None;
        assert_eq!(
            ledger.record(CELL, headless),
            Err(EvidenceError::MissingCorpus)
        );
    }

    #[test]
    fn placeholder_digests_never_parse() {
        assert!("unmeasured".parse::<Sha256Hex>().is_err());
        assert!("1".repeat(63).parse::<Sha256Hex>().is_err());
        assert!("A".repeat(64).parse::<Sha256Hex>().is_err());
        assert_eq!(
            "11".repeat(32).parse::<Sha256Hex>(),
            Ok(Sha256Hex([0x11; 32]))
        );
    }

    #[test]
    fn nested_and_concurrent_intervals_are_not_addends() {
        let outer = sample(0, 100);
        let nested = sample(10, 20);
        let concurrent = sample(90, 150);
        let disjoint = sample(100, 150);
        assert!(matches!(
            outer.sum(&nested),
            Err(EvidenceError::OverlappingIntervals(..))
        ));
        assert!(matches!(
            outer.sum(&concurrent),
            Err(EvidenceError::OverlappingIntervals(..))
        ));
        let total = outer.sum(&disjoint).expect("disjoint intervals add");
        assert_eq!(total.elapsed_ns, 150);
        assert_eq!(total.cpu_ns, Some(150));
        assert_eq!(total.rss_peak_bytes, Some(1 << 20));
        assert_eq!(total.interval.end_ns, 150);

        let mut unmeasured_cpu = disjoint.clone();
        unmeasured_cpu.cpu_ns = None;
        assert_eq!(
            outer.sum(&unmeasured_cpu),
            Err(EvidenceError::MismatchedTreatment)
        );
        let mut other_build = disjoint;
        other_build.identity.binary_sha256 = Sha256Hex([0x44; 32]);
        assert_eq!(
            outer.sum(&other_build),
            Err(EvidenceError::MismatchedTreatment)
        );
    }

    #[test]
    fn repeated_samples_and_empty_cells_survive_a_round_trip() {
        let mut ledger = Ledger::parse(LEDGER_TOML).expect("checked-in ledger");
        // The checked-in ledger accumulates samples over time, so the test
        // pins only its own deltas: the cell under test and the surviving
        // empty cells, never the absolute measured-cell count.
        let measured_before = ledger
            .cells
            .iter()
            .filter(|cell| !cell.samples.is_empty())
            .count();
        let samples_before = ledger
            .cells
            .iter()
            .find(|cell| cell.id == CELL)
            .expect("cell under test")
            .samples
            .len();
        ledger.record(CELL, sample(0, 10)).expect("first run");
        ledger
            .record(CELL, sample(0, 10))
            .expect("identical second run");
        assert_eq!(
            ledger.record("offline.c150.x86_64.leveldb", sample(0, 10)),
            Err(EvidenceError::UnknownCell(
                "offline.c150.x86_64.leveldb".into()
            ))
        );

        let reparsed = Ledger::parse(&ledger.render().expect("render")).expect("round trip");
        assert_eq!(reparsed, ledger);
        let cell = reparsed
            .cells
            .iter()
            .find(|cell| cell.id == CELL)
            .expect("cell under test");
        assert_eq!(cell.samples.len(), samples_before + 2);
        let measured_after = reparsed
            .cells
            .iter()
            .filter(|cell| !cell.samples.is_empty())
            .count();
        assert_eq!(
            measured_after,
            measured_before + usize::from(samples_before == 0)
        );
        assert_eq!(reparsed.cells.len(), ledger.cells.len());
    }
}
