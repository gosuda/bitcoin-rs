#![allow(dead_code, reason = "each consumer uses a different subset")]

use anyhow::Result;
use bitcoin_rs_node::metrics::EvidenceIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntervalKind {
    Inside,
    Outside,
    DomainDefined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interval {
    pub kind: IntervalKind,
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

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum EvidenceError {
    #[error("digest {0:?} is not 64 lowercase hex characters")]
    MalformedDigest(String),
    #[error("ledger schema: {0}")]
    Schema(String),
    #[error("product sample carries no corpus identity")]
    MissingCorpus,
    #[error("interval {0:?} ends before it starts")]
    InvertedInterval(Interval),
    #[error("samples differ in path, owner or identity")]
    MismatchedTreatment,
    #[error("intervals {0:?} and {1:?} overlap; nested or concurrent work is not an addend")]
    OverlappingIntervals(Interval, Interval),
    #[error("summed measurement overflows u64")]
    Overflow,
    #[error("cell {0:?} is not declared in the ledger")]
    UnknownCell(String),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub path: String,
    pub owner: String,
    pub identity: EvidenceIdentity,
    pub interval: Interval,
    pub cpu_ns: Option<u64>,
    pub elapsed_ns: u64,
    pub rss_peak_bytes: Option<u64>,
    pub io_bytes: Option<u64>,
    pub storage_bytes: Option<u64>,
}

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

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    pub id: String,
    pub samples: Vec<Sample>,
}

pub const LEDGER_SCHEMA: &str = "bitcoin-rs-hot-path-ledger-v2";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Ledger {
    pub schema: String,
    pub cells: Vec<Cell>,
    #[serde(flatten)]
    pub contract: std::collections::BTreeMap<String, toml::Value>,
}

impl Ledger {
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

    pub fn render(&self) -> Result<String, EvidenceError> {
        toml::to_string(self).map_err(|error| EvidenceError::Schema(error.to_string()))
    }
}

pub const MIN_SAMPLES_FOR_P99: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quantiles {
    pub n: usize,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
}

impl Quantiles {
    #[must_use]
    pub fn of(samples: &[u64]) -> Option<Self> {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let max = *sorted.last()?;
        let at = |percent: u64| -> u64 {
            let last_rank = u64::try_from(sorted.len() - 1).unwrap_or(u64::MAX);
            let scaled = percent.saturating_mul(last_rank);
            let lower = usize::try_from(scaled / 100).unwrap_or(usize::MAX);
            let remainder = scaled % 100;
            let low = sorted[lower];
            let high = sorted.get(lower + 1).copied().unwrap_or(low);
            let span = u128::from(high - low);
            let step = span * u128::from(remainder);
            low + u64::try_from((step + 50) / 100).unwrap_or(u64::MAX)
        };
        Some(Self {
            n: sorted.len(),
            p50: at(50),
            p95: at(95),
            p99: at(99),
            max,
        })
    }

    #[must_use]
    pub const fn p99_supported(&self) -> bool {
        self.n >= MIN_SAMPLES_FOR_P99
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "benchmark evidence rejection tests")]
mod tests {
    use super::*;
    use bitcoin_rs_node::metrics::{CorpusIdentity, Sha256Hex};

    const LEDGER_TOML: &str = include_str!("../../../docs/benchmarks/hot-path-ledger.toml");
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

    #[test]
    fn quantiles_are_exact_order_statistics_with_a_support_floor() {
        assert_eq!(Quantiles::of(&[]), None, "an empty set is not a zero");

        let single = Quantiles::of(&[7]).expect("one sample");
        assert_eq!(
            (single.p50, single.p95, single.p99, single.max),
            (7, 7, 7, 7)
        );
        assert!(!single.p99_supported());

        let ranks: Vec<u64> = (0..=100).rev().collect();
        let exact = Quantiles::of(&ranks).expect("101 samples");
        assert_eq!(
            (exact.n, exact.p50, exact.p95, exact.p99, exact.max),
            (101, 50, 95, 99, 100)
        );
        assert!(exact.p99_supported());
        assert!(
            !Quantiles::of(&ranks[..99])
                .expect("99 samples")
                .p99_supported()
        );

        let spread = Quantiles::of(&[40, 10, 30, 20]).expect("four samples");
        assert_eq!(
            (spread.p50, spread.p95, spread.p99, spread.max),
            (25, 39, 40, 40)
        );
    }
}
