use alloc::string::String;

use anyhow::Result;

use super::error::EvidenceError;
use super::identity::EvidenceIdentity;
use super::interval::Interval;

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
    pub(super) fn check(&self) -> Result<(), EvidenceError> {
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
