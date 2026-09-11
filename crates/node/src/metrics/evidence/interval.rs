use anyhow::Result;

use super::error::EvidenceError;

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
    pub(super) fn check(self) -> Result<(), EvidenceError> {
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
