pub(crate) const MIN_SAMPLES_FOR_P99: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PercentileError {
    #[error("percentiles refuse an empty sample set")]
    Empty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quantiles {
    pub n: usize,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
}

impl Quantiles {
    pub fn of(samples: &[u64]) -> Result<Self, PercentileError> {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let max = sorted.last().copied().ok_or(PercentileError::Empty)?;
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
        Ok(Self {
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
mod tests {
    use super::*;

    fn quantiles(samples: &[u64]) -> Quantiles {
        match Quantiles::of(samples) {
            Ok(quantiles) => quantiles,
            Err(error) => panic!("samples {samples:?} must quantify: {error}"),
        }
    }

    #[test]
    fn one_sample_is_every_quantile() {
        assert_eq!(
            quantiles(&[13]),
            Quantiles {
                n: 1,
                p50: 13,
                p95: 13,
                p99: 13,
                max: 13,
            }
        );
        assert!(!quantiles(&[13]).p99_supported());
    }

    #[test]
    fn two_samples_interpolate_with_half_up_rank_rounding() {
        assert_eq!(
            quantiles(&[10, 20]),
            Quantiles {
                n: 2,
                p50: 15,
                p95: 20,
                p99: 20,
                max: 20,
            }
        );
        assert_eq!(
            quantiles(&[10, 11]).p50,
            11,
            "the halfway rank must round up"
        );
    }

    #[test]
    fn seven_unsorted_samples_keep_exact_order_statistics() {
        assert_eq!(
            quantiles(&[7, 3, 1, 9, 5, 4, 8]),
            Quantiles {
                n: 7,
                p50: 5,
                p95: 9,
                p99: 9,
                max: 9,
            }
        );
    }

    #[test]
    fn one_hundred_ranks_quantify_and_cross_the_p99_gate() {
        let ranks: Vec<u64> = (1..=100).collect();
        assert_eq!(
            quantiles(&ranks),
            Quantiles {
                n: 100,
                p50: 51,
                p95: 95,
                p99: 99,
                max: 100,
            }
        );
        assert!(quantiles(&ranks).p99_supported());
        let short = quantiles(&ranks[..99]);
        assert_eq!(short.p99, 98);
        assert!(!short.p99_supported());
    }

    #[test]
    fn an_empty_sample_set_is_refused_not_zeroed() {
        assert_eq!(Quantiles::of(&[]), Err(PercentileError::Empty));
    }
}
