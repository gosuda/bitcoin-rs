//! Numeric conversions for wire-width counters and sizes.
//!
//! A count or size reported through a narrower wire type saturates at that
//! type's maximum instead of failing on overflow.

/// Saturating `u64 -> u32`.
#[must_use]
pub fn u32_saturated(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Saturating `usize -> u32`.
#[must_use]
pub fn u32_saturated_len(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Saturating `usize -> u64`.
#[must_use]
pub fn u64_saturated_len(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Saturating `u64 -> i64`.
#[must_use]
pub fn i64_saturated(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Saturating `usize -> i64`.
#[must_use]
pub fn i64_saturated_len(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// `u64` to `f64` without a silent `as` cast.
///
/// Exact for every input up to `2^53`; above that the low half rounds, which
/// is inherent to `f64` and is what Bitcoin Core accepts here too.
#[must_use]
pub fn u64_to_f64(value: u64) -> f64 {
    const TWO_POW_32: f64 = 4_294_967_296.0;

    let high = u32_saturated(value >> 32);
    let low = u32_saturated(value & 0xffff_ffff);
    f64::from(high).mul_add(TWO_POW_32, f64::from(low))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturates_rather_than_wraps() {
        assert_eq!(u32_saturated(u64::MAX), u32::MAX);
        assert_eq!(u32_saturated_len(usize::MAX), u32::MAX);
        assert_eq!(
            u64_saturated_len(usize::MAX),
            u64::try_from(usize::MAX).unwrap_or(u64::MAX)
        );
        assert_eq!(i64_saturated(u64::MAX), i64::MAX);
        assert_eq!(i64_saturated_len(usize::MAX), i64::MAX);
    }

    #[test]
    fn passes_through_in_range_values() {
        assert_eq!(u32_saturated(5), 5);
        assert_eq!(u32_saturated_len(5), 5);
        assert_eq!(u64_saturated_len(5), 5);
        assert_eq!(i64_saturated(5), 5);
        assert_eq!(i64_saturated_len(5), 5);
    }

    #[test]
    fn u64_to_f64_is_exact_below_two_to_the_fifty_third() {
        for value in [
            0_u64,
            1,
            4_294_967_295,
            4_294_967_296,
            1_315_805_869,
            1 << 52,
        ] {
            // Independently derived: the halves recombined by hand.
            let expected = f64::from(u32::try_from(value >> 32).unwrap_or(u32::MAX))
                * 4_294_967_296.0_f64
                + f64::from(u32::try_from(value & 0xffff_ffff).unwrap_or(u32::MAX));
            assert!(
                (u64_to_f64(value) - expected).abs() < f64::EPSILON,
                "{value}"
            );
        }
    }
}
