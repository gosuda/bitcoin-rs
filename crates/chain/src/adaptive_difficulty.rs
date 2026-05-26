//! Fixed-point adaptive difficulty adjustment primitives.

use core::ops::{Mul, Shl, Shr};

/// Number of fractional bits in fixed-point values.
pub const SCALE_BITS: u32 = 16;
/// Fixed-point representation of `1.0`.
pub const FIXED_ONE: i64 = 1_i64 << SCALE_BITS;
/// Number of timestamps retained by the sliding regression window.
pub const WINDOW_SIZE: usize = 32;
/// Bit mask used to wrap the power-of-two timestamp ring.
pub const WINDOW_MASK: usize = WINDOW_SIZE - 1;

const TARGET_BLOCK_TIME: i64 = 600;
const ALPHA_FAST_SHIFT: u32 = 1;
const ALPHA_SLOW_SHIFT: u32 = 3;
const VARIANCE_THRESHOLD: i64 = 19_660;
const U256_LIMBS: usize = 4;
const LIMB_BITS: usize = 64;
const LIMB_BITS_U32: u32 = 64;
const U256_BITS: usize = U256_LIMBS * LIMB_BITS;

/// Little-endian 256-bit unsigned integer used by the adaptive target engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256(pub [u64; U256_LIMBS]);

impl U256 {
    /// Returns zero.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0; U256_LIMBS])
    }
}

impl Shl<i32> for U256 {
    type Output = Self;

    fn shl(self, rhs: i32) -> Self::Output {
        let Ok(shift) = usize::try_from(rhs) else {
            return self;
        };
        if shift >= U256_BITS {
            return Self::zero();
        }

        let mut parts = [0_u64; U256_LIMBS];
        let shift_words = shift / LIMB_BITS;
        let shift_bits = u32::try_from(shift & (LIMB_BITS - 1))
            .unwrap_or_else(|_| unreachable!("masked shift is below 64"));

        for source in 0..(U256_LIMBS - shift_words) {
            let target = source + shift_words;
            parts[target] |= self.0[source] << shift_bits;
            if shift_bits > 0 && target + 1 < U256_LIMBS {
                parts[target + 1] |= self.0[source] >> (LIMB_BITS_U32 - shift_bits);
            }
        }

        Self(parts)
    }
}

impl Shr<i32> for U256 {
    type Output = Self;

    fn shr(self, rhs: i32) -> Self::Output {
        let Ok(shift) = usize::try_from(rhs) else {
            return self;
        };
        if shift >= U256_BITS {
            return Self::zero();
        }

        let mut parts = [0_u64; U256_LIMBS];
        let shift_words = shift / LIMB_BITS;
        let shift_bits = u32::try_from(shift & (LIMB_BITS - 1))
            .unwrap_or_else(|_| unreachable!("masked shift is below 64"));

        for (target, part) in parts.iter_mut().enumerate().take(U256_LIMBS - shift_words) {
            let source = target + shift_words;
            *part |= self.0[source] >> shift_bits;
            if shift_bits > 0 && source + 1 < U256_LIMBS {
                *part |= self.0[source + 1] << (LIMB_BITS_U32 - shift_bits);
            }
        }

        Self(parts)
    }
}

impl Mul<u64> for U256 {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        let mut parts = [0_u64; U256_LIMBS];
        let mut carry = 0_u128;
        for (source, target) in self.0.into_iter().zip(&mut parts) {
            let result = u128::from(source)
                .saturating_mul(u128::from(rhs))
                .saturating_add(carry);
            let low = result & u128::from(u64::MAX);
            *target = u64::try_from(low).unwrap_or_else(|_| unreachable!("masked limb fits u64"));
            carry = result >> LIMB_BITS;
        }
        Self(parts)
    }
}

/// Zero-allocation adaptive difficulty controller.
#[derive(Debug, Clone)]
pub struct DifficultyController {
    timestamps: [u32; WINDOW_SIZE],
    current_ewma_slope: i64,
    total_blocks: u64,
}

impl Default for DifficultyController {
    fn default() -> Self {
        Self::new()
    }
}

impl DifficultyController {
    /// Creates an empty controller.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            timestamps: [0; WINDOW_SIZE],
            current_ewma_slope: FIXED_ONE,
            total_blocks: 0,
        }
    }

    /// Pushes a block timestamp into the fixed-size ring.
    pub fn push_timestamp(&mut self, timestamp: u32) {
        let idx = usize::try_from(self.total_blocks)
            .unwrap_or_else(|_| unreachable!("usize supports required block index width"))
            & WINDOW_MASK;
        self.timestamps[idx] = timestamp;
        self.total_blocks = self.total_blocks.saturating_add(1);
    }

    /// Calculates the normalized least-squares slope for the active window.
    #[must_use]
    pub fn calculate_lsm_slope(&self) -> Option<i64> {
        if self.total_blocks < u64::try_from(WINDOW_SIZE).unwrap_or(0) {
            return None;
        }

        let n = i64::try_from(WINDOW_SIZE).unwrap_or_else(|_| unreachable!("window fits i64"));
        let mut sum_x = 0_i64;
        let mut sum_y = 0_i64;
        let mut sum_xx = 0_i64;
        let mut sum_xy = 0_i64;

        let start_height = self
            .total_blocks
            .saturating_sub(u64::try_from(WINDOW_SIZE).unwrap_or(0));

        for x in 0..n {
            let actual_idx = usize::try_from(
                start_height + u64::try_from(x).unwrap_or_else(|_| unreachable!("x fits u64")),
            )
            .unwrap_or_else(|_| unreachable!("usize supports required block index width"))
                & WINDOW_MASK;
            let y = i64::from(self.timestamps[actual_idx]);

            sum_x += x;
            sum_y += y;
            sum_xx += x * x;
            sum_xy += x * y;
        }

        let sum_x_squared = sum_x * sum_x;
        let denominator = n * sum_xx - sum_x_squared;
        if denominator == 0 {
            return Some(FIXED_ONE);
        }

        let sum_xy_projection = sum_x * sum_y;
        let numerator = n * sum_xy - sum_xy_projection;
        let actual_slope = (numerator << SCALE_BITS) / denominator;
        Some(actual_slope / TARGET_BLOCK_TIME)
    }

    /// Advances the EWMA and returns the ASERT-scaled bounded target.
    #[must_use]
    pub fn next_target(&mut self, current_target: U256) -> U256 {
        let Some(lsm_slope) = self.calculate_lsm_slope() else {
            return current_target;
        };

        let delta = (lsm_slope - self.current_ewma_slope).abs();
        let alpha_shift = if delta > VARIANCE_THRESHOLD {
            ALPHA_SLOW_SHIFT
        } else {
            ALPHA_FAST_SHIFT
        };

        let next_ewma = (lsm_slope >> alpha_shift)
            + (self.current_ewma_slope - (self.current_ewma_slope >> alpha_shift));
        self.current_ewma_slope = next_ewma;

        let error = next_ewma - FIXED_ONE;
        let shift_factor = error >> SCALE_BITS;
        let fractional_part = error & (FIXED_ONE - 1);
        let target_factor =
            FIXED_ONE + fractional_part + ((fractional_part * fractional_part) >> (SCALE_BITS + 1));

        let mut next_target = current_target;
        let shift = i32::try_from(shift_factor).unwrap_or_else(|_| {
            if shift_factor.is_positive() {
                i32::MAX
            } else {
                i32::MIN
            }
        });
        if shift > 0 {
            next_target = next_target << shift;
        } else if shift < 0 {
            next_target = next_target >> shift.saturating_abs();
        }

        let multiplier =
            u64::try_from(target_factor).unwrap_or_else(|_| unreachable!("factor is non-negative"));
        next_target = (next_target * multiplier)
            >> i32::try_from(SCALE_BITS).unwrap_or_else(|_| unreachable!("scale fits i32"));

        let max_target = current_target << 2;
        let min_target = current_target >> 2;

        if next_target > max_target {
            max_target
        } else if next_target < min_target {
            min_target
        } else {
            next_target
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DifficultyController, FIXED_ONE, U256, WINDOW_MASK, WINDOW_SIZE};

    fn timestamp(height: usize, spacing: usize) -> u32 {
        u32::try_from(height * spacing).unwrap_or_else(|_| unreachable!("timestamp fits u32"))
    }

    #[test]
    fn lsm_slope_requires_full_window() {
        let mut controller = DifficultyController::new();
        for height in 0..(WINDOW_SIZE - 1) {
            controller.push_timestamp(timestamp(height, 600));
        }

        assert_eq!(controller.calculate_lsm_slope(), None);
    }

    #[test]
    fn lsm_slope_is_normalized_to_target_spacing() {
        let mut controller = DifficultyController::new();
        for height in 0..WINDOW_SIZE {
            controller.push_timestamp(timestamp(height, 600));
        }

        assert_eq!(controller.calculate_lsm_slope(), Some(FIXED_ONE));
    }

    #[test]
    fn ring_uses_latest_window_after_wrap() {
        let mut controller = DifficultyController::new();
        for height in 0..(WINDOW_SIZE * 3) {
            controller.push_timestamp(timestamp(height, 600));
        }

        let next_slot = usize::try_from(controller.total_blocks)
            .unwrap_or_else(|_| unreachable!("height fits usize"))
            & WINDOW_MASK;
        assert_eq!(next_slot, 0);
        assert_eq!(controller.calculate_lsm_slope(), Some(FIXED_ONE));
    }

    #[test]
    fn target_is_bounded_to_four_times_current_target() {
        let mut controller = DifficultyController::new();
        for height in 0..WINDOW_SIZE {
            controller.push_timestamp(timestamp(height, 24_000));
        }

        let current = U256([100, 0, 0, 0]);
        assert_eq!(controller.next_target(current), current << 2);
    }

    #[test]
    fn u256_shifts_across_limbs() {
        let value = U256([1, 0, 0, 0]);
        assert_eq!(value << 65, U256([0, 2, 0, 0]));
        assert_eq!((value << 65) >> 65, value);
    }
}
