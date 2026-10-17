//! Core rolling minimum fee.
//!
//! Port of Core `CTxMemPool::GetMinFee`, `CTxMemPool::trackPackageRemoved`,
//! and the rolling-fee lines of `CTxMemPool::removeForBlock`
//! (`bitcoin-core/src/txmempool.cpp:423-424,877-924`): one state machine over
//! `rate` (Core `rollingMinimumFeeRate`), `last_update` (Core
//! `lastRollingFeeUpdate`), and `block_since_bump` (Core
//! `blockSinceLastRollingFeeBump`). The pool owns it behind a mutex and reads
//! it through [`crate::Mempool::min_fee_sat_per_kvb`]; a capacity eviction or
//! replacement trim raises it, and every committed block connection stamps
//! it for decay.
//!
//! Core measures capacity as allocator usage against the byte limit; btcrs
//! measures total virtual size against `max_total_bytes` — the floor rises
//! in larger steps (recorded in `CONCEPTS.md`, "Rolling minimum fee").

use crate::policy::ROLLING_FEE_HALFLIFE_SECS;

/// Core's exponential decay floor for admission, relay, and eviction.
///
/// [`Self::current`] is line-for-line Core `GetMinFee`: while no block has
/// been connected since the last bump, or the rate is zero, the stored rate
/// is returned unchanged; otherwise, when the clock has moved more than ten
/// seconds past `last_update`, the rate decays with a twelve-hour half-life —
/// divided by four while usage is below a quarter of the limit, by two below
/// half — and a decayed rate under half the incremental relay fee resets the
/// floor to zero. [`Self::track_package_removed`] is Core
/// `trackPackageRemoved`; [`Self::note_block`] is the rolling-fee postamble
/// of Core `removeForBlock`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct RollingMinFee {
    /// Current floor in sat/kvB before the incremental-relay max (Core
    /// `rollingMinimumFeeRate`, a `double`).
    rate: f64,
    /// Seconds timestamp of the last decay or connected block (Core
    /// `lastRollingFeeUpdate`).
    last_update: u64,
    /// Whether a block connected since the last bump (Core
    /// `blockSinceLastRollingFeeBump`); decay runs only while set.
    block_since_bump: bool,
}

impl RollingMinFee {
    /// Core `CTxMemPool::GetMinFee`: reads, and possibly decays, the rolling
    /// floor for a pool whose capacity metric is `usage` against `limit`.
    ///
    /// `incremental` is the incremental relay fee in sat/kvB: half of it is
    /// the reset threshold, and a decayed rate never reads below it. The
    /// result is already rounded (`llround`) and floored at `incremental`;
    /// the reset path returns exactly `0`, matching Core, so the pool-level
    /// caller falls back to its configured min-relay rate.
    #[must_use]
    #[allow(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        reason = "Core stores this rate as a double: u64 -> f64 mirrors Core's CAmount/double and size_t/double conversions (exact below 2^53, same rounding above), and f64::round() as u64 reproduces llround on a rate that is never negative — a bump is a u64 feerate and decay only divides it toward zero — so the cast cannot lose sign or truncate a value Core would keep."
    )]
    pub(crate) fn current(&mut self, now: u64, usage: u64, limit: u64, incremental: u64) -> u64 {
        if !self.block_since_bump || self.rate == 0.0 {
            return self.rounded_rate();
        }
        if now > self.last_update.saturating_add(10) {
            let mut halflife = ROLLING_FEE_HALFLIFE_SECS as f64;
            if usage < limit / 4 {
                halflife /= 4.0;
            } else if usage < limit / 2 {
                halflife /= 2.0;
            }
            let elapsed = (now - self.last_update) as f64;
            #[expect(
                clippy::suboptimal_flops,
                reason = "Core GetMinFee divides by pow(2.0, elapsed / halflife) (txmempool.cpp); exp2 is not shown bit-identical to libm pow(2.0, x), so the port keeps the C++-mirroring powf."
            )]
            let decay = 2f64.powf(elapsed / halflife);
            self.rate /= decay;
            self.last_update = now;
            if self.rate < incremental as f64 / 2.0 {
                self.rate = 0.0;
                return 0;
            }
        }
        self.rounded_rate().max(incremental)
    }

    /// Core `CTxMemPool::trackPackageRemoved`: raise the floor to `removed`,
    /// the sat/kvB rate of the package (evicted chunk or replacement trim)
    /// that just left plus the incremental relay fee, and hold decay until
    /// the next connected block. A lower or equal rate changes nothing and
    /// leaves the block stamp untouched. Reports whether the stored rate
    /// actually rose, so the pool can revision its stamp exactly on raises.
    pub(crate) fn track_package_removed(&mut self, removed: u64) -> bool {
        #[allow(
            clippy::as_conversions,
            clippy::cast_precision_loss,
            reason = "Core compares the CAmount package rate against the double floor; the u64 -> f64 widening is exact below 2^53 and rounds identically above."
        )]
        let removed = removed as f64;
        if removed > self.rate {
            self.rate = removed;
            self.block_since_bump = false;
            true
        } else {
            false
        }
    }

    /// Core `removeForBlock`'s rolling-fee postamble: stamp the connected
    /// block so the floor may decay again after the ten-second grace.
    pub(crate) fn note_block(&mut self, now: u64) {
        self.last_update = now;
        self.block_since_bump = true;
    }

    /// `llround(rollingMinimumFeeRate)`: round half away from zero.
    fn rounded_rate(&self) -> u64 {
        #[allow(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "llround on a non-negative rate: the floor is a u64 feerate bumped toward zero by decay, so f64::round() as u64 matches Core's llround; an out-of-range double saturates where Core would already have wrapped its int64 arithmetic."
        )]
        {
            self.rate.round() as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RollingMinFee;
    use crate::policy::ROLLING_FEE_HALFLIFE_SECS;

    const HOUR: u64 = 3_600;
    const DAY: u64 = 24 * HOUR;
    const INCREMENTAL: u64 = 1_000;
    const LIMIT: u64 = 1_000;
    const HALF: u64 = LIMIT / 2;
    const QUARTER: u64 = LIMIT / 4;

    /// `5_000` sat/kvB decayed at full halflife over 12 h, and the 11-second
    /// clock tick just past the grace window.
    #[test]
    fn fresh_state_reads_zero_and_survives_a_block_stamp() {
        let mut rolling = RollingMinFee::default();
        assert_eq!(rolling.current(0, 0, LIMIT, INCREMENTAL), 0);
        assert_eq!(rolling.current(1, u64::MAX, LIMIT, INCREMENTAL), 0);
        rolling.note_block(10);
        assert_eq!(rolling.current(u64::MAX, 0, LIMIT, INCREMENTAL), 0);
    }

    #[test]
    fn bumped_floor_holds_until_a_block_stamps_it() {
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(5_000);
        assert_eq!(rolling.current(0, 0, LIMIT, INCREMENTAL), 5_000);
        assert_eq!(rolling.current(100 * DAY, HALF, LIMIT, INCREMENTAL), 5_000);
        assert_eq!(rolling.current(u64::MAX - 1, 0, LIMIT, INCREMENTAL), 5_000);
    }

    #[test]
    fn block_stamp_gates_decay_on_the_strict_ten_second_boundary() {
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(5_000);
        rolling.note_block(1_000);
        assert_eq!(rolling.current(1_000, HALF, LIMIT, INCREMENTAL), 5_000);
        assert_eq!(rolling.current(1_010, HALF, LIMIT, INCREMENTAL), 5_000);
        // One second past the grace: one decay of 11 s at full halflife.
        assert_eq!(rolling.current(1_011, HALF, LIMIT, INCREMENTAL), 4_999);
        // The decay restamped the clock: the same second reads again without
        // a second decay.
        assert_eq!(rolling.current(1_011, HALF, LIMIT, INCREMENTAL), 4_999);
    }

    #[test]
    fn usage_boundaries_pick_the_halflife_divisor() {
        // usage == limit / 2 is not below half: full 12 h halflife.
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(5_000);
        rolling.note_block(0);
        assert_eq!(rolling.current(12 * HOUR, HALF, LIMIT, INCREMENTAL), 2_500);

        // usage == limit / 4 is not below a quarter, but is below half:
        // 6 h halflife.
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(5_000);
        rolling.note_block(0);
        assert_eq!(
            rolling.current(12 * HOUR, QUARTER, LIMIT, INCREMENTAL),
            1_250
        );

        // One vbyte under each boundary crosses into the faster divisor:
        // limit / 2 - 1 -> 6 h halflife.
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(5_000);
        rolling.note_block(0);
        assert_eq!(
            rolling.current(12 * HOUR, HALF - 1, LIMIT, INCREMENTAL),
            1_250
        );
    }

    #[test]
    fn below_quarter_usage_quarters_the_halflife() {
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(5_000);
        rolling.note_block(0);
        // 6 h at a 3 h halflife halves twice: 5_000 -> 1_250. At the 6 h
        // halflife the same window would leave 2_500.
        assert_eq!(
            rolling.current(6 * HOUR, QUARTER - 1, LIMIT, INCREMENTAL),
            1_250
        );
        assert_eq!(ROLLING_FEE_HALFLIFE_SECS, 12 * HOUR);
    }

    #[test]
    fn decay_below_half_incremental_resets_to_zero() {
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(900);
        rolling.note_block(0);
        // 900 / 2 == 450 < 1_000 / 2: Core zeroes the rate and returns 0,
        // not the incremental floor.
        assert_eq!(rolling.current(12 * HOUR, HALF, LIMIT, INCREMENTAL), 0);
        // The reset state short-circuits: later clocks and blocks stay 0.
        assert_eq!(rolling.current(u64::MAX, 0, LIMIT, INCREMENTAL), 0);
        rolling.note_block(u64::MAX - 1);
        assert_eq!(rolling.current(u64::MAX, 0, LIMIT, INCREMENTAL), 0);
    }

    #[test]
    fn decayed_rate_never_reads_below_incremental() {
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(1_500);
        rolling.note_block(0);
        // 750 survives the reset threshold (750 >= 500) and reads at the
        // incremental floor.
        assert_eq!(rolling.current(12 * HOUR, HALF, LIMIT, INCREMENTAL), 1_000);
    }

    #[test]
    fn rounding_is_half_away_from_zero() {
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(3_001);
        rolling.note_block(0);
        // 1_500.5 rounds away from zero, as Core's llround.
        assert_eq!(rolling.current(12 * HOUR, HALF, LIMIT, INCREMENTAL), 1_501);
    }

    #[test]
    fn reset_threshold_boundary_survives_at_exactly_half_incremental() {
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(8_000);
        rolling.note_block(0);
        // Two days = four halvings (172_800 s / 43_200 s): 8_000 / 16 == 500
        // == incremental / 2. The reset is strict (`<`), so the rate
        // survives at the incremental floor.
        assert_eq!(rolling.current(2 * DAY, HALF, LIMIT, INCREMENTAL), 1_000);
    }

    #[test]
    fn lower_and_equal_bumps_are_ignored_and_keep_decay_armed() {
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(5_000);
        rolling.track_package_removed(3_000);
        rolling.track_package_removed(5_000);
        rolling.note_block(0);
        // Had any ignored bump cleared the block stamp, this read would
        // return the held 5_000 instead of decaying.
        assert_eq!(rolling.current(12 * HOUR, HALF, LIMIT, INCREMENTAL), 2_500);

        // A strictly higher bump stores itself and holds decay again even
        // after a stamp.
        rolling.track_package_removed(6_000);
        assert_eq!(rolling.current(12 * HOUR, HALF, LIMIT, INCREMENTAL), 6_000);
    }

    #[test]
    fn held_rate_reads_raw_without_the_incremental_floor() {
        // Core's early return (`no block since bump` or `rate == 0`) has no
        // incremental floor: only the post-decay path takes
        // `max(rate, incremental)`. A held 600 reads as 600.
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(600);
        assert_eq!(rolling.current(0, 0, LIMIT, INCREMENTAL), 600);
        assert_eq!(rolling.current(10, 0, LIMIT, INCREMENTAL), 600);
    }

    #[test]
    fn reads_never_raise_the_floor() {
        let mut rolling = RollingMinFee::default();
        rolling.track_package_removed(4_000);
        rolling.note_block(0);
        // Usage 0: quarter halflife; 3 h decays once: 4_000 -> 2_000.
        let first = rolling.current(3 * HOUR, 0, LIMIT, INCREMENTAL);
        assert_eq!(first, 2_000);
        // The read moved the clock: the stored rate is now 2_000 at
        // last_update 3 h. Rising usage slows the divisor from a quarter to
        // the full halflife, but the same 3 h still decays 2_000 -> 1_682.
        let second = rolling.current(6 * HOUR, LIMIT, LIMIT, INCREMENTAL);
        assert_eq!(second, 1_682);
        // Rising time with usage held at the limit keeps decaying.
        let third = rolling.current(9 * HOUR, LIMIT, LIMIT, INCREMENTAL);
        assert_eq!(third, 1_414);
        assert!(third <= second, "reads must never raise the floor");
    }
}
