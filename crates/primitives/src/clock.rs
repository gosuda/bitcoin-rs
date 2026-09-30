//! Wall-clock readings as whole UNIX seconds.
//!
//! A time before the epoch reads as 0 rather than failing: every caller
//! compares or records these values, and none can act on a pre-1970 clock.

use std::time::{SystemTime, UNIX_EPOCH};

/// Whole seconds from the UNIX epoch to `time`, or 0 before the epoch.
#[must_use]
pub fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// [`unix_seconds`] of the current wall clock.
#[must_use]
pub fn unix_now() -> u64 {
    unix_seconds(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::unix_seconds;

    #[test]
    fn truncates_to_whole_seconds_and_zeroes_pre_epoch() {
        assert_eq!(unix_seconds(UNIX_EPOCH), 0);
        assert_eq!(
            unix_seconds(UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_999)),
            1_700_000_000
        );
        assert_eq!(unix_seconds(UNIX_EPOCH - Duration::from_secs(1)), 0);
    }
}
