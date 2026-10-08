/// Number of blocks spanned by median-time-past.
pub const MEDIAN_TIME_PAST_WINDOW: usize = 11;

/// BIP113 locktime-cutoff selection: the one rule every caller shares.
#[must_use]
pub const fn locktime_cutoff(
    csv_active: bool,
    prev_median_time_past: u32,
    candidate_time: u32,
) -> u32 {
    if csv_active {
        prev_median_time_past
    } else {
        candidate_time
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn locktime_cutoff_rule_switches_on_csv_activation() {
        assert_eq!(super::locktime_cutoff(true, 500, 999), 500);
        assert_eq!(super::locktime_cutoff(false, 500, 999), 999);
    }
}
