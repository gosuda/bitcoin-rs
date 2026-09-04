use crate::ConsensusError;

/// Number of blocks spanned by median-time-past.
///
/// BIP113 locktime evaluation and BIP9 versionbits both use this window.
pub const MEDIAN_TIME_PAST_WINDOW: usize = 11;

/// BIP113 locktime-cutoff selection: the one rule every caller shares.
///
/// While CSV is active the cutoff is the previous tip's median-time-past;
/// before activation it is the candidate block's own header time.
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

/// Checks BIP113 locktime evaluation against previous median-time-past.
pub fn check_bip113(tx_lock_time: u32, median_time_past: u32) -> Result<(), ConsensusError> {
    if tx_lock_time <= median_time_past {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP113",
        reason: format!("locktime {tx_lock_time} exceeds median-time-past {median_time_past}"),
    })
}

#[cfg(test)]
mod tests {
    use super::check_bip113;

    #[test]
    fn locktime_at_mtp_passes() {
        assert_eq!(check_bip113(1_000, 1_000), Ok(()));
    }

    #[test]
    fn locktime_after_mtp_fails() {
        assert!(check_bip113(1_001, 1_000).is_err());
    }

    #[test]
    fn locktime_cutoff_rule_switches_on_csv_activation() {
        assert_eq!(super::locktime_cutoff(true, 500, 999), 500);
        assert_eq!(super::locktime_cutoff(false, 500, 999), 999);
    }
}
