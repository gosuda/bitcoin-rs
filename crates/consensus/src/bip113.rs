use crate::ConsensusError;

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
}
