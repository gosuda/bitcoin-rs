use crate::ConsensusError;

/// Checks BIP65 absolute-locktime ordering for `OP_CHECKLOCKTIMEVERIFY`.
pub fn check_bip65(tx_lock_time: u32, required_lock_time: u32) -> Result<(), ConsensusError> {
    if tx_lock_time >= required_lock_time {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP65",
        reason: format!("locktime {tx_lock_time} is below required {required_lock_time}"),
    })
}

#[cfg(test)]
mod tests {
    use super::check_bip65;

    #[test]
    fn sufficient_locktime_passes() {
        assert_eq!(check_bip65(500, 500), Ok(()));
    }

    #[test]
    fn low_locktime_fails() {
        assert!(check_bip65(499, 500).is_err());
    }
}
