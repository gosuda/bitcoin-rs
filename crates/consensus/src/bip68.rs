use crate::ConsensusError;

const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// Checks BIP68 relative-locktime availability for a transaction version and sequence.
pub fn check_bip68(tx_version: i32, sequence: u32) -> Result<(), ConsensusError> {
    if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 || tx_version >= 2 {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP68",
        reason: "relative locktime requires transaction version 2 or higher".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::check_bip68;

    #[test]
    fn version_two_relative_lock_passes() {
        assert_eq!(check_bip68(2, 1), Ok(()));
    }

    #[test]
    fn version_one_relative_lock_fails() {
        assert!(check_bip68(1, 1).is_err());
    }
}
