use crate::ConsensusError;

/// Checks BIP112 `OP_CHECKSEQUENCEVERIFY` ordering for one input.
pub fn check_bip112(
    tx_version: i32,
    input_sequence: u32,
    required_sequence: u32,
) -> Result<(), ConsensusError> {
    if tx_version >= 2 && input_sequence >= required_sequence {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP112",
        reason: format!(
            "sequence {input_sequence} with version {tx_version} is below required {required_sequence}"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::check_bip112;

    #[test]
    fn sufficient_sequence_passes() {
        assert_eq!(check_bip112(2, 10, 10), Ok(()));
    }

    #[test]
    fn low_sequence_fails() {
        assert!(check_bip112(2, 9, 10).is_err());
    }
}
