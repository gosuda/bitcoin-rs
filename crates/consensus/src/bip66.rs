use crate::ConsensusError;

/// Checks BIP66 strict DER signature encoding, including a trailing sighash byte.
pub fn check_bip66(signature_with_sighash: &[u8]) -> Result<(), ConsensusError> {
    bitcoin::ecdsa::Signature::from_slice(signature_with_sighash)
        .map(|_| ())
        .map_err(|error| ConsensusError::Bip {
            bip: "BIP66",
            reason: error.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::check_bip66;

    #[test]
    fn strict_der_signature_passes() {
        let sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01];
        assert_eq!(check_bip66(&sig), Ok(()));
    }

    #[test]
    fn malformed_der_signature_fails() {
        assert!(check_bip66(&[1, 2, 3, 1]).is_err());
    }
}
