use bitcoin::Script;

use crate::ConsensusError;

/// Checks that a script pubkey is a valid BIP341 taproot output.
pub fn check_bip341(script_pubkey: &Script) -> Result<(), ConsensusError> {
    if script_pubkey.is_p2tr() {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP341",
        reason: "script pubkey is not a v1 32-byte taproot witness program".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::script::Builder;

    use super::check_bip341;

    #[test]
    fn p2tr_output_passes() {
        let script = Builder::new().push_int(1).push_slice([3; 32]).into_script();
        assert_eq!(check_bip341(script.as_script()), Ok(()));
    }

    #[test]
    fn non_taproot_output_fails() {
        let script = Builder::new().push_int(0).push_slice([3; 20]).into_script();
        assert!(check_bip341(script.as_script()).is_err());
    }
}
