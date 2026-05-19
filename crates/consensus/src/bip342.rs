use bitcoin::Script;

use crate::ConsensusError;

const MAX_SCRIPT_SIZE: usize = 10_000;

/// Checks BIP342 tapscript size and non-empty script invariants.
pub fn check_bip342(tapscript: &Script) -> Result<(), ConsensusError> {
    if tapscript.is_empty() {
        return Err(ConsensusError::Bip {
            bip: "BIP342",
            reason: "empty tapscript".to_owned(),
        });
    }
    if tapscript.len() > MAX_SCRIPT_SIZE {
        return Err(ConsensusError::Bip {
            bip: "BIP342",
            reason: format!(
                "tapscript size {} exceeds {MAX_SCRIPT_SIZE}",
                tapscript.len()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;
    use bitcoin::script::Builder;

    use super::check_bip342;

    #[test]
    fn non_empty_tapscript_passes() {
        let script = Builder::new().push_int(1).into_script();
        assert_eq!(check_bip342(script.as_script()), Ok(()));
    }

    #[test]
    fn empty_tapscript_fails() {
        assert!(check_bip342(ScriptBuf::new().as_script()).is_err());
    }
}
