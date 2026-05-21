use bitcoin::{Script, script::Builder};

use crate::ConsensusError;

/// Checks that the coinbase script starts with the minimally encoded block height.
pub fn check_bip34(height: u32, coinbase_script_sig: &Script) -> Result<(), ConsensusError> {
    let expected = Builder::new().push_int(i64::from(height)).into_script();
    if coinbase_script_sig
        .as_bytes()
        .starts_with(expected.as_bytes())
    {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP34",
        reason: format!("coinbase does not start with height {height}"),
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::{ScriptBuf, script::Builder};

    use super::check_bip34;

    #[test]
    fn matching_coinbase_height_passes() {
        let script = Builder::new().push_int(100).into_script();
        assert_eq!(check_bip34(100, script.as_script()), Ok(()));
    }

    #[test]
    fn small_coinbase_heights_use_opcode_prefixes() {
        let height_one = Builder::new().push_int(1).push_int(1).into_script();
        assert_eq!(height_one.as_bytes(), &[0x51, 0x51]);
        assert_eq!(check_bip34(1, height_one.as_script()), Ok(()));

        let height_sixteen = Builder::new().push_int(16).into_script();
        assert_eq!(height_sixteen.as_bytes(), &[0x60]);
        assert_eq!(check_bip34(16, height_sixteen.as_script()), Ok(()));
    }

    #[test]
    fn pushdata_encoding_for_small_height_fails() {
        let script = ScriptBuf::from_bytes(vec![0x01, 0x01]);
        assert!(check_bip34(1, script.as_script()).is_err());
    }

    #[test]
    fn data_push_prefix_after_small_integer_range_passes() {
        let script = Builder::new().push_int(17).into_script();
        assert_eq!(script.as_bytes(), &[0x01, 0x11]);
        assert_eq!(check_bip34(17, script.as_script()), Ok(()));
    }

    #[test]
    fn mismatched_coinbase_height_fails() {
        let script = Builder::new().push_int(101).into_script();
        assert!(check_bip34(100, script.as_script()).is_err());
    }
}
