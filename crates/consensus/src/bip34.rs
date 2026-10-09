use bitcoin_rs_script::push_int;

use crate::ConsensusError;

/// Checks that the coinbase script starts with the minimally encoded block
/// height.
pub fn check_bip34(height: u32, coinbase_script_sig: &[u8]) -> Result<(), ConsensusError> {
    let expected = push_int(i64::from(height));
    if coinbase_script_sig.starts_with(&expected) {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP34",
        reason: format!("coinbase does not start with height {height}"),
    })
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_script::push_int;

    use super::check_bip34;

    #[test]
    fn matching_coinbase_height_passes() {
        let script = push_int(100);
        assert_eq!(check_bip34(100, &script), Ok(()));
    }

    #[test]
    fn small_coinbase_heights_use_opcode_prefixes() {
        let height_one = [push_int(1), push_int(1)].concat();
        assert_eq!(height_one, [0x51, 0x51]);
        assert_eq!(check_bip34(1, &height_one), Ok(()));

        let height_sixteen = push_int(16);
        assert_eq!(height_sixteen, [0x60]);
        assert_eq!(check_bip34(16, &height_sixteen), Ok(()));
    }

    #[test]
    fn signet_block_one_coinbase_prefix_passes() {
        assert_eq!(check_bip34(1, &[0x51, 0x51]), Ok(()));
    }

    #[test]
    fn pushdata_encoding_for_small_height_fails() {
        assert!(check_bip34(1, &[0x01, 0x01]).is_err());
    }

    #[test]
    fn data_push_prefix_after_small_integer_range_passes() {
        let script = push_int(17);
        assert_eq!(script, [0x01, 0x11]);
        assert_eq!(check_bip34(17, &script), Ok(()));
    }

    #[test]
    fn mismatched_coinbase_height_fails() {
        let script = push_int(101);
        assert!(check_bip34(100, &script).is_err());
    }
}
