use bitcoin::Script;

use crate::ConsensusError;

/// Checks that the coinbase script starts with the minimally encoded block height.
pub fn check_bip34(height: u32, coinbase_script_sig: &Script) -> Result<(), ConsensusError> {
    let expected = encode_script_number(i64::from(height));
    let bytes = coinbase_script_sig.as_bytes();
    if bytes.first().copied() == u8::try_from(expected.len()).ok()
        && bytes.get(1..=expected.len()) == Some(expected.as_slice())
    {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP34",
        reason: format!("coinbase does not start with height {height}"),
    })
}

fn encode_script_number(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let mut abs = value.unsigned_abs();
    let mut result = Vec::new();
    while abs > 0 {
        result.push(abs.to_le_bytes()[0]);
        abs >>= 8;
    }
    let negative = value.is_negative();
    if let Some(last) = result.last_mut() {
        if *last & 0x80 != 0 {
            result.push(if negative { 0x80 } else { 0 });
        } else if negative {
            *last |= 0x80;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use bitcoin::script::Builder;

    use super::check_bip34;

    #[test]
    fn matching_coinbase_height_passes() {
        let script = Builder::new().push_int(100).into_script();
        assert_eq!(check_bip34(100, script.as_script()), Ok(()));
    }

    #[test]
    fn mismatched_coinbase_height_fails() {
        let script = Builder::new().push_int(101).into_script();
        assert!(check_bip34(100, script.as_script()).is_err());
    }
}
