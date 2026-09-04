use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Sighash, Tx, Witness};

use crate::ConsensusError;

/// Checks that BIP143 sighash computation succeeds for a segwit-v0 spend.
pub fn check_bip143(
    tx: &Tx,
    input_idx: usize,
    script_code: &[u8],
    value: Amount,
    sighash_type: Sighash,
) -> Result<(), ConsensusError> {
    Sighash::compute_bip143(tx, input_idx, script_code, value, sighash_type)
        .map(|_| ())
        .map_err(|error| ConsensusError::Bip {
            bip: "BIP143",
            reason: error.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, Sighash, Tx, TxIn, TxOut, Witness,
    };

    use super::check_bip143;

    #[test]
    fn valid_input_index_computes() {
        let tx = transaction();
        assert_eq!(
            check_bip143(&tx, 0, &[0x51], Amount::SAT, Sighash::All),
            Ok(())
        );
    }

    #[test]
    fn out_of_range_input_fails() {
        let tx = transaction();
        assert!(check_bip143(&tx, 1, &[0x51], Amount::SAT, Sighash::All).is_err());
    }

    fn transaction() -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::SAT,
                script_pubkey: Script::new(),
            }],
        }
    }
}
