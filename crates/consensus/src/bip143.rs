use bitcoin_rs_primitives::{Sighash, Tx};

use crate::ConsensusError;

/// Checks that BIP143 sighash computation succeeds for a segwit-v0 spend.
pub fn check_bip143(
    tx: &Tx,
    input_idx: usize,
    script_code: &[u8],
    value: u64,
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
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
        transaction,
    };
    use bitcoin_rs_primitives::{Sighash, Tx};

    use super::check_bip143;

    #[test]
    fn valid_input_index_computes() {
        let tx = Tx(transaction());
        assert_eq!(check_bip143(&tx, 0, &[0x51], 1, Sighash::All), Ok(()));
    }

    #[test]
    fn out_of_range_input_fails() {
        let tx = Tx(transaction());
        assert!(check_bip143(&tx, 1, &[0x51], 1, Sighash::All).is_err());
    }

    fn transaction() -> Transaction {
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }
}
