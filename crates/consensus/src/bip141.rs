use bitcoin::Transaction;

use crate::ConsensusError;

const MAX_SCRIPT_ELEMENT_SIZE: usize = 10_000;

/// Checks basic BIP141 witness stack element size invariants.
pub fn check_bip141(tx: &Transaction) -> Result<(), ConsensusError> {
    for (input_index, input) in tx.input.iter().enumerate() {
        for item in &input.witness {
            if item.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ConsensusError::Bip {
                    bip: "BIP141",
                    reason: format!(
                        "input {input_index} witness item size {} exceeds {MAX_SCRIPT_ELEMENT_SIZE}",
                        item.len()
                    ),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
        transaction,
    };

    use super::check_bip141;

    #[test]
    fn normal_non_witness_transaction_passes() {
        let tx = transaction_with_witness(Witness::new());
        assert_eq!(check_bip141(&tx), Ok(()));
    }

    #[test]
    fn oversized_witness_item_fails() {
        let mut witness = Witness::new();
        witness.push(vec![0; 10_001]);
        let tx = transaction_with_witness(witness);
        assert!(check_bip141(&tx).is_err());
    }

    fn transaction_with_witness(witness: Witness) -> Transaction {
        Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }
}
