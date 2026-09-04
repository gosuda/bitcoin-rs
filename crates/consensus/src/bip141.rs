use bitcoin_rs_primitives::Tx;

use crate::ConsensusError;

const MAX_SCRIPT_ELEMENT_SIZE: usize = 10_000;

/// Checks basic BIP141 witness stack element size invariants.
pub fn check_bip141(tx: &Tx) -> Result<(), ConsensusError> {
    for (input_index, input) in tx.inputs.iter().enumerate() {
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
    use bitcoin_rs_primitives::{Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut};

    use super::check_bip141;

    #[test]
    fn normal_non_witness_transaction_passes() {
        let tx = transaction_with_witness(Vec::new());
        assert_eq!(check_bip141(&tx), Ok(()));
    }

    #[test]
    fn oversized_witness_item_fails() {
        let tx = transaction_with_witness(vec![vec![0; 10_001]]);
        assert!(check_bip141(&tx).is_err());
    }

    fn transaction_with_witness(witness: Vec<Vec<u8>>) -> Tx {
        Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: witness.into(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::new(),
            }],
        }
    }
}
