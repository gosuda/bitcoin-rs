use std::collections::BTreeSet;

use bitcoin_rs_primitives::Tx;
use bitcoin_rs_script::{Interpreter, VerifyFlags};

use crate::rust_path::UtxoView;
use crate::{ConsensusError, MAX_BLOCK_SIGOPS_COST, MAX_MONEY};

/// Verifies non-contextual and input-script transaction rules.
pub fn verify_transaction(
    tx: &Tx,
    prevouts: &impl UtxoView,
    _height: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    let bitcoin_tx = &tx.0;
    if bitcoin_tx.input.is_empty() {
        return Err(ConsensusError::EmptyInputs);
    }
    if bitcoin_tx.output.is_empty() {
        return Err(ConsensusError::EmptyOutputs);
    }

    let output_value = total_output_value(tx)?;
    if bitcoin_tx.is_coinbase() {
        return Ok(());
    }

    let mut seen = BTreeSet::new();
    let mut input_value = 0u64;
    let interpreter = Interpreter;
    for (input_index, input) in bitcoin_tx.input.iter().enumerate() {
        if input.previous_output.is_null() {
            return Err(ConsensusError::NullPrevout { input_index });
        }
        if !seen.insert(input.previous_output) {
            return Err(ConsensusError::DuplicateInput { input_index });
        }
        let prevout = prevouts
            .lookup(&input.previous_output)
            .ok_or(ConsensusError::MissingPrevout { input_index })?;
        input_value = input_value
            .checked_add(prevout.value.to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        let witness = input.witness.to_vec();
        interpreter
            .execute(
                prevout.script_pubkey.as_bytes(),
                input.script_sig.as_bytes(),
                &witness,
                flags,
                &prevout,
                tx,
                input_index,
            )
            .map_err(|error| ConsensusError::Script {
                input_index,
                reason: error.to_string(),
            })?;
    }

    if input_value < output_value {
        return Err(ConsensusError::InputsLessThanOutputs {
            input_value,
            output_value,
        });
    }

    let sigop_cost =
        u32::try_from(bitcoin_tx.total_sigop_cost(|outpoint| prevouts.lookup(outpoint)))
            .unwrap_or(u32::MAX);
    if sigop_cost > MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: MAX_BLOCK_SIGOPS_COST,
        });
    }

    Ok(())
}

fn total_output_value(tx: &Tx) -> Result<u64, ConsensusError> {
    tx.0.output.iter().try_fold(0u64, |sum, output| {
        let next = sum
            .checked_add(output.value.to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        if next > MAX_MONEY {
            Err(ConsensusError::OutputValueOverflow)
        } else {
            Ok(next)
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::hashes::Hash as _;
    use bitcoin::script::Builder;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
        transaction,
    };
    use bitcoin_rs_primitives::Tx;
    use bitcoin_rs_script::VerifyFlags;

    use super::verify_transaction;
    use crate::ConsensusError;

    #[test]
    fn coinbase_transaction_skips_prevout_lookup() {
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let utxos = BTreeMap::new();
        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    #[test]
    fn duplicate_non_coinbase_input_is_rejected() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![spending_input(outpoint), spending_input(outpoint)],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );
        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::NONE),
            Err(ConsensusError::DuplicateInput { input_index: 1 })
        );
    }

    fn spending_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: Builder::new().push_int(1).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }
}
