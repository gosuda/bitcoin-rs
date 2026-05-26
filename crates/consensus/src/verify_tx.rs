use std::collections::BTreeSet;

#[cfg(feature = "bitcoinconsensus")]
use bitcoin::Script;
#[cfg(feature = "bitcoinconsensus")]
use bitcoin::consensus::encode;

use bitcoin_rs_primitives::Tx;
use bitcoin_rs_script::{Interpreter, VerifyFlags};

use crate::rust_path::UtxoView;
use crate::{ConsensusError, MAX_BLOCK_SIGOPS_COST, MAX_MONEY};

const LOCKTIME_THRESHOLD: u32 = 500_000_000;
const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const MIN_COINBASE_SCRIPT_SIG_SIZE: usize = 2;
const MAX_COINBASE_SCRIPT_SIG_SIZE: usize = 100;

/// Returns `true` iff the transaction is locktime-final at `block_height` and the timestamp cutoff.
///
/// Implements Bitcoin Core's `IsFinalTx`:
///   - locktime == 0: always final.
///   - locktime < `LOCKTIME_THRESHOLD`: height-based; final iff locktime < `block_height`.
///   - locktime >= `LOCKTIME_THRESHOLD`: timestamp-based; final iff locktime < `locktime_cutoff`.
///   - all inputs have sequence == `SEQUENCE_FINAL`: final regardless of locktime.
///
/// Callers choose the timestamp cutoff: block header time before BIP113, previous-tip MTP after.
#[must_use]
pub fn is_final_tx(tx: &bitcoin::Transaction, block_height: u32, locktime_cutoff: u32) -> bool {
    is_final_tx_with_locktime_cutoff(tx, block_height, locktime_cutoff)
}

/// Verifies that a coinbase transaction's scriptSig length is within consensus bounds.
pub fn verify_coinbase_script_sig_size(tx: &bitcoin::Transaction) -> Result<(), ConsensusError> {
    if let Some(input) = tx.input.first().filter(|_| tx.is_coinbase()) {
        let len = input.script_sig.len();
        if !(MIN_COINBASE_SCRIPT_SIG_SIZE..=MAX_COINBASE_SCRIPT_SIG_SIZE).contains(&len) {
            return Err(ConsensusError::CoinbaseScriptSigSize { len });
        }
    }
    Ok(())
}

/// Returns `true` iff the transaction is locktime-final at `block_height` and `locktime_cutoff`.
///
/// Callers choose the timestamp cutoff: block header time before BIP113, previous-tip MTP after.
#[must_use]
fn is_final_tx_with_locktime_cutoff(
    tx: &bitcoin::Transaction,
    block_height: u32,
    locktime_cutoff: u32,
) -> bool {
    let lock_time = tx.lock_time.to_consensus_u32();
    if lock_time == 0 {
        return true;
    }

    let threshold = if lock_time < LOCKTIME_THRESHOLD {
        block_height
    } else {
        locktime_cutoff
    };
    if lock_time < threshold {
        return true;
    }

    let sequence_final = bitcoin::Sequence::from_consensus(SEQUENCE_FINAL);
    tx.input
        .iter()
        .all(|input| input.sequence == sequence_final)
}

/// Verifies non-contextual and input-script transaction rules without contextual MTP checks.
pub fn verify_transaction(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_with_mtp(tx, prevouts, height, 0, flags)
}

/// Verifies non-contextual and input-script transaction rules with a caller-selected timestamp cutoff.
///
/// The historical `_with_mtp` suffix is retained for source compatibility. Callers pass block
/// header time before BIP113 activation and previous-tip MTP after activation.
pub fn verify_transaction_with_mtp(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_borrowed_with_mtp(&tx.0, prevouts, height, locktime_cutoff, flags)
}

/// Verifies non-contextual and input-script transaction rules for a borrowed transaction without contextual MTP checks.
pub fn verify_transaction_borrowed(
    tx: &bitcoin::Transaction,
    prevouts: &impl UtxoView,
    height: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_borrowed_with_mtp(tx, prevouts, height, 0, flags)
}

/// Verifies non-contextual and input-script transaction rules for a borrowed transaction.
///
/// The historical `_with_mtp` suffix is retained for source compatibility. Callers pass block
/// header time before BIP113 activation and previous-tip MTP after activation.
pub fn verify_transaction_borrowed_with_mtp(
    tx: &bitcoin::Transaction,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_borrowed_with_locktime_cutoff(tx, prevouts, height, locktime_cutoff, flags)
}

/// Verifies non-contextual and input-script transaction rules for a borrowed transaction.
fn verify_transaction_borrowed_with_locktime_cutoff(
    tx: &bitcoin::Transaction,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    if !is_final_tx_with_locktime_cutoff(tx, height, locktime_cutoff) {
        return Err(ConsensusError::Bip {
            bip: "BIP113",
            reason: format!(
                "non-final transaction at height {height} locktime cutoff \
                 {locktime_cutoff}: locktime {}",
                tx.lock_time.to_consensus_u32()
            ),
        });
    }

    if tx.input.is_empty() {
        return Err(ConsensusError::EmptyInputs);
    }
    if tx.output.is_empty() {
        return Err(ConsensusError::EmptyOutputs);
    }

    let output_value = total_output_value_borrowed(tx)?;
    if tx.is_coinbase() {
        verify_coinbase_script_sig_size(tx)?;
        return Ok(());
    }

    let mut seen = BTreeSet::new();
    for (input_index, input) in tx.input.iter().enumerate() {
        if input.previous_output.is_null() {
            return Err(ConsensusError::NullPrevout { input_index });
        }
        if !seen.insert(input.previous_output) {
            return Err(ConsensusError::DuplicateInput { input_index });
        }
    }

    let mut input_value = 0u64;
    let mut input_prevouts = Vec::with_capacity(tx.input.len());
    for (input_index, input) in tx.input.iter().enumerate() {
        let prevout = prevouts
            .lookup(&input.previous_output)
            .ok_or(ConsensusError::MissingPrevout { input_index })?;
        input_value = input_value
            .checked_add(prevout.value.to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        input_prevouts.push(prevout);
    }

    if input_value < output_value {
        return Err(ConsensusError::InputsLessThanOutputs {
            input_value,
            output_value,
        });
    }

    #[cfg(feature = "bitcoinconsensus")]
    let serialized_tx = encode::serialize(tx);

    for (input_index, (input, prevout)) in tx.input.iter().zip(input_prevouts.iter()).enumerate() {
        #[cfg(feature = "bitcoinconsensus")]
        verify_input_script(
            input_index,
            input,
            prevout,
            tx,
            serialized_tx.as_slice(),
            flags,
        )?;
        #[cfg(not(feature = "bitcoinconsensus"))]
        verify_input_script(input_index, input, prevout, tx, flags)?;
    }

    let sigop_cost_result = tx.total_sigop_cost(|outpoint| prevouts.lookup(outpoint));
    let sigop_cost = u32::try_from(sigop_cost_result).unwrap_or(u32::MAX);
    if sigop_cost > MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: MAX_BLOCK_SIGOPS_COST,
        });
    }

    Ok(())
}

#[cfg(feature = "bitcoinconsensus")]
fn verify_input_script(
    input_index: usize,
    input: &bitcoin::TxIn,
    prevout: &bitcoin::TxOut,
    tx: &bitcoin::Transaction,
    serialized_tx: &[u8],
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    let script = Script::from_bytes(prevout.script_pubkey.as_bytes());
    if script.is_p2tr() && flags.contains(VerifyFlags::TAPROOT) {
        return verify_input_script_with_interpreter(input_index, input, prevout, tx, flags);
    }

    script
        .verify_with_flags(
            input_index,
            prevout.value,
            serialized_tx,
            flags.consensus_bits(),
        )
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: format!("script verification failed: {error}"),
        })
}

#[cfg(not(feature = "bitcoinconsensus"))]
fn verify_input_script(
    input_index: usize,
    input: &bitcoin::TxIn,
    prevout: &bitcoin::TxOut,
    tx: &bitcoin::Transaction,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_input_script_with_interpreter(input_index, input, prevout, tx, flags)
}

fn verify_input_script_with_interpreter(
    input_index: usize,
    input: &bitcoin::TxIn,
    prevout: &bitcoin::TxOut,
    tx: &bitcoin::Transaction,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    let witness = input.witness.to_vec();

    Interpreter
        .execute(
            prevout.script_pubkey.as_bytes(),
            input.script_sig.as_bytes(),
            &witness,
            flags,
            prevout,
            tx,
            input_index,
        )
        .map(|_| ())
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: error.to_string(),
        })
}

fn total_output_value_borrowed(tx: &bitcoin::Transaction) -> Result<u64, ConsensusError> {
    tx.output.iter().try_fold(0u64, |sum, output| {
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

    use super::{
        is_final_tx_with_locktime_cutoff, verify_coinbase_script_sig_size, verify_transaction,
        verify_transaction_with_mtp,
    };
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
    fn coinbase_script_sig_size_rejects_invalid_lengths() {
        for len in [0, 1, 101] {
            let tx = coinbase_transaction_with_script_sig_len(len);
            let utxos = BTreeMap::new();
            let expected = Err(ConsensusError::CoinbaseScriptSigSize { len });

            assert_eq!(verify_coinbase_script_sig_size(&tx.0), expected);
            assert_eq!(
                verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
                expected
            );
        }
    }

    #[test]
    fn coinbase_script_sig_size_accepts_valid_boundaries() {
        let utxos = BTreeMap::new();
        for len in [2, 100] {
            let tx = coinbase_transaction_with_script_sig_len(len);

            assert_eq!(verify_coinbase_script_sig_size(&tx.0), Ok(()));
            assert_eq!(
                verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
                Ok(())
            );
        }
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

    #[cfg(feature = "bitcoinconsensus")]
    #[test]
    fn non_coinbase_true_script_passes() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([3; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![spending_input(outpoint)],
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
            Ok(())
        );
    }

    #[cfg(feature = "bitcoinconsensus")]
    #[test]
    fn non_coinbase_false_script_reports_script_error() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([5; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![spending_input(outpoint)],
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
                script_pubkey: Builder::new().push_int(0).into_script(),
            },
        );

        assert!(matches!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::NONE),
            Err(ConsensusError::Script { input_index: 0, .. })
        ));
    }

    #[test]
    fn underfunded_transaction_fails_before_script_execution() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([4; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![spending_input(outpoint)],
            output: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(0).into_script(),
            },
        );

        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::NONE),
            Err(ConsensusError::InputsLessThanOutputs {
                input_value: 50,
                output_value: 100,
            })
        );
    }

    #[test]
    fn verify_transaction_rejects_non_final_height_lock() {
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::from_consensus(200),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let utxos = BTreeMap::new();

        let result = verify_transaction_with_mtp(&tx, &utxos, 100, 0, VerifyFlags::MANDATORY);

        assert!(matches!(
            result,
            Err(ConsensusError::Bip { bip: "BIP113", .. })
        ));
    }

    #[test]
    fn timestamp_locktime_uses_caller_supplied_cutoff() {
        let tx = Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::from_consensus(500_000_100),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        assert!(!is_final_tx_with_locktime_cutoff(&tx, 1, 500_000_100));
        assert!(is_final_tx_with_locktime_cutoff(&tx, 1, 500_000_101));
    }

    fn spending_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: Builder::new().push_int(1).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    fn coinbase_transaction_with_script_sig_len(len: usize) -> Tx {
        Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1; len]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        })
    }
}
