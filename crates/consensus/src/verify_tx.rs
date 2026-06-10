use std::collections::BTreeSet;

#[cfg(feature = "bitcoinconsensus")]
use bitcoin::{Script, consensus::encode};
use bitcoin_rs_primitives::Tx;
#[cfg(not(feature = "kernel"))]
use bitcoin_rs_script::Interpreter;
use bitcoin_rs_script::VerifyFlags;

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
    verify_transaction_borrowed_with_locktime_cutoff(
        tx,
        prevouts,
        height,
        locktime_cutoff,
        flags,
        false,
    )
}

/// Verifies non-script transaction rules for a borrowed transaction with a caller-selected
/// timestamp cutoff.
///
/// Checks finality, empty inputs/outputs, coinbase scriptSig size, duplicate inputs, null
/// prevouts, missing prevouts, input/output value balance, and sigop limits. Skips interpreter
/// and `bitcoinconsensus` script execution.
pub fn verify_transaction_borrowed_non_script_with_mtp(
    tx: &bitcoin::Transaction,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
) -> Result<(), ConsensusError> {
    verify_transaction_borrowed_with_locktime_cutoff(
        tx,
        prevouts,
        height,
        locktime_cutoff,
        VerifyFlags::NONE,
        true,
    )
}

fn verify_transaction_borrowed_with_locktime_cutoff(
    tx: &bitcoin::Transaction,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    skip_scripts: bool,
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
    let mut verified_prevouts = Vec::with_capacity(tx.input.len());
    #[cfg(all(feature = "bitcoinconsensus", not(feature = "kernel")))]
    let mut serialized_tx = None;
    for (input_index, input) in tx.input.iter().enumerate() {
        let prevout = prevouts
            .lookup(&input.previous_output)
            .ok_or(ConsensusError::MissingPrevout { input_index })?;
        input_value = input_value
            .checked_add(prevout.value.to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;

        // R2: in the kernel build the per-input interpreter/bitcoinconsensus
        // dispatch is compiled out; script verdicts come from the batched
        // kernel call after prevout resolution.
        #[cfg(not(feature = "kernel"))]
        if !skip_scripts {
            #[cfg(feature = "bitcoinconsensus")]
            if verify_non_taproot_with_bitcoinconsensus(
                input_index,
                &prevout,
                tx,
                flags,
                &mut serialized_tx,
            )? {
                verified_prevouts.push((input.previous_output, prevout));
                continue;
            }

            let witness = input.witness.to_vec();
            Interpreter
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
        verified_prevouts.push((input.previous_output, prevout));
    }

    // KTD5: under the kernel feature every script class routes through Core's
    // engine — one transaction parse plus one sighash precompute shared across
    // inputs. When scripts are skipped (assume-valid), no kernel call happens.
    #[cfg(feature = "kernel")]
    if !skip_scripts {
        crate::kernel::verify_tx_scripts(tx, &verified_prevouts, flags)?;
    }

    if input_value < output_value {
        return Err(ConsensusError::InputsLessThanOutputs {
            input_value,
            output_value,
        });
    }

    let mut sigop_lookup_cursor = 0usize;
    let sigop_cost = u32::try_from(tx.total_sigop_cost(|outpoint| {
        cached_prevout_lookup(&verified_prevouts, &mut sigop_lookup_cursor, outpoint)
    }))
    .unwrap_or(u32::MAX);
    if sigop_cost > MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: MAX_BLOCK_SIGOPS_COST,
        });
    }

    Ok(())
}

fn cached_prevout_lookup(
    prevouts: &[(bitcoin::OutPoint, bitcoin::TxOut)],
    cursor: &mut usize,
    outpoint: &bitcoin::OutPoint,
) -> Option<bitcoin::TxOut> {
    if prevouts.is_empty() {
        return None;
    }
    if *cursor >= prevouts.len() {
        *cursor = 0;
    }
    if let Some((cached_outpoint, txout)) = prevouts.get(*cursor)
        && cached_outpoint == outpoint
    {
        *cursor = (*cursor).saturating_add(1);
        return Some(txout.clone());
    }
    let (index, txout) =
        prevouts
            .iter()
            .enumerate()
            .find_map(|(index, (cached_outpoint, txout))| {
                (cached_outpoint == outpoint).then_some((index, txout))
            })?;
    *cursor = index.saturating_add(1);
    Some(txout.clone())
}

#[cfg(feature = "bitcoinconsensus")]
fn verify_non_taproot_with_bitcoinconsensus(
    input_index: usize,
    prevout: &bitcoin::TxOut,
    tx: &bitcoin::Transaction,
    flags: VerifyFlags,
    serialized_tx: &mut Option<Vec<u8>>,
) -> Result<bool, ConsensusError> {
    let script = Script::from_bytes(prevout.script_pubkey.as_bytes());
    if script.is_p2tr() && flags.contains(VerifyFlags::TAPROOT) {
        return Ok(false);
    }

    let bytes = serialized_tx.get_or_insert_with(|| encode::serialize(tx));
    script
        .verify_with_flags(
            input_index,
            prevout.value,
            bytes.as_slice(),
            flags.consensus_bits(),
        )
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: format!("script verification failed: {error}"),
        })?;
    Ok(true)
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
    use std::{cell::Cell, collections::BTreeMap};

    use bitcoin::hashes::Hash as _;
    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    use bitcoin::opcodes::all::OP_EQUAL;
    use bitcoin::script::Builder;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
        transaction,
    };
    use bitcoin_rs_primitives::Tx;
    use bitcoin_rs_script::VerifyFlags;

    use super::{
        is_final_tx_with_locktime_cutoff, verify_coinbase_script_sig_size, verify_transaction,
        verify_transaction_borrowed, verify_transaction_borrowed_with_mtp,
        verify_transaction_with_mtp,
    };
    use crate::{ConsensusError, rust_path::UtxoView};

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

    #[test]
    fn verify_transaction_accepts_multi_input_true_scripts() {
        let first = OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        };
        let second = OutPoint {
            txid: Txid::from_byte_array([2; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![true_spending_input(first), true_spending_input(second)],
            output: vec![TxOut {
                value: Amount::from_sat(75),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            first,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );
        utxos.insert(
            second,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );

        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    #[test]
    fn verify_transaction_reuses_prevouts_for_sigop_counting() {
        let first = OutPoint {
            txid: Txid::from_byte_array([11; 32]),
            vout: 0,
        };
        let second = OutPoint {
            txid: Txid::from_byte_array([12; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![true_spending_input(first), true_spending_input(second)],
            output: vec![TxOut {
                value: Amount::from_sat(75),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            first,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );
        utxos.insert(
            second,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );
        let view = CountingUtxoView::new(utxos);

        assert_eq!(
            verify_transaction(&tx, &view, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
        assert_eq!(view.lookup_count(), tx.0.input.len());
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn verify_transaction_accepts_non_taproot_spend_with_script_sig_data() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([3; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Builder::new().push_int(7).push_int(7).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
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
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
        );

        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn verify_transaction_rejects_non_taproot_spend_with_script_sig_mismatch() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([4; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Builder::new().push_int(7).push_int(8).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
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
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
        );

        let result = verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY);

        assert!(matches!(
            result,
            Err(ConsensusError::Script {
                input_index: 0,
                reason
            }) if reason.starts_with("script verification failed:")
        ));
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn verify_transaction_routes_taproot_spends_to_interpreter() {
        let first = OutPoint {
            txid: Txid::from_byte_array([5; 32]),
            vout: 0,
        };
        let second = OutPoint {
            txid: Txid::from_byte_array([6; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![true_spending_input(first), true_spending_input(second)],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            first,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: p2tr_script_pubkey(),
            },
        );
        utxos.insert(
            second,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );

        let result = verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY);

        assert_eq!(
            result,
            Err(ConsensusError::Script {
                input_index: 0,
                reason:
                    "taproot key-path verification requires all prevouts for multi-input transactions"
                        .to_owned(),
            })
        );
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_accepts_non_taproot_spend_with_script_sig_data() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([7; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Builder::new().push_int(7).push_int(7).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
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
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
        );

        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    /// R2 pin: in the kernel build the script verdict carries the kernel
    /// dispatch marker, proving the Rust interpreter (whose call site is
    /// `cfg(not(feature = "kernel"))`) did not produce it.
    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_rejects_script_sig_mismatch_with_kernel_verdict() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([8; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Builder::new().push_int(7).push_int(8).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
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
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
        );

        let result = verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY);

        assert!(matches!(
            result,
            Err(ConsensusError::Script {
                input_index: 0,
                reason
            }) if reason.starts_with("kernel script verification failed:")
        ));
    }

    /// Assume-valid semantics: the non-script entry must accept a transaction
    /// whose script the kernel would reject — no kernel invocation when
    /// scripts are skipped.
    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_skip_scripts_entry_accepts_invalid_script() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([9; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Builder::new().push_int(7).push_int(8).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
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
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
        );

        assert_eq!(
            super::verify_transaction_borrowed_non_script_with_mtp(&tx.0, &utxos, 0, 0),
            Ok(())
        );
        assert!(matches!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
            Err(ConsensusError::Script { input_index: 0, .. })
        ));
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

    #[test]
    fn borrowed_transaction_paths_share_locktime_and_coinbase_rules() {
        let coinbase = coinbase_transaction_with_script_sig_len(2);
        let utxos = BTreeMap::new();

        assert_eq!(
            verify_transaction_borrowed(&coinbase.0, &utxos, 0, VerifyFlags::MANDATORY),
            Ok(())
        );

        let non_final = Transaction {
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

        assert!(matches!(
            verify_transaction_borrowed_with_mtp(
                &non_final,
                &utxos,
                1,
                500_000_100,
                VerifyFlags::MANDATORY
            ),
            Err(ConsensusError::Bip { bip: "BIP113", .. })
        ));
    }

    fn spending_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: Builder::new().push_int(1).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    fn true_spending_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    struct CountingUtxoView {
        utxos: BTreeMap<OutPoint, TxOut>,
        lookups: Cell<usize>,
    }

    impl CountingUtxoView {
        fn new(utxos: BTreeMap<OutPoint, TxOut>) -> Self {
            Self {
                utxos,
                lookups: Cell::new(0),
            }
        }

        fn lookup_count(&self) -> usize {
            self.lookups.get()
        }
    }

    impl UtxoView for CountingUtxoView {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.lookups.set(self.lookups.get().saturating_add(1));
            self.utxos.get(outpoint).cloned()
        }
    }

    #[cfg(feature = "bitcoinconsensus")]
    fn p2tr_script_pubkey() -> ScriptBuf {
        let mut bytes = Vec::with_capacity(34);
        bytes.push(0x51);
        bytes.push(0x20);
        bytes.extend_from_slice(&[7; 32]);
        ScriptBuf::from_bytes(bytes)
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
