//! Consensus transaction sigop-cost accounting.
//!
//! This is the single transaction-level BIP141 accounting implementation used
//! by consensus verification and mempool preparation. Script-level counters
//! remain owned by `bitcoin-rs-script`.

use bitcoin_rs_primitives::{OutPoint, Tx, TxOut};
use bitcoin_rs_script::VerifyFlags;
use bitcoin_rs_script::script::{
    Instruction, instructions, is_p2sh, is_push_only, is_witness_program,
};
use bitcoin_rs_script::sigops::{count_accurate, count_segwit, count_tx_legacy};
use hashbrown::HashMap;

/// Counts transaction sigop cost against resolved previous outputs.
///
/// The counting rules are documented in the repository's
/// [mempool policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/mempool-policy.md).
/// This function does not verify scripts or select activation flags. Witness
/// costs use the caller's effective flag set: `CLEANSTACK` implies `WITNESS`,
/// matching the script interpreter's [`VerifyFlags::filled`] normalization.
/// Legacy and P2SH accounting retain the repository's existing always-on BIP16
/// policy.
///
/// Callers may supply incomplete or unordered prevouts and must retain their
/// own missing-input and validation status. Input order permits a linear pass
/// without allocation; other input orders build one borrowed lookup index.
#[must_use]
pub fn transaction_sigop_cost(tx: &Tx, prevouts: &[(OutPoint, TxOut)], flags: VerifyFlags) -> u32 {
    let flags = flags.filled();
    let mut cost = count_tx_legacy(tx).saturating_mul(4);
    // Core's coinbase cost never includes previous-output or witness sigops.
    if tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null() {
        return cost;
    }
    let mut cursor = 0;
    let mut indexed = None;
    for input in &tx.inputs {
        let prevout = if let Some((outpoint, output)) = prevouts.get(cursor)
            && *outpoint == input.previous_output
        {
            cursor += 1;
            output
        } else {
            let resolved = indexed.get_or_insert_with(|| {
                let mut resolved = HashMap::with_capacity(prevouts.len());
                for (outpoint, output) in prevouts {
                    resolved.entry(*outpoint).or_insert(output);
                }
                resolved
            });
            let Some(output) = resolved.get(&input.previous_output) else {
                continue;
            };
            *output
        };
        let redeem = if is_p2sh(&prevout.script_pubkey) && is_push_only(&input.script_sig) {
            last_push(&input.script_sig)
        } else {
            None
        };
        if let Some(script) = redeem {
            cost = cost.saturating_add(count_accurate(script).saturating_mul(4));
        }
        if flags.contains(VerifyFlags::WITNESS) {
            let witness_program = if is_witness_program(&prevout.script_pubkey) {
                Some(prevout.script_pubkey.as_slice())
            } else {
                redeem.filter(|script| is_witness_program(script))
            };
            if let Some(program) = witness_program {
                cost = cost.saturating_add(count_segwit(program, &input.witness));
            }
        }
    }
    cost
}

fn last_push(script: &[u8]) -> Option<&[u8]> {
    let mut last = None;
    for instruction in instructions(script) {
        match instruction.ok()? {
            Instruction::PushBytes(bytes) => last = Some(bytes),
            Instruction::Op(_) => last = None,
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{Amount, Hash256, LockTime, Script, Sequence, TxIn, Txid, Witness};
    use bitcoin_rs_script::script::{opcode, push_data};

    use super::*;

    #[test]
    fn non_push_only_p2sh_does_not_count_redeem_sigops() {
        let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[1; 32])), 0);
        let script_sig = [vec![opcode::OP_DUP], push_data(&[opcode::OP_CHECKSIG])].concat();
        let tx = Tx {
            version: 2,
            lock_time: LockTime::from_consensus(0),
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Script::from_bytes(script_sig),
                sequence: Sequence::from_consensus(u32::MAX),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::new(),
            }],
        };
        let p2sh = [
            vec![opcode::OP_HASH160, 0x14],
            vec![1; 20],
            vec![opcode::OP_EQUAL],
        ]
        .concat();
        assert_eq!(
            transaction_sigop_cost(
                &tx,
                &[(
                    outpoint,
                    TxOut {
                        value: Amount::from_sat(10_000),
                        script_pubkey: Script::from_bytes(p2sh),
                    }
                )],
                VerifyFlags::STANDARD,
            ),
            0
        );
    }
    /// Core v31.1 activates nested witness accounting only behind P2SH.
    /// These expectations come directly from Core's witness sigop rules.
    /// <https://github.com/bitcoin/bitcoin/blob/v31.1/src/script/script.cpp#L170-L189>
    /// <https://github.com/bitcoin/bitcoin/blob/v31.1/src/script/interpreter.cpp#L2139-L2166>
    #[test]
    fn transaction_sigop_cost_uses_prevout_type_and_push_only_redeem_rules() {
        let p2sh = [
            vec![opcode::OP_HASH160, 0x14],
            vec![1; 20],
            vec![opcode::OP_EQUAL],
        ]
        .concat();
        let p2wpkh = [vec![0x00, 0x14], vec![2; 20]].concat();
        let cases = [
            (
                vec![bitcoin_rs_script::eval::OP_DROP, opcode::OP_PUSHNUM_1],
                push_data(&p2wpkh),
                0,
            ),
            (p2sh, push_data(&p2wpkh), 1),
        ];
        for (script_pubkey, script_sig, expected) in cases {
            let tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid::default(), 0),
                    script_sig: Script::from_bytes(script_sig),
                    sequence: Sequence::from_consensus(u32::MAX),
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: Script::new(),
                }],
                lock_time: LockTime::from_consensus(0),
            };
            let prevouts = [(
                tx.inputs[0].previous_output,
                TxOut {
                    value: Amount::from_sat(2),
                    script_pubkey: Script::from_bytes(script_pubkey),
                },
            )];
            assert_eq!(
                super::transaction_sigop_cost(&tx, &prevouts, VerifyFlags::STANDARD),
                expected
            );
        }
    }

    #[test]
    fn transaction_sigop_cost_resolves_partial_and_unordered_prevouts() {
        let tx = Tx {
            version: 2,
            inputs: (0..3)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(Txid::default(), vout),
                    script_sig: Script::new(),
                    sequence: Sequence::from_consensus(u32::MAX),
                    witness: Witness::from_stack(vec![vec![opcode::OP_PUSHNUM_1 + 1, opcode::OP_CHECKMULTISIG]]),
                })
                .collect(),
            outputs: Vec::new(),
            lock_time: LockTime::from_consensus(0),
        };
        let prevouts = [
            (
                tx.inputs[2].previous_output,
                TxOut {
                    value: Amount::from_sat(2),
                    script_pubkey: Script::from_bytes([vec![0x00, 0x20], vec![3; 32]].concat()),
                },
            ),
            (
                tx.inputs[0].previous_output,
                TxOut {
                    value: Amount::from_sat(2),
                    script_pubkey: Script::from_bytes([vec![0x00, 0x14], vec![4; 20]].concat()),
                },
            ),
        ];
        assert_eq!(
            super::transaction_sigop_cost(&tx, &prevouts, VerifyFlags::STANDARD),
            3
        );
        assert_eq!(
            super::transaction_sigop_cost(&tx, &[], VerifyFlags::STANDARD),
            0
        );
    }

    /// BIP141 charges one sigop for each resolved P2WPKH input. Interleaved
    /// missing inputs and reverse-ordered prevouts must not lose matches.
    #[test]
    fn transaction_sigop_cost_resolves_many_interleaved_missing_inputs() {
        const INPUTS: u32 = 4_096;
        let tx = Tx {
            version: 2,
            inputs: (0..INPUTS)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(Txid::default(), vout),
                    script_sig: Script::new(),
                    sequence: Sequence::from_consensus(u32::MAX),
                    witness: Witness::new(),
                })
                .collect(),
            outputs: Vec::new(),
            lock_time: LockTime::from_consensus(0),
        };
        let mut prevouts: Vec<_> = tx
            .inputs
            .iter()
            .step_by(2)
            .map(|input| {
                (
                    input.previous_output,
                    TxOut {
                        value: Amount::from_sat(2),
                        script_pubkey: Script::from_bytes([vec![0x00, 0x14], vec![4; 20]].concat()),
                    },
                )
            })
            .collect();
        assert_eq!(
            transaction_sigop_cost(&tx, &prevouts, VerifyFlags::STANDARD),
            INPUTS / 2
        );
        prevouts.reverse();
        assert_eq!(
            transaction_sigop_cost(&tx, &prevouts, VerifyFlags::STANDARD),
            INPUTS / 2
        );
    }
    /// Core v31.1 `CountWitnessSigOps` returns zero without WITNESS.
    /// P2SH is explicitly enabled in both contexts; the repository's separate
    /// always-on P2SH policy is not changed by this BIP141 activation check.
    /// <https://github.com/bitcoin/bitcoin/blob/v31.1/src/script/interpreter.cpp#L2139-L2166>
    #[test]
    fn witness_sigop_cost_follows_the_active_bip141_flags() {
        let p2sh = [
            vec![opcode::OP_HASH160, 0x14],
            vec![1; 20],
            vec![opcode::OP_EQUAL],
        ]
        .concat();
        let p2wpkh = [vec![0x00, 0x14], vec![2; 20]].concat();
        let p2wsh = [vec![0x00, 0x20], vec![2; 32]].concat();
        let multisig = vec![opcode::OP_PUSHNUM_1 + 1, opcode::OP_CHECKMULTISIG];
        let cases = [
            (p2sh.clone(), push_data(&multisig), Vec::new(), 12, 12),
            (p2wpkh, Vec::new(), Vec::new(), 4, 5),
            (p2wsh.clone(), Vec::new(), vec![multisig.clone()], 4, 6),
            (p2sh, push_data(&p2wsh), vec![multisig], 4, 6),
        ];
        for (script_pubkey, script_sig, witness, inactive_cost, active_cost) in cases {
            let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[1; 32])), 0);
            let tx = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: outpoint,
                    script_sig: Script::from_bytes(script_sig),
                    sequence: Sequence::from_consensus(u32::MAX),
                    witness: Witness::from_stack(witness),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(9_000),
                    script_pubkey: Script::from_bytes(vec![opcode::OP_CHECKSIG]),
                }],
                lock_time: LockTime::from_consensus(0),
            };
            let prevouts = [(
                outpoint,
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: Script::from_bytes(script_pubkey),
                },
            )];
            assert_eq!(
                transaction_sigop_cost(&tx, &prevouts, VerifyFlags::P2SH),
                inactive_cost
            );
            // Preserve the repository's existing P2SH accounting policy even
            // for callers whose execution flags omit P2SH.
            assert_eq!(
                transaction_sigop_cost(&tx, &prevouts, VerifyFlags::NONE),
                inactive_cost
            );
            assert_eq!(
                transaction_sigop_cost(
                    &tx,
                    &prevouts,
                    VerifyFlags::P2SH.union(VerifyFlags::WITNESS)
                ),
                active_cost
            );
            assert_eq!(
                transaction_sigop_cost(&tx, &prevouts, VerifyFlags::CLEANSTACK),
                active_cost
            );
            assert_eq!(
                transaction_sigop_cost(&tx, &prevouts, VerifyFlags::STANDARD),
                active_cost
            );
        }
    }
}
