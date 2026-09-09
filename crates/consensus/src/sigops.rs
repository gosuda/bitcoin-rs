//! Consensus transaction sigop-cost accounting.
//!
//! This is the single transaction-level BIP141 accounting implementation used
//! by consensus verification and mempool preparation. Script-level counters
//! remain owned by `bitcoin-rs-script`.

use bitcoin_rs_primitives::{OutPoint, Tx, TxOut};
use bitcoin_rs_script::script::{
    Instruction, instructions, is_p2sh, is_push_only, is_witness_program,
};
use bitcoin_rs_script::sigops::{count_accurate, count_segwit, count_tx_legacy};
use hashbrown::HashMap;

/// Counts BIP141 transaction sigop cost against resolved previous outputs.
///
/// Legacy and P2SH sigops cost four units; witness-v0 sigops cost one. Nested
/// witness programs require a P2SH prevout and a push-only scriptSig. Taproot
/// retains its separate per-input budget. These are counting rules, not script
/// verification or activation decisions; callers retain their validation flags
/// and activation checks. Missing prevouts contribute no contextual sigops.
///
/// Prevouts may be incomplete or unordered. Input order permits a linear pass
/// without allocation, which is the normal admission/consensus preparation order.
/// A missing or unordered input builds a borrowed index once rather than
/// repeatedly scanning the full prevout slice.
/// The rules follow BIP141 and Core v31.1 `GetTransactionSigOpCost`,
/// `CScript::GetSigOpCount` and `CountWitnessSigOps`.
#[must_use]
pub fn transaction_sigop_cost(tx: &Tx, prevouts: &[(OutPoint, TxOut)]) -> u32 {
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
        let witness_program = if is_witness_program(&prevout.script_pubkey) {
            Some(prevout.script_pubkey.as_slice())
        } else {
            redeem.filter(|script| is_witness_program(script))
        };
        if let Some(program) = witness_program {
            cost = cost.saturating_add(count_segwit(program, &input.witness));
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
    use bitcoin_rs_primitives::{Hash256, TxIn, Txid};
    use bitcoin_rs_script::script::{opcode, push_data};

    use super::*;

    #[test]
    fn non_push_only_p2sh_does_not_count_redeem_sigops() {
        let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[1; 32])), 0);
        let script_sig = [vec![opcode::OP_DUP], push_data(&[opcode::OP_CHECKSIG])].concat();
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig,
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 9_000,
                script_pubkey: Vec::new(),
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
                        value: 10_000,
                        script_pubkey: p2sh,
                    }
                )],
            ),
            0
        );
    }
    /// Core v31.1 activates nested witness accounting only behind P2SH.
    /// These expectations come directly from Core's witness sigop rules.
    /// <https://github.com/bitcoin/bitcoin/blob/v31.1/src/script/script.cpp#L170-L189>
    /// <https://github.com/bitcoin/bitcoin/blob/v31.1/src/script/interpreter.cpp#L1974-L1997>
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
                    script_sig,
                    sequence: u32::MAX,
                    witness: Vec::new(),
                }],
                outputs: vec![TxOut {
                    value: 1,
                    script_pubkey: Vec::new(),
                }],
                lock_time: 0,
            };
            let prevouts = [(
                tx.inputs[0].previous_output,
                TxOut {
                    value: 2,
                    script_pubkey,
                },
            )];
            assert_eq!(super::transaction_sigop_cost(&tx, &prevouts), expected);
        }
    }

    #[test]
    fn transaction_sigop_cost_resolves_partial_and_unordered_prevouts() {
        let tx = Tx {
            version: 2,
            inputs: (0..3)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(Txid::default(), vout),
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: vec![vec![opcode::OP_PUSHNUM_1 + 1, opcode::OP_CHECKMULTISIG]],
                })
                .collect(),
            outputs: Vec::new(),
            lock_time: 0,
        };
        let prevouts = [
            (
                tx.inputs[2].previous_output,
                TxOut {
                    value: 2,
                    script_pubkey: [vec![0x00, 0x20], vec![3; 32]].concat(),
                },
            ),
            (
                tx.inputs[0].previous_output,
                TxOut {
                    value: 2,
                    script_pubkey: [vec![0x00, 0x14], vec![4; 20]].concat(),
                },
            ),
        ];
        assert_eq!(super::transaction_sigop_cost(&tx, &prevouts), 3);
        assert_eq!(super::transaction_sigop_cost(&tx, &[]), 0);
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
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: Vec::new(),
                })
                .collect(),
            outputs: Vec::new(),
            lock_time: 0,
        };
        let mut prevouts: Vec<_> = tx
            .inputs
            .iter()
            .step_by(2)
            .map(|input| {
                (
                    input.previous_output,
                    TxOut {
                        value: 2,
                        script_pubkey: [vec![0x00, 0x14], vec![4; 20]].concat(),
                    },
                )
            })
            .collect();
        assert_eq!(transaction_sigop_cost(&tx, &prevouts), INPUTS / 2);
        prevouts.reverse();
        assert_eq!(transaction_sigop_cost(&tx, &prevouts), INPUTS / 2);
    }
}
