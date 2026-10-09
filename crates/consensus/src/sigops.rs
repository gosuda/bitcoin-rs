//! Consensus transaction sigop-cost accounting.

use crate::verify_tx::is_coinbase;
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut};
use bitcoin_rs_script::VerifyFlags;
use bitcoin_rs_script::sigops::{count_accurate, count_segwit, count_tx_legacy};
use bitcoin_rs_script::{Instruction, instructions, is_p2sh, is_push_only, is_witness_program};
use hashbrown::HashMap;

/// Counts transaction sigop cost against resolved previous outputs.
#[must_use]
pub fn transaction_sigop_cost(tx: &Tx, prevouts: &[(OutPoint, TxOut)], flags: VerifyFlags) -> u32 {
    let flags = flags.filled();
    let mut cost = count_tx_legacy(tx).saturating_mul(4);
    // Core's coinbase cost never includes previous-output or witness sigops.
    if is_coinbase(tx) {
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
    use bitcoin_rs_script::{opcode, push_data};

    use super::*;

    fn single_input_tx(script_sig: Vec<u8>, witness: Vec<Vec<u8>>) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[1; 32])), 0),
                script_sig: Script::from_bytes(script_sig),
                sequence: Sequence::from_consensus(u32::MAX),
                witness: Witness::from_stack(witness),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::from_bytes(vec![opcode::OP_CHECKSIG]),
            }],
        }
    }

    fn prevout(outpoint: OutPoint, script_pubkey: Vec<u8>) -> (OutPoint, TxOut) {
        (
            outpoint,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(script_pubkey),
            },
        )
    }

    #[test]
    fn transaction_sigop_cost_follows_prevout_class_and_bip141_flags() {
        let p2sh = [
            vec![opcode::OP_HASH160, 0x14],
            vec![1; 20],
            vec![opcode::OP_EQUAL],
        ]
        .concat();
        let p2wpkh = [vec![0x00, 0x14], vec![2; 20]].concat();
        let p2wsh = [vec![0x00, 0x20], vec![2; 32]].concat();
        let multisig = vec![opcode::OP_PUSHNUM_1 + 1, opcode::OP_CHECKMULTISIG];
        // (prevout, scriptSig, witness, costs without/with WITNESS, including +4 output cost)
        let cases = [
            (p2sh.clone(), push_data(&multisig), Vec::new(), 12, 12),
            (p2wpkh.clone(), Vec::new(), Vec::new(), 4, 5),
            (p2wsh.clone(), Vec::new(), vec![multisig.clone()], 4, 6),
            (p2sh.clone(), push_data(&p2wsh), vec![multisig], 4, 6),
            (p2sh.clone(), push_data(&p2wpkh), Vec::new(), 4, 5),
            (
                p2sh,
                [vec![opcode::OP_DUP], push_data(&[opcode::OP_CHECKSIG])].concat(),
                Vec::new(),
                4,
                4,
            ),
            (
                vec![bitcoin_rs_script::opcode::OP_DROP, opcode::OP_PUSHNUM_1],
                push_data(&p2wpkh),
                Vec::new(),
                4,
                4,
            ),
        ];

        for (script_pubkey, script_sig, witness, inactive_cost, active_cost) in cases {
            let tx = single_input_tx(script_sig, witness);
            let prevouts = [prevout(tx.inputs[0].previous_output, script_pubkey)];
            for flags in [VerifyFlags::P2SH, VerifyFlags::NONE] {
                assert_eq!(
                    transaction_sigop_cost(&tx, &prevouts, flags),
                    inactive_cost,
                    "{flags:?}"
                );
            }
            for flags in [
                VerifyFlags::P2SH.union(VerifyFlags::WITNESS),
                VerifyFlags::CLEANSTACK,
                VerifyFlags::STANDARD,
            ] {
                assert_eq!(
                    transaction_sigop_cost(&tx, &prevouts, flags),
                    active_cost,
                    "{flags:?}"
                );
            }
        }
    }

    #[test]
    fn transaction_sigop_cost_resolves_prevouts_by_outpoint() {
        const INPUTS: u32 = 4_096;
        let witness_tx = |count: u32, witness: Witness| Tx {
            version: 2,
            lock_time: LockTime::from_consensus(0),
            inputs: (0..count)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(Txid::default(), vout),
                    script_sig: Script::new(),
                    sequence: Sequence::from_consensus(u32::MAX),
                    witness: witness.clone(),
                })
                .collect(),
            outputs: Vec::new(),
        };

        // Two of three inputs resolved, out of order: one P2WSH bare multisig
        // (2) plus one P2WPKH (1).
        let multisig_witness = Witness::from_stack(vec![vec![
            opcode::OP_PUSHNUM_1 + 1,
            opcode::OP_CHECKMULTISIG,
        ]]);
        let tx = witness_tx(3, multisig_witness);
        let unordered = [
            prevout(
                tx.inputs[2].previous_output,
                [vec![0x00, 0x20], vec![3; 32]].concat(),
            ),
            prevout(
                tx.inputs[0].previous_output,
                [vec![0x00, 0x14], vec![4; 20]].concat(),
            ),
        ];
        assert_eq!(
            transaction_sigop_cost(&tx, &unordered, VerifyFlags::STANDARD),
            3
        );
        assert_eq!(transaction_sigop_cost(&tx, &[], VerifyFlags::STANDARD), 0);

        let tx = witness_tx(INPUTS, Witness::new());
        let mut prevouts: Vec<_> = tx
            .inputs
            .iter()
            .step_by(2)
            .map(|input| {
                prevout(
                    input.previous_output,
                    [vec![0x00, 0x14], vec![4; 20]].concat(),
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
}
