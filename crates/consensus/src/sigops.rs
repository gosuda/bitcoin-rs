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

/// Returns BIP141 transaction sigop cost against the resolved input scripts.
///
/// Legacy and P2SH sigops cost four units; native and P2SH-nested witness-v0
/// sigops cost one unit. Taproot has a separate per-input budget. Missing
/// prevouts contribute no contextual cost, allowing callers that are still
/// preparing a transaction to retain an explicit missing-input fact.
#[must_use]
pub fn transaction_sigop_cost(tx: &Tx, prevouts: &[(OutPoint, TxOut)]) -> u32 {
    let mut cost = count_tx_legacy(tx).saturating_mul(4);
    for input in &tx.inputs {
        let Some(prevout) = prevouts
            .iter()
            .find(|(outpoint, _)| *outpoint == input.previous_output)
            .map(|(_, output)| output)
        else {
            continue;
        };
        // Core's P2SH contextual count applies only to push-only scriptSig.
        // The same redeem script is the only source of nested witness-v0
        // accounting; arbitrary scriptSig data cannot activate it.
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
                &[((outpoint), TxOut {
                    value: 10_000,
                    script_pubkey: p2sh,
                })],
            ),
            0
        );
    }
}
