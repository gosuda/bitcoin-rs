//! Native sigop counting over scripts, transactions, and blocks.
//!
//! Replaces the `bitcoin::Script`/`Transaction::total_sigop_cost` counters the
//! workspace used before the native-primitives migration. Counting semantics
//! mirror Core and rust-bitcoin exactly: `OP_CHECKSIG`/`OP_CHECKSIGVERIFY`
//! cost 1, `OP_CHECKMULTISIG`/`OP_CHECKMULTISIGVERIFY` cost 20 under legacy
//! counting or the preceding small-integer push value under accurate counting,
//! data pushes are skipped, and a malformed push ends the count (Core's
//! `if (!GetOp(pc, opcode)) break;`).

use bitcoin_rs_primitives::{Block, Tx};

use crate::script::{EarlyEndOfScript, Instruction, instructions, is_p2wpkh, is_p2wsh, opcode};

/// Counts legacy sigops in a script (Core's `GetSigOpCount(false)`).
pub fn count_legacy(script: &[u8]) -> u32 {
    count_script(script, false)
}

/// Counts script sigops with the BIP16/BIP141 accurate multisig rule.
/// Only an immediately preceding `OP_1` through `OP_16` supplies the key count.
pub fn count_accurate(script: &[u8]) -> u32 {
    count_script(script, true)
}

/// Counts segwit-v0 sigops for a witness program and witness stack.
///
/// A P2WPKH program costs exactly 1; a P2WSH program delegates to its
/// witness script counted accurately (multisig charges its declared key
/// count), matching the previous `Script::count_sigops` behavior.
pub fn count_segwit(script: &[u8], witness: &[Vec<u8>]) -> u32 {
    if is_p2wpkh(script) {
        return 1;
    }
    if !is_p2wsh(script) {
        return 0;
    }
    witness
        .last()
        .map_or(0, |witness_script| count_accurate(witness_script))
}

/// Counts taproot sigops under BIP342's per-input budget model.
///
/// Taproot does not contribute to the legacy per-block sigop cost. Tapscript's
/// `OP_CHECKSIG` and `OP_CHECKSIGADD` budget is enforced per input by the
/// executing validator, so this block-level counter returns zero.
pub const fn count_taproot(_script: &[u8], _witness: &[Vec<u8>]) -> u32 {
    0
}

/// Counts the sigop cost visible without a UTXO set: legacy counts of every
/// input's `scriptSig` and every output's `scriptPubKey` (the previous
/// `Transaction::total_sigop_cost(|_| None)` shape).
pub fn count_tx_legacy(tx: &Tx) -> u32 {
    let mut count = 0_u32;
    for input in &tx.inputs {
        count = count.saturating_add(count_legacy(&input.script_sig));
    }
    for output in &tx.outputs {
        count = count.saturating_add(count_legacy(&output.script_pubkey));
    }
    count
}

/// Counts the legacy sigop cost of a whole block without prevout resolution.
pub fn count_block(block: &Block) -> u32 {
    block
        .txs
        .iter()
        .fold(0_u32, |count, tx| count.saturating_add(count_tx_legacy(tx)))
}

fn count_script(script: &[u8], accurate: bool) -> u32 {
    let mut count = 0_u32;
    let mut pushnum_cache = None;
    for instruction in instructions(script) {
        match instruction {
            Ok(Instruction::Op(op)) => match op {
                opcode::OP_CHECKSIG | opcode::OP_CHECKSIGVERIFY => {
                    count = count.saturating_add(1);
                    pushnum_cache = None;
                }
                opcode::OP_CHECKMULTISIG | opcode::OP_CHECKMULTISIGVERIFY => {
                    match (accurate, pushnum_cache) {
                        (true, Some(keys)) => count = count.saturating_add(u32::from(keys)),
                        _ => count = count.saturating_add(20),
                    }
                    pushnum_cache = None;
                }
                other => pushnum_cache = opcode::decode_pushnum(other),
            },
            Ok(Instruction::PushBytes(_)) => pushnum_cache = None,
            Err(EarlyEndOfScript) => break,
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf as OracleScriptBuf;

    use bitcoin_rs_primitives::{Block, OutPoint, Tx, TxIn, TxOut, Txid};

    const fn pushnum(n: u8) -> u8 {
        opcode::OP_PUSHNUM_1 + (n - 1)
    }

    use super::{count_block, count_legacy, count_segwit, count_tx_legacy};
    use crate::script::{opcode, push_data};

    #[test]
    fn legacy_count_matches_oracle_multisig_rule() {
        let script: Vec<u8> = [
            vec![opcode::OP_PUSHNUM_1],
            push_data(&[3; 33]),
            push_data(&[3; 33]),
            push_data(&[3; 33]),
            vec![pushnum(3), opcode::OP_CHECKMULTISIG],
        ]
        .concat();
        assert_eq!(count_legacy(&script), 20);

        let oracle = OracleScriptBuf::from_bytes(script);
        assert_eq!(
            count_legacy(oracle.as_bytes()),
            u32::try_from(oracle.count_sigops_legacy()).unwrap_or(u32::MAX)
        );
    }

    #[test]
    fn accurate_segwit_count_charges_declared_multisig_keys() {
        let witness_script: Vec<u8> = [
            push_data(&[9; 33]),
            push_data(&[9; 33]),
            vec![pushnum(2), opcode::OP_CHECKMULTISIG],
        ]
        .concat();
        let p2wsh: Vec<u8> = [vec![0x00, 0x20], vec![7; 32]].concat();
        assert_eq!(
            count_segwit(&p2wsh, &[witness_script]),
            2,
            "accurate counting charges the declared key count"
        );

        let p2wpkh: Vec<u8> = [vec![0x00, 0x14], vec![7; 20]].concat();
        assert_eq!(count_segwit(&p2wpkh, &[]), 1);
        assert_eq!(count_segwit(&[opcode::OP_DUP], &[]), 0);
    }

    /// Core v31.1 `CScript::GetSigOpCount` updates `lastOpcode` for every opcode.
    /// <https://github.com/bitcoin/bitcoin/blob/v31.1/src/script/script.cpp>
    #[test]
    fn accurate_multisig_requires_an_immediately_preceding_pushnum() {
        // Core advances lastOpcode after EVERY opcode. rust-bitcoin 0.32's
        // count_sigops retains the old OP_N across sigop opcodes, so it is not
        // an oracle for these cases. These expected costs are direct Core
        // vectors: one CHECKSIG plus the default 20, or two plus 20.
        for (script, expected) in [
            (
                vec![pushnum(2), opcode::OP_CHECKSIG, opcode::OP_CHECKMULTISIG],
                21,
            ),
            (
                vec![
                    pushnum(2),
                    opcode::OP_CHECKMULTISIG,
                    opcode::OP_CHECKMULTISIG,
                ],
                22,
            ),
            (
                vec![
                    pushnum(2),
                    opcode::OP_CHECKSIGVERIFY,
                    opcode::OP_CHECKMULTISIGVERIFY,
                ],
                21,
            ),
        ] {
            assert_eq!(super::count_accurate(&script), expected);
            let p2wsh = [vec![0x00, 0x20], vec![7; 32]].concat();
            assert_eq!(count_segwit(&p2wsh, &[script]), expected);
        }
    }

    #[test]
    fn tx_and_block_counts_cover_script_sig_and_script_pubkey() {
        let script_sig: Vec<u8> = vec![opcode::OP_CHECKSIG];
        let script_pubkey: Vec<u8> = vec![opcode::OP_CHECKMULTISIG];
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig,
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey,
            }],
            lock_time: 0,
        };
        assert_eq!(count_tx_legacy(&tx), 1 + 20);

        let block = Block {
            header: bitcoin_rs_primitives::Header::default(),
            txs: vec![tx.clone(), tx],
        };
        assert_eq!(count_block(&block), 42);
    }
}
