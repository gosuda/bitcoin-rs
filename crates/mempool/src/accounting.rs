//! Prevout-aware accounting shared by admission and acceptance previews.
//!
//! These are accounting facts, not a second validation engine. The gateway
//! still verifies scripts and commits policy decisions; a preview may provide
//! incomplete prevouts and must retain its explicit missing-input fact.

use bitcoin_rs_consensus::transaction_sigop_cost;
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut};
use bitcoin_rs_script::VerifyFlags;

use crate::standardness::PackageTxContext;

/// Derives admission accounting from the resolved input outputs.
///
/// `prevouts` contains one entry per resolved transaction input, in any order.
/// Missing inputs remain an explicit fact: a saturating provisional fee must
/// never make an incomplete transaction admissible. Range validation remains
/// the existing consensus verifier's responsibility.
#[must_use]
pub fn prepared_context(
    tx: &Tx,
    prevouts: &[(OutPoint, TxOut)],
    missing_inputs: bool,
) -> PackageTxContext {
    let input_value = prevouts
        .iter()
        .fold(0_u64, |sum, (_, output)| sum.saturating_add(output.value));
    let output_value = tx
        .outputs
        .iter()
        .fold(0_u64, |sum, output| sum.saturating_add(output.value));
    PackageTxContext {
        fee: input_value.saturating_sub(output_value),
        vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
        sigop_cost: transaction_sigop_cost(tx, prevouts, VerifyFlags::STANDARD),
        missing_inputs,
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_primitives::{TxIn, Txid, consensus_bytes};
    use bitcoin_rs_script::script::{opcode, push_data};

    use super::*;

    fn transaction(script_sig: Vec<u8>, witness: Vec<Vec<u8>>, output: Vec<u8>) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig,
                sequence: u32::MAX,
                witness,
            }],
            outputs: vec![TxOut {
                value: 9_000,
                script_pubkey: output,
            }],
            lock_time: 0,
        }
    }

    fn p2sh() -> Vec<u8> {
        [
            vec![opcode::OP_HASH160, 0x14],
            vec![1; 20],
            vec![opcode::OP_EQUAL],
        ]
        .concat()
    }

    fn witness_program(length: u8) -> Vec<u8> {
        [vec![0x00, length], vec![2; usize::from(length)]].concat()
    }

    fn assert_oracle(tx: &Tx, prevout_script: Vec<u8>, expected: u32) {
        let prevouts = vec![(
            tx.inputs[0].previous_output,
            TxOut {
                value: 10_000,
                script_pubkey: prevout_script.clone(),
            },
        )];
        let oracle: bitcoin::Transaction = deserialize(&consensus_bytes(tx))
            .unwrap_or_else(|error| panic!("oracle transaction decode failed: {error}"));
        let oracle_outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(*tx.inputs[0].previous_output.txid.as_bytes()),
            vout: tx.inputs[0].previous_output.vout,
        };
        let oracle_output = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(10_000),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(prevout_script),
        };
        let oracle_cost = oracle.total_sigop_cost(|outpoint| {
            (*outpoint == oracle_outpoint).then_some(oracle_output.clone())
        });
        assert_eq!(
            u32::try_from(oracle_cost),
            Ok(expected),
            "independent rust-bitcoin oracle"
        );
        assert_eq!(
            transaction_sigop_cost(tx, &prevouts, VerifyFlags::STANDARD),
            expected
        );
        let context = prepared_context(tx, &prevouts, false);
        assert_eq!(context.fee, 1_000);
        assert_eq!(u32::try_from(oracle.vsize()), Ok(context.vsize));
        assert_eq!(context.sigop_cost, expected);
        assert!(!context.missing_inputs);
    }

    /// Independent vectors follow BIP141's Sigops section and Core v31.1
    /// `GetTransactionSigOpCost`; rust-bitcoin is the executable oracle.
    /// <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#sigops>
    /// <https://github.com/bitcoin/bitcoin/blob/v31.1/src/consensus/tx_verify.cpp>
    #[test]
    fn bip141_accounting_matches_independent_transaction_oracle() {
        assert_oracle(
            &transaction(Vec::new(), Vec::new(), vec![opcode::OP_CHECKSIG]),
            vec![opcode::OP_PUSHNUM_1],
            4,
        );
        let multisig = vec![opcode::OP_PUSHNUM_1 + 1, opcode::OP_CHECKMULTISIG];
        assert_oracle(
            &transaction(push_data(&multisig), Vec::new(), Vec::new()),
            p2sh(),
            8,
        );
        assert_oracle(
            &transaction(Vec::new(), Vec::new(), Vec::new()),
            witness_program(20),
            1,
        );
        assert_oracle(
            &transaction(Vec::new(), vec![multisig.clone()], Vec::new()),
            witness_program(32),
            2,
        );
        assert_oracle(
            &transaction(push_data(&witness_program(32)), vec![multisig], Vec::new()),
            p2sh(),
            2,
        );
        assert_oracle(
            &transaction(Vec::new(), vec![vec![opcode::OP_CHECKSIG]], Vec::new()),
            [vec![opcode::OP_PUSHNUM_1, 0x20], vec![3; 32]].concat(),
            0,
        );
    }

    #[test]
    fn arbitrary_redeem_data_does_not_activate_witness_accounting() {
        let tx = transaction(push_data(&witness_program(20)), Vec::new(), Vec::new());
        assert_oracle(&tx, vec![opcode::OP_PUSHNUM_1], 0);
    }

    #[test]
    fn non_push_only_p2sh_scripts_have_no_redeem_sigops() {
        let script_sig = [vec![opcode::OP_DUP], push_data(&[opcode::OP_CHECKSIG])].concat();
        let tx = transaction(script_sig, Vec::new(), Vec::new());
        let prevouts = [(
            tx.inputs[0].previous_output,
            TxOut {
                value: 10_000,
                script_pubkey: p2sh(),
            },
        )];
        // Core v31.1 CScript::GetSigOpCount(scriptSig) returns zero on
        // any opcode above OP_16; rust-bitcoin 0.32's P2SH helper does not
        // enforce that precondition, so Core supplies this malformed-input
        // expectation rather than the library oracle used for valid shapes.
        // https://github.com/bitcoin/bitcoin/blob/v31.1/src/script/script.cpp#L170-L189
        assert_eq!(
            transaction_sigop_cost(&tx, &prevouts, VerifyFlags::STANDARD),
            0
        );
    }

    #[test]
    fn incomplete_accounting_preserves_the_missing_input_fact() {
        let tx = transaction(Vec::new(), Vec::new(), Vec::new());
        let context = prepared_context(&tx, &[], true);
        assert!(context.missing_inputs);
        assert_eq!(context.fee, 0);
    }
}
