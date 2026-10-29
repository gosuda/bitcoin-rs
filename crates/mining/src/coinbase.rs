use bitcoin_rs_primitives::{
    Amount, Block, Hash256, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_script::push_int;
use thiserror::Error;

use crate::template::CoinbaseBudget;

/// BIP141 `OP_RETURN` `PUSH36` `aa21a9ed` prefix. Core `MINIMUM_WITNESS_COMMITMENT` is 38 bytes.
const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

pub const WITNESS_RESERVED_VALUE: [u8; 32] = [0; 32];

/// Candidate assembly failure.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum MiningError {
    #[error("coinbase value overflows satoshi range")]
    CoinbaseValueOverflow,
    #[error("selected transaction fees overflow the satoshi range")]
    FeeOverflow,
    #[error("candidate {field} overflows its supported width")]
    CandidateScalarOverflow { field: &'static str },
    #[error("coinbase reservation exhausts the {field} limit")]
    CapacityExhausted { field: &'static str },
    #[error("failed to meet compact target in {tries} nonce attempts")]
    Unsolved { tries: u64 },
}

pub(crate) fn build_coinbase(
    height: u32,
    subsidy_halving_interval: u32,
    fees: u64,
    payout: &[u8],
    witness_commitment: Option<&Hash256>,
) -> Result<Tx, MiningError> {
    let value = bitcoin_rs_consensus::block_subsidy(height, subsidy_halving_interval)
        .checked_add(fees)
        .ok_or(MiningError::CoinbaseValueOverflow)?;

    let mut witness = Witness::new();
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(value),
        script_pubkey: payout.to_vec().into(),
    }];

    if let Some(commitment) = witness_commitment {
        witness.push(WITNESS_RESERVED_VALUE.to_vec());
        outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: witness_commitment_script(commitment).into(),
        });
    }

    Ok(Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0; 32])), 0xffff_ffff),
            script_sig: coinbase_script_sig(height).into(),
            sequence: Sequence::MAX,
            witness,
        }],
        outputs,
        lock_time: LockTime::ZERO,
    })
}

pub fn witness_commitment_script(commitment: &Hash256) -> Vec<u8> {
    let mut script = Vec::with_capacity(38);
    script.extend_from_slice(&WITNESS_COMMITMENT_PREFIX);
    script.extend_from_slice(commitment.as_byte_array());
    script
}

#[must_use]
pub fn needs_witness_reserved_value(block: &Block, segwit_active: bool) -> bool {
    if !segwit_active {
        return false;
    }
    let Some(coinbase) = block.txs.first() else {
        return false;
    };
    if !coinbase_has_witness_commitment(coinbase) {
        return false;
    }
    let Some(input) = coinbase.inputs.first() else {
        return false;
    };
    input.witness.is_empty()
}

pub fn update_uncommitted_block_structures(block: &mut Block, segwit_active: bool) {
    if !needs_witness_reserved_value(block, segwit_active) {
        return;
    }
    block.txs[0].inputs[0]
        .witness
        .push(WITNESS_RESERVED_VALUE.to_vec());
}

fn coinbase_has_witness_commitment(tx: &Tx) -> bool {
    tx.outputs.iter().any(|output| {
        output.script_pubkey.len() >= 38
            && output.script_pubkey.starts_with(&WITNESS_COMMITMENT_PREFIX)
    })
}

fn coinbase_script_sig(height: u32) -> Vec<u8> {
    let mut script = push_int(i64::from(height));
    if script.len() < CoinbaseBudget::MIN_SCRIPT_SIG_LEN {
        script.push(0x00);
    }
    script
}

#[cfg(test)]
mod uncommitted_witness_tests {
    use super::{
        WITNESS_RESERVED_VALUE, needs_witness_reserved_value, update_uncommitted_block_structures,
        witness_commitment_script,
    };
    use bitcoin_rs_primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Witness,
    };

    fn commitment_block(witness: Vec<Vec<u8>>, with_commitment: bool) -> Block {
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }];
        if with_commitment {
            outputs.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: witness_commitment_script(&Hash256::from_le_bytes(&[0xab; 32]))
                    .into(),
            });
        }
        Block {
            header: Header {
                version: 0x2000_0000,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txs: vec![Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(vec![0x51, 0x00]),
                    sequence: Sequence::MAX,
                    witness: witness.into(),
                }],
                outputs,
                lock_time: LockTime::ZERO,
            }],
        }
    }

    #[test]
    fn predicate_matches_fill_branch_including_empty_shapes() {
        let mut fillable = commitment_block(Vec::new(), true);
        assert!(needs_witness_reserved_value(&fillable, true));
        update_uncommitted_block_structures(&mut fillable, true);
        assert_eq!(
            fillable.txs[0].inputs[0].witness,
            Witness::from_stack(vec![WITNESS_RESERVED_VALUE.to_vec()])
        );

        let mut no_txs = commitment_block(Vec::new(), true);
        no_txs.txs.clear();
        assert!(!needs_witness_reserved_value(&no_txs, true));
        update_uncommitted_block_structures(&mut no_txs, true);
        assert_eq!(no_txs.txs, Vec::<bitcoin_rs_primitives::Tx>::new());

        let mut no_inputs = commitment_block(Vec::new(), true);
        no_inputs.txs[0].inputs.clear();
        assert!(!needs_witness_reserved_value(&no_inputs, true));
        update_uncommitted_block_structures(&mut no_inputs, true);
        assert_eq!(
            no_inputs.txs[0].inputs,
            Vec::<bitcoin_rs_primitives::TxIn>::new()
        );
    }

    #[test]
    fn reserved_nonce_fills_only_an_empty_witness_under_a_commitment() {
        let custom = vec![vec![0x11; 32]];
        let reserved = vec![WITNESS_RESERVED_VALUE.to_vec()];
        for (witness, with_commitment, segwit_active, want) in [
            (Vec::new(), true, true, reserved),
            (custom.clone(), true, true, custom.clone()),
            (Vec::new(), false, true, Vec::new()),
            (Vec::new(), true, false, Vec::new()),
            (custom.clone(), false, true, custom),
        ] {
            let mut block = commitment_block(witness, with_commitment);
            update_uncommitted_block_structures(&mut block, segwit_active);
            assert_eq!(
                block.txs[0].inputs[0].witness,
                Witness::from_stack(want.clone()),
                "commitment={with_commitment} segwit={segwit_active} want={want:?}"
            );
        }
    }
}
