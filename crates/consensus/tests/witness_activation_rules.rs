//! BIP141 activation/commitment regressions at the exported block-rule boundary.
//!
//! Independent references: BIP141 commitment structure and Bitcoin Core v31.0
//! `CheckWitnessMalleation`. These fixtures isolate block witness rules; they
//! are not mined or UTXO-valid chain fixtures.

use bitcoin_rs_consensus::block_view::BlockView;
use bitcoin_rs_consensus::verify_block::{
    BlockRuleContext, verify_block_rules, verify_block_rules_precomputed,
};
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_primitives::{Block, BlockHash, Header, OutPoint, Tx, TxIn, TxOut, Txid};

const PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
// SHA256d(00*32 || 00*32): coinbase-only witness root and zero reserved value.
const ZERO_RESERVED_COMMITMENT: [u8; 32] = [
    0xe2, 0xf6, 0x1c, 0x3f, 0x71, 0xd1, 0xde, 0xfd, 0x3f, 0xa9, 0x99, 0xdf, 0xa3, 0x69,
    0x53, 0x75, 0x5c, 0x69, 0x06, 0x89, 0x79, 0x99, 0x62, 0xb4, 0x8b, 0xeb, 0xd8, 0x36,
    0x97, 0x4e, 0x8c, 0xf9,
];

fn commitment_output() -> TxOut {
    let mut script_pubkey = PREFIX.to_vec();
    script_pubkey.extend_from_slice(&ZERO_RESERVED_COMMITMENT);
    TxOut {
        value: 0,
        script_pubkey,
    }
}

fn coinbase(with_witness: bool, with_commitment: bool) -> Tx {
    let mut tx = Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: vec![1, 1],
            sequence: u32::MAX,
            witness: if with_witness {
                vec![vec![0; 32]]
            } else {
                Vec::new()
            },
        }],
        outputs: vec![TxOut {
            value: 50,
            script_pubkey: Vec::new(),
        }],
        lock_time: 0,
    };
    if with_commitment {
        tx.outputs.push(commitment_output());
    }
    tx
}

fn block(tx: Tx) -> Block {
    let merkle_root = tx.txid().into();
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root,
            time: 0,
            bits: 0,
            nonce: 0,
        },
        txs: vec![tx],
    }
}

fn verify_with_activation(block: &Block, segwit_active: bool) -> Result<(), ConsensusError> {
    let txids = block.txs.iter().map(Tx::txid).collect();
    let mut view = BlockView::new(&block.txs, txids);
    if view.facts().has_witness() {
        let _ = view.witness_ids();
    }
    verify_block_rules_precomputed(block, BlockRuleContext { segwit_active }, view.facts())
}

#[test]
fn active_commitment_without_reserved_value_is_rejected() {
    let block = block(coinbase(false, true));
    assert_eq!(verify_block_rules(&block), Err(ConsensusError::WitnessCommitment));
}

#[test]
fn active_witness_free_block_without_commitment_is_valid_at_this_stage() {
    let block = block(coinbase(false, false));
    assert_eq!(verify_block_rules(&block), Ok(()));
}

#[test]
fn preactivation_witness_without_commitment_is_rejected() {
    let block = block(coinbase(true, false));
    assert_eq!(
        verify_with_activation(&block, false),
        Err(ConsensusError::WitnessCommitment)
    );
}

#[test]
fn preactivation_commitment_like_output_does_not_authorize_witness() {
    let block = block(coinbase(true, true));
    assert_eq!(
        verify_with_activation(&block, false),
        Err(ConsensusError::WitnessCommitment)
    );
}

#[test]
fn active_commitment_with_exact_reserved_value_is_valid_at_this_stage() {
    let block = block(coinbase(true, true));
    assert_eq!(verify_block_rules(&block), Ok(()));
}

#[test]
fn active_witness_without_commitment_is_rejected() {
    let block = block(coinbase(true, false));
    assert_eq!(verify_block_rules(&block), Err(ConsensusError::WitnessCommitment));
}
