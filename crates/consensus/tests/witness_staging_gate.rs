//! Body/header binding regressions for `check_block_body_binding`.
//!
//! Independent reference: BIP141 commitment structure and Bitcoin Core v31.0
//! `CheckWitnessMalleation` and `CheckBlock`. These fixtures isolate the
//! staging-time gate that prevents a peer from wedging sync by sending a body
//! that does not bind to its header (issue #1070). They are not mined or
//! UTXO-valid chain fixtures.

use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_consensus::{check_block_body_binding, compute_merkle_root};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness,
};

const PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
// SHA256d(00*32 || 00*32): coinbase-only witness root and zero reserved value.
const ZERO_RESERVED_COMMITMENT: [u8; 32] = [
    0xe2, 0xf6, 0x1c, 0x3f, 0x71, 0xd1, 0xde, 0xfd, 0x3f, 0xa9, 0x99, 0xdf, 0xa3, 0x69, 0x53, 0x75,
    0x5c, 0x69, 0x06, 0x89, 0x79, 0x99, 0x62, 0xb4, 0x8b, 0xeb, 0xd8, 0x36, 0x97, 0x4e, 0x8c, 0xf9,
];

fn commitment_output(value: [u8; 32]) -> TxOut {
    let mut script_pubkey = PREFIX.to_vec();
    script_pubkey.extend_from_slice(&value);
    TxOut {
        value: Amount::from_sat(0),
        script_pubkey: Script::from_bytes(script_pubkey),
    }
}

fn coinbase(witness: Option<Vec<Vec<u8>>>, commitment: Option<[u8; 32]>) -> Tx {
    let mut tx = Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(vec![1, 1]),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: witness.map_or_else(Witness::new, Witness::from_stack),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    if let Some(commitment) = commitment {
        tx.outputs.push(commitment_output(commitment));
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
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs: vec![tx],
    }
}

/// (a) A block with a BIP141 commitment but a witness-stripped coinbase
/// must be rejected: the peer removed the witness, and the stager must not
/// keep this body.
#[test]
fn commitment_block_with_stripped_witness_is_rejected() {
    let block = block(coinbase(None, Some(ZERO_RESERVED_COMMITMENT)));
    assert_eq!(
        check_block_body_binding(&block, true),
        Err(ConsensusError::WitnessNonceSize)
    );
}

/// (b) A block with a well-formed coinbase witness (1×32B) but a commitment
/// that does not match the computed witness merkle root must be rejected.
#[test]
fn commitment_block_with_mismatched_commitment_is_rejected() {
    let wrong_commitment = [0xFF; 32];
    let block = block(coinbase(Some(vec![vec![0; 32]]), Some(wrong_commitment)));
    assert_eq!(
        check_block_body_binding(&block, true),
        Err(ConsensusError::WitnessCommitment)
    );
}

/// (c) A block with a BIP141 commitment and a matching coinbase witness
/// passes the staging gate.
#[test]
fn commitment_block_with_correct_witness_passes() {
    let block = block(coinbase(
        Some(vec![vec![0; 32]]),
        Some(ZERO_RESERVED_COMMITMENT),
    ));
    assert_eq!(check_block_body_binding(&block, true), Ok(()));
}

/// (d) A block without a BIP141 commitment or witness data passes the staging
/// gate.
#[test]
fn block_without_commitment_passes() {
    let block = block(coinbase(None, None));
    assert_eq!(check_block_body_binding(&block, true), Ok(()));
}

/// (e) A pre-segwit block with a commitment-like output and no witness must
/// pass the gate. Before segwit activation the commitment is not enforced,
/// so a coincidental `6a24aa21a9ed` output must not trigger a witness-nonce
/// check that the apply path would not perform (P1-1 regression).
#[test]
fn commitment_output_pre_segwit_without_witness_passes() {
    let block = block(coinbase(None, Some(ZERO_RESERVED_COMMITMENT)));
    assert_eq!(check_block_body_binding(&block, false), Ok(()));
}

/// (f) A block without a commitment but with injected witness data must be
/// rejected as unexpected-witness. A malicious peer can add bogus witness
/// to a non-witness transaction without changing the txid or block hash, so
/// the gate must catch this before staging (P1-2 regression).
#[test]
fn no_commitment_with_injected_witness_is_rejected() {
    let block = block(coinbase(Some(vec![vec![0; 32]]), None));
    assert_eq!(
        check_block_body_binding(&block, true),
        Err(ConsensusError::UnexpectedWitness)
    );
}

/// A peer cannot replace non-witness transaction bytes while retaining the
/// valid header. The changed txid no longer matches the header Merkle root.
#[test]
fn altered_non_witness_transaction_is_rejected() {
    let mut malformed = block(coinbase(None, None));
    let expected_hash = malformed.block_hash();
    malformed.txs[0].outputs[0].value = Amount::from_sat(49);
    assert_eq!(malformed.block_hash(), expected_hash);

    assert_eq!(
        check_block_body_binding(&malformed, true),
        Err(ConsensusError::MerkleRoot)
    );
}

/// A matching but ambiguous transaction-ID tree is rejected before staging.
#[test]
fn merkle_mutation_is_rejected() {
    let tx = coinbase(None, None);
    let mut leaves = vec![*tx.txid().as_bytes(); 2];
    let Some(root) = compute_merkle_root(&mut leaves) else {
        panic!("two leaves must have a Merkle root");
    };
    let mutated = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::from_le_bytes(&root),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs: vec![tx.clone(), tx],
    };

    assert_eq!(
        check_block_body_binding(&mutated, true),
        Err(ConsensusError::MerkleMutation)
    );
}
