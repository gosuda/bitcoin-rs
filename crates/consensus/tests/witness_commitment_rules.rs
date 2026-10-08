//! BIP141 witness-commitment rules at both exported block entries.
//!
//! Independent references: BIP141 commitment structure and Bitcoin Core v31.0
//! `CheckWitnessMalleation` / `CheckBlock`. The staging gate
//! (`check_block_body_binding`, issue #1070) and the block-rule entry must
//! agree on every witness/commitment/activation shape, so one table pins both.
//! Fixtures isolate block witness rules; they are not mined or UTXO-valid.

use bitcoin_rs_consensus::verify_block::{
    BlockRuleContext, verify_block_rules, verify_block_rules_precomputed,
};
use bitcoin_rs_consensus::{
    BlockFacts, BlockView, ConsensusError, check_block_body_binding, compute_merkle_root,
};
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

fn coinbase(witness: bool, commitment: Option<[u8; 32]>) -> Tx {
    let mut tx = Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![1, 1]),
            sequence: Sequence::MAX,
            witness: if witness {
                Witness::from_stack(vec![vec![0; 32]])
            } else {
                Witness::new()
            },
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::ZERO,
    };
    if let Some(commitment) = commitment {
        tx.outputs.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: Script::from_bytes([PREFIX.as_slice(), &commitment].concat()),
        });
    }
    tx
}

fn block(txs: Vec<Tx>, merkle_root: Hash256) -> Block {
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root,
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs,
    }
}

fn single(tx: Tx) -> Block {
    let root = tx.txid().into();
    block(vec![tx], root)
}

/// The block-rule entry under an explicit activation context; the active
/// context goes through the context-free default entry.
fn rules(block: &Block, segwit_active: bool) -> Result<(), ConsensusError> {
    if segwit_active {
        return verify_block_rules(block);
    }
    let txids = block.txs.iter().map(Tx::txid).collect();
    let mut view = BlockView::from_facts(&block.txs, BlockFacts::from_txids(&block.txs, txids));
    if view.facts().has_witness() {
        let _ = view.witness_ids();
    }
    verify_block_rules_precomputed(block, BlockRuleContext { segwit_active }, view.facts())
}

#[test]
fn staging_gate_and_block_rules_agree_on_witness_commitment_shapes() {
    use ConsensusError::{UnexpectedWitness, WitnessCommitment, WitnessNonceSize};
    let zero = Some(ZERO_RESERVED_COMMITMENT);
    // (coinbase witness, commitment, segwit active, verdict at both entries)
    let cases = [
        // A peer stripped the reserved value from a committed coinbase.
        (false, zero, true, Err(WitnessNonceSize)),
        (true, Some([0xff; 32]), true, Err(WitnessCommitment)),
        (true, zero, true, Ok(())),
        (false, None, true, Ok(())),
        // Injected witness without a commitment keeps the txid and block hash.
        (true, None, true, Err(UnexpectedWitness)),
        // Pre-activation a commitment-like output is not enforced (P1-1) and
        // never authorizes witness data.
        (false, zero, false, Ok(())),
        (true, zero, false, Err(UnexpectedWitness)),
        (true, None, false, Err(UnexpectedWitness)),
    ];
    for (witness, commitment, active, expected) in cases {
        let block = single(coinbase(witness, commitment));
        let shape = format!("witness={witness} commitment={commitment:?} active={active}");
        assert_eq!(
            check_block_body_binding(&block, active),
            expected,
            "gate {shape}"
        );
        assert_eq!(rules(&block, active), expected, "rules {shape}");
    }
}

#[test]
fn witness_without_commitment_is_unexpected_even_outside_coinbase() {
    let txs = vec![
        coinbase(false, None),
        Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256::from_le_bytes(&[1; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![1]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::new(),
            }],
        },
    ];
    let mut leaves = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    let Some(root) = compute_merkle_root(&mut leaves) else {
        panic!("two transactions must have a Merkle root");
    };
    let block = block(txs, Hash256::from_le_bytes(&root));
    for active in [false, true] {
        assert_eq!(
            check_block_body_binding(&block, active),
            Err(ConsensusError::UnexpectedWitness)
        );
        assert_eq!(
            rules(&block, active),
            Err(ConsensusError::UnexpectedWitness)
        );
    }
}

/// A peer cannot replace non-witness transaction bytes while retaining the
/// valid header: the changed txid no longer matches the header Merkle root.
#[test]
fn altered_non_witness_transaction_is_rejected() {
    let mut malformed = single(coinbase(false, None));
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
    let tx = coinbase(false, None);
    let mut leaves = vec![*tx.txid().as_bytes(); 2];
    let Some(root) = compute_merkle_root(&mut leaves) else {
        panic!("two leaves must have a Merkle root");
    };
    let mutated = block(vec![tx.clone(), tx], Hash256::from_le_bytes(&root));
    assert_eq!(
        check_block_body_binding(&mutated, true),
        Err(ConsensusError::MerkleMutation)
    );
}
