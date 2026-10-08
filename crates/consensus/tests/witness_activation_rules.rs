//! BIP141 activation in block rules and staging, per Core v31.0
//! `CheckWitnessMalleation` / `CheckBlock`; fixtures are not mined chain blocks.

use bitcoin_rs_consensus::block_view::BlockView;
use bitcoin_rs_consensus::verify_block::{
    BlockRuleContext, verify_block_rules, verify_block_rules_precomputed,
};
use bitcoin_rs_consensus::{ConsensusError, check_block_body_binding, compute_merkle_root};
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

fn coinbase(witness: Option<Vec<u8>>, commitment: Option<[u8; 32]>) -> Tx {
    let mut tx = Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(vec![1, 1]),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: witness.map_or_else(Witness::new, |item| Witness::from_stack(vec![item])),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    if let Some(commitment) = commitment {
        tx.outputs.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: Script::from_bytes([PREFIX.as_slice(), &commitment].concat()),
        });
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

/// (coinbase witness item, commitment, segwit active, verdict)
type Case<C> = (Option<Vec<u8>>, C, bool, Result<(), ConsensusError>);

fn rules_verdict(block: &Block, segwit_active: bool) -> Result<(), ConsensusError> {
    let txids = block.txs.iter().map(Tx::txid).collect();
    let mut view = BlockView::new(&block.txs, txids);
    if view.facts().has_witness() {
        let _ = view.witness_ids();
    }
    verify_block_rules_precomputed(block, BlockRuleContext { segwit_active }, view.facts())
}

#[test]
fn block_rules_bind_witness_data_to_an_activated_commitment() {
    let reserved = vec![0u8; 32];
    let cases: [Case<bool>; 8] = [
        (None, false, false, Ok(())),
        (None, false, true, Ok(())),
        (None, true, false, Ok(())),
        (None, true, true, Err(ConsensusError::WitnessNonceSize)),
        (
            Some(reserved.clone()),
            false,
            false,
            Err(ConsensusError::UnexpectedWitness),
        ),
        (
            Some(reserved.clone()),
            true,
            false,
            Err(ConsensusError::UnexpectedWitness),
        ),
        (Some(reserved), true, true, Ok(())),
        // A commitment with a wrong-width reserved nonce is not a nonce.
        (
            Some(vec![0u8; 31]),
            true,
            true,
            Err(ConsensusError::WitnessNonceSize),
        ),
    ];
    for (witness, commitment, segwit_active, expected) in cases {
        let label = format!("witness {witness:?} commitment {commitment} active {segwit_active}");
        let commitment = commitment.then_some(ZERO_RESERVED_COMMITMENT);
        let block = block(coinbase(witness, commitment));
        assert_eq!(rules_verdict(&block, segwit_active), expected, "{label}");
        if segwit_active {
            assert_eq!(verify_block_rules(&block), expected, "{label}");
        }
    }
    // Witness data with no commitment is unexpected even once segwit is active.
    let block = block(coinbase(Some(vec![0u8; 32]), None));
    assert_eq!(
        rules_verdict(&block, true),
        Err(ConsensusError::UnexpectedWitness)
    );
}

/// The staging gate must reach the same witness verdicts as the apply path and
/// additionally bind the commitment to the witness Merkle root, so a peer can
/// neither strip nor forge witness data behind a valid header.
#[test]
fn the_staging_gate_binds_the_commitment_to_the_witness_root() {
    let reserved = vec![0u8; 32];
    let cases: [Case<Option<[u8; 32]>>; 7] = [
        (None, None, true, Ok(())),
        (
            None,
            Some(ZERO_RESERVED_COMMITMENT),
            true,
            Err(ConsensusError::WitnessNonceSize),
        ),
        // Before activation a coincidental `6a24aa21a9ed` output must not
        // trigger a witness-nonce check the apply path would not perform.
        (None, Some(ZERO_RESERVED_COMMITMENT), false, Ok(())),
        (
            Some(reserved.clone()),
            None,
            true,
            Err(ConsensusError::UnexpectedWitness),
        ),
        (
            Some(reserved.clone()),
            Some([0xff; 32]),
            true,
            Err(ConsensusError::WitnessCommitment),
        ),
        (Some(reserved), Some(ZERO_RESERVED_COMMITMENT), true, Ok(())),
        (
            Some(vec![0u8; 33]),
            Some(ZERO_RESERVED_COMMITMENT),
            true,
            Err(ConsensusError::WitnessNonceSize),
        ),
    ];
    for (witness, commitment, segwit_active, expected) in cases {
        let label = format!("witness {witness:?} commitment {commitment:?} active {segwit_active}");
        let block = block(coinbase(witness, commitment));
        assert_eq!(
            check_block_body_binding(&block, segwit_active),
            expected,
            "{label}"
        );
    }
}

/// A peer cannot swap non-witness transaction bytes under a valid header: the
/// changed txid no longer matches the header Merkle root, and an ambiguous
/// duplicate-tail tree is refused before staging.
#[test]
fn the_staging_gate_rejects_rebodied_and_ambiguous_merkle_trees() {
    let mut malformed = block(coinbase(None, None));
    let expected_hash = malformed.block_hash();
    malformed.txs[0].outputs[0].value = Amount::from_sat(49);
    assert_eq!(malformed.block_hash(), expected_hash);
    assert_eq!(
        check_block_body_binding(&malformed, true),
        Err(ConsensusError::MerkleRoot)
    );

    let tx = coinbase(None, None);
    let mut leaves = vec![*tx.txid().as_bytes(); 2];
    let Some(root) = compute_merkle_root(&mut leaves) else {
        panic!("two leaves must have a Merkle root");
    };
    let mut mutated = block(tx.clone());
    mutated.header.merkle_root = Hash256::from_le_bytes(&root);
    mutated.txs.push(tx);
    assert_eq!(
        check_block_body_binding(&mutated, true),
        Err(ConsensusError::MerkleMutation)
    );
}
