use bitcoin::Txid;
use bitcoin::Weight;
use bitcoin::consensus::Encodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::Block;

use crate::ConsensusError;
use crate::sha256d64::{Avx2Sha256d64, detect_avx2};

/// Context needed for block rules whose activation is height-dependent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRuleContext {
    /// Whether BIP141 segwit block rules are active for the candidate block.
    pub segwit_active: bool,
}

impl BlockRuleContext {
    /// Conservative non-contextual mode: enforce checks from active softforks.
    #[must_use]
    pub const fn non_contextual() -> Self {
        Self {
            segwit_active: true,
        }
    }
}

/// Verifies non-contextual block rules that do not require a UTXO set.
pub fn verify_block_rules(block: &Block) -> Result<(), ConsensusError> {
    let txids: Vec<Txid> = block
        .0
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect();
    let has_witness = block_has_witness(&block.0);
    verify_block_rules_precomputed(
        &block.0,
        BlockRuleContext::non_contextual(),
        &txids,
        has_witness,
    )
}

/// Verifies block rules for callers that already hold the transaction IDs
/// and witness presence, such as the node hot path.
///
/// Performs no allocation or hashing beyond the existing rule implementation.
pub fn verify_block_rules_precomputed(
    block: &bitcoin::Block,
    context: BlockRuleContext,
    txids: &[Txid],
    has_witness: bool,
) -> Result<(), ConsensusError> {
    debug_assert_eq!(has_witness, block_has_witness(block));
    let txdata = &block.txdata;
    if txdata.is_empty() {
        return Err(ConsensusError::EmptyBlock);
    }
    if txids.len() != txdata.len() {
        return Err(ConsensusError::MerkleRoot);
    }
    if !txdata[0].is_coinbase() {
        return Err(ConsensusError::MissingCoinbase);
    }
    for (tx_index, tx) in txdata.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(ConsensusError::ExtraCoinbase { tx_index });
        }
    }
    verify_merkle_root_with_txids(block, txids)?;
    if context.segwit_active && has_witness && !block.check_witness_commitment() {
        return Err(ConsensusError::WitnessCommitment);
    }
    let weight = block.weight().to_wu();
    let max = Weight::MAX_BLOCK.to_wu();
    if weight > max {
        return Err(ConsensusError::BlockWeight { weight, max });
    }
    Ok(())
}

fn block_has_witness(block: &bitcoin::Block) -> bool {
    block
        .txdata
        .iter()
        .any(|tx| tx.input.iter().any(|input| !input.witness.is_empty()))
}

/// Verifies the header Merkle root and rejects mutated Merkle trees.
///
/// `txids` must contain one transaction ID per block transaction in block order.
///
/// # Errors
///
/// Returns [`ConsensusError::MerkleRoot`] for an empty or mismatched tree and
/// [`ConsensusError::MerkleMutation`] when duplicate branches make the tree
/// ambiguous.
pub fn verify_merkle_root_with_txids(
    block: &bitcoin::Block,
    txids: &[bitcoin::Txid],
) -> Result<(), ConsensusError> {
    let mut hashes = txids.to_vec();
    let Some((root, mutated)) = merkle_root_and_mutation(&mut hashes)? else {
        return Err(ConsensusError::MerkleRoot);
    };
    if block.header.merkle_root != root.into() {
        return Err(ConsensusError::MerkleRoot);
    }
    if mutated {
        return Err(ConsensusError::MerkleMutation);
    }
    Ok(())
}

/// Root-only precheck for the hot windowed apply path.
///
/// Computes the merkle root from caller-supplied transaction IDs and compares
/// it to the block header. Mutation is intentionally ignored here; the later
/// consensus path owns the mutation check and its error precedence.
///
/// On a nonempty successful reduction the mutable `txids` scratch buffer is
/// consumed and reduced in place to a single element (the root). Returns
/// `false` for empty input, encoding failure, or a root that does not match
/// the block header's merkle root.
#[doc(hidden)]
pub fn block_merkle_root_matches_txids(block: &bitcoin::Block, txids: &mut Vec<Txid>) -> bool {
    match merkle_root_and_mutation(txids) {
        Ok(Some((root, _))) => block.header.merkle_root == root.into(),
        _ => false,
    }
}

fn merkle_root_and_mutation(
    hashes: &mut Vec<Txid>,
) -> Result<Option<(Txid, bool)>, ConsensusError> {
    if hashes.is_empty() {
        return Ok(None);
    }
    if hashes.len() == 1 {
        return Ok(Some((hashes[0], false)));
    }
    let kernel = detect_avx2();
    let mut mutated = false;
    while hashes.len() > 1 {
        mutated |= hashes.chunks_exact(2).any(|pair| pair[0] == pair[1]);
        next_merkle_level(hashes, kernel.as_ref())?;
    }
    Ok(Some((hashes[0], mutated)))
}

fn next_merkle_level(
    level: &mut Vec<Txid>,
    kernel: Option<&Avx2Sha256d64>,
) -> Result<(), ConsensusError> {
    let original_len = level.len();
    let new_len = original_len.div_ceil(2);
    let pair_count = original_len / 2;

    if let Some(kernel) = kernel {
        let mut input = [[0u8; 64]; 8];
        let mut output = [[0u8; 32]; 8];
        let mut idx = 0;
        while idx + 8 <= pair_count {
            for lane in 0..8 {
                let left = level[2 * (idx + lane)].as_byte_array();
                let right = level[2 * (idx + lane) + 1].as_byte_array();
                input[lane][0..32].copy_from_slice(left.as_slice());
                input[lane][32..64].copy_from_slice(right.as_slice());
            }
            kernel.transform_8way(&input, &mut output);
            for lane in 0..8 {
                level[idx + lane] = Txid::from_byte_array(output[lane]);
            }
            idx += 8;
        }
    }

    let start = if kernel.is_some() {
        (pair_count / 8) * 8
    } else {
        0
    };
    for pos in start..new_len {
        let left = level[2 * pos];
        let right = level[(2 * pos + 1).min(original_len - 1)];
        let mut encoder = Txid::engine();
        left.consensus_encode(&mut encoder)
            .map_err(|error| ConsensusError::Encoding(error.to_string()))?;
        right
            .consensus_encode(&mut encoder)
            .map_err(|error| ConsensusError::Encoding(error.to_string()))?;
        level[pos] = Txid::from_engine(encoder);
    }
    level.truncate(new_len);
    Ok(())
}

#[cfg(test)]
/// Scalar oracle used by the reducer test suite.
fn merkle_root_and_mutation_scalar(
    hashes: &mut Vec<Txid>,
) -> Result<Option<(Txid, bool)>, ConsensusError> {
    if hashes.is_empty() {
        return Ok(None);
    }
    let mut mutated = false;
    while hashes.len() > 1 {
        mutated |= hashes.chunks_exact(2).any(|pair| pair[0] == pair[1]);
        next_merkle_level_scalar(hashes)?;
    }
    Ok(Some((hashes[0], mutated)))
}

#[cfg(test)]
fn next_merkle_level_scalar(level: &mut Vec<Txid>) -> Result<(), ConsensusError> {
    let original_len = level.len();
    for idx in 0..original_len.div_ceil(2) {
        let left = level[2 * idx];
        let right = level[(2 * idx + 1).min(original_len - 1)];
        let mut encoder = Txid::engine();
        left.consensus_encode(&mut encoder)
            .map_err(|error| ConsensusError::Encoding(error.to_string()))?;
        right
            .consensus_encode(&mut encoder)
            .map_err(|error| ConsensusError::Encoding(error.to_string()))?;
        level[idx] = Txid::from_engine(encoder);
    }
    level.truncate(original_len.div_ceil(2));
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness, absolute, block, transaction,
    };
    use bitcoin_rs_primitives::Block;

    use super::{
        BlockRuleContext, block_has_witness, block_merkle_root_matches_txids,
        merkle_root_and_mutation, merkle_root_and_mutation_scalar, verify_block_rules,
        verify_block_rules_precomputed, verify_merkle_root_with_txids,
    };
    use crate::ConsensusError;
    use crate::sha256d64::detect_avx2;

    #[test]
    fn valid_single_coinbase_block_passes() {
        let block = Block(bitcoin::Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![coinbase_tx()],
        });
        let mut fixed = block;
        let Some(root) = fixed.0.compute_merkle_root() else {
            panic!("single coinbase block should have merkle root");
        };
        fixed.0.header.merkle_root = root;
        assert_eq!(verify_block_rules(&fixed), Ok(()));
    }

    #[test]
    fn missing_coinbase_is_rejected() {
        let tx = Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let block = Block(bitcoin::Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![tx],
        });
        assert_eq!(
            verify_block_rules(&block),
            Err(ConsensusError::MissingCoinbase)
        );
    }

    #[test]
    fn contextual_rules_skip_bip141_commitment_before_segwit_activation() {
        let block = block_with_transactions(vec![coinbase_tx(), witness_spend_tx()]);

        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: false,
                },
            ),
            Ok(())
        );
    }

    #[test]
    fn contextual_rules_enforce_bip141_commitment_after_segwit_activation() {
        let block = block_with_transactions(vec![coinbase_tx(), witness_spend_tx()]);

        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: true,
                },
            ),
            Err(ConsensusError::WitnessCommitment)
        );
    }

    #[test]
    fn contextual_rules_always_enforce_block_weight_limit() {
        let mut coinbase = coinbase_tx();
        coinbase.input[0].script_sig = ScriptBuf::from_bytes(vec![1; 1_000_001]);
        let block = block_with_transactions(vec![coinbase]);

        assert!(matches!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: false,
                },
            ),
            Err(ConsensusError::BlockWeight { .. })
        ));
        assert!(matches!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: true,
                },
            ),
            Err(ConsensusError::BlockWeight { .. })
        ));
    }

    #[test]
    fn duplicate_transaction_ids_are_rejected_even_with_matching_merkle_root() {
        let tx = spend_tx(0x03);
        let block = block_with_transactions(vec![coinbase_tx(), spend_tx(0x02), tx.clone(), tx]);

        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: false,
                },
            ),
            Err(ConsensusError::MerkleMutation)
        );
    }

    #[test]
    fn duplicate_transaction_ids_without_merkle_mutation_reach_later_validation() {
        let tx = spend_tx(0x04);
        let distinct = spend_tx(0x05);
        let block = block_with_transactions(vec![coinbase_tx(), tx.clone(), distinct, tx]);

        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: false,
                },
            ),
            Ok(())
        );
    }

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn witness_spend_tx() -> Transaction {
        let mut witness = Witness::new();
        witness.push(vec![1; 32]);
        Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([2; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn spend_tx(seed: u8) -> Transaction {
        Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([seed; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn block_with_transactions(txdata: Vec<Transaction>) -> Block {
        let mut block = Block(bitcoin::Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata,
        });
        let Some(root) = block.0.compute_merkle_root() else {
            panic!("block should have merkle root");
        };
        block.0.header.merkle_root = root;
        block
    }
    fn check_block_rules(block: &Block, context: BlockRuleContext) -> Result<(), ConsensusError> {
        let txids: Vec<Txid> = block
            .0
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect();
        let has_witness = block_has_witness(&block.0);
        verify_block_rules_precomputed(&block.0, context, &txids, has_witness)
    }

    fn txid(seed: u8) -> Txid {
        Txid::from_byte_array([seed; 32])
    }

    fn txids(count: usize) -> Vec<Txid> {
        (0..count)
            .map(|seed| match u8::try_from(seed) {
                Ok(seed) => txid(seed),
                Err(error) => panic!("test leaf count must fit u8: {error}"),
            })
            .collect()
    }

    fn candidate_merkle(hashes: &mut Vec<Txid>) -> Option<(Txid, bool)> {
        match merkle_root_and_mutation(hashes) {
            Ok(result) => result,
            Err(error) => panic!("candidate Merkle reduction failed: {error}"),
        }
    }

    fn scalar_merkle(hashes: &mut Vec<Txid>) -> Option<(Txid, bool)> {
        match merkle_root_and_mutation_scalar(hashes) {
            Ok(result) => result,
            Err(error) => panic!("scalar Merkle reduction failed: {error}"),
        }
    }

    fn candidate_merkle_nonempty(hashes: &mut Vec<Txid>) -> (Txid, bool) {
        match candidate_merkle(hashes) {
            Some(result) => result,
            None => panic!("test Merkle tree must be nonempty"),
        }
    }

    fn scalar_merkle_nonempty(hashes: &mut Vec<Txid>) -> (Txid, bool) {
        match scalar_merkle(hashes) {
            Some(result) => result,
            None => panic!("test Merkle tree must be nonempty"),
        }
    }

    /// Reports whether `candidate_merkle` dispatches to the AVX2 or scalar
    /// `SHA256d` backend. Does not assert AVX2 availability — scalar-only hosts
    /// and generic runners remain supported.
    fn candidate_reducer_backend() -> &'static str {
        if detect_avx2().is_some() {
            "avx2"
        } else {
            "scalar"
        }
    }

    #[test]
    fn avx2_matches_scalar_for_all_leaf_counts_0_to_129() {
        eprintln!(
            "avx2_matches_scalar_for_all_leaf_counts_0_to_129: candidate reducer backend = {}",
            candidate_reducer_backend()
        );
        for leaf_count in 0..=129 {
            let txids = txids(leaf_count);
            let mut avx = txids.clone();
            let mut scalar = txids;
            let avx_result = candidate_merkle(&mut avx);
            let scalar_result = scalar_merkle(&mut scalar);
            assert_eq!(avx_result, scalar_result, "leaf count {leaf_count}");
        }
    }

    #[test]
    fn lane_boundary_pairs_seven_and_eight() {
        eprintln!(
            "lane_boundary_pairs_seven_and_eight: candidate reducer backend = {}",
            candidate_reducer_backend()
        );
        for leaf_count in [14, 15, 16, 17, 31, 32, 33] {
            let txids = txids(leaf_count);
            let mut avx = txids.clone();
            let mut scalar = txids;
            assert_eq!(
                candidate_merkle(&mut avx),
                scalar_merkle(&mut scalar),
                "leaf count {leaf_count}"
            );
        }
    }

    #[test]
    fn nonadjacent_duplicates_are_not_mutated() {
        eprintln!(
            "nonadjacent_duplicates_are_not_mutated: candidate reducer backend = {}",
            candidate_reducer_backend()
        );
        let a = txid(1);
        let b = txid(2);

        // [A, B, A]
        for input in [vec![a, b, a], vec![a, b, b, a]] {
            let mut avx = input.clone();
            let mut scalar = input;
            let (root, mutated) = candidate_merkle_nonempty(&mut avx);
            let (scalar_root, scalar_mutated) = scalar_merkle_nonempty(&mut scalar);
            assert!(!mutated, "non-adjacent duplicate must not mutate");
            assert_eq!(root, scalar_root);
            assert_eq!(mutated, scalar_mutated);
        }
    }

    #[test]
    fn synthetic_odd_duplicate_distinguishes_padding_from_mutation() {
        eprintln!(
            "synthetic_odd_duplicate_distinguishes_padding_from_mutation: candidate reducer backend = {}",
            candidate_reducer_backend()
        );
        let a = txid(1);
        let b = txid(2);

        // [A, B, B] (3 leaves) -- the trailing B is an odd duplicate and is padding.
        let mut avx = vec![a, b, b];
        let mut scalar = avx.clone();
        let (root, mutated) = candidate_merkle_nonempty(&mut avx);
        let (scalar_root, scalar_mutated) = scalar_merkle_nonempty(&mut scalar);
        assert!(!mutated, "odd self-pair is not a mutation");
        assert_eq!(root, scalar_root);
        assert_eq!(mutated, scalar_mutated);

        // [A, B, B, B] (4 leaves) -- positions 2 and 3 are a real duplicate pair.
        let mut avx = vec![a, b, b, b];
        let mut scalar = avx.clone();
        let (root, mutated) = candidate_merkle_nonempty(&mut avx);
        let (scalar_root, scalar_mutated) = scalar_merkle_nonempty(&mut scalar);
        assert!(mutated, "real adjacent duplicate must mutate");
        assert_eq!(root, scalar_root);
        assert_eq!(mutated, scalar_mutated);
    }

    #[test]
    fn core_ambiguous_six_leaf_tree_vs_duplicated_tail() {
        eprintln!(
            "core_ambiguous_six_leaf_tree_vs_duplicated_tail: candidate reducer backend = {}",
            candidate_reducer_backend()
        );
        // Core test vector: [1..6] and [1..6, 5, 6] share a root but only the
        // duplicated version is mutated.
        let one_to_six: Vec<Txid> = (1u8..=6).map(txid).collect();
        let one_to_six_duplicated: Vec<Txid> = (1u8..=6).chain([5, 6]).map(txid).collect();

        let mut avx_six = one_to_six.clone();
        let mut scalar_six = one_to_six;
        let (root_six, mutated_six) = candidate_merkle_nonempty(&mut avx_six);
        let (scalar_root_six, scalar_mutated_six) = scalar_merkle_nonempty(&mut scalar_six);
        assert!(!mutated_six);
        assert_eq!(root_six, scalar_root_six);
        assert_eq!(mutated_six, scalar_mutated_six);

        let mut avx_dup = one_to_six_duplicated.clone();
        let mut scalar_dup = one_to_six_duplicated;
        let (root_dup, mutated_dup) = candidate_merkle_nonempty(&mut avx_dup);
        let (scalar_root_dup, scalar_mutated_dup) = scalar_merkle_nonempty(&mut scalar_dup);
        assert!(mutated_dup, "duplicated tail must be mutated");
        assert_eq!(root_dup, scalar_root_dup);
        assert_eq!(mutated_dup, scalar_mutated_dup);

        // Roots match despite the mutation flag.
        assert_eq!(root_six, root_dup);
    }

    #[test]
    fn merkle_root_error_precedes_mutation_error() {
        // Two duplicate transactions give a valid merkle root but the block
        // header is wrong. The wrong root must be reported before the mutation.
        let a = txid(1);
        let txids = [a, a];
        let wrong_root = TxMerkleNode::from_byte_array([0xff; 32]);
        let block = Block(bitcoin::Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: wrong_root,
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![],
        });
        assert_eq!(
            verify_merkle_root_with_txids(&block.0, &txids),
            Err(ConsensusError::MerkleRoot),
            "wrong root must be reported before the duplicate mutation"
        );
    }

    #[test]
    fn missing_coinbase_precedes_merkle_mutation() {
        // A block with a duplicate transaction but no coinbase must fail on the
        // missing coinbase structural check before the merkle mutation path.
        let tx = Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut block = block_with_transactions(vec![tx.clone(), tx]);
        block.0.header.merkle_root = block
            .0
            .compute_merkle_root()
            .unwrap_or_else(TxMerkleNode::all_zeros);
        assert_eq!(
            verify_block_rules(&block),
            Err(ConsensusError::MissingCoinbase)
        );
    }

    #[test]
    fn block_merkle_root_matches_txids_ignores_mutation() {
        // The window precheck helper must return true for a matching root
        // even when the tree is mutated.
        let a = txid(1);
        let mut expected_hashes = vec![a, a];
        let (expected_root, _) = scalar_merkle_nonempty(&mut expected_hashes);
        let expected = TxMerkleNode::from(expected_root);
        let mut block = block_with_transactions(vec![coinbase_tx()]);
        block.0.header.merkle_root = expected;
        let mut check = vec![a, a];
        assert!(block_merkle_root_matches_txids(&block.0, &mut check));
    }
}
