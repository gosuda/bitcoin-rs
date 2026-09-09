use bitcoin_rs_primitives::{Block, Hash256, Tx, Txid, Wtxid, encode::double_sha256};

use crate::ConsensusError;
use crate::sha256d64::{self, Avx2Sha256d64, detect_avx2};

/// BIP141 witness commitment output prefix: `OP_RETURN` `OP_PUSHBYTES_36` `commitment_header`.
const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// Eight AVX2 lanes hash eight parent pairs, so a tree needs 16 leaves before
/// the batch kernel can issue work. Smaller trees stay on the spine.
const AVX2_MERKLE_MIN_LEAVES: usize = sha256d64::LANES * 2;

/// BIP141 maximum block weight in weight units.
const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

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
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    let has_witness = block_has_witness(block);
    let wtxids: Vec<Wtxid> = block.txs.iter().map(Tx::wtxid).collect();
    verify_block_rules_precomputed(
        block,
        BlockRuleContext::non_contextual(),
        &txids,
        &wtxids,
        has_witness,
    )
}

/// Verifies block rules for callers that already hold the transaction IDs,
/// witness transaction IDs, and witness presence, such as the node hot path.
///
/// `wtxids` must hold one witness ID per transaction in block order; callers
/// that computed them once for the witness-commitment check pass the cached
/// slice, so no stage re-serializes and re-hashes the block.
///
/// Performs no allocation or hashing beyond the existing rule implementation.
pub fn verify_block_rules_precomputed(
    block: &Block,
    context: BlockRuleContext,
    txids: &[Txid],
    wtxids: &[Wtxid],
    has_witness: bool,
) -> Result<(), ConsensusError> {
    debug_assert_eq!(has_witness, block_has_witness(block));
    let txdata = &block.txs;
    if txdata.is_empty() {
        return Err(ConsensusError::EmptyBlock);
    }
    if txids.len() != txdata.len() {
        return Err(ConsensusError::MerkleRoot);
    }
    if !is_coinbase(&txdata[0]) {
        return Err(ConsensusError::MissingCoinbase);
    }
    for (tx_index, tx) in txdata.iter().enumerate().skip(1) {
        if is_coinbase(tx) {
            return Err(ConsensusError::ExtraCoinbase { tx_index });
        }
    }
    verify_merkle_root_with_txids(block, txids)?;
    if context.segwit_active && has_witness {
        debug_assert_eq!(
            wtxids.len(),
            txdata.len(),
            "witness-carrying blocks need one cached wtxid per transaction"
        );
        if !block_witness_commitment_matches(block, wtxids) {
            return Err(ConsensusError::WitnessCommitment);
        }
    }
    let weight = block.weight();
    if weight > MAX_BLOCK_WEIGHT {
        return Err(ConsensusError::BlockWeight {
            weight,
            max: MAX_BLOCK_WEIGHT,
        });
    }
    Ok(())
}

/// Verifies the header Merkle root and rejects mutated Merkle trees.
///
/// `txids` must contain one transaction ID per block transaction in block
/// order. The slice is borrowed. Small trees and hosts without AVX2 reduce
/// through an O(log n) right-spine frontier; AVX2-capable hosts copy once
/// when the tree can fill an 8-lane SHA-256d batch.
///
/// # Errors
///
/// Returns [`ConsensusError::MerkleRoot`] for an empty or mismatched tree and
/// [`ConsensusError::MerkleMutation`] when duplicate branches make the tree
/// ambiguous. The root verdict always takes precedence over the mutation
/// verdict.
pub fn verify_merkle_root_with_txids(block: &Block, txids: &[Txid]) -> Result<(), ConsensusError> {
    let Some((root, mutated)) = merkle_root_and_mutation_borrowed(txids) else {
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
/// consensus path owns the mutation check and its error precedence. The slice
/// is borrowed and reduced through the same production walker as
/// [`verify_merkle_root_with_txids`].
#[doc(hidden)]
pub fn block_merkle_root_matches_txids(block: &Block, txids: &[Txid]) -> bool {
    match merkle_root_and_mutation_borrowed(txids) {
        Some((root, _)) => block.header.merkle_root == root.into(),
        None => false,
    }
}

/// Returns `true` when any transaction input carries witness data (Core's
/// `CBlock::HasWitness`).
pub fn block_has_witness(block: &Block) -> bool {
    block
        .txs
        .iter()
        .any(|tx| tx.inputs.iter().any(|input| !input.witness.is_empty()))
}

/// Returns `true` for the one-input, null-prevout coinbase shape.
fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1
        && tx.inputs[0].previous_output.txid == Txid::default()
        && tx.inputs[0].previous_output.vout == u32::MAX
}

/// Double-SHA256 over `left || right`, the Merkle parent of two nodes.
fn hash_merkle_pair(left: Txid, right: Txid) -> Txid {
    Txid(hash_merkle_bytes(left.as_bytes(), right.as_bytes()))
}

fn hash_merkle_bytes(left: &[u8; 32], right: &[u8; 32]) -> Hash256 {
    let mut pair = [0u8; 64];
    pair[..32].copy_from_slice(left);
    pair[32..].copy_from_slice(right);
    double_sha256(&pair)
}

/// Merkle reduction over borrowed leaves.
///
/// Trees that cannot fill one AVX2 batch, and hosts without AVX2, stream
/// leaves through [`merkle_root_spine`]. Trees with at least
/// [`AVX2_MERKLE_MIN_LEAVES`] on an AVX2 host copy once into the
/// level-synchronous 8-way reducer. Comparing two equal *real* adjacent nodes
/// at any level flags the tree as mutated; the odd leftover paired with its
/// duplicate-last copy never does.
fn merkle_root_and_mutation_borrowed(txids: &[Txid]) -> Option<(Txid, bool)> {
    if txids.len() >= AVX2_MERKLE_MIN_LEAVES && detect_avx2().is_some() {
        let mut hashes = txids.to_vec();
        return merkle_root_and_mutation(&mut hashes);
    }
    merkle_root_spine(txids)
}

/// Allocation-free scalar walker: one pending node per tree level, so scratch
/// is O(log n) and the caller's slice is neither cloned nor mutated.
fn merkle_root_spine(txids: &[Txid]) -> Option<(Txid, bool)> {
    if txids.is_empty() {
        return None;
    }
    // One pending node per level; u64::MAX leaves span 64 levels.
    let mut spine: [Option<Txid>; 64] = [None; 64];
    let mut mutated = false;
    for leaf in txids.iter().copied() {
        let mut current = leaf;
        let mut height = 0;
        while let Some(left) = spine[height] {
            spine[height] = None;
            if left == current {
                mutated = true;
            }
            current = hash_merkle_pair(left, current);
            height += 1;
        }
        spine[height] = Some(current);
    }
    // Fold the right spine bottom-up: the carry rises to each pending height
    // through duplicate-last self-pairs (never a mutation), then joins that
    // pending node as its right sibling.
    let mut carry: Option<(Txid, usize)> = None;
    for (height, slot) in spine.iter().enumerate() {
        let Some(node) = *slot else { continue };
        carry = Some(match carry {
            None => (node, height),
            Some((accumulated, accumulated_height)) => {
                let mut right = accumulated;
                let mut right_height = accumulated_height;
                while right_height < height {
                    right = hash_merkle_pair(right, right);
                    right_height += 1;
                }
                if node == right {
                    mutated = true;
                }
                (hash_merkle_pair(node, right), height + 1)
            }
        });
    }
    let Some((root, _)) = carry else {
        // Unreachable: the first leaf of non-empty input parks a node in the
        // spine, so the fold above ran at least once.
        return None;
    };
    Some((root, mutated))
}

fn merkle_root_and_mutation(hashes: &mut Vec<Txid>) -> Option<(Txid, bool)> {
    if hashes.is_empty() {
        return None;
    }
    if hashes.len() == 1 {
        return Some((hashes[0], false));
    }
    let kernel = detect_avx2();
    let mut mutated = false;
    while hashes.len() > 1 {
        mutated |= hashes.chunks_exact(2).any(|pair| pair[0] == pair[1]);
        next_merkle_level(hashes, kernel.as_ref());
    }
    Some((hashes[0], mutated))
}

fn next_merkle_level(level: &mut Vec<Txid>, kernel: Option<&Avx2Sha256d64>) {
    fold_parent_level(level, kernel, Txid::as_bytes, Txid::from);
}

fn next_bytes_level(level: &mut Vec<[u8; 32]>, kernel: Option<&Avx2Sha256d64>) {
    fold_parent_level(level, kernel, |node| node, Hash256::to_le_bytes);
}

fn fold_parent_level<T: Copy>(
    level: &mut Vec<T>,
    kernel: Option<&Avx2Sha256d64>,
    as_bytes: impl Fn(&T) -> &[u8; 32],
    from_hash: impl Fn(Hash256) -> T,
) {
    let original_len = level.len();
    let new_len = original_len.div_ceil(2);
    let pair_count = original_len / 2;
    let start = match kernel {
        Some(kernel) => hash_avx2_parent_batches(level, pair_count, kernel, &as_bytes, &from_hash),
        None => 0,
    };
    for pos in start..new_len {
        let left = as_bytes(&level[2 * pos]);
        let right = as_bytes(&level[(2 * pos + 1).min(original_len - 1)]);
        level[pos] = from_hash(hash_merkle_bytes(left, right));
    }
    level.truncate(new_len);
}

fn hash_avx2_parent_batches<T: Copy>(
    level: &mut [T],
    pair_count: usize,
    kernel: &Avx2Sha256d64,
    as_bytes: impl Fn(&T) -> &[u8; 32],
    from_hash: impl Fn(Hash256) -> T,
) -> usize {
    let mut input = [[0u8; 64]; sha256d64::LANES];
    let mut output = [[0u8; 32]; sha256d64::LANES];
    let mut idx = 0;
    while idx + sha256d64::LANES <= pair_count {
        for lane in 0..sha256d64::LANES {
            let left = as_bytes(&level[2 * (idx + lane)]);
            let right = as_bytes(&level[2 * (idx + lane) + 1]);
            input[lane][..32].copy_from_slice(left);
            input[lane][32..].copy_from_slice(right);
        }
        kernel.transform_8way(&input, &mut output);
        for lane in 0..sha256d64::LANES {
            level[idx + lane] = from_hash(Hash256::from_le_bytes(&output[lane]));
        }
        idx += sha256d64::LANES;
    }
    idx
}

/// BIP141 witness commitment verification over cached witness IDs.
///
/// Finds the last coinbase output matching the commitment prefix, extracts the
/// reserved value from the coinbase witness (must be exactly one 32-byte
/// element), builds the witness merkle tree (coinbase leaf = all-zeros), and
/// checks `SHA256d(witness_merkle_root || reserved) == commitment`.
///
/// `wtxids` must contain one witness ID per block transaction in block order;
/// computing them here would re-serialize and re-hash every transaction on a
/// path the node can already serve from its parse-once view.
pub fn block_witness_commitment_matches(block: &Block, wtxids: &[Wtxid]) -> bool {
    let Some(coinbase) = block.txs.first() else {
        return false;
    };
    // Highest matching output: iterate in reverse to find the last one.
    let Some(commitment) = coinbase
        .outputs
        .iter()
        .rev()
        .find(|output| {
            output.script_pubkey.len() >= 38
                && output.script_pubkey[..6] == WITNESS_COMMITMENT_PREFIX
        })
        .map(|output| &output.script_pubkey[6..38])
    else {
        return false;
    };
    // BIP141: coinbase witness must have exactly one 32-byte element (the reserved value).
    let Some(input) = coinbase.inputs.first() else {
        return false;
    };
    if input.witness.len() != 1 {
        return false;
    }
    let reserved = &input.witness[0];
    if reserved.len() != 32 {
        return false;
    }

    // Build witness merkle leaves: coinbase leaf is all-zero (its wtxid is zero per BIP141).
    if wtxids.len() != block.txs.len() {
        return false;
    }
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(block.txs.len());
    for (index, wtxid) in wtxids.iter().enumerate() {
        leaves.push(if index == 0 {
            [0_u8; 32]
        } else {
            *wtxid.as_bytes()
        });
    }
    let Some(root) = merkle_root_bytes(&mut leaves) else {
        return false;
    };

    let mut buffer = [0_u8; 64];
    buffer[..32].copy_from_slice(&root);
    buffer[32..].copy_from_slice(reserved);
    &sha256d(&buffer)[..] == commitment
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    double_sha256(data).to_le_bytes()
}

fn merkle_root_bytes(leaves: &mut Vec<[u8; 32]>) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    let kernel = if leaves.len() >= AVX2_MERKLE_MIN_LEAVES {
        detect_avx2()
    } else {
        None
    };
    while leaves.len() > 1 {
        next_bytes_level(leaves, kernel.as_ref());
    }
    Some(leaves[0])
}

#[cfg(test)]
fn merkle_root_and_mutation_scalar(hashes: &mut Vec<Txid>) -> Option<(Txid, bool)> {
    if hashes.is_empty() {
        return None;
    }
    let mut mutated = false;
    while hashes.len() > 1 {
        mutated |= hashes.chunks_exact(2).any(|pair| pair[0] == pair[1]);
        next_merkle_level_scalar(hashes);
    }
    Some((hashes[0], mutated))
}

#[cfg(test)]
fn next_merkle_level_scalar(level: &mut Vec<Txid>) {
    let original_len = level.len();
    for idx in 0..original_len.div_ceil(2) {
        let left = level[2 * idx];
        let right = level[(2 * idx + 1).min(original_len - 1)];
        let mut pair = [0u8; 64];
        pair[..32].copy_from_slice(left.as_bytes());
        pair[32..].copy_from_slice(right.as_bytes());
        level[idx] = Txid(double_sha256(&pair));
    }
    level.truncate(original_len.div_ceil(2));
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, Wtxid,
    };

    use super::{
        BlockRuleContext, WITNESS_COMMITMENT_PREFIX, block_has_witness,
        block_merkle_root_matches_txids, is_coinbase, merkle_root_and_mutation,
        merkle_root_and_mutation_borrowed, merkle_root_and_mutation_scalar, merkle_root_bytes,
        merkle_root_spine, sha256d, verify_block_rules, verify_block_rules_precomputed,
        verify_merkle_root_with_txids,
    };
    use crate::ConsensusError;

    #[test]
    fn valid_single_coinbase_block_passes() {
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs: vec![coinbase_tx()],
        };
        let mut fixed = block;
        let mut hashes: Vec<Txid> = fixed.txs.iter().map(Tx::txid).collect();
        let (root, _) = merkle_root_and_mutation_scalar(&mut hashes)
            .unwrap_or_else(|| panic!("single coinbase block should have merkle root"));
        fixed.header.merkle_root = root.into();
        assert_eq!(verify_block_rules(&fixed), Ok(()));
    }

    #[test]
    fn missing_coinbase_is_rejected() {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[1; 32])), 0),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs: vec![tx],
        };
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
        coinbase.inputs[0].script_sig = vec![1; 1_000_001];
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

    // --- BIP141 witness commitment tests ---

    #[test]
    fn bip141_witness_commitment_last_output_wins() {
        // Coinbase has two commitment outputs: first valid, last bogus.
        // The last matching output is checked, so the bogus commitment rejects the block.
        let reserved = vec![0u8; 32];
        let spend = witness_spend_tx();
        let valid = compute_witness_commitment(&[coinbase_tx(), spend.clone()], &reserved);

        let mut coinbase = coinbase_tx();
        coinbase.inputs[0].witness = vec![reserved];
        coinbase.outputs.push(TxOut {
            value: 0,
            script_pubkey: commitment_script(&valid),
        });
        coinbase.outputs.push(TxOut {
            value: 0,
            script_pubkey: commitment_script(&[0xff; 32]),
        });

        let block = block_with_transactions(vec![coinbase, spend]);
        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: true
                }
            ),
            Err(ConsensusError::WitnessCommitment)
        );
    }

    #[test]
    fn bip141_witness_commitment_last_output_wins_valid() {
        // Coinbase has two commitment outputs: first bogus, last valid.
        // The last matching output is checked, so the valid commitment accepts the block.
        let reserved = vec![0u8; 32];
        let spend = witness_spend_tx();
        let valid = compute_witness_commitment(&[coinbase_tx(), spend.clone()], &reserved);

        let mut coinbase = coinbase_tx();
        coinbase.inputs[0].witness = vec![reserved];
        coinbase.outputs.push(TxOut {
            value: 0,
            script_pubkey: commitment_script(&[0xff; 32]),
        });
        coinbase.outputs.push(TxOut {
            value: 0,
            script_pubkey: commitment_script(&valid),
        });

        let block = block_with_transactions(vec![coinbase, spend]);
        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: true
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn bip141_coinbase_witness_must_have_exactly_one_32_byte_element() {
        let spend = witness_spend_tx();
        let commitment = compute_witness_commitment(&[coinbase_tx(), spend.clone()], &[0u8; 32]);

        let make_block = |witness: Vec<Vec<u8>>| -> Block {
            let mut coinbase = coinbase_tx();
            coinbase.inputs[0].witness = witness;
            coinbase.outputs.push(TxOut {
                value: 0,
                script_pubkey: commitment_script(&commitment),
            });
            block_with_transactions(vec![coinbase, spend.clone()])
        };

        // No witness elements → rejected.
        let block = make_block(Vec::new());
        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: true
                }
            ),
            Err(ConsensusError::WitnessCommitment)
        );

        // 31-byte element → rejected.
        let block = make_block(vec![vec![0u8; 31]]);
        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: true
                }
            ),
            Err(ConsensusError::WitnessCommitment)
        );

        // Two elements (both 32 bytes) → rejected.
        let block = make_block(vec![vec![0u8; 32], vec![0u8; 32]]);
        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: true
                }
            ),
            Err(ConsensusError::WitnessCommitment)
        );
    }

    #[test]
    fn bip141_valid_commitment_with_proper_reserved_value_passes() {
        let reserved = vec![0u8; 32];
        let spend = witness_spend_tx();
        let commitment = compute_witness_commitment(&[coinbase_tx(), spend.clone()], &reserved);

        let mut coinbase = coinbase_tx();
        coinbase.inputs[0].witness = vec![reserved];
        coinbase.outputs.push(TxOut {
            value: 0,
            script_pubkey: commitment_script(&commitment),
        });

        let block = block_with_transactions(vec![coinbase, spend]);
        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: true
                }
            ),
            Ok(())
        );
    }

    // --- Merkle reducer tests ---

    #[test]
    fn avx2_matches_scalar_for_all_leaf_counts_0_to_129() {
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
    fn witness_byte_fold_matches_txid_fold_across_sizes() {
        for leaf_count in 1..=33 {
            let leaves = txids(leaf_count);
            let mut bytes: Vec<[u8; 32]> = leaves.iter().map(|txid| *txid.as_bytes()).collect();
            let bytes_root = merkle_root_bytes(&mut bytes);
            let mut hashes = leaves;
            let txid_root = merkle_root_and_mutation(&mut hashes).map(|(root, _)| *root.as_bytes());
            assert_eq!(bytes_root, txid_root, "leaf count {leaf_count}");
        }
    }

    #[test]
    fn lane_boundary_pairs_seven_and_eight() {
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
    fn borrowed_merkle_matches_in_place_across_sizes_and_mutation() {
        // Distinct leaves past the u8 seed space of `txids()`, so large
        // counts stay non-mutated by construction.
        let distinct = |count: usize| -> Vec<Txid> {
            (0..count)
                .map(|index| {
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&index.to_le_bytes());
                    Txid(Hash256::from_le_bytes(&bytes))
                })
                .collect()
        };
        let sizes = (0..=130usize).chain([255, 256, 257, 264, 1000]);
        for leaf_count in sizes {
            // tail 0: clean; 1: a duplicate-tail padding self-pair must stay
            // unmutated; 2: a real adjacent duplicate pair must flag it.
            for tail in 0..=2usize {
                let mut leaves = distinct(leaf_count);
                if leaf_count >= 2 {
                    for _ in 0..tail {
                        leaves.push(leaves[1]);
                    }
                }
                let mut expected = leaves.clone();
                let spine = merkle_root_spine(&leaves);
                let in_place = merkle_root_and_mutation(&mut expected);
                assert_eq!(spine, in_place, "leaf count {leaf_count} tail {tail}");
                assert_eq!(
                    merkle_root_and_mutation_borrowed(&leaves),
                    spine,
                    "leaf count {leaf_count} tail {tail} production dispatch"
                );
            }
        }
    }

    #[test]
    fn borrowed_final_spine_fold_flags_equal_real_siblings() {
        // All-equal leaves at an odd width: the trailing lone leaf is raised
        // through duplicate-last self-pairs (never a mutation by itself), and
        // the final fold then joins it against real spine nodes whose value
        // the raised branch equals. The fold must flag those equal real
        // siblings exactly where the in-place reducer's final-level pair
        // check does, with the same root.
        for leaf_count in [3usize, 7] {
            let leaves = vec![txid(0x2b); leaf_count];
            let mut in_place = leaves.clone();
            assert_eq!(
                merkle_root_spine(&leaves),
                merkle_root_and_mutation(&mut in_place),
                "leaf count {leaf_count}"
            );
            assert_eq!(
                merkle_root_and_mutation_borrowed(&leaves),
                merkle_root_spine(&leaves),
                "leaf count {leaf_count} production dispatch"
            );
            let Some((_, mutated)) = merkle_root_and_mutation_borrowed(&leaves) else {
                panic!("borrowed merkle root over a non-empty leaf set");
            };
            assert!(mutated, "leaf count {leaf_count}");
        }
    }

    #[test]
    fn borrowed_verification_covers_empty_even_odd_and_mutation() {
        let header_with = |merkle_root: Hash256| Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root,
            time: 0,
            bits: 0,
            nonce: 0,
        };
        // Empty input is a MerkleRoot error regardless of the header.
        let empty = Block {
            header: header_with(Hash256::default()),
            txs: Vec::new(),
        };
        assert_eq!(
            verify_merkle_root_with_txids(&empty, &[]),
            Err(ConsensusError::MerkleRoot)
        );
        for leaf_count in [1usize, 2, 3, 4, 5, 6, 7, 8, 9] {
            let leaves = txids(leaf_count);
            let mut expected = leaves.clone();
            let Some((root, mutated)) = candidate_merkle(&mut expected) else {
                panic!("merkle root over a non-empty leaf set");
            };
            // Matching root: Ok, unless the tree is genuinely mutated.
            let matching = Block {
                header: header_with(root.into()),
                txs: Vec::new(),
            };
            assert_eq!(
                verify_merkle_root_with_txids(&matching, &leaves),
                if mutated {
                    Err(ConsensusError::MerkleMutation)
                } else {
                    Ok(())
                },
                "leaf count {leaf_count}"
            );
            // A wrong root outranks the mutation verdict.
            let wrong = Block {
                header: header_with(Hash256::from_le_bytes(&[0xff; 32])),
                txs: Vec::new(),
            };
            assert_eq!(
                verify_merkle_root_with_txids(&wrong, &leaves),
                Err(ConsensusError::MerkleRoot),
                "leaf count {leaf_count}"
            );
        }
        // A genuinely mutated tree with a matching root reports MerkleMutation.
        let duplicated = vec![txid(1), txid(1)];
        let mut expected = duplicated.clone();
        let Some((root, mutated)) = candidate_merkle(&mut expected) else {
            panic!("merkle root over duplicated leaves");
        };
        assert!(mutated);
        let mutated_block = Block {
            header: header_with(root.into()),
            txs: Vec::new(),
        };
        assert_eq!(
            verify_merkle_root_with_txids(&mutated_block, &duplicated),
            Err(ConsensusError::MerkleMutation)
        );
    }

    #[test]
    fn nonadjacent_duplicates_are_not_mutated() {
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
        let wrong_root = Hash256::from_le_bytes(&[0xff; 32]);
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: wrong_root,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs: Vec::new(),
        };
        assert_eq!(
            verify_merkle_root_with_txids(&block, &txids),
            Err(ConsensusError::MerkleRoot),
            "wrong root must be reported before the duplicate mutation"
        );
    }

    #[test]
    fn missing_coinbase_precedes_merkle_mutation() {
        // A block with a duplicate transaction but no coinbase must fail on the
        // missing coinbase structural check before the merkle mutation path.
        let tx = spend_tx(1);
        let block = block_with_transactions(vec![tx.clone(), tx]);
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
        let expected: Hash256 = expected_root.into();
        let mut block = block_with_transactions(vec![coinbase_tx()]);
        block.header.merkle_root = expected;
        let check = vec![a, a];
        assert!(block_merkle_root_matches_txids(&block, &check));
    }

    #[test]
    fn is_coinbase_detects_null_prevout() {
        assert!(is_coinbase(&coinbase_tx()));
        assert!(!is_coinbase(&witness_spend_tx()));
        assert!(!is_coinbase(&spend_tx(1)));
    }

    // --- Test helpers ---

    fn coinbase_tx() -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: vec![1, 1],
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        }
    }

    fn witness_spend_tx() -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[2; 32])), 0),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: vec![vec![1; 32]],
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        }
    }

    fn spend_tx(seed: u8) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[seed; 32])), 0),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        }
    }

    fn block_with_transactions(txs: Vec<Tx>) -> Block {
        let mut block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs,
        };
        let Some(root) = compute_merkle_root_from_txs(&block.txs) else {
            panic!("block should have merkle root");
        };
        block.header.merkle_root = root;
        block
    }

    fn check_block_rules(block: &Block, context: BlockRuleContext) -> Result<(), ConsensusError> {
        let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
        let wtxids: Vec<Wtxid> = block.txs.iter().map(Tx::wtxid).collect();
        let has_witness = block_has_witness(block);
        verify_block_rules_precomputed(block, context, &txids, &wtxids, has_witness)
    }

    fn compute_merkle_root_from_txs(txs: &[Tx]) -> Option<Hash256> {
        let mut hashes: Vec<Txid> = txs.iter().map(Tx::txid).collect();
        merkle_root_and_mutation(&mut hashes).map(|(root, _)| root.into())
    }

    /// Builds a BIP141 witness commitment scriptPubKey from a 32-byte commitment.
    fn commitment_script(commitment: &[u8; 32]) -> Vec<u8> {
        let mut script = WITNESS_COMMITMENT_PREFIX.to_vec();
        script.extend_from_slice(commitment);
        script
    }

    /// Computes the BIP141 witness commitment for a block's transaction set.
    fn compute_witness_commitment(txs: &[Tx], reserved: &[u8]) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = txs
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                if i == 0 {
                    [0u8; 32]
                } else {
                    *tx.wtxid().as_bytes()
                }
            })
            .collect();
        let root = merkle_root_bytes(&mut leaves).unwrap_or([0u8; 32]);
        let mut buffer = [0u8; 64];
        buffer[..32].copy_from_slice(&root);
        buffer[32..].copy_from_slice(reserved);
        sha256d(&buffer)
    }

    fn txid(seed: u8) -> Txid {
        Txid(Hash256::from_le_bytes(&[seed; 32]))
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
        merkle_root_and_mutation(hashes)
    }

    fn scalar_merkle(hashes: &mut Vec<Txid>) -> Option<(Txid, bool)> {
        merkle_root_and_mutation_scalar(hashes)
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
}
