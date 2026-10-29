//! Block rule checks over shared parse-once facts.

use bitcoin_rs_primitives::{Block, Hash256, Network, Tx, Txid, Wtxid, encode::double_sha256};

use crate::ConsensusError;
use crate::bip9::SoftforkState;
use crate::block_view::BlockFacts;
use crate::sha256d64::{self, Avx2Sha256d64, detect_avx2};

const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

const MINIMUM_WITNESS_COMMITMENT: usize = 38;

const AVX2_MERKLE_MIN_LEAVES: usize = sha256d64::LANES * 2;

pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

pub const MAX_BLOCK_SERIALIZED_SIZE: u64 = 4_000_000;

const MERKLE_NODE_SERIALIZED_SIZE: usize = 64;

#[must_use]
pub fn is_sixty_four_byte_mutation(txs: &[Tx]) -> bool {
    txs.first().is_some_and(|first| !first.is_coinbase())
        && txs
            .iter()
            .any(|tx| tx.base_size() == MERKLE_NODE_SERIALIZED_SIZE)
}

#[must_use]
pub fn verify_flags(
    network: Network,
    height: u32,
    block_hash: Hash256,
    softfork_state: SoftforkState,
) -> bitcoin_rs_script::VerifyFlags {
    use bitcoin_rs_script::VerifyFlags;

    let mut flags = VerifyFlags::NONE;
    if !network.is_bip16_p2sh_exception(block_hash) {
        flags = flags.union(VerifyFlags::P2SH);
    }
    if network.is_bip66_active(height) {
        flags = flags.union(VerifyFlags::DERSIG);
    }
    if network.is_bip65_active(height) {
        flags = flags.union(VerifyFlags::CHECKLOCKTIMEVERIFY);
    }
    if softfork_state.csv_active {
        flags = flags.union(VerifyFlags::CHECKSEQUENCEVERIFY);
    }
    if softfork_state.segwit_active {
        flags = flags
            .union(VerifyFlags::WITNESS)
            .union(VerifyFlags::NULLDUMMY);
    }
    if network.is_taproot_active(height) {
        flags = flags.union(VerifyFlags::TAPROOT);
    }
    flags
}

#[derive(Clone, Copy, Debug)]
pub struct BlockRuleContext {
    pub segwit_active: bool,
}

pub fn verify_block_rules(block: &Block) -> Result<(), ConsensusError> {
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    let mut facts = BlockFacts::from_txids(&block.txs, txids);
    if facts.has_witness() {
        facts.or_insert_wtxids_from(&block.txs);
    }
    let context = BlockRuleContext {
        segwit_active: true,
    };
    verify_block_rules_precomputed(block, context, &facts)
}

pub fn verify_block_rules_precomputed(
    block: &Block,
    context: BlockRuleContext,
    facts: &BlockFacts,
) -> Result<(), ConsensusError> {
    verify_block_structure(block, facts)?;

    if let Some(wtxids) = facts.wtxids() {
        check_witness_malleation(block, context.segwit_active, wtxids)?;
    } else if context.segwit_active && witness_commitment(block).is_some() {
        return Err(ConsensusError::WitnessNonceSize);
    } else if facts.has_witness() {
        return Err(ConsensusError::UnexpectedWitness);
    }

    let weight = facts.weight();
    if weight > MAX_BLOCK_WEIGHT {
        return Err(ConsensusError::BlockWeight {
            weight,
            max: MAX_BLOCK_WEIGHT,
        });
    }
    Ok(())
}

pub fn verify_block_non_contextual(block: &Block) -> Result<(), ConsensusError> {
    let facts = BlockFacts::from_txids(&block.txs, block.txids());
    verify_block_structure(block, &facts)?;
    let size = u64::try_from(block.stripped_size()).unwrap_or(u64::MAX);
    let max = MAX_BLOCK_WEIGHT / 4;
    if size > max {
        return Err(ConsensusError::BlockBaseSize { size, max });
    }
    let mut sigop_cost = 0_u32;
    for tx in &block.txs {
        crate::verify_tx::verify_transaction_structure(tx)?;
        sigop_cost = sigop_cost
            .saturating_add(bitcoin_rs_script::sigops::count_tx_legacy(tx).saturating_mul(4));
    }
    if sigop_cost > crate::MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: crate::MAX_BLOCK_SIGOPS_COST,
        });
    }
    Ok(())
}

fn verify_block_structure(block: &Block, facts: &BlockFacts) -> Result<(), ConsensusError> {
    let txdata = &block.txs;
    if txdata.is_empty() {
        return Err(ConsensusError::EmptyBlock);
    }
    if facts.tx_count() != txdata.len() {
        return Err(ConsensusError::MerkleRoot);
    }
    if !txdata[0].is_coinbase() {
        return Err(if is_sixty_four_byte_mutation(txdata) {
            ConsensusError::SixtyFourByteMutation
        } else {
            ConsensusError::MissingCoinbase
        });
    }
    for (tx_index, tx) in txdata.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(ConsensusError::ExtraCoinbase { tx_index });
        }
    }

    let Some(root) = facts.merkle_root() else {
        return Err(ConsensusError::MerkleRoot);
    };
    if block.header.merkle_root != root.into() {
        return Err(ConsensusError::MerkleRoot);
    }
    if facts.merkle_mutated() {
        return Err(ConsensusError::MerkleMutation);
    }

    Ok(())
}

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

#[doc(hidden)]
pub fn block_merkle_root_matches_txids(block: &Block, txids: &[Txid]) -> bool {
    match merkle_root_and_mutation_borrowed(txids) {
        Some((root, _)) => block.header.merkle_root == root.into(),
        None => false,
    }
}

fn hash_merkle_pair(left: Txid, right: Txid) -> Txid {
    Txid(hash_merkle_bytes(left.as_bytes(), right.as_bytes()))
}

fn hash_merkle_bytes(left: &[u8; 32], right: &[u8; 32]) -> Hash256 {
    let mut pair = [0u8; 64];
    pair[..32].copy_from_slice(left);
    pair[32..].copy_from_slice(right);
    double_sha256(&pair)
}

pub(crate) fn merkle_root_and_mutation_borrowed(txids: &[Txid]) -> Option<(Txid, bool)> {
    if txids.len() >= AVX2_MERKLE_MIN_LEAVES && detect_avx2().is_some() {
        let mut hashes = txids.to_vec();
        return merkle_root_and_mutation(&mut hashes);
    }
    merkle_root_spine(txids)
}

fn merkle_root_spine(txids: &[Txid]) -> Option<(Txid, bool)> {
    if txids.is_empty() {
        return None;
    }
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
    let (root, _) = carry?;
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
        mutated |= hashes
            .as_chunks::<2>()
            .0
            .iter()
            .any(|pair| pair[0] == pair[1]);
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

pub(crate) fn witness_commitment_index(coinbase: &Tx) -> Option<usize> {
    coinbase.outputs.iter().rposition(|output| {
        output.script_pubkey.len() >= MINIMUM_WITNESS_COMMITMENT
            && output.script_pubkey[..6] == WITNESS_COMMITMENT_PREFIX
    })
}

fn witness_commitment(block: &Block) -> Option<&[u8]> {
    let coinbase = block.txs.first()?;
    let index = witness_commitment_index(coinbase)?;
    coinbase
        .outputs
        .get(index)?
        .script_pubkey
        .get(6..MINIMUM_WITNESS_COMMITMENT)
}

fn check_witness_malleation(
    block: &Block,
    expect_commitment: bool,
    wtxids: &[Wtxid],
) -> Result<(), ConsensusError> {
    if expect_commitment {
        if let Some(commitment) = witness_commitment(block) {
            let Some(input) = block.txs.first().and_then(|tx| tx.inputs.first()) else {
                return Err(ConsensusError::WitnessNonceSize);
            };
            if input.witness.len() != 1 || input.witness[0].len() != 32 {
                return Err(ConsensusError::WitnessNonceSize);
            }
            if !witness_commitment_hash_matches(block, wtxids, commitment, &input.witness[0]) {
                return Err(ConsensusError::WitnessCommitment);
            }
            return Ok(());
        }
    }
    if block.txs.iter().any(Tx::has_witness) {
        return Err(ConsensusError::UnexpectedWitness);
    }
    Ok(())
}

#[must_use]
pub fn block_witness_commitment_matches(block: &Block, wtxids: &[Wtxid]) -> bool {
    check_witness_malleation(block, true, wtxids).is_ok()
}
pub fn check_block_body_binding(block: &Block, segwit_active: bool) -> Result<(), ConsensusError> {
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    verify_merkle_root_with_txids(block, &txids)?;
    if is_sixty_four_byte_mutation(&block.txs) {
        return Err(ConsensusError::SixtyFourByteMutation);
    }

    let commitment = witness_commitment(block);
    if commitment.is_none() && !block.txs.iter().any(Tx::has_witness) {
        return Ok(());
    }
    if segwit_active && commitment.is_some() {
        let Some(input) = block.txs.first().and_then(|tx| tx.inputs.first()) else {
            return Err(ConsensusError::WitnessNonceSize);
        };
        if input.witness.len() != 1 || input.witness[0].len() != 32 {
            return Err(ConsensusError::WitnessNonceSize);
        }
    }
    let wtxids: Vec<Wtxid> = block.txs.iter().map(Tx::wtxid).collect();
    check_witness_malleation(block, segwit_active, &wtxids)
}

fn witness_commitment_hash_matches(
    block: &Block,
    wtxids: &[Wtxid],
    commitment: &[u8],
    reserved: &[u8],
) -> bool {
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
    let Some(root) = compute_merkle_root(&mut leaves) else {
        return false;
    };

    let mut buffer = [0_u8; 64];
    buffer[..32].copy_from_slice(&root);
    buffer[32..].copy_from_slice(reserved);
    &double_sha256(&buffer).to_le_bytes()[..] == commitment
}

/// Bitcoin merkle root over raw 32-byte leaves.
#[must_use]
pub fn compute_merkle_root(leaves: &mut Vec<[u8; 32]>) -> Option<[u8; 32]> {
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
mod tests;
