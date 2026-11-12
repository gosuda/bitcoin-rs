use crate::primitives::{
    Block, BlockImage, Hash256, Network, TransactionView, Tx, Txid, Wtxid, encode::double_sha256,
};

use crate::ConsensusError;
use crate::bip9::SoftforkState;
use crate::block_view::{BlockFacts, HEADER_LEN};
use crate::sha256d64::{self, Avx2Sha256d64, detect_avx2};

const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

const MINIMUM_WITNESS_COMMITMENT: usize = 38;

const AVX2_MERKLE_MIN_LEAVES: usize = sha256d64::LANES * 2;

pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

pub const MAX_BLOCK_SERIALIZED_SIZE: u64 = 4_000_000;

const MERKLE_NODE_SERIALIZED_SIZE: usize = 64;

pub const WITNESS_SCALE_FACTOR: u64 = 4;

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
) -> crate::script::VerifyFlags {
    use crate::script::VerifyFlags;

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
    verify_block_merkle_and_size(block, facts)?;
    verify_coinbase_placement(&block.txs)?;
    verify_block_transactions_and_legacy_sigops(&block.txs)?;
    verify_block_witness_rules(block, context, facts)?;
    verify_block_weight(facts)
}

/// The image entry of the same rules: the header and the merkle root are read
/// from the image bytes, and the per-transaction structure checks read
/// `TransactionView`s, so no owned transaction graph is built.
pub fn verify_block_image_rules(
    image: &BlockImage,
    context: BlockRuleContext,
    facts: &BlockFacts,
) -> Result<(), ConsensusError> {
    verify_image_merkle_and_size(image, facts)?;
    verify_image_coinbase_placement(image)?;
    verify_image_transactions_and_legacy_sigops(image)?;
    verify_image_witness_rules(image, context, facts)?;
    verify_block_weight(facts)
}

fn verify_image_merkle_and_size(
    image: &BlockImage,
    facts: &BlockFacts,
) -> Result<(), ConsensusError> {
    let (root, mutated): (Hash256, bool) = match facts.merkle_root() {
        Some(root) => (root.into(), facts.merkle_mutated()),
        None if image.tx_count() == 0 => (Hash256::from_le_bytes(&[0; 32]), false),
        None => return Err(ConsensusError::MerkleRoot),
    };
    if image.header().merkle_root != root {
        return Err(ConsensusError::MerkleRoot);
    }
    if mutated {
        return Err(ConsensusError::MerkleMutation);
    }
    let stripped = HEADER_LEN
        .saturating_add(u64::from(image.layout().tx_count().len()))
        .saturating_add(
            image
                .identities()
                .iter()
                .map(|identity| u64::from(identity.base_size()))
                .sum(),
        );
    let max = MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR;
    if image.tx_count() == 0 || stripped > max {
        return Err(ConsensusError::BlockBaseSize {
            size: stripped,
            max,
        });
    }
    Ok(())
}

fn verify_image_coinbase_placement(image: &BlockImage) -> Result<(), ConsensusError> {
    let tx_count = image.tx_count();
    if tx_count == 0 {
        return Ok(());
    }
    if !image.tx(0).is_coinbase() {
        return Err(if is_image_sixty_four_byte_mutation(image) {
            ConsensusError::SixtyFourByteMutation
        } else {
            ConsensusError::MissingCoinbase
        });
    }
    for tx_index in 1..tx_count {
        if image.tx(tx_index).is_coinbase() {
            return Err(ConsensusError::ExtraCoinbase { tx_index });
        }
    }
    Ok(())
}

#[must_use]
pub fn is_image_sixty_four_byte_mutation(image: &BlockImage) -> bool {
    image.tx_count() > 0
        && !image.tx(0).is_coinbase()
        && (0..image.tx_count())
            .any(|index| image.tx(index).base_size() == MERKLE_NODE_SERIALIZED_SIZE)
}

fn verify_image_transactions_and_legacy_sigops(image: &BlockImage) -> Result<(), ConsensusError> {
    let mut sigop_cost = 0_u32;
    for index in 0..image.tx_count() {
        let tx = image.tx(index);
        crate::verify_tx::verify_transaction_structure_view(tx.into())?;
        sigop_cost = sigop_cost.saturating_add(
            crate::script::sigops::count_tx_legacy_view(tx.into()).saturating_mul(4),
        );
    }
    if sigop_cost > crate::MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: crate::MAX_BLOCK_SIGOPS_COST,
        });
    }
    Ok(())
}

fn verify_image_witness_rules(
    image: &BlockImage,
    context: BlockRuleContext,
    facts: &BlockFacts,
) -> Result<(), ConsensusError> {
    if let Some(wtxids) = facts.wtxids() {
        return check_image_witness_malleation(image, context, wtxids);
    }
    if context.segwit_active && image_witness_commitment(image).is_some() {
        return Err(ConsensusError::WitnessNonceSize);
    }
    if facts.has_witness() {
        return Err(ConsensusError::UnexpectedWitness);
    }
    Ok(())
}

fn image_witness_commitment(image: &BlockImage) -> Option<&[u8]> {
    if image.tx_count() == 0 {
        return None;
    }
    let coinbase = image.tx(0);
    let index = image_witness_commitment_index(&coinbase)?;
    coinbase
        .output_script(index)
        .get(6..MINIMUM_WITNESS_COMMITMENT)
}

pub(crate) fn image_witness_commitment_index(coinbase: &TransactionView<'_>) -> Option<usize> {
    (0..coinbase.output_count()).rev().find(|index| {
        let script = coinbase.output_script(*index);
        script.len() >= MINIMUM_WITNESS_COMMITMENT && script[..6] == WITNESS_COMMITMENT_PREFIX
    })
}

fn check_image_witness_malleation(
    image: &BlockImage,
    context: BlockRuleContext,
    wtxids: &[Wtxid],
) -> Result<(), ConsensusError> {
    if context.segwit_active {
        if let Some(commitment) = image_witness_commitment(image) {
            let coinbase = image.tx(0);
            if coinbase.input_count() == 0 {
                return Err(ConsensusError::WitnessNonceSize);
            }
            if coinbase.witness_item_count(0) != 1 || coinbase.witness_item(0, 0).len() != 32 {
                return Err(ConsensusError::WitnessNonceSize);
            }
            if !image_witness_commitment_hash_matches(
                image,
                wtxids,
                commitment,
                coinbase.witness_item(0, 0),
            ) {
                return Err(ConsensusError::WitnessCommitment);
            }
            return Ok(());
        }
    }
    if image.has_witness() {
        return Err(ConsensusError::UnexpectedWitness);
    }
    Ok(())
}

fn image_witness_commitment_hash_matches(
    image: &BlockImage,
    wtxids: &[Wtxid],
    commitment: &[u8],
    reserved: &[u8],
) -> bool {
    if wtxids.len() != image.tx_count() {
        return false;
    }
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(image.tx_count());
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

fn verify_block_merkle_and_size(block: &Block, facts: &BlockFacts) -> Result<(), ConsensusError> {
    if facts.tx_count() != block.txs.len() {
        return Err(ConsensusError::MerkleRoot);
    }
    verify_merkle_root_and_mutation(block, facts)?;
    let size = u64::try_from(block.stripped_size()).unwrap_or(u64::MAX);
    let max = MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR;
    if block.txs.is_empty() || size > max {
        return Err(ConsensusError::BlockBaseSize { size, max });
    }
    Ok(())
}

fn verify_merkle_root_and_mutation(
    block: &Block,
    facts: &BlockFacts,
) -> Result<(), ConsensusError> {
    let (root, mutated): (Hash256, bool) = match facts.merkle_root() {
        Some(root) => (root.into(), facts.merkle_mutated()),
        None if block.txs.is_empty() => (Hash256::from_le_bytes(&[0; 32]), false),
        None => return Err(ConsensusError::MerkleRoot),
    };
    if block.header.merkle_root != root {
        return Err(ConsensusError::MerkleRoot);
    }
    if mutated {
        return Err(ConsensusError::MerkleMutation);
    }
    Ok(())
}

fn verify_coinbase_placement(txs: &[Tx]) -> Result<(), ConsensusError> {
    let Some((first, _)) = txs.split_first() else {
        return Ok(());
    };
    if !first.is_coinbase() {
        return Err(if is_sixty_four_byte_mutation(txs) {
            ConsensusError::SixtyFourByteMutation
        } else {
            ConsensusError::MissingCoinbase
        });
    }
    for (tx_index, tx) in txs.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(ConsensusError::ExtraCoinbase { tx_index });
        }
    }
    Ok(())
}

fn verify_block_witness_rules(
    block: &Block,
    context: BlockRuleContext,
    facts: &BlockFacts,
) -> Result<(), ConsensusError> {
    if let Some(wtxids) = facts.wtxids() {
        return check_witness_malleation(block, context, wtxids);
    }
    if context.segwit_active && witness_commitment(block).is_some() {
        return Err(ConsensusError::WitnessNonceSize);
    }
    if facts.has_witness() {
        return Err(ConsensusError::UnexpectedWitness);
    }
    Ok(())
}

fn verify_block_weight(facts: &BlockFacts) -> Result<(), ConsensusError> {
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
    verify_block_merkle_and_size(block, &facts)?;
    verify_coinbase_placement(&block.txs)?;
    verify_block_transactions_and_legacy_sigops(&block.txs)
}

fn verify_block_transactions_and_legacy_sigops(txs: &[Tx]) -> Result<(), ConsensusError> {
    let mut sigop_cost = 0_u32;
    for tx in txs {
        crate::verify_tx::verify_transaction_structure(tx)?;
        sigop_cost =
            sigop_cost.saturating_add(crate::script::sigops::count_tx_legacy(tx).saturating_mul(4));
    }
    if sigop_cost > crate::MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: crate::MAX_BLOCK_SIGOPS_COST,
        });
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
    context: BlockRuleContext,
    wtxids: &[Wtxid],
) -> Result<(), ConsensusError> {
    if context.segwit_active {
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
    check_witness_malleation(
        block,
        BlockRuleContext {
            segwit_active: true,
        },
        wtxids,
    )
    .is_ok()
}

#[must_use]
pub fn block_image_witness_commitment_matches(image: &BlockImage, wtxids: &[Wtxid]) -> bool {
    if image.tx_count() == 0 || wtxids.len() != image.tx_count() {
        return false;
    }
    let coinbase = image.tx(0);
    let mut commitment = None;
    for i in (0..coinbase.output_count()).rev() {
        let script = coinbase.output_script(i);
        if script.len() >= MINIMUM_WITNESS_COMMITMENT
            && script.get(..6) == Some(&WITNESS_COMMITMENT_PREFIX)
        {
            commitment = script.get(6..MINIMUM_WITNESS_COMMITMENT);
            break;
        }
    }
    if let Some(commitment) = commitment {
        if coinbase.input_count() == 0 {
            return false;
        }
        if coinbase.witness_item_count(0) != 1 || coinbase.witness_item(0, 0).len() != 32 {
            return false;
        }
        let nonce = coinbase.witness_item(0, 0);
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(wtxids.len());
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
        buffer[32..].copy_from_slice(nonce);
        return &double_sha256(&buffer).to_le_bytes()[..] == commitment;
    }
    !image.has_witness()
}
pub fn check_block_body_binding(
    block: &Block,
    context: BlockRuleContext,
) -> Result<(), ConsensusError> {
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    verify_merkle_root_with_txids(block, &txids)?;
    if is_sixty_four_byte_mutation(&block.txs) {
        return Err(ConsensusError::SixtyFourByteMutation);
    }

    let commitment = witness_commitment(block);
    if commitment.is_none() && !block.txs.iter().any(Tx::has_witness) {
        return Ok(());
    }
    if context.segwit_active && commitment.is_some() {
        let Some(input) = block.txs.first().and_then(|tx| tx.inputs.first()) else {
            return Err(ConsensusError::WitnessNonceSize);
        };
        if input.witness.len() != 1 || input.witness[0].len() != 32 {
            return Err(ConsensusError::WitnessNonceSize);
        }
    }
    let wtxids: Vec<Wtxid> = block.txs.iter().map(Tx::wtxid).collect();
    check_witness_malleation(block, context, &wtxids)
}

/// The image entry of the same body-binding gate for the download window:
/// identities supply the transaction ids and the witness commitment reads
/// the coinbase through its view.
pub fn check_image_body_binding(
    image: &BlockImage,
    context: BlockRuleContext,
) -> Result<(), ConsensusError> {
    let txids: Vec<Txid> = image.identities().iter().map(|id| id.txid()).collect();
    let (root, mutated) = merkle_root_and_mutation_borrowed(&txids)
        .map(|(root, mutated)| (Hash256::from(root), mutated))
        .ok_or(ConsensusError::MerkleRoot)?;
    if image.header().merkle_root != root {
        return Err(ConsensusError::MerkleRoot);
    }
    if mutated {
        return Err(ConsensusError::MerkleMutation);
    }
    if is_image_sixty_four_byte_mutation(image) {
        return Err(ConsensusError::SixtyFourByteMutation);
    }

    let commitment = image_witness_commitment(image);
    if commitment.is_none() && !image.has_witness() {
        return Ok(());
    }
    if context.segwit_active && commitment.is_some() {
        let coinbase = image.tx(0);
        if coinbase.input_count() == 0 {
            return Err(ConsensusError::WitnessNonceSize);
        }
        if coinbase.witness_item_count(0) != 1 || coinbase.witness_item(0, 0).len() != 32 {
            return Err(ConsensusError::WitnessNonceSize);
        }
    }
    let wtxids: Vec<Wtxid> = image
        .identities()
        .iter()
        .map(|identity| identity.wtxid().unwrap_or_else(|| Wtxid(identity.txid().0)))
        .collect();
    check_image_witness_malleation(image, context, &wtxids)
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
