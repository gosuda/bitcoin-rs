//! Block rule checks over shared parse-once facts.

use bitcoin_rs_primitives::{Block, Hash256, Network, Tx, Txid, Wtxid, encode::double_sha256};

use crate::ConsensusError;
use crate::bip9::SoftforkState;
use crate::block_view::BlockFacts;
use crate::sha256d64::{self, Avx2Sha256d64, detect_avx2};
use crate::verify_tx::is_coinbase;

/// BIP141 witness commitment output prefix: `OP_RETURN` `OP_PUSHBYTES_36`
/// `commitment_header`.
const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// Eight AVX2 lanes hash eight parent pairs, so a tree needs 16 leaves before
/// the batch kernel can issue work.
const AVX2_MERKLE_MIN_LEAVES: usize = sha256d64::LANES * 2;

/// BIP141 maximum block weight in weight units.
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// Consensus maximum serialized block size.
pub const MAX_BLOCK_SERIALIZED_SIZE: u64 = 4_000_000;

/// Computes contextual script verification flags for a block.
#[must_use]
pub fn verify_flags(
    network: Network,
    height: u32,
    block_hash: Hash256,
    softfork_state: SoftforkState,
) -> bitcoin_rs_script::VerifyFlags {
    use bitcoin_rs_script::VerifyFlags;

    // P2SH (BIP16) is enforced except for Core's single grandfathered block.
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
    let mut facts = BlockFacts::from_txids(&block.txs, txids);
    if facts.has_witness() {
        facts.or_insert_wtxids_from(&block.txs);
    }
    verify_block_rules_precomputed(block, BlockRuleContext::non_contextual(), &facts)
}

/// Verifies block rules from facts derived once for the supplied block.
pub fn verify_block_rules_precomputed(
    block: &Block,
    context: BlockRuleContext,
    facts: &BlockFacts,
) -> Result<(), ConsensusError> {
    let txdata = &block.txs;
    if txdata.is_empty() {
        return Err(ConsensusError::EmptyBlock);
    }
    if facts.tx_count() != txdata.len() {
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

    let Some(root) = facts.merkle_root() else {
        return Err(ConsensusError::MerkleRoot);
    };
    if block.header.merkle_root != root.into() {
        return Err(ConsensusError::MerkleRoot);
    }
    if facts.merkle_mutated() {
        return Err(ConsensusError::MerkleMutation);
    }

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

/// Verifies the header Merkle root and rejects mutated Merkle trees.
/// `txids` must cover the block in transaction order; root errors precede mutation errors.
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
/// Mutation is ignored here and checked by full consensus validation.
#[doc(hidden)]
pub fn block_merkle_root_matches_txids(block: &Block, txids: &[Txid]) -> bool {
    match merkle_root_and_mutation_borrowed(txids) {
        Some((root, _)) => block.header.merkle_root == root.into(),
        None => false,
    }
}

/// Returns `true` when any transaction input carries witness data (Core's
/// `CBlock::HasWitness`).
fn block_has_witness(block: &Block) -> bool {
    block
        .txs
        .iter()
        .any(|tx| tx.inputs.iter().any(|input| !input.witness.is_empty()))
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
pub(crate) fn merkle_root_and_mutation_borrowed(txids: &[Txid]) -> Option<(Txid, bool)> {
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
    // Duplicate-last self-pairs pad the spine without flagging mutation.
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

/// The last coinbase output carrying the BIP141 commitment prefix.
pub(crate) fn witness_commitment(block: &Block) -> Option<&[u8]> {
    block
        .txs
        .first()?
        .outputs
        .iter()
        .rev()
        .find(|output| {
            output.script_pubkey.len() >= 38
                && output.script_pubkey[..6] == WITNESS_COMMITMENT_PREFIX
        })
        .map(|output| &output.script_pubkey[6..38])
}

/// Core `CheckWitnessMalleation`.
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
    if block_has_witness(block) {
        return Err(ConsensusError::UnexpectedWitness);
    }
    Ok(())
}

/// Returns whether the block's BIP141 commitment matches `wtxids`.
#[must_use]
pub fn block_witness_commitment_matches(block: &Block, wtxids: &[Wtxid]) -> bool {
    check_witness_malleation(block, true, wtxids).is_ok()
}
/// Checks that a block body is bound to its header before staging.
pub fn check_block_body_binding(block: &Block, segwit_active: bool) -> Result<(), ConsensusError> {
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    verify_merkle_root_with_txids(block, &txids)?;

    let commitment = witness_commitment(block);
    if commitment.is_none() && !block_has_witness(block) {
        return Ok(());
    }
    // Reject malformed nonces before deriving witness IDs.
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
    &sha256d(&buffer)[..] == commitment
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    double_sha256(data).to_le_bytes()
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
mod tests {
    use bitcoin_rs_primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint,
        Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };

    use super::{
        BlockRuleContext, WITNESS_COMMITMENT_PREFIX, block_merkle_root_matches_txids,
        compute_merkle_root, is_coinbase, merkle_root_and_mutation,
        merkle_root_and_mutation_borrowed, merkle_root_spine, sha256d, verify_block_rules,
        verify_block_rules_precomputed, verify_flags, verify_merkle_root_with_txids,
    };
    use crate::ConsensusError;
    use crate::bip9::SoftforkState;
    use crate::block_view::BlockFacts;
    use bitcoin_rs_script::VerifyFlags;

    /// (witness leaves, coinbase witness stack, verdict)
    type BindingCase = (Vec<[u8; 32]>, Vec<Vec<u8>>, Result<(), ConsensusError>);

    fn coinbase_tx() -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: Script::from_bytes(vec![1, 1]),
                sequence: Sequence::from_consensus(u32::MAX),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::from_consensus(0),
        }
    }

    fn spend_tx(seed: u8, witness: Vec<Vec<u8>>) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[seed; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(u32::MAX),
                witness: Witness::from_stack(witness),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::from_consensus(0),
        }
    }

    fn witness_spend_tx() -> Tx {
        spend_tx(2, vec![vec![1; 32]])
    }

    fn block_with_transactions(txs: Vec<Tx>) -> Block {
        let mut hashes: Vec<Txid> = txs.iter().map(Tx::txid).collect();
        let Some((root, _)) = merkle_root_and_mutation(&mut hashes) else {
            panic!("block should have merkle root");
        };
        Block {
            header: header_with(root.into()),
            txs,
        }
    }

    fn header_with(merkle_root: Hash256) -> Header {
        Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root,
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        }
    }

    fn check_block_rules(block: &Block, context: BlockRuleContext) -> Result<(), ConsensusError> {
        let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
        let mut facts = BlockFacts::from_txids(&block.txs, txids);
        if facts.has_witness() {
            facts.or_insert_wtxids_from(&block.txs);
        }
        verify_block_rules_precomputed(block, context, &facts)
    }

    fn commitment_output(commitment: [u8; 32]) -> TxOut {
        let mut script = WITNESS_COMMITMENT_PREFIX.to_vec();
        script.extend_from_slice(&commitment);
        TxOut {
            value: Amount::from_sat(0),
            script_pubkey: Script::from_bytes(script),
        }
    }

    fn compute_witness_commitment(txs: &[Tx], reserved: &[u8]) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = txs
            .iter()
            .enumerate()
            .map(|(index, tx)| {
                if index == 0 {
                    [0u8; 32]
                } else {
                    *tx.wtxid().as_bytes()
                }
            })
            .collect();
        let root = compute_merkle_root(&mut leaves).unwrap_or([0u8; 32]);
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

    fn distinct_txids(count: usize) -> Vec<Txid> {
        (0..count)
            .map(|index| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&index.to_le_bytes());
                Txid(Hash256::from_le_bytes(&bytes))
            })
            .collect()
    }

    fn oracle_root(leaves: &[Txid]) -> Option<[u8; 32]> {
        use bitcoin::hashes::Hash as _;
        bitcoin::merkle_tree::calculate_root(
            leaves
                .iter()
                .map(|leaf| bitcoin::Txid::from_byte_array(*leaf.as_bytes())),
        )
        .map(bitcoin::hashes::Hash::to_byte_array)
    }

    #[test]
    fn verify_flags_follow_activation_and_the_bip16_exception() {
        let flags = verify_flags(
            Network::Mainnet,
            481_824,
            Hash256::from_le_bytes(&[0x11; 32]),
            SoftforkState {
                csv_active: true,
                segwit_active: true,
            },
        );
        for expected in [
            VerifyFlags::P2SH,
            VerifyFlags::DERSIG,
            VerifyFlags::CHECKLOCKTIMEVERIFY,
            VerifyFlags::CHECKSEQUENCEVERIFY,
            VerifyFlags::WITNESS,
            VerifyFlags::NULLDUMMY,
        ] {
            assert!(flags.contains(expected), "missing {expected:?}");
        }

        let exception = match "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
            .parse::<BlockHash>()
        {
            Ok(hash) => Hash256::from(hash),
            Err(error) => panic!("invalid BIP16 exception hash: {error}"),
        };
        let exempt = verify_flags(
            Network::Mainnet,
            170_060,
            exception,
            SoftforkState {
                csv_active: false,
                segwit_active: false,
            },
        );
        assert!(!exempt.contains(VerifyFlags::P2SH));
    }

    #[test]
    fn structural_block_rules_hold_under_both_activation_states() {
        let duplicated = spend_tx(3, Vec::new());
        let cases: [(Vec<Tx>, Result<(), ConsensusError>); 6] = [
            (vec![coinbase_tx()], Ok(())),
            (
                vec![coinbase_tx(), coinbase_tx()],
                Err(ConsensusError::ExtraCoinbase { tx_index: 1 }),
            ),
            // A block whose only transaction spends a real prevout.
            (
                vec![spend_tx(1, Vec::new())],
                Err(ConsensusError::MissingCoinbase),
            ),
            // No coinbase AND an adjacent duplicate: the structural check wins.
            (
                vec![duplicated.clone(), duplicated.clone()],
                Err(ConsensusError::MissingCoinbase),
            ),
            // Adjacent duplicate txids make the Merkle tree ambiguous.
            (
                vec![
                    coinbase_tx(),
                    spend_tx(2, Vec::new()),
                    duplicated.clone(),
                    duplicated.clone(),
                ],
                Err(ConsensusError::MerkleMutation),
            ),
            // Non-adjacent duplicates are not a Merkle mutation; BIP30 owns
            // that rejection at a later stage.
            (
                vec![
                    coinbase_tx(),
                    duplicated.clone(),
                    spend_tx(5, Vec::new()),
                    duplicated,
                ],
                Ok(()),
            ),
        ];

        for (txs, expected) in cases {
            let block = block_with_transactions(txs);
            for segwit_active in [false, true] {
                assert_eq!(
                    check_block_rules(&block, BlockRuleContext { segwit_active }),
                    expected,
                    "segwit_active {segwit_active}"
                );
            }
            assert_eq!(
                verify_block_rules(&block),
                expected,
                "the public entry derives the same facts"
            );
        }
        let mut wrong = block_with_transactions(vec![coinbase_tx()]);
        wrong.header.merkle_root = Hash256::default();
        assert_eq!(
            check_block_rules(
                &wrong,
                BlockRuleContext {
                    segwit_active: true
                }
            ),
            Err(ConsensusError::MerkleRoot)
        );
    }

    #[test]
    fn witness_without_commitment_and_oversized_blocks_are_rejected() {
        let witness_block = block_with_transactions(vec![coinbase_tx(), witness_spend_tx()]);
        let mut heavy = coinbase_tx();
        heavy.inputs[0].script_sig = Script::from_bytes(vec![1; 1_000_001]);
        let heavy_block = block_with_transactions(vec![heavy]);

        for segwit_active in [false, true] {
            let context = BlockRuleContext { segwit_active };
            assert_eq!(
                check_block_rules(&witness_block, context),
                Err(ConsensusError::UnexpectedWitness),
                "segwit_active {segwit_active}"
            );
            assert!(
                matches!(
                    check_block_rules(&heavy_block, context),
                    Err(ConsensusError::BlockWeight { .. })
                ),
                "segwit_active {segwit_active}"
            );
        }
    }

    #[test]
    fn bip141_commitment_selection_and_reserved_nonce_shape() {
        let reserved = vec![0u8; 32];
        let spend = witness_spend_tx();
        let valid = compute_witness_commitment(&[coinbase_tx(), spend.clone()], &reserved);
        let bogus = [0xff; 32];
        let nonce = vec![reserved];

        let cases: [BindingCase; 7] = [
            (vec![valid], nonce.clone(), Ok(())),
            // Last matching output wins in both directions.
            (vec![bogus, valid], nonce.clone(), Ok(())),
            (
                vec![valid, bogus],
                nonce,
                Err(ConsensusError::WitnessCommitment),
            ),
            (
                vec![valid],
                Vec::new(),
                Err(ConsensusError::WitnessNonceSize),
            ),
            (
                vec![valid],
                vec![vec![0u8; 31]],
                Err(ConsensusError::WitnessNonceSize),
            ),
            (
                vec![valid],
                vec![vec![0u8; 33]],
                Err(ConsensusError::WitnessNonceSize),
            ),
            (
                vec![valid],
                vec![vec![0u8; 32], vec![0u8; 32]],
                Err(ConsensusError::WitnessNonceSize),
            ),
        ];

        for (commitments, witness, expected) in cases {
            let mut coinbase = coinbase_tx();
            coinbase.inputs[0].witness = Witness::from_stack(witness);
            coinbase
                .outputs
                .extend(commitments.iter().copied().map(commitment_output));
            let block = block_with_transactions(vec![coinbase, spend.clone()]);
            assert_eq!(
                check_block_rules(
                    &block,
                    BlockRuleContext {
                        segwit_active: true
                    }
                ),
                expected
            );
        }
    }

    #[test]
    fn every_merkle_reducer_agrees_with_the_oracle_and_on_mutation() {
        let sizes = (0..=130usize).chain([255, 256, 257, 264, 1000]);
        for leaf_count in sizes {
            for tail in 0..=2usize {
                let mut leaves = distinct_txids(leaf_count);
                if leaf_count >= 2 {
                    // tail 0: clean; 1: a duplicate-tail padding self-pair
                    // must stay unmutated; 2: a real adjacent duplicate pair
                    // must flag it.
                    for _ in 0..tail {
                        leaves.push(leaves[1]);
                    }
                }
                let label = format!("leaf count {leaf_count} tail {tail}");
                let mut in_place = leaves.clone();
                let spine = merkle_root_spine(&leaves);
                assert_eq!(merkle_root_and_mutation(&mut in_place), spine, "{label}");
                assert_eq!(
                    merkle_root_and_mutation_borrowed(&leaves),
                    spine,
                    "{label} production dispatch"
                );
                assert_eq!(
                    spine.map(|(root, _)| *root.as_bytes()),
                    oracle_root(&leaves),
                    "{label} against rust-bitcoin"
                );
                let mut bytes: Vec<[u8; 32]> = leaves.iter().map(|leaf| *leaf.as_bytes()).collect();
                assert_eq!(
                    compute_merkle_root(&mut bytes),
                    oracle_root(&leaves),
                    "{label} byte fold"
                );
            }
        }
    }

    #[test]
    fn mutation_flags_distinguish_padding_from_real_duplicate_pairs() {
        let (a, b) = (txid(1), txid(2));
        let one_to_six: Vec<Txid> = (1u8..=6).map(txid).collect();
        let cases: [(Vec<Txid>, bool); 8] = [
            // Non-adjacent duplicates are honest trees.
            (vec![a, b, a], false),
            (vec![a, b, b, a], false),
            // An odd trailing leaf is padded against itself: not a mutation.
            (vec![a, b, b], false),
            (vec![a, b, b, b], true),
            (one_to_six.clone(), false),
            // Core's ambiguous pair: same root, only the tail copy mutated.
            ((1u8..=6).chain([5, 6]).map(txid).collect(), true),
            // All-equal odd widths: the raised branch meets equal real spine
            // siblings in the final fold.
            (vec![txid(0x2b); 3], true),
            (vec![txid(0x2b); 7], true),
        ];

        for (leaves, expected_mutated) in cases {
            let mut in_place = leaves.clone();
            let Some((root, mutated)) = merkle_root_and_mutation(&mut in_place) else {
                panic!("test Merkle tree must be nonempty");
            };
            assert_eq!(mutated, expected_mutated, "{leaves:?}");
            assert_eq!(merkle_root_spine(&leaves), Some((root, mutated)));
            assert_eq!(
                merkle_root_and_mutation_borrowed(&leaves),
                Some((root, mutated))
            );
            assert_eq!(Some(*root.as_bytes()), oracle_root(&leaves));
        }
        // The mutated tail shares its root with the honest six-leaf tree.
        assert_eq!(
            oracle_root(&one_to_six),
            oracle_root(&(1u8..=6).chain([5, 6]).map(txid).collect::<Vec<_>>())
        );
    }

    #[test]
    fn header_merkle_verification_orders_root_before_mutation() {
        let empty = Block {
            header: header_with(Hash256::default()),
            txs: Vec::new(),
        };
        assert_eq!(
            verify_merkle_root_with_txids(&empty, &[]),
            Err(ConsensusError::MerkleRoot)
        );

        let wrong = Block {
            header: header_with(Hash256::from_le_bytes(&[0xff; 32])),
            txs: Vec::new(),
        };
        for leaf_count in 1..=9usize {
            let leaves = txids(leaf_count);
            let Some((root, mutated)) = merkle_root_and_mutation_borrowed(&leaves) else {
                panic!("merkle root over a non-empty leaf set");
            };
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
            assert_eq!(
                verify_merkle_root_with_txids(&wrong, &leaves),
                Err(ConsensusError::MerkleRoot),
                "leaf count {leaf_count}"
            );
        }

        // A mutated tree: matching root reports the mutation, a wrong root
        // still outranks it, and the window precheck ignores mutation.
        let duplicated = vec![txid(1), txid(1)];
        let Some((root, mutated)) = merkle_root_and_mutation_borrowed(&duplicated) else {
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
        assert_eq!(
            verify_merkle_root_with_txids(&wrong, &duplicated),
            Err(ConsensusError::MerkleRoot),
            "wrong root must be reported before the duplicate mutation"
        );
        assert!(block_merkle_root_matches_txids(&mutated_block, &duplicated));
        assert!(!block_merkle_root_matches_txids(&wrong, &duplicated));
        assert!(!block_merkle_root_matches_txids(&empty, &[]));
    }

    #[test]
    fn is_coinbase_detects_null_prevout() {
        assert!(is_coinbase(&coinbase_tx()));
        assert!(!is_coinbase(&witness_spend_tx()));
        assert!(!is_coinbase(&spend_tx(1, Vec::new())));
    }
}
