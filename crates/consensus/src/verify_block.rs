//! Block rule checks over shared parse-once facts.

use bitcoin_rs_primitives::{Block, Tx, Txid};

use crate::ConsensusError;
use crate::block_view::BlockFacts;

#[allow(dead_code, unreachable_pub)]
mod legacy {
    include!("verify_block_impl.rs");
}

pub(crate) use legacy::merkle_root_and_mutation_borrowed;
pub use legacy::{
    BlockRuleContext, block_has_witness, block_merkle_root_matches_txids,
    block_witness_commitment_matches, verify_merkle_root_with_txids,
};

/// BIP141 maximum block weight in weight units.
const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

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
///
/// The caller supplies transaction identities, witness presence, Merkle facts,
/// and block weight through [`BlockFacts`], so this entry does not re-serialize
/// transactions or rebuild the Merkle tree on the validation hot path.
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

    // BIP141/Core select a coinbase commitment independently of witness
    // presence. A selected commitment requires its reserved-value proof even
    // when every input witness is empty. Without an active commitment, witness
    // data is forbidden (including before SegWit activation).
    let has_witness_commitment = context.segwit_active
        && txdata[0].outputs.iter().rev().any(|output| {
            output.script_pubkey.len() >= 38
                && output.script_pubkey[..6] == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
        });
    if has_witness_commitment {
        let Some(wtxids) = facts.wtxids() else {
            return Err(ConsensusError::WitnessCommitment);
        };
        if wtxids.len() != txdata.len() || !block_witness_commitment_matches(block, wtxids) {
            return Err(ConsensusError::WitnessCommitment);
        }
    } else if facts.has_witness() {
        return Err(ConsensusError::WitnessCommitment);
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

/// Returns `true` for the one-input, null-prevout coinbase shape.
fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1
        && tx.inputs[0].previous_output.txid == Txid::default()
        && tx.inputs[0].previous_output.vout == u32::MAX
}
