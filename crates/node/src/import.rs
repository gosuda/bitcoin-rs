//! Block import pipeline (skeleton).
//!
//! The real pipeline lands as follow-up turns wire P2P → download →
//! decode → consensus validation → UTXO commit → chain tip advance
//! → index / filter / coinstats updates → RPC long-poll wake. This
//! file declares the contract those commits fill in.

use anyhow::{Context as _, Result};

use bitcoin_rs_primitives::{Block, Hash256};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, CompactTarget, LockTime, Script, Sequence, Witness};

use crate::state::NodeState;

/// Outcome of importing one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Block hash in canonical little-endian form.
    pub hash: Hash256,
    /// Number of transactions in the block.
    pub tx_count: usize,
    /// Whether the block was applied to the active chain.
    ///
    /// Successful decode now publishes the block as a synthetic active-chain
    /// tip through [`NodeState::apply_block`].
    pub applied: bool,
}

/// Decodes `block_bytes`, applies the decoded block, and returns the outcome.
///
/// V1 contract: synthetically apply after decode. Returns an error if the bytes
/// are malformed or the block cannot connect to the current synthetic tip.
pub fn import_block(state: &NodeState, block_bytes: &[u8]) -> Result<ImportOutcome> {
    let block = Block::consensus_decode(block_bytes)
        .with_context(|| format!("decode block ({} bytes)", block_bytes.len()))?;
    let hash = block.block_hash().0;
    let tx_count = block.txs.len();
    let _tip = state.apply_block(&block).context("apply_block")?;
    Ok(ImportOutcome {
        hash,
        tx_count,
        applied: true,
    })
}

#[cfg(test)]
mod tests;
