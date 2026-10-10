//! Read-only, receipt-checked access to the existing retained undo owner.

use std::sync::atomic::Ordering;

use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_primitives::{Block, Hash256, deserialize};
use bitcoin_rs_storage::{DurableHead, pruning::HistoryLease};
use bitcoin_rs_utxo::contract::{
    BlockSpends, BlockSpendsError, BlockUndoSource, HistoryUnavailable, UndoLoadError,
    block_spent_outputs, decode_undo_record_for_block,
};

use crate::{AssumeUtxoDiskStatus, Chainstate};

/// Limit the owned raw record before copying and decoding. Engine-internal
/// pages/cache/decompression are outside the storage method's copy bound.
const MAX_UNDO_QUERY_BYTES: usize = 64 * 1024 * 1024;
const MAX_BLOCK_QUERY_BYTES: usize = 4_000_000;
/// Conservative upper bound on verbose script/transaction expansion.
const MAX_PROJECTED_QUERY_BYTES: usize = 64 * 1024 * 1024;

impl BlockUndoSource for Chainstate {
    fn block_spends(
        &self,
        hash: Hash256,
        expected_applied_hash: Hash256,
    ) -> Result<BlockSpends, BlockSpendsError> {
        let (head, height, lease, availability) = {
            let _transition = self.chain_transition.lock();
            self.check_undo_read_state(expected_applied_hash)?;
            let tree = self.block_tree.read();
            let node = tree
                .node_by_hash(hash)
                .ok_or(BlockSpendsError::UnknownBlock)?;
            let height = node.height;
            drop(tree);
            let head = self
                .durable_head
                .load()?
                .ok_or(HistoryUnavailable::Missing)?;
            if head.tip != expected_applied_hash {
                return Err(BlockSpendsError::Retry);
            }
            let (lease, availability) = match self.history.request_history(height) {
                Ok(lease) => {
                    let availability = if certified(&self.block_tree.read(), &head, height, hash)? {
                        Ok(())
                    } else {
                        Err(HistoryUnavailable::Missing)
                    };
                    (Some(lease), availability)
                }
                Err(reason @ HistoryUnavailable::Pruned { .. }) => (None, Err(reason)),
                Err(reason) => return Err(reason.into()),
            };
            (head, height, lease, availability)
        };
        // No tree/write/transition lock spans body I/O, decoding or projection.
        let result = self.read_block_spends(hash, height, availability);
        self.recheck_undo_read(
            expected_applied_hash,
            &head,
            height,
            lease.as_ref(),
            availability,
        )?;
        result
    }
}

impl Chainstate {
    fn check_undo_read_state(&self, expected: Hash256) -> Result<(), BlockSpendsError> {
        if self.is_closed_for_recovery() {
            return Err(BlockSpendsError::Closed);
        }
        if self.shutdown.load(Ordering::Acquire) {
            return Err(HistoryUnavailable::Shutdown.into());
        }
        let applied = self.applied_tip.load_full();
        let hash = applied
            .as_ref()
            .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash);
        if hash != expected {
            return Err(BlockSpendsError::Retry);
        }
        Ok(())
    }

    fn recheck_undo_read(
        &self,
        expected: Hash256,
        head: &DurableHead,
        height: u32,
        lease: Option<&HistoryLease>,
        availability: Result<(), HistoryUnavailable>,
    ) -> Result<(), BlockSpendsError> {
        let _transition = self.chain_transition.lock();
        self.check_undo_read_state(expected)?;
        if self.durable_head.load()?.as_ref() != Some(head) {
            return Err(BlockSpendsError::Retry);
        }
        if let Some(lease) = lease {
            if lease.floor() != Some(height) {
                let _probe = self.history.request_history(height)?;
                return Err(BlockSpendsError::Retry);
            }
        } else {
            match self.history.request_history(height) {
                Err(current) if availability == Err(current) => {}
                Err(current) => return Err(current.into()),
                Ok(_lease) => return Err(BlockSpendsError::Retry),
            }
        }
        Ok(())
    }

    fn read_block_spends(
        &self,
        hash: Hash256,
        height: u32,
        availability: Result<(), HistoryUnavailable>,
    ) -> Result<BlockSpends, BlockSpendsError> {
        let store = self
            .block_body_store
            .as_ref()
            .ok_or(BlockSpendsError::BodyRead(
                bitcoin_rs_storage::BoundedReadError::Unsupported,
            ))?;
        let bytes = store
            .load_block_body_bounded(height, hash, MAX_BLOCK_QUERY_BYTES)
            .map_err(BlockSpendsError::BodyRead)?
            .ok_or_else(|| availability.err().unwrap_or(HistoryUnavailable::Missing))?;
        let block: Block = deserialize(&bytes)
            .map_err(|_| BlockSpendsError::Corrupt("block body does not decode"))?;
        if block.block_hash().0 != hash {
            return Err(BlockSpendsError::Corrupt("block body hash differs"));
        }
        let txids = block
            .txs
            .iter()
            .map(bitcoin_rs_primitives::Tx::txid)
            .collect::<Vec<_>>();
        bitcoin_rs_consensus::verify_merkle_root_with_txids(&block, &txids).map_err(|_| {
            BlockSpendsError::Corrupt("transactions do not match the header merkle root")
        })?;
        drop(bytes);
        // Genesis has no spent inputs, but getblock still requires its real
        // retained body. Only the REST spent-output adapter can answer its
        // protocol-defined empty row without loading a body.
        if height == 0 && hash == self.network.genesis_block_hash() {
            return Ok(BlockSpends {
                block,
                spent: Ok(vec![Vec::new()]),
            });
        }
        if let Err(reason) = availability {
            ensure_projection_budget(&block, std::iter::empty())?;
            return Ok(BlockSpends {
                block,
                spent: Err(reason),
            });
        }
        let record = self
            .undo_store
            .load_undo_bounded(height, hash, MAX_UNDO_QUERY_BYTES)?
            .ok_or(UndoLoadError::Missing { hash, height })?;
        let undo = decode_undo_record_for_block(&record, &block)
            .map_err(|source| UndoLoadError::Unreadable { hash, source })?;
        drop(record);
        // Bound map/output allocation before copying each restored script.
        ensure_projection_budget(
            &block,
            undo.restores()
                .iter()
                .map(|coin| coin.txout.script_pubkey.len()),
        )?;
        let spent = block_spent_outputs(&block, height, &undo)?;
        Ok(BlockSpends {
            block,
            spent: Ok(spent),
        })
    }
}

fn ancestor_is(
    tree: &BlockTree,
    anchor: Hash256,
    height: u32,
    hash: Hash256,
    remaining: &mut usize,
) -> Result<bool, BlockSpendsError> {
    let Some(tip) = tree.lookup(anchor) else {
        return Ok(false);
    };
    Ok(tree
        .node_at_height_from_bounded(tip, height, remaining)
        .map_err(|_| BlockSpendsError::ResourceLimit)?
        .and_then(|id| tree.node(id).ok())
        .is_some_and(|node| node.hash == hash))
}

fn certified(
    tree: &BlockTree,
    head: &DurableHead,
    height: u32,
    hash: Hash256,
) -> Result<bool, BlockSpendsError> {
    // Shared across current, archive and retained-disconnect anchors. This
    // bounds time under the transition even when header sync selected a fork.
    let mut remaining = 4096;
    match head.assumeutxo {
        AssumeUtxoDiskStatus::Failed { .. } => return Err(BlockSpendsError::Closed),
        AssumeUtxoDiskStatus::Validating {
            base_height,
            historical_height,
            historical_hash,
            ..
        } if height <= base_height => {
            return if height <= historical_height {
                ancestor_is(tree, historical_hash, height, hash, &mut remaining)
            } else {
                Ok(false)
            };
        }
        _ => {}
    }
    if ancestor_is(tree, head.tip, height, hash, &mut remaining)? {
        return Ok(true);
    }
    match head.undo_extent {
        Some((extent_height, extent_hash)) if height <= extent_height => {
            ancestor_is(tree, extent_hash, height, hash, &mut remaining)
        }
        _ => Ok(false),
    }
}

fn ensure_projection_budget(
    block: &Block,
    restore_scripts: impl Iterator<Item = usize>,
) -> Result<(), BlockSpendsError> {
    // Hex/witness duplication, bounded fixed JSON fields per element, and a
    // conservative 64x expansion for script asm/hex/descriptor strings. Same-
    // block scripts occur in the body and at most once as a valid input.
    let mut estimate = block.total_size().saturating_mul(4);
    let mut scripts = restore_scripts.fold(0_usize, usize::saturating_add);
    for tx in &block.txs {
        estimate =
            estimate.saturating_add((tx.inputs.len() + tx.outputs.len() + 1).saturating_mul(1024));
        scripts = scripts.saturating_add(
            tx.inputs
                .iter()
                .map(|input| input.script_sig.len())
                .sum::<usize>(),
        );
        scripts = scripts.saturating_add(
            tx.outputs
                .iter()
                .map(|output| output.script_pubkey.len().saturating_mul(2))
                .sum::<usize>(),
        );
    }
    if estimate.saturating_add(scripts.saturating_mul(64)) > MAX_PROJECTED_QUERY_BYTES {
        return Err(BlockSpendsError::ResourceLimit);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/block_spends_tests.rs"]
mod tests;
