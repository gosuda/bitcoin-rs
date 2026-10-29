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
pub(crate) const MAX_UNDO_QUERY_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_BLOCK_QUERY_BYTES: usize = 4_000_000;

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
        let segwit_active = {
            let tree = self.block_tree.read();
            let id = tree.lookup(hash).ok_or(BlockSpendsError::Corrupt(
                "retained body header is absent from the block tree",
            ))?;
            bitcoin_rs_chain::deployment_statuses(&tree, self.network, Some(id))
                .map_err(|error| match error {
                    bitcoin_rs_chain::DeploymentQueryError::Budget { .. } => {
                        BlockSpendsError::ResourceLimit
                    }
                    bitcoin_rs_chain::DeploymentQueryError::Chain(_)
                    | bitcoin_rs_chain::DeploymentQueryError::IncompleteAncestry => {
                        BlockSpendsError::Corrupt("block deployment ancestry is inconsistent")
                    }
                })?
                .into_iter()
                .find(|status| status.name == "segwit")
                .ok_or(BlockSpendsError::Corrupt(
                    "SegWit deployment status is absent",
                ))?
                .active_at_block
        };
        bitcoin_rs_consensus::check_block_body_binding(&block, segwit_active).map_err(|_| {
            BlockSpendsError::Corrupt("block body does not match its header commitments")
        })?;
        drop(bytes);
        if height == 0 && hash == self.network.genesis_block_hash() {
            return Ok(BlockSpends {
                block,
                spent: Ok(vec![Vec::new()]),
            });
        }
        if let Err(reason) = availability {
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

#[cfg(test)]
mod tests;
