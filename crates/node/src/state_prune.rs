//! Manual pruning serialized against authoritative chain transitions.

use bitcoin_rs_index::block_log::BlockLog;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_primitives::deserialize;
use bitcoin_rs_rpc::context::PruneResult;
use bitcoin_rs_rpc::context::PruneService;
use bitcoin_rs_rpc::context::PruneServiceError;
use bitcoin_rs_rpc::context::PruneStatus;
use bitcoin_rs_storage::FlatFileBlockStore;
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::pruning::PruneError;
use hashbrown::HashMap;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

/// Storage-backed implementation of RPC manual pruning.
pub(super) struct NodePruneService<S: KvStore> {
    store: Arc<S>,
    block_files: Arc<FlatFileBlockStore>,
    block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
    blocks: Arc<RwLock<BlockLog>>,
    transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    authority: bitcoin_rs_chainstate::PruneAuthority,
    pruneheight: Mutex<Option<u32>>,
    /// Height the last clean checkpoint would restore to, 0 when none exists.
    ///
    /// Undo pruning is bounded by this, not by the in-memory applied tip, which
    /// can run far ahead of it.
    durable_tip_height: Arc<AtomicU32>,
    /// Registry the prune line is recorded into after a committed pass, and
    /// whose live leases clamp this pass's line below every pinned floor.
    retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
}

impl<S: KvStore> NodePruneService<S> {
    /// Creates a manual pruning service over the chainstate store and RPC block cache.
    pub(crate) fn new(
        store: Arc<S>,
        block_files: Arc<FlatFileBlockStore>,
        block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
        authority: bitcoin_rs_chainstate::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
        retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    ) -> anyhow::Result<Self> {
        let pruneheight = bitcoin_rs_storage::pruning::load_pruneheight(&*store)?;
        Ok(Self {
            store,
            block_files,
            block_body_store,
            blocks,
            transactions,
            authority,
            pruneheight: Mutex::new(pruneheight),
            durable_tip_height,
            retention,
        })
    }
}

impl<S: KvStore> PruneService for NodePruneService<S> {
    fn prune_to_height(
        &self,
        requested_height: u32,
    ) -> core::result::Result<PruneResult, PruneServiceError> {
        let authority = self
            .authority
            .begin()
            .map_err(|error| PruneServiceError::failed(error.to_string()))?;
        let applied_tip_height = authority
            .applied_tip_height()
            .ok_or_else(|| PruneServiceError::failed("applied tip is unavailable"))?;
        let mut pruneheight = self.pruneheight.lock();
        let updated_pruneheight =
            pruneheight.map_or(requested_height, |height| height.max(requested_height));
        let durable_tip_height = self.durable_tip_height.load(Ordering::Acquire);
        let mut pruned_txids = Vec::new();
        let staged = bitcoin_rs_storage::pruning::prune_to_height(
            &*self.store,
            &self.block_files,
            &self.retention,
            applied_tip_height,
            durable_tip_height,
            updated_pruneheight,
            |pruned_below| {
                let prune_candidates: Vec<(u32, bitcoin_rs_primitives::BlockHash)> = {
                    let blocks = self.blocks.read();
                    blocks
                        .iter()
                        .filter(|record| record.height < pruned_below && record.tx_count > 0)
                        .map(|record| (record.height, record.hash))
                        .collect()
                };
                for (height, hash) in prune_candidates {
                    let bytes = self
                        .block_body_store
                        .load_block_body(height, hash.0)?
                        .unwrap_or_default();
                    if bytes.is_empty() {
                        continue;
                    }
                    let block = deserialize::<Block>(&bytes).map_err(|error| {
                        StorageError::IncompatibleData(format!(
                            "stored block body at height {height} failed decode: {error}"
                        ))
                    })?;
                    pruned_txids.extend(block.txs.iter().map(Tx::txid));
                }
                Ok(())
            },
        )
        .map_err(|err| match err {
            // The reorg-margin/overflow refusals are operator-facing RPC text; pass them through verbatim.
            PruneError::Storage(StorageError::InvalidOperation(message)) => {
                PruneServiceError::failed(message)
            }
            other => PruneServiceError::failed(other.to_string()),
        })?;

        if !pruned_txids.is_empty() {
            let mut transactions = self.transactions.write();
            for txid in pruned_txids {
                transactions.remove(&txid);
            }
        }

        *pruneheight = Some(updated_pruneheight);

        Ok(PruneResult {
            requested_height,
            pruneheight: updated_pruneheight,
            block_rows_removed: staged.blocks.blocks_removed,
            undo_rows_removed: staged.undo.blocks_removed,
            bytes_freed: staged
                .blocks
                .bytes_freed
                .saturating_add(staged.undo.bytes_freed),
        })
    }

    fn status(&self) -> PruneStatus {
        PruneStatus {
            pruned: true,
            pruneheight: *self.pruneheight.lock(),
        }
    }
}
