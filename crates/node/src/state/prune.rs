//! Manual pruning serialized against authoritative chain transitions.

use anyhow::Result;
use anyhow::bail;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN;
use bitcoin_rs_primitives::deserialize;
use bitcoin_rs_rpc::context::BlockLog;
use bitcoin_rs_rpc::context::PruneResult;
use bitcoin_rs_rpc::context::PruneService;
use bitcoin_rs_rpc::context::PruneServiceError;
use bitcoin_rs_rpc::context::PruneStatus;
use bitcoin_rs_storage::ColumnFamily;
use bitcoin_rs_storage::FlatFileBlockStore;
use bitcoin_rs_storage::pruning::PrunePolicy;
use bitcoin_rs_storage::pruning::reclaim_staged_flat_block_files;
use bitcoin_rs_storage::pruning::stage_block_and_undo_prune;
use bitcoin_rs_storage::{KvStore, WriteBatch};
use core::mem::size_of;
use hashbrown::HashMap;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

const PRUNEHEIGHT_METADATA_KEY: &[u8] = b"node:pruneheight";

pub(super) fn load_pruneheight<S: KvStore>(store: &S) -> Result<Option<u32>> {
    let Some(bytes) = store.get(ColumnFamily::UtxoMeta, PRUNEHEIGHT_METADATA_KEY)? else {
        return Ok(None);
    };
    if bytes.len() != size_of::<u32>() {
        bail!("invalid persisted pruneheight length {}", bytes.len());
    }
    let mut encoded = [0_u8; size_of::<u32>()];
    encoded.copy_from_slice(&bytes);
    Ok(Some(u32::from_be_bytes(encoded)))
}

/// Storage-backed implementation of RPC manual pruning.
pub struct NodePruneService<S: KvStore> {
    store: Arc<S>,
    block_files: Arc<FlatFileBlockStore>,
    block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
    blocks: Arc<RwLock<BlockLog>>,
    transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    authority: crate::apply::PruneAuthority,
    pruneheight: Mutex<Option<u32>>,
    /// Height the last clean checkpoint would restore to, 0 when none exists.
    ///
    /// Undo pruning is bounded by this, not by the in-memory applied tip, which
    /// can run far ahead of it.
    durable_tip_height: Arc<AtomicU32>,
}

impl<S: KvStore> NodePruneService<S> {
    /// Creates a manual pruning service over the chainstate store and RPC block cache.
    pub(crate) fn new(
        store: Arc<S>,
        block_files: Arc<FlatFileBlockStore>,
        block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
        authority: crate::apply::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
    ) -> Result<Self> {
        let pruneheight = load_pruneheight(&*store)?;
        Ok(Self {
            store,
            block_files,
            block_body_store,
            blocks,
            transactions,
            authority,
            pruneheight: Mutex::new(pruneheight),
            durable_tip_height,
        })
    }
}

impl<S: KvStore> PruneService for NodePruneService<S> {
    fn prune_to_height(
        &self,
        requested_height: u32,
    ) -> core::result::Result<PruneResult, PruneServiceError> {
        let policy = PrunePolicy {
            target_size_mb: 0,
            keep_below_tip: CORE_REORG_SAFETY_MARGIN,
        };
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
        let safe_prune_height = applied_tip_height.saturating_sub(policy.retention_depth());
        if updated_pruneheight > safe_prune_height {
            return Err(PruneServiceError::failed(
                "prune height is within reorg safety margin",
            ));
        }
        let pruner_tip = updated_pruneheight
            .checked_add(policy.retention_depth())
            .ok_or_else(|| PruneServiceError::failed("prune height overflow"))?;

        let durable_tip_height = self.durable_tip_height.load(Ordering::Acquire);
          let effective_prune_below = pruner_tip
              .min(durable_tip_height)
              .saturating_sub(policy.retention_depth());
          let prune_candidates: Vec<(u32, bitcoin_rs_primitives::BlockHash, usize)> = {
            let blocks = self.blocks.read();
            blocks
                .iter()
                .filter(|record| record.height < effective_prune_below && record.tx_count > 0)
                .map(|record| (record.height, record.hash, record.tx_count))
                .collect()
        };

        let mut pruned_txids = Vec::new();
        for (height, hash, tx_count) in prune_candidates {
            if tx_count == 0 {
                continue;
            }
            let bytes = self
                .block_body_store
                .load_block_body(height, hash.0)
                .map_err(|error| PruneServiceError::failed(error.to_string()))?
                .unwrap_or_default();
            if bytes.is_empty() {
                continue;
            }
            let block = deserialize::<Block>(&bytes).map_err(|error| {
                PruneServiceError::failed(format!(
                    "stored block body at height {height} failed decode: {error}"
                ))
            })?;
            pruned_txids.extend(block.txs.iter().map(Tx::txid));
        }
        let mut batch = self.store.new_batch();
        let (block_outcome, undo_outcome, prunable_files) = stage_block_and_undo_prune(
            &*self.store,
            &mut batch,
            &self.block_files,
            pruner_tip,
            self.durable_tip_height.load(Ordering::Acquire),
            policy,
        )
        .map_err(|err| PruneServiceError::failed(err.to_string()))?;
        batch.put(
            ColumnFamily::UtxoMeta,
            PRUNEHEIGHT_METADATA_KEY,
            &updated_pruneheight.to_be_bytes(),
        );
        self.store
            .write(batch)
            .map_err(|err| PruneServiceError::failed(err.to_string()))?;
        reclaim_staged_flat_block_files(&*self.store, &self.block_files, &prunable_files)
            .map_err(|err| PruneServiceError::failed(err.to_string()))?;

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
            block_rows_removed: block_outcome.blocks_removed,
            undo_rows_removed: undo_outcome.blocks_removed,
            bytes_freed: block_outcome
                .bytes_freed
                .saturating_add(undo_outcome.bytes_freed),
        })
    }

    fn status(&self) -> PruneStatus {
        PruneStatus {
            pruned: true,
            pruneheight: *self.pruneheight.lock(),
        }
    }
}
