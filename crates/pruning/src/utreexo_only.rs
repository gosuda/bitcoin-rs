use alloc::sync::Arc;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{KvStore, WriteBatch};

use crate::block_pruner::{BLOCK_DATA_CF, block_body_key};
use crate::{PruneError, PruneOutcome, PrunePolicy, row_len_u64};

/// Event emitted after a block has been indexed, filter-indexed, and committed to the UTXO view.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockProcessed {
    /// Connected block height.
    pub height: u32,
    /// Connected block hash.
    pub hash: Hash256,
    /// Serialized block-body byte count reported by the caller.
    pub body_bytes: u64,
}

/// Coordinates immediate block-body deletion for Utreexo-only operation.
pub struct UtreexoOnlyCoordinator<S: KvStore> {
    store: Arc<S>,
    policy: PrunePolicy,
}

impl<S: KvStore> UtreexoOnlyCoordinator<S> {
    /// Creates a coordinator over `store`.
    #[must_use]
    pub const fn new(store: Arc<S>, policy: PrunePolicy) -> Self {
        Self { store, policy }
    }

    /// Returns true when this coordinator will delete block bodies.
    #[must_use]
    pub const fn is_engaged(&self) -> bool {
        self.policy.is_utreexo_only()
    }

    /// Deletes the processed block body when Utreexo-only pruning is active.
    pub fn block_processed(&mut self, event: BlockProcessed) -> Result<PruneOutcome, PruneError> {
        if !self.is_engaged() {
            return Ok(PruneOutcome::default());
        }

        let key = block_body_key(event.height, event.hash);
        let Some(body) = self.store.get(BLOCK_DATA_CF, &key)? else {
            return Ok(PruneOutcome::default());
        };

        let mut outcome = PruneOutcome::default();
        outcome.record_removed(row_len_u64(&body)?);

        let mut batch = self.store.new_batch();
        batch.delete(BLOCK_DATA_CF, &key);
        self.store.write(batch)?;

        tracing::debug!(
            height = event.height,
            hash = %event.hash,
            bytes_freed = outcome.bytes_freed,
            reported_body_bytes = event.body_bytes,
            "dropped Utreexo-only block body"
        );

        Ok(outcome)
    }
}
