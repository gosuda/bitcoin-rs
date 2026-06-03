use alloc::sync::Arc;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch};

use crate::{PruneError, PruneOutcome, PrunePolicy, row_len_u64};

const BLOCK_BODY_PREFIX: u8 = b'b';
pub(crate) const BLOCK_BODY_PREFIX_BYTES: &[u8] = b"b";
const HEIGHT_START: usize = 1;
const HEIGHT_END: usize = 5;
const KEY_LEN: usize = 37;

/// Column family used for serialized block-body rows.
pub const BLOCK_DATA_CF: ColumnFamily = ColumnFamily::BlockBodies;

/// Builds the canonical pruning key for a stored block body.
#[must_use]
pub fn block_body_key(height: u32, hash: Hash256) -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    key[0] = BLOCK_BODY_PREFIX;
    key[HEIGHT_START..HEIGHT_END].copy_from_slice(&height.to_be_bytes());
    key[HEIGHT_END..].copy_from_slice(hash.as_byte_array());
    key
}

/// Prunes persisted block-body rows according to a [`PrunePolicy`].
pub struct BlockPruner<S: KvStore> {
    store: Arc<S>,
    policy: PrunePolicy,
}

impl<S: KvStore> BlockPruner<S> {
    /// Creates a block pruner over `store`.
    #[must_use]
    pub const fn new(store: Arc<S>, policy: PrunePolicy) -> Self {
        Self { store, policy }
    }

    /// Returns this pruner's policy.
    #[must_use]
    pub const fn policy(&self) -> PrunePolicy {
        self.policy
    }

    /// Deletes block-body rows below the effective reorg-safety horizon until the target is met.
    pub fn prune_step(&mut self, current_tip_height: u32) -> Result<PruneOutcome, PruneError> {
        if self.policy.is_full_node() {
            return Ok(PruneOutcome::default());
        }

        prune_prefixed_rows(
            &*self.store,
            BLOCK_DATA_CF,
            BLOCK_BODY_PREFIX_BYTES,
            current_tip_height,
            self.policy,
        )
    }
}

pub(crate) fn prune_prefixed_rows<S: KvStore>(
    store: &S,
    cf: ColumnFamily,
    prefix: &[u8],
    current_tip_height: u32,
    policy: PrunePolicy,
) -> Result<PruneOutcome, PruneError> {
    let mut batch = store.new_batch();
    let outcome =
        prune_prefixed_rows_into_batch(store, &mut batch, cf, prefix, current_tip_height, policy)?;

    if !outcome.is_empty() {
        store.write(batch)?;
        tracing::debug!(
            bytes_freed = outcome.bytes_freed,
            blocks_removed = outcome.blocks_removed,
            "pruned block storage rows"
        );
    }

    Ok(outcome)
}

pub(crate) fn prune_prefixed_rows_into_batch<S: KvStore>(
    store: &S,
    batch: &mut S::WriteBatch,
    cf: ColumnFamily,
    prefix: &[u8],
    current_tip_height: u32,
    policy: PrunePolicy,
) -> Result<PruneOutcome, PruneError> {
    let target_bytes = policy.target_size_bytes();
    let prune_below_height = current_tip_height.saturating_sub(policy.retention_depth());
    let mut total_bytes = 0_u64;
    let mut candidates = Vec::new();

    for row in store.iter_prefix(cf, prefix)? {
        let (key, value) = row?;
        let row_bytes = row_len_u64(&value)?;
        total_bytes = total_bytes.saturating_add(row_bytes);

        if let Some(height) = row_height(&key, prefix)
            && height < prune_below_height
        {
            candidates.push((key, row_bytes));
        }
    }

    if total_bytes <= target_bytes || candidates.is_empty() {
        return Ok(PruneOutcome::default());
    }

    let mut remaining_bytes = total_bytes;
    let mut outcome = PruneOutcome::default();

    for (key, row_bytes) in candidates {
        if remaining_bytes <= target_bytes {
            break;
        }

        batch.delete(cf, &key);
        remaining_bytes = remaining_bytes.saturating_sub(row_bytes);
        outcome.record_removed(row_bytes);
    }

    Ok(outcome)
}

fn row_height(key: &[u8], prefix: &[u8]) -> Option<u32> {
    if key.len() != KEY_LEN || !key.starts_with(prefix) {
        return None;
    }

    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&key[HEIGHT_START..HEIGHT_END]);
    Some(u32::from_be_bytes(bytes))
}
