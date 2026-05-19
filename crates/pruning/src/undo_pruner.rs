use alloc::sync::Arc;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::KvStore;

use crate::block_pruner::prune_prefixed_rows;
use crate::{PruneError, PruneOutcome, PrunePolicy};

const BLOCK_UNDO_PREFIX: u8 = b'u';
const BLOCK_UNDO_PREFIX_BYTES: &[u8] = b"u";
const HEIGHT_START: usize = 1;
const HEIGHT_END: usize = 5;
const KEY_LEN: usize = 37;

/// Builds the canonical pruning key for stored undo data for one block.
#[must_use]
pub fn block_undo_key(height: u32, hash: Hash256) -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    key[0] = BLOCK_UNDO_PREFIX;
    key[HEIGHT_START..HEIGHT_END].copy_from_slice(&height.to_be_bytes());
    key[HEIGHT_END..].copy_from_slice(hash.as_byte_array());
    key
}

/// Prunes persisted undo rows according to a [`PrunePolicy`].
pub struct UndoPruner<S: KvStore> {
    store: Arc<S>,
    policy: PrunePolicy,
}

impl<S: KvStore> UndoPruner<S> {
    /// Creates an undo pruner over `store`.
    #[must_use]
    pub const fn new(store: Arc<S>, policy: PrunePolicy) -> Self {
        Self { store, policy }
    }

    /// Returns this pruner's policy.
    #[must_use]
    pub const fn policy(&self) -> PrunePolicy {
        self.policy
    }

    /// Deletes undo rows below the effective reorg-safety horizon until the target is met.
    pub fn prune_step(&mut self, current_tip_height: u32) -> Result<PruneOutcome, PruneError> {
        if self.policy.is_full_node() {
            return Ok(PruneOutcome::default());
        }

        prune_prefixed_rows(
            &*self.store,
            BLOCK_UNDO_PREFIX_BYTES,
            current_tip_height,
            self.policy,
        )
    }
}
