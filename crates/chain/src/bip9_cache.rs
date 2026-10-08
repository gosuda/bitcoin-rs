//! Bip9Cache — memoization layer for BIP9 deployment-state lookups.
//!
//! `compute_state` in [`crate::deployment`] performs recursive tree walks that
//! span entire retarget periods. Without memoization each `apply_block` would
//! pay ~351 retarget periods of MTP + vote-count lookups on mainnet Taproot.
//!
//! The cache is internal to that one contextual source: it stores only the
//! states the source resolved, keyed by `(node_id, deployment_id)`. Because a
//! node's state is a pure function of its ancestry, entries stay correct
//! across branch switches; entries for permanently invalid nodes are dropped
//! by `BlockTree::invalidate_subtree` via [`Bip9Cache::invalidate_node`].

use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::node::NodeId;

/// Cached BIP9 deployment-state lookup.
///
/// Wraps an interior `RwLock<HashMap>` so the cache is `Send + Sync` and the
/// reader/writer paths are non-blocking under contention. State is stored as
/// a stable `u8` tag supplied by the deployment-state encoder in consensus;
/// the chain crate does not interpret it.
///
/// PRE: a tag is the deployment state's encoded discriminant.
/// POST: cache readers obtain the same tag for a live `(node_id, deployment_id)`.
/// INVARIANT: Branch invalidation discards entries by node, not by height.
#[derive(Default)]
pub(crate) struct Bip9Cache {
    entries: RwLock<HashMap<(NodeId, u32), u8>>,
}

impl Bip9Cache {
    /// Inserts or updates the cached state for `(node_id, deployment_id)`.
    pub(crate) fn insert(&self, node_id: NodeId, deployment_id: u32, tag: u8) {
        self.entries.write().insert((node_id, deployment_id), tag);
    }

    /// Returns the cached state tag for `(node_id, deployment_id)`, if any.
    #[must_use]
    pub(crate) fn get(&self, node_id: NodeId, deployment_id: u32) -> Option<u8> {
        self.entries.read().get(&(node_id, deployment_id)).copied()
    }

    /// Removes every cached deployment state for `node_id`, keeping other
    /// nodes' entries. Used when the node's subtree is invalidated.
    pub(crate) fn invalidate_node(&self, node_id: NodeId) {
        self.entries.write().retain(|(id, _), _| *id != node_id);
    }
}
