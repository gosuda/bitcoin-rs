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
/// a stable `u8` tag supplied by consensus and a `u32` height marker for the
/// activation epoch.
#[derive(Debug, Default)]
pub(crate) struct Bip9Cache {
    entries: RwLock<HashMap<(NodeId, u32), CachedState>>,
}

/// Cached deployment-state record.
///
/// The `tag` is an opaque stable u8 supplied by the deployment-state encoder;
/// the chain crate does not interpret it. The `since_height` is the activation
/// (or start-of-current-period) height for diagnostic display.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachedState {
    /// Caller-defined state discriminant.
    pub tag: u8,
    /// Block height at which the state was determined.
    pub since_height: u32,
}

impl Bip9Cache {
    /// Builds an empty cache.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Inserts or updates the cached state for `(node_id, deployment_id)`.
    pub(crate) fn insert(&self, node_id: NodeId, deployment_id: u32, state: CachedState) {
        self.entries.write().insert((node_id, deployment_id), state);
    }

    /// Returns the cached state for `(node_id, deployment_id)`, if any.
    #[must_use]
    pub(crate) fn get(&self, node_id: NodeId, deployment_id: u32) -> Option<CachedState> {
        self.entries.read().get(&(node_id, deployment_id)).copied()
    }

    /// Removes every cached deployment state for `node_id`, keeping other
    /// nodes' entries. Used when the node's subtree is invalidated.
    pub(crate) fn invalidate_node(&self, node_id: NodeId) {
        self.entries.write().retain(|(id, _), _| *id != node_id);
    }
}
