//! Bip9Cache — memoization layer for BIP9 deployment-state lookups.
//!
//! `compute_state` in node::bip9_context performs recursive tree walks that
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
pub struct Bip9Cache {
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
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or updates the cached state for `(node_id, deployment_id)`.
    pub fn insert(&self, node_id: NodeId, deployment_id: u32, state: CachedState) {
        self.entries.write().insert((node_id, deployment_id), state);
    }

    /// Returns the cached state for `(node_id, deployment_id)`, if any.
    #[must_use]
    pub fn get(&self, node_id: NodeId, deployment_id: u32) -> Option<CachedState> {
        self.entries.read().get(&(node_id, deployment_id)).copied()
    }

    /// Removes the cached state for `(node_id, deployment_id)`. Used on reorg.
    pub fn invalidate(&self, node_id: NodeId, deployment_id: u32) {
        self.entries.write().remove(&(node_id, deployment_id));
    }

    /// Removes every cached deployment state for `node_id`, keeping other
    /// nodes' entries. Used when the node's subtree is invalidated.
    pub fn invalidate_node(&self, node_id: NodeId) {
        self.entries.write().retain(|(id, _), _| *id != node_id);
    }

    /// Clears every cached entry.
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Returns the number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns true when no entries are cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_returns_none() {
        let cache = Bip9Cache::new();
        let node_id = NodeId::new(0);
        assert!(cache.get(node_id, 0).is_none());
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn insert_and_retrieve_round_trips() {
        let cache = Bip9Cache::new();
        let node_id = NodeId::new(42);
        let state = CachedState {
            tag: 3,
            since_height: 709_632,
        };
        cache.insert(node_id, 1, state);
        let Some(retrieved) = cache.get(node_id, 1) else {
            panic!("expected cached state");
        };
        assert_eq!(retrieved.tag, 3);
        assert_eq!(retrieved.since_height, 709_632);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = Bip9Cache::new();
        let node_id = NodeId::new(0);
        cache.insert(
            node_id,
            0,
            CachedState {
                tag: 1,
                since_height: 0,
            },
        );
        cache.invalidate(node_id, 0);
        assert!(cache.get(node_id, 0).is_none());
    }

    #[test]
    fn invalidate_node_removes_every_deployment_of_that_node_only() {
        let cache = Bip9Cache::new();
        let node_id = NodeId::new(7);
        let other_id = NodeId::new(8);
        for deployment_id in 0..2_u32 {
            cache.insert(
                node_id,
                deployment_id,
                CachedState {
                    tag: 1,
                    since_height: 0,
                },
            );
        }
        cache.insert(
            other_id,
            0,
            CachedState {
                tag: 1,
                since_height: 0,
            },
        );

        cache.invalidate_node(node_id);

        assert!(cache.get(node_id, 0).is_none());
        assert!(cache.get(node_id, 1).is_none());
        assert!(cache.get(other_id, 0).is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn clear_empties_all_entries() {
        let cache = Bip9Cache::new();
        let node_id_a = NodeId::new(0);
        let node_id_b = NodeId::new(1);
        cache.insert(
            node_id_a,
            0,
            CachedState {
                tag: 1,
                since_height: 0,
            },
        );
        cache.insert(
            node_id_b,
            0,
            CachedState {
                tag: 1,
                since_height: 0,
            },
        );
        cache.clear();
        assert!(cache.is_empty());
    }
}
