//! Node adapter for index-owned positional reconciliation.
//!
//! `bitcoin-rs-index` owns cursor encoding and rollback/forward/rebuild policy.
//! Node contributes only its coherent [`ChainSnapshot`] shape and an adapter
//! over the authoritative [`BlockTree`].

use bitcoin_rs_chain::{BlockTree, NodeId, TipSnapshot};
use bitcoin_rs_index::reconcile as index_reconcile;
use bitcoin_rs_primitives::Hash256;

use crate::state::ChainSnapshot;

/// Durable cursor length, owned by the index subsystem.
pub const CURSOR_BYTE_LEN: usize = index_reconcile::CURSOR_BYTE_LEN;

/// Node-facing cursor shape for callers that consume [`ChainSnapshot`].
///
/// Durable representation and reconciliation semantics are owned by
/// [`bitcoin_rs_index::reconcile::ConsumerCursor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumerCursor {
    /// Process epoch the consumed events belong to.
    pub epoch: u64,
    /// Commit-counter value of the last consumed event.
    pub sequence: u64,
    /// Height of the mirrored tip.
    pub height: u32,
    /// Hash of the mirrored tip.
    pub hash: Hash256,
}

impl ConsumerCursor {
    /// Builds a cursor from one coherent node snapshot.
    #[must_use]
    pub const fn from_snapshot(snapshot: &ChainSnapshot) -> Self {
        Self {
            epoch: snapshot.epoch,
            sequence: snapshot.sequence,
            height: snapshot.tip_height,
            hash: snapshot.tip_hash,
        }
    }

    /// Encodes the index-owned durable representation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CURSOR_BYTE_LEN] {
        self.as_index_cursor().to_bytes()
    }

    /// Decodes the index-owned durable representation.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        index_reconcile::ConsumerCursor::from_bytes(bytes).map(Self::from_index_cursor)
    }

    const fn as_index_cursor(self) -> index_reconcile::ConsumerCursor {
        index_reconcile::ConsumerCursor {
            epoch: self.epoch,
            sequence: self.sequence,
            height: self.height,
            hash: self.hash,
        }
    }

    const fn from_index_cursor(cursor: index_reconcile::ConsumerCursor) -> Self {
        Self {
            epoch: cursor.epoch,
            sequence: cursor.sequence,
            height: cursor.height,
            hash: cursor.hash,
        }
    }
}

pub use index_reconcile::ReconcilePlan;

struct BlockTreeActiveChain<'a> {
    tree: &'a BlockTree,
    active_tip: NodeId,
}

impl index_reconcile::ActiveChainView for BlockTreeActiveChain<'_> {
    fn contains(&self, position: Hash256) -> bool {
        self.tree.lookup(position).is_some()
    }

    fn position_on_active_chain(&self, position: Hash256, height: u32) -> bool {
        let Some(position_id) = self.tree.lookup(position) else {
            return false;
        };
        self.tree
            .node_at_height_from(self.active_tip, height)
            .is_some_and(|active| active == position_id)
    }

    fn common_ancestor_height(&self, position: Hash256) -> Option<u32> {
        let position_id = self.tree.lookup(position)?;
        let ancestor = self.tree.find_common_ancestor(position_id, self.active_tip)?;
        self.tree.node(ancestor).ok().map(|node| node.height)
    }
}

const fn target(tip: &TipSnapshot) -> index_reconcile::ChainTip {
    index_reconcile::ChainTip {
        hash: tip.hash,
        height: tip.height,
    }
}

const fn identity(snapshot: &ChainSnapshot) -> index_reconcile::ChainIdentity {
    index_reconcile::ChainIdentity {
        epoch: snapshot.epoch,
        sequence: snapshot.sequence,
        tip_hash: snapshot.tip_hash,
        tip_height: snapshot.tip_height,
    }
}

/// Plans one reconciliation pass through index-owned policy.
#[must_use]
pub fn plan(cursor: &ConsumerCursor, target_tip: &TipSnapshot, tree: &BlockTree) -> ReconcilePlan {
    let chain = BlockTreeActiveChain {
        tree,
        active_tip: target_tip.tip_id,
    };
    index_reconcile::plan(&cursor.as_index_cursor(), target(target_tip), &chain)
}

/// Plans from a coherent node snapshot through index-owned policy.
#[must_use]
pub fn plan_from_snapshot(
    cursor: &ConsumerCursor,
    snapshot: &ChainSnapshot,
    target_tip: &TipSnapshot,
    tree: &BlockTree,
) -> ReconcilePlan {
    let chain = BlockTreeActiveChain {
        tree,
        active_tip: target_tip.tip_id,
    };
    index_reconcile::plan_from_identity(
        &cursor.as_index_cursor(),
        &identity(snapshot),
        target(target_tip),
        &chain,
    )
}

/// Height of the newest block shared by `position` and `active_tip`.
#[must_use]
pub fn common_ancestor_height(
    tree: &BlockTree,
    position: Hash256,
    active_tip: NodeId,
) -> Option<u32> {
    let chain = BlockTreeActiveChain { tree, active_tip };
    index_reconcile::ActiveChainView::common_ancestor_height(&chain, position)
}

/// Canonical stale-branch depth, with the decision owned by `index`.
#[must_use]
pub fn rollback_depth(
    tree: &BlockTree,
    position: Hash256,
    position_height: u32,
    active_tip: NodeId,
) -> Option<u32> {
    let chain = BlockTreeActiveChain { tree, active_tip };
    index_reconcile::rollback_depth(&chain, position, position_height)
}

/// Whether `position` at `height` lies on the selected active chain.
#[must_use]
pub fn position_on_active_chain(
    tree: &BlockTree,
    position: Hash256,
    height: u32,
    active_tip: NodeId,
) -> bool {
    let chain = BlockTreeActiveChain { tree, active_tip };
    index_reconcile::ActiveChainView::position_on_active_chain(&chain, position, height)
}
