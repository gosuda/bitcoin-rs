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

/// Canonical durable cursor owned by the index subsystem.
pub use index_reconcile::ConsumerCursor;

/// Builds the canonical cursor from one coherent node snapshot.
#[must_use]
pub const fn cursor_from_snapshot(snapshot: &ChainSnapshot) -> ConsumerCursor {
    ConsumerCursor {
        epoch: snapshot.epoch,
        sequence: snapshot.sequence,
        height: snapshot.tip_height,
        hash: snapshot.tip_hash,
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
    index_reconcile::plan(cursor, target(target_tip), &chain)
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
        cursor,
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
