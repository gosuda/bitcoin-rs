//! Reusable chain-event reconciliation seam for index consumers (#77).
//!
//! A reconciliation consumer persists a [`ConsumerCursor`] naming the exact
//! chain state its rows already mirror. It wakes on a chain-event hint (or a
//! poll tick), reads a fresh chain snapshot, and re-plans from its own
//! persisted position over `BlockTree`. Hints are only wake-ups, never a
//! replay log: a dropped hint, a missed sequence range, or a process restart
//! all converge through the same position-based plan over the chain itself.

use bitcoin_rs_chain::{BlockTree, NodeId, TipSnapshot};
use bitcoin_rs_primitives::Hash256;

use crate::state::events::ChainSnapshot;

/// Durable cursor length: epoch (8 LE) + sequence (8 LE) + height (4 LE) + hash.
pub const CURSOR_BYTE_LEN: usize = 52;

/// Consumer view of the chain state its rows already mirror.
///
/// `epoch` and `sequence` name the publisher event stream the consumer
/// consumed; the row position itself is anchored by `height` and `hash`. A
/// new process epoch never invalidates rows, but it does invalidate the
/// advisory identity: a cursor from an older epoch must be re-planned from
/// its row position before it may be trusted again.
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
    /// Builds the cursor for a fully consumed snapshot.
    #[must_use]
    pub const fn from_snapshot(snapshot: &ChainSnapshot) -> Self {
        Self {
            epoch: snapshot.epoch,
            sequence: snapshot.sequence,
            height: snapshot.tip_height,
            hash: snapshot.tip_hash,
        }
    }

    /// Encodes the durable representation in [`Self::CURSOR_BYTE_LEN`] bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CURSOR_BYTE_LEN] {
        let mut bytes = [0_u8; CURSOR_BYTE_LEN];
        bytes[..8].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.height.to_le_bytes());
        bytes[20..].copy_from_slice(&self.hash.to_le_bytes());
        bytes
    }

    /// Decodes the durable representation; `None` on any length mismatch.
    ///
    /// A `None` result is advisory-cursor corruption only. Row correctness is
    /// anchored by the watermark, so consumers treat it as "no cursor" and
    /// re-plan from the row position.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CURSOR_BYTE_LEN {
            return None;
        }
        Some(Self {
            epoch: u64::from_le_bytes(bytes[..8].try_into().ok()?),
            sequence: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            height: u32::from_le_bytes(bytes[16..20].try_into().ok()?),
            hash: Hash256::from_le_bytes(&bytes[20..].try_into().ok()?),
        })
    }
}

/// What a consumer must do to move its rows onto the active chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcilePlan {
    /// The cursor names the live tip exactly; nothing to do.
    CaughtUp,
    /// The cursor position is on the active chain; connect
    /// `from_height..=target` in order.
    Forward {
        /// First height the consumer still has to index.
        from_height: u32,
    },
    /// The cursor position is orphaned; disconnect back to `ancestor_height`
    /// first, then connect forward. The ancestor lies on the active chain by
    /// construction, so the forward leg always resumes from it.
    RollbackAndForward {
        /// Last height shared by the cursor branch and the active chain.
        ancestor_height: u32,
    },
    /// The cursor block is absent from the tree (pruned or never seen);
    /// rebuild from the consumer's earliest anchor.
    Rebuild,
}

/// Plans one reconciliation pass for `cursor` against the applied tip.
///
/// This is the canonical decision for a single-position consumer. The
/// transaction index applies the same primitives through its per-capability
/// selection, because its two watermarks can diverge and roll back
/// independently; a consumer with one cursor calls this directly. The
/// epoch/sequence fields never alter the plan — rows survive restarts, so the
/// decision always derives from the cursor position on the current tree.
#[must_use]
pub fn plan(cursor: &ConsumerCursor, target: &TipSnapshot, tree: &BlockTree) -> ReconcilePlan {
    let Some(cursor_id) = tree.lookup(cursor.hash) else {
        return ReconcilePlan::Rebuild;
    };
    if cursor.height == target.height && cursor.hash == target.hash {
        return ReconcilePlan::CaughtUp;
    }
    if position_on_active_chain_by_id(tree, cursor_id, cursor.height, target.tip_id) {
        return ReconcilePlan::Forward {
            from_height: cursor.height.saturating_add(1),
        };
    }
    ReconcilePlan::RollbackAndForward {
        ancestor_height: common_ancestor_height(tree, cursor.hash, target.tip_id).unwrap_or(0),
    }
}

/// Plans reconciliation from a publisher snapshot and a tree tip.
///
/// Sequence continuity is only a wake-up optimization: a gap, epoch change,
/// or tip mismatch all use the same position-based rollback/forward plan.
/// This keeps dropped hints and process restarts equivalent to delivered hints.
#[must_use]
#[allow(clippy::suspicious_operation_groupings)]
pub fn plan_from_snapshot(
    cursor: &ConsumerCursor,
    snapshot: &ChainSnapshot,
    target: &TipSnapshot,
    tree: &BlockTree,
) -> ReconcilePlan {
    let identity_matches = cursor.epoch == snapshot.epoch
        && cursor.sequence == snapshot.sequence
        && cursor.hash == snapshot.tip_hash
        && cursor.height == snapshot.tip_height;
    if identity_matches {
        return ReconcilePlan::CaughtUp;
    }
    plan(cursor, target, tree)
}

/// Height of the newest block shared by the cursor branch and the active
/// chain ending at `active_tip`.
///
/// Both nodes live in the same tree, so the walk always reaches at least the
/// genesis anchor; `None` means one of the nodes is no longer resolvable.
#[must_use]
pub fn common_ancestor_height(
    tree: &BlockTree,
    position: Hash256,
    active_tip: NodeId,
) -> Option<u32> {
    let position_id = tree.lookup(position)?;
    common_ancestor_height_by_id(tree, position_id, active_tip)
}
/// Canonical stale-branch depth used to choose rollback versus rebuild.
///
/// The depth is measured from the persisted position back to its newest
/// ancestor shared with the active chain. `None` means the position is no
/// longer resolvable in the tree.
#[must_use]
pub fn rollback_depth(
    tree: &BlockTree,
    position: Hash256,
    position_height: u32,
    active_tip: NodeId,
) -> Option<u32> {
    common_ancestor_height(tree, position, active_tip)
        .map(|ancestor_height| position_height.saturating_sub(ancestor_height))
}
/// Returns whether the block `position` at `height` lies on the active chain
/// ending at `active_tip`.
///
/// Absent blocks are simply off-chain; callers decide whether that means
/// rollback or rebuild.
#[must_use]
pub fn position_on_active_chain(
    tree: &BlockTree,
    position: Hash256,
    height: u32,
    active_tip: NodeId,
) -> bool {
    let Some(id) = tree.lookup(position) else {
        return false;
    };
    position_on_active_chain_by_id(tree, id, height, active_tip)
}

fn position_on_active_chain_by_id(
    tree: &BlockTree,
    position_id: NodeId,
    height: u32,
    active_tip: NodeId,
) -> bool {
    tree.node_at_height_from(active_tip, height)
        .is_some_and(|active| active == position_id)
}

fn common_ancestor_height_by_id(
    tree: &BlockTree,
    position_id: NodeId,
    active_tip: NodeId,
) -> Option<u32> {
    let ancestor = tree.find_common_ancestor(position_id, active_tip)?;
    let node = tree.node(ancestor).ok()?;
    Some(node.height)
}
