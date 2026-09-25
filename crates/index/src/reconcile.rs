//! Derived-index reconciliation state and policy over supplied authoritative chain facts.
//!
//! The index owner decides how durable derived state reaches consistency with a
//! supplied active chain. The caller owns the authoritative chain representation
//! and implements `crate::reconcile::ActiveChainView`; agreement between index watermarks alone
//! never prove query readiness.

use bitcoin_rs_primitives::Hash256;

use crate::{IndexCapabilities, IndexCapability, IndexWatermark, IndexWatermarks};

/// Durable consumer-cursor length: epoch (8 LE) + sequence (8 LE) + height (4 LE) + hash.
pub(crate) const CURSOR_BYTE_LEN: usize = 52;

pub(crate) trait ActiveChainView {
    /// Whether `position` at `height` lies on the selected active chain.
    fn position_on_active_chain(&self, position: Hash256, height: u32) -> bool;

    /// Height of the newest block shared by `position` and the selected active
    /// chain, or `None` when ancestry cannot be resolved.
    fn common_ancestor_height(&self, position: Hash256) -> Option<u32>;
}

/// Durable position of an index consumer relative to committed chain events.
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
    /// Encodes the durable representation in `CURSOR_BYTE_LEN` bytes.
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
    /// Cursor corruption is advisory-state corruption only. Row correctness is
    /// anchored by capability watermarks, so consumers re-plan from row state.
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

/// Canonical stale-branch depth used to choose rollback versus rebuild.
#[must_use]
pub(crate) fn rollback_depth(
    chain: &impl ActiveChainView,
    position: Hash256,
    position_height: u32,
) -> Option<u32> {
    chain
        .common_ancestor_height(position)
        .map(|ancestor_height| position_height.saturating_sub(ancestor_height))
}

/// Reconciliation leg one capability's rows are executing against the
/// applied tip. Forward is the resting leg: a watermark that names the
/// applied tip is ready; one below it is catching up.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReconcileLeg {
    /// Rows extend the active chain from the durable watermark.
    #[default]
    Forward,
    /// Rows on an abandoned or ahead-of-tip branch are deleted block by
    /// block from `from_height` down to the common ancestor `to_height`.
    RollingBack {
        /// Height of the watermark being rewound.
        from_height: u32,
        /// Height of the last block shared with the active chain.
        to_height: u32,
    },
    /// The rows were reset and rebuild from genesis.
    Rebuilding,
}

/// Reconciliation legs of every capability the worker owns.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcilePhase([ReconcileLeg; 3]);

impl ReconcilePhase {
    /// Every capability moving forward.
    pub(crate) const FORWARD: Self = Self([ReconcileLeg::Forward; 3]);

    /// Returns the phase with `leg` assigned to every capability in
    /// `capabilities`.
    ///
    /// INVARIANT: `legs[capability.index()]` is that capability's leg.
    #[must_use]
    pub fn with_leg(mut self, capabilities: IndexCapabilities, leg: ReconcileLeg) -> Self {
        for capability in capabilities.iter() {
            self.0[capability.index()] = leg;
        }
        self
    }

    /// Capabilities whose rows are rebuilding from genesis.
    #[must_use]
    pub fn rebuilding(self) -> IndexCapabilities {
        IndexCapability::ALL
            .into_iter()
            .filter(|&capability| matches!(self.0[capability.index()], ReconcileLeg::Rebuilding))
            .collect()
    }

    /// Widest rollback in flight: the highest watermark being rewound and
    /// the lowest common ancestor any capability rewinds to.
    #[must_use]
    pub(crate) fn rolling_back(self) -> Option<(u32, u32)> {
        self.0
            .into_iter()
            .filter_map(|leg| match leg {
                ReconcileLeg::RollingBack {
                    from_height,
                    to_height,
                } => Some((from_height, to_height)),
                ReconcileLeg::Forward | ReconcileLeg::Rebuilding => None,
            })
            .reduce(|(from_a, to_a), (from_b, to_b)| (from_a.max(from_b), to_a.min(to_b)))
    }

    /// Ends every rollback leg; rebuild legs persist until their rows reach
    /// the applied tip.
    #[must_use]
    pub(crate) fn rollbacks_finished(self) -> Self {
        let finish = |leg| match leg {
            ReconcileLeg::RollingBack { .. } => ReconcileLeg::Forward,
            other => other,
        };
        Self(self.0.map(finish))
    }
}

/// Whether a nonempty capability set has one exact durable watermark.
///
/// `Valid(None)` is an aligned, unindexed selection, not an empty selection
/// and not proof that a query is ready.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum SelectedWatermark {
    /// Every selected capability has the same optional height and block hash.
    Valid(Option<IndexWatermark>),
    /// No capability was selected, or selected capabilities disagree.
    Invalid,
}

/// Selects an exact common watermark without consulting or owning chainstate.
#[must_use]
pub(crate) fn selected_watermark(
    watermarks: IndexWatermarks,
    capabilities: IndexCapabilities,
) -> SelectedWatermark {
    let mut selected = IndexCapability::ALL
        .into_iter()
        .filter(|&capability| capabilities.contains(capability))
        .map(|capability| watermarks.get(capability));
    let Some(first) = selected.next() else {
        return SelectedWatermark::Invalid;
    };
    if selected.all(|watermark| watermark == first) {
        SelectedWatermark::Valid(first)
    } else {
        SelectedWatermark::Invalid
    }
}

/// Coherent applied-tip position supplied by the authoritative chain owner.
///
/// The chain owner (node) implements this over its single-write snapshot
/// publication; the index runtime reads the cursor wherever it previously read
/// a publisher snapshot. The index does not own or advance these fields.
pub trait ChainCursorSource: Send + Sync {
    /// Returns the current consumer-visible chain cursor.
    fn cursor(&self) -> ConsumerCursor;
}

/// [`ActiveChainView`] adapters over the authoritative [`BlockTree`].
///
/// The index owns reconciliation policy; the tree only answers topology
/// questions against one selected active tip.
pub(crate) mod block_tree {
    use bitcoin_rs_chain::{BlockTree, NodeId};
    use bitcoin_rs_primitives::Hash256;

    use super::ActiveChainView;

    struct BlockTreeActiveChain<'a> {
        tree: &'a BlockTree,
        active_tip: NodeId,
    }

    impl ActiveChainView for BlockTreeActiveChain<'_> {
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
            let ancestor = self
                .tree
                .find_common_ancestor(position_id, self.active_tip)?;
            self.tree.node(ancestor).ok().map(|node| node.height)
        }
    }

    /// Canonical stale-branch depth, with the decision owned by `index`.
    #[must_use]
    pub(crate) fn rollback_depth(
        tree: &BlockTree,
        position: Hash256,
        position_height: u32,
        active_tip: NodeId,
    ) -> Option<u32> {
        let chain = BlockTreeActiveChain { tree, active_tip };
        super::rollback_depth(&chain, position, position_height)
    }

    /// Whether `position` at `height` lies on the selected active chain.
    #[must_use]
    pub(crate) fn position_on_active_chain(
        tree: &BlockTree,
        position: Hash256,
        height: u32,
        active_tip: NodeId,
    ) -> bool {
        let chain = BlockTreeActiveChain { tree, active_tip };
        ActiveChainView::position_on_active_chain(&chain, position, height)
    }
}
