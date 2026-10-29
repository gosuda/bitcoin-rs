//! Derived-index reconciliation state and policy over supplied authoritative chain facts.

use bitcoin_rs_primitives::Hash256;

use crate::{IndexCapabilities, IndexCapability};

pub(crate) const CURSOR_BYTE_LEN: usize = 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumerCursor {
    pub epoch: u64,
    pub sequence: u64,
    pub height: u32,
    pub hash: Hash256,
}

impl ConsumerCursor {
    #[must_use]
    pub(crate) fn to_bytes(self) -> [u8; CURSOR_BYTE_LEN] {
        let mut bytes = [0_u8; CURSOR_BYTE_LEN];
        bytes[..8].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.height.to_le_bytes());
        bytes[20..].copy_from_slice(&self.hash.to_le_bytes());
        bytes
    }
}

pub(crate) mod block_tree {
    use bitcoin_rs_chain::{BlockTree, NodeId};
    use bitcoin_rs_primitives::Hash256;

    #[must_use]
    pub(crate) fn rollback_depth(
        tree: &BlockTree,
        position: Hash256,
        position_height: u32,
        active_tip: NodeId,
    ) -> Option<u32> {
        let position_id = tree.lookup(position)?;
        let ancestor = tree.find_common_ancestor(position_id, active_tip)?;
        let ancestor_height = tree.node(ancestor).ok().map(|node| node.height)?;
        Some(position_height.saturating_sub(ancestor_height))
    }

    #[must_use]
    pub(crate) fn position_on_active_chain(
        tree: &BlockTree,
        position: Hash256,
        height: u32,
        active_tip: NodeId,
    ) -> bool {
        let Some(position_id) = tree.lookup(position) else {
            return false;
        };
        tree.node_at_height_from(active_tip, height)
            .is_some_and(|active| active == position_id)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ReconcileLeg {
    #[default]
    Forward,
    RollingBack {
        from_height: u32,
        to_height: u32,
    },
    Rebuilding,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReconcilePhase([ReconcileLeg; 4]);

impl ReconcilePhase {
    pub(crate) const FORWARD: Self = Self([ReconcileLeg::Forward; 4]);

    /// INVARIANT: `legs[capability.index()]` is that capability's leg.
    #[must_use]
    pub(crate) fn with_leg(mut self, capabilities: IndexCapabilities, leg: ReconcileLeg) -> Self {
        for capability in capabilities.iter() {
            self.0[capability.index()] = leg;
        }
        self
    }

    #[must_use]
    pub(crate) fn rebuilding(self) -> IndexCapabilities {
        IndexCapability::ALL
            .into_iter()
            .filter(|&capability| matches!(self.0[capability.index()], ReconcileLeg::Rebuilding))
            .collect()
    }

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

    #[must_use]
    pub(crate) fn rollbacks_finished(self) -> Self {
        let finish = |leg| match leg {
            ReconcileLeg::RollingBack { .. } => ReconcileLeg::Forward,
            other => other,
        };
        Self(self.0.map(finish))
    }
}

pub trait ChainCursorSource: Send + Sync {
    fn cursor(&self) -> ConsumerCursor;
}
