use bitcoin_rs_primitives::Hash256;

use crate::{IndexCapabilities, IndexCapability};

pub const CURSOR_BYTE_LEN: usize = 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumerCursor {
    pub epoch: u64,
    pub sequence: u64,
    pub height: u32,
    pub hash: Hash256,
}

impl ConsumerCursor {
    #[must_use]
    pub fn to_bytes(self) -> [u8; CURSOR_BYTE_LEN] {
        let mut bytes = [0_u8; CURSOR_BYTE_LEN];
        bytes[..8].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.height.to_le_bytes());
        bytes[20..].copy_from_slice(&self.hash.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CursorDecodeError> {
        let Ok(fixed): Result<&[u8; CURSOR_BYTE_LEN], _> = bytes.try_into() else {
            return Err(CursorDecodeError::InvalidLength {
                expected: CURSOR_BYTE_LEN,
                found: bytes.len(),
            });
        };
        let mut epoch = [0_u8; 8];
        epoch.copy_from_slice(&fixed[..8]);
        let mut sequence = [0_u8; 8];
        sequence.copy_from_slice(&fixed[8..16]);
        let mut height = [0_u8; 4];
        height.copy_from_slice(&fixed[16..20]);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&fixed[20..52]);
        Ok(Self {
            epoch: u64::from_le_bytes(epoch),
            sequence: u64::from_le_bytes(sequence),
            height: u32::from_le_bytes(height),
            hash: Hash256::from_le_bytes(&hash),
        })
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CursorDecodeError {
    #[error("invalid cursor length: expected {expected}, found {found}")]
    InvalidLength { expected: usize, found: usize },
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

#[cfg(test)]
mod tests {
    use super::{CURSOR_BYTE_LEN, ConsumerCursor, CursorDecodeError};
    use bitcoin_rs_primitives::Hash256;

    // IDX-05
    #[test]
    fn cursor_round_trips_the_documented_field_layout() {
        let cursor = ConsumerCursor {
            epoch: 0x0102_0304_0506_0708,
            sequence: 0x1112_1314_1516_1718,
            height: 0x2122_2324,
            hash: Hash256::from_le_bytes(&[0x31; 32]),
        };
        let bytes = cursor.to_bytes();
        assert_eq!(bytes.len(), CURSOR_BYTE_LEN);
        assert_eq!(&bytes[..8], &0x0102_0304_0506_0708_u64.to_le_bytes());
        assert_eq!(&bytes[8..16], &0x1112_1314_1516_1718_u64.to_le_bytes());
        assert_eq!(&bytes[16..20], &0x2122_2324_u32.to_le_bytes());
        assert_eq!(ConsumerCursor::from_bytes(&bytes), Ok(cursor));
    }

    // IDX-05
    #[test]
    fn cursor_decode_rejects_any_length_other_than_52() {
        for found in [0, CURSOR_BYTE_LEN - 1, CURSOR_BYTE_LEN + 1] {
            assert_eq!(
                ConsumerCursor::from_bytes(&vec![0_u8; found]),
                Err(CursorDecodeError::InvalidLength {
                    expected: CURSOR_BYTE_LEN,
                    found,
                }),
                "a {found}-byte cursor must not decode"
            );
        }
    }
}
