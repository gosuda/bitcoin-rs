use alloc::vec::Vec;

use bitcoin_rs_primitives::{Hash256, PeerEndpoint, Txid};

pub(crate) struct MutationSequence;

impl MutationSequence {
    pub(crate) const fn advance(current: u64) -> u64 {
        current.wrapping_add(1)
    }

    pub(crate) fn base(current: u64, len: usize) -> u64 {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        if len == 0 {
            0
        } else {
            current.wrapping_sub(len - 1)
        }
    }

    pub(crate) fn at(base: u64, index: usize) -> Option<u64> {
        let offset = u64::try_from(index).ok()?;
        Some(base.wrapping_add(offset))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemovalReason {
    BlockInclusion,
    Conflict,
    Replaced,
    Descendant,
    PolicyEviction,
    Expiry,
    Clear,
    Reorg,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationOutcome {
    Accepted,
    Removed(RemovalReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationChange {
    /// Transaction id in native consensus byte order.
    pub txid: Hash256,
    pub outcome: MutationOutcome,
}

pub(crate) fn change(txid: &Txid, outcome: MutationOutcome) -> MutationChange {
    MutationChange {
        txid: Hash256::from(*txid),
        outcome,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationResult {
    pub changes: Vec<MutationChange>,
    /// Mempool sequence assigned to `changes[0]`; each later change took the
    /// next value. `0` when `changes` is empty.
    pub sequence_base: u64,
}

impl MutationResult {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            changes: Vec::new(),
            sequence_base: 0,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    #[must_use]
    pub fn sequence_of(&self, index: usize) -> Option<u64> {
        if index >= self.changes.len() {
            return None;
        }
        MutationSequence::at(self.sequence_base, index)
    }

    #[must_use]
    pub fn removed_txids(&self) -> Vec<Txid> {
        self.changes
            .iter()
            .filter(|change| matches!(change.outcome, MutationOutcome::Removed(_)))
            .map(|change| Txid::from(change.txid))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PeerToken {
    pub endpoint: Option<PeerEndpoint>,
    pub addr: Option<bitcoin_rs_primitives::PeerEndpoint>,
    pub connection_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionOrigin {
    Rpc,
    Esplora,
    Snapshot,
    Peer(PeerToken),
    Reorg,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalOrigin {
    Rpc,
    Esplora,
    Snapshot,
}

impl From<LocalOrigin> for AdmissionOrigin {
    fn from(origin: LocalOrigin) -> Self {
        match origin {
            LocalOrigin::Rpc => Self::Rpc,
            LocalOrigin::Esplora => Self::Esplora,
            LocalOrigin::Snapshot => Self::Snapshot,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationEnvelope {
    pub origin: AdmissionOrigin,
    pub result: MutationResult,
    /// Accepted bodies retained under the commit writer, keyed by change index.
    /// Empty when no observer requests transaction payloads.
    pub accepted_transactions: Vec<(usize, alloc::sync::Arc<bitcoin_rs_primitives::Tx>)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_of_only_returns_sequences_for_committed_changes() {
        let result = MutationResult {
            changes: vec![change(&Txid::default(), MutationOutcome::Accepted); 3],
            sequence_base: 41,
        };
        assert_eq!(result.sequence_of(0), Some(41));
        assert_eq!(result.sequence_of(1), Some(42));
        assert_eq!(result.sequence_of(2), Some(43));
        for index in [result.len(), result.len() + 1, usize::MAX] {
            assert_eq!(
                result.sequence_of(index),
                None,
                "out-of-bounds index {index}"
            );
        }
    }

    #[test]
    fn sequence_of_wraps_for_an_in_bounds_change() {
        let result = MutationResult {
            changes: vec![change(&Txid::default(), MutationOutcome::Accepted); 2],
            sequence_base: u64::MAX,
        };
        assert_eq!(result.sequence_of(0), Some(u64::MAX));
        assert_eq!(result.sequence_of(1), Some(0));
        assert_eq!(result.sequence_of(2), None);
    }

    #[test]
    fn empty_mutation_has_no_sequence_at_any_index() {
        let result = MutationResult::empty();
        for index in [0, 1, usize::MAX] {
            assert_eq!(result.sequence_of(index), None);
        }
    }
}
