//! Core-compatible projection of concrete service status.
//!
//! Txindex owns lifecycle and progress. This module owns the `getcapabilities`
//! wire types and the one-method pull seam RPC needs because it cannot depend
//! on `node`. See the indexing contract's `IDX-02` for the capability rules.

use serde::{Deserialize, Serialize};

/// Stable identifier used by the RPC capability report.
pub const TXINDEX_CAPABILITY: &str = "txindex";

/// Lifecycle state reported for a compiled RPC capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CapabilityState {
    /// The capability is current with the applied chain tip.
    Ready,
    /// The capability is catching up to the applied chain tip.
    CatchingUp {
        /// Height covered by the capability.
        processed_height: u32,
        /// Applied-chain height the capability is approaching.
        target_height: u32,
    },
    /// The capability is deleting rows on a branch the applied chain
    /// abandoned, block by block, down to the common ancestor.
    RollingBack {
        /// Height of the watermark being rewound.
        from_height: u32,
        /// Height of the last block shared with the applied chain.
        to_height: u32,
    },
    /// The capability was reset and is rebuilding from genesis.
    Rebuilding {
        /// Height the rebuild has reached.
        processed_height: u32,
        /// Applied-chain height the rebuild is approaching.
        target_height: u32,
    },
    /// The capability failed and cannot currently provide complete answers.
    Failed {
        /// Failure description.
        reason: String,
    },
    /// The capability is not enabled for this node.
    Disabled,
    /// The capability is opening and cannot answer yet.
    Opening,
    /// The capability worker was abandoned during shutdown.
    ShutdownAbandoned,
}

/// Status of one concrete node capability exposed through RPC.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityStatus {
    /// Stable capability identifier.
    pub id: String,
    /// Whether the capability is compiled into this binary.
    pub compiled: bool,
    /// Whether the capability is enabled for this node.
    pub enabled: bool,
    /// Current lifecycle state.
    pub state: CapabilityState,
}

/// Point-in-time status report for concrete node capabilities.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    /// Status rows in the node's stable capability order.
    pub capabilities: Vec<CapabilityStatus>,
}

/// Live txindex row. The worker maps its own lifecycle onto [`CapabilityStatus`].
pub trait TxIndexCapabilitySource: Send + Sync {
    /// Compiled/enabled/lifecycle row for the txindex capability.
    fn capability(&self) -> CapabilityStatus;
}

/// Construct the stable txindex row from its enablement and lifecycle state.
#[must_use]
pub fn txindex_status(enabled: bool, state: CapabilityState) -> CapabilityStatus {
    CapabilityStatus {
        id: TXINDEX_CAPABILITY.to_owned(),
        compiled: true,
        enabled,
        state,
    }
}

/// Disabled txindex row used when no worker is attached.
#[must_use]
pub fn disabled_txindex() -> CapabilityStatus {
    txindex_status(false, CapabilityState::Disabled)
}

/// Point-in-time `getcapabilities` snapshot for the concrete txindex row.
#[must_use]
pub fn txindex_snapshot(source: Option<&dyn TxIndexCapabilitySource>) -> CapabilitySnapshot {
    CapabilitySnapshot {
        capabilities: vec![
            source.map_or_else(disabled_txindex, TxIndexCapabilitySource::capability),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReadyEnabled;

    impl TxIndexCapabilitySource for ReadyEnabled {
        fn capability(&self) -> CapabilityStatus {
            CapabilityStatus {
                id: TXINDEX_CAPABILITY.to_owned(),
                compiled: true,
                enabled: true,
                state: CapabilityState::Ready,
            }
        }
    }

    #[test]
    // CONTRACT: docs/contracts/indexing.md#IDX-02
    fn missing_source_is_the_disabled_txindex_row() {
        let snapshot = txindex_snapshot(None);
        assert_eq!(snapshot.capabilities, vec![disabled_txindex()]);
    }

    #[test]
    fn attached_source_is_the_worker_row() {
        let snapshot = txindex_snapshot(Some(&ReadyEnabled));
        assert_eq!(snapshot.capabilities[0].state, CapabilityState::Ready);
        assert!(snapshot.capabilities[0].enabled);
    }
}
