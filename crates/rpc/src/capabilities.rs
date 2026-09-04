//! Core-compatible projection of concrete service status.
//!
//! Txindex owns lifecycle and progress. This module renders those facts
//! into the `getcapabilities` wire types.

use crate::context::{CapabilitySnapshot, CapabilityState, CapabilityStatus};

/// Stable identifier used by the RPC capability report.
pub const TXINDEX_CAPABILITY: &str = "txindex";

/// Worker-owned txindex facts that RPC projects into [`CapabilityStatus`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxIndexStatus {
    /// The worker is opening and cannot answer yet.
    Opening,
    /// The worker was abandoned during shutdown.
    ShutdownAbandoned,
    /// The worker failed and cannot currently provide complete answers.
    Failed {
        /// Failure description.
        reason: String,
    },
    /// The worker is deleting rows on an abandoned branch.
    RollingBack {
        /// Height of the watermark being rewound.
        from_height: u32,
        /// Height of the last block shared with the applied chain.
        to_height: u32,
    },
    /// The worker was reset and is rebuilding from genesis.
    Rebuilding {
        /// Height the rebuild has reached.
        processed_height: u32,
        /// Applied-chain height the rebuild is approaching.
        target_height: u32,
    },
    /// The worker is catching up to the applied chain tip.
    CatchingUp {
        /// Height covered by the capability.
        processed_height: u32,
        /// Applied-chain height the capability is approaching.
        target_height: u32,
    },
    /// The worker is current with the applied chain tip.
    Ready,
}

/// Live txindex status source implemented by the index worker.
pub trait TxIndexStatusSource: Send + Sync {
    /// Whether the Core `--txindex` surface or its script-index dependency is enabled.
    fn enabled(&self) -> bool;
    /// Worker-owned status, or `None` when the worker is not running.
    fn status(&self) -> Option<TxIndexStatus>;
}

/// Projects txindex worker facts into the Core-compatible capability row.
#[must_use]
pub fn txindex_capability(enabled: bool, status: Option<TxIndexStatus>) -> CapabilityStatus {
    let state = match status {
        Some(TxIndexStatus::Opening) => CapabilityState::Opening,
        Some(TxIndexStatus::ShutdownAbandoned) => CapabilityState::ShutdownAbandoned,
        Some(TxIndexStatus::Failed { reason }) => CapabilityState::Failed { reason },
        Some(TxIndexStatus::RollingBack {
            from_height,
            to_height,
        }) => CapabilityState::RollingBack {
            from_height,
            to_height,
        },
        Some(TxIndexStatus::Rebuilding {
            processed_height,
            target_height,
        }) => CapabilityState::Rebuilding {
            processed_height,
            target_height,
        },
        Some(TxIndexStatus::CatchingUp {
            processed_height,
            target_height,
        }) => CapabilityState::CatchingUp {
            processed_height,
            target_height,
        },
        Some(TxIndexStatus::Ready) => CapabilityState::Ready,
        None => CapabilityState::Disabled,
    };
    CapabilityStatus {
        id: TXINDEX_CAPABILITY.to_owned(),
        compiled: true,
        enabled,
        state,
    }
}

/// Point-in-time `getcapabilities` snapshot for the concrete txindex row.
#[must_use]
pub fn txindex_snapshot(source: Option<&dyn TxIndexStatusSource>) -> CapabilitySnapshot {
    let (enabled, status) =
        source.map_or((false, None), |source| (source.enabled(), source.status()));
    CapabilitySnapshot {
        capabilities: vec![txindex_capability(enabled, status)],
    }
}
