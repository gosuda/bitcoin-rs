//! Core-compatible projection of concrete service status.
//!
//! The derived-index runtime owns lifecycle and progress. This module owns the
//! `getcapabilities` wire types and the one-method pull seam the RPC surface
//! consumes. See the indexing contract's `IDX-02` for the capability rules.

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

impl CapabilityState {
    /// Every lifecycle outcome, in report order.
    pub const ALL: [Self; 8] = [
        Self::Ready,
        Self::CatchingUp {
            processed_height: 0,
            target_height: 0,
        },
        Self::RollingBack {
            from_height: 0,
            to_height: 0,
        },
        Self::Rebuilding {
            processed_height: 0,
            target_height: 0,
        },
        Self::Failed {
            reason: String::new(),
        },
        Self::Disabled,
        Self::Opening,
        Self::ShutdownAbandoned,
    ];

    /// The `getcapabilities` wire spelling of this state: the serde tag, so a
    /// metrics label and the RPC row for one poll are the same token.
    #[must_use]
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::CatchingUp { .. } => "CatchingUp",
            Self::RollingBack { .. } => "RollingBack",
            Self::Rebuilding { .. } => "Rebuilding",
            Self::Failed { .. } => "Failed",
            Self::Disabled => "Disabled",
            Self::Opening => "Opening",
            Self::ShutdownAbandoned => "ShutdownAbandoned",
        }
    }
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
pub trait DerivedIndexCapabilitySource: Send + Sync {
    /// Compiled/enabled/lifecycle row for the txindex capability.
    fn capability(&self) -> CapabilityStatus;
}

/// Construct the stable txindex row from its enablement and lifecycle state.
#[must_use]
pub fn derived_index_status(enabled: bool, state: CapabilityState) -> CapabilityStatus {
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
    derived_index_status(false, CapabilityState::Disabled)
}

/// Point-in-time `getcapabilities` snapshot for the concrete txindex row.
#[must_use]
pub fn txindex_snapshot(source: Option<&dyn DerivedIndexCapabilitySource>) -> CapabilitySnapshot {
    CapabilitySnapshot {
        capabilities: vec![
            source.map_or_else(disabled_txindex, DerivedIndexCapabilitySource::capability),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReadyEnabled;

    impl DerivedIndexCapabilitySource for ReadyEnabled {
        fn capability(&self) -> CapabilityStatus {
            derived_index_status(true, CapabilityState::Ready)
        }
    }

    #[test]
    // CONTRACT: docs/contracts/indexing.md#IDX-02
    fn missing_source_is_the_disabled_txindex_row() {
        let snapshot = txindex_snapshot(None);
        assert_eq!(snapshot.capabilities, vec![disabled_txindex()]);
    }

    /// Extracts the serde tag of a rendered `CapabilityState`: a bare string
    /// for unit outcomes, the object key for payload outcomes.
    fn wire_tag(rendered: &str) -> &str {
        if let Some(rest) = rendered.strip_prefix("{\"") {
            rest.split('"').next().unwrap_or(rest)
        } else {
            rendered.trim_matches('"')
        }
    }

    #[test]
    // CONTRACT: docs/contracts/indexing.md#IDX-02
    fn wire_names_match_the_serde_spelling() {
        for state in &CapabilityState::ALL {
            let rendered = serde_json::to_string(state)
                .unwrap_or_else(|error| panic!("serialize {state:?}: {error}"));
            assert_eq!(
                wire_tag(&rendered),
                state.wire_name(),
                "label and getcapabilities row must be one vocabulary"
            );
        }
        let distinct: std::collections::BTreeSet<_> = CapabilityState::ALL
            .iter()
            .map(CapabilityState::wire_name)
            .collect();
        assert_eq!(
            distinct.len(),
            CapabilityState::ALL.len(),
            "distinct outcomes must keep distinct labels"
        );
    }

    #[test]
    // CONTRACT: docs/contracts/indexing.md#IDX-02
    fn attached_source_is_the_worker_row() {
        let snapshot = txindex_snapshot(Some(&ReadyEnabled));
        assert_eq!(
            snapshot.capabilities,
            vec![derived_index_status(true, CapabilityState::Ready)]
        );
    }
}
