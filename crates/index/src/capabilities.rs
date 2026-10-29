//! Core-compatible projection of concrete service status.

use serde::{Deserialize, Serialize};

pub(crate) const TXINDEX_CAPABILITY: &str = "txindex";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CapabilityState {
    Ready,
    CatchingUp {
        processed_height: u32,
        target_height: u32,
    },
    RollingBack {
        from_height: u32,
        to_height: u32,
    },
    Rebuilding {
        processed_height: u32,
        target_height: u32,
    },
    Failed {
        reason: String,
    },
    Disabled,
    Opening,
    ShutdownAbandoned,
}

impl CapabilityState {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityStatus {
    pub id: String,
    pub compiled: bool,
    pub enabled: bool,
    pub state: CapabilityState,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub capabilities: Vec<CapabilityStatus>,
}

pub trait DerivedIndexCapabilitySource: Send + Sync {
    fn capability(&self) -> CapabilityStatus;
}

#[must_use]
pub fn derived_index_status(enabled: bool, state: CapabilityState) -> CapabilityStatus {
    CapabilityStatus {
        id: TXINDEX_CAPABILITY.to_owned(),
        compiled: true,
        enabled,
        state,
    }
}

#[must_use]
pub(crate) fn disabled_txindex() -> CapabilityStatus {
    derived_index_status(false, CapabilityState::Disabled)
}

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
    fn missing_source_is_the_disabled_txindex_row() {
        let snapshot = txindex_snapshot(None);
        assert_eq!(snapshot.capabilities, vec![disabled_txindex()]);
    }

    fn wire_tag(rendered: &str) -> &str {
        if let Some(rest) = rendered.strip_prefix("{\"") {
            rest.split('"').next().unwrap_or(rest)
        } else {
            rendered.trim_matches('"')
        }
    }

    #[test]
    fn wire_names_match_the_serde_spelling() {
        for state in &CapabilityState::ALL {
            let rendered = sonic_rs::to_string(state)
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
    fn attached_source_is_the_worker_row() {
        let snapshot = txindex_snapshot(Some(&ReadyEnabled));
        assert_eq!(
            snapshot.capabilities,
            vec![derived_index_status(true, CapabilityState::Ready)]
        );
    }
}
