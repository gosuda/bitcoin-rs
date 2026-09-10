//! Node configuration DTOs, resolution, and validation.
//!
//! Source layers and their merge semantics live in `overrides`; `resolve`
//! applies them to the resolved types and validates the result. Authentication,
//! network selection, and runtime-only dependencies have separate owners.

mod auth;
mod network;
mod overrides;
mod resolution;
mod runtime;
mod types;

pub use auth::Auth;
pub use network::NetworkSelection;
pub use overrides::{
    ChainstateJournalOverrides, IndexOverrides, MiningOverrides, ObservabilityOverrides,
    P2pOverrides, RpcOverrides, StorageOverrides, UserConfig, ValidationOverrides,
};
pub use resolution::resolve;
pub use runtime::RuntimeInputs;
pub use types::{
    ChainstateJournalConfig, IndexConfig, MiningConfig, NodeConfig, NotificationConfig,
    ObservabilityConfig, P2pConfig, RpcConfig, ScriptIndexMode, StorageConfig, ValidationConfig,
};

#[cfg(test)]
mod tests;
