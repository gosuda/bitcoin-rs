//! Node configuration DTOs, resolution, and validation.
//!
//! Public configuration paths are stable; private modules own authentication,
//! network profiles, journal settings, source-layer merging, resolved settings,
//! and runtime dependencies respectively.

mod auth;
mod journal;
mod network;
mod overrides;
mod resolved;
mod runtime;

pub use auth::Auth;
pub use journal::{ChainstateJournalConfig, ChainstateJournalOverrides};
pub use network::NetworkSelection;
pub use overrides::{
    IndexOverrides, MiningOverrides, ObservabilityOverrides, P2pOverrides, RpcOverrides,
    StorageOverrides, UserConfig, ValidationOverrides,
};
pub use resolved::{
    IndexConfig, MiningConfig, NodeConfig, NotificationConfig, ObservabilityConfig, P2pConfig,
    RpcConfig, ScriptIndexMode, StorageConfig, ValidationConfig, resolve,
};
pub use runtime::RuntimeInputs;

#[cfg(test)]
mod tests;
