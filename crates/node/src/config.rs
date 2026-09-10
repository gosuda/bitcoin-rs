//! Node configuration: source layers, resolved settings, and runtime inputs.
//!
//! Source-layer merging lives in `layer`, ordered resolution in `resolution`,
//! and cross-field validation on `NodeConfig`. Authentication, network profiles,
//! and journal settings own their respective invariants in private modules.
//! Re-exports preserve the existing `config` and crate-root API.

mod auth;
mod index;
mod journal;
mod layer;
mod network;
mod resolution;
mod resolved;
mod runtime;

pub use auth::Auth;
pub use index::ScriptIndexMode;
pub use journal::{ChainstateJournalConfig, ChainstateJournalOverrides};
pub use layer::{
    IndexOverrides, MiningOverrides, ObservabilityOverrides, P2pOverrides, RpcOverrides,
    StorageOverrides, UserConfig, ValidationOverrides,
};
pub use network::NetworkSelection;
pub use resolution::resolve;
pub use resolved::{
    IndexConfig, MiningConfig, NodeConfig, NotificationConfig, ObservabilityConfig, P2pConfig,
    RpcConfig, StorageConfig, ValidationConfig,
};
pub use runtime::RuntimeInputs;

#[cfg(test)]
mod tests;
