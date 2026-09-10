//! Node configuration DTOs, resolution, and validation.

mod auth;
mod journal;
mod network;
mod resolve;
mod resolved;
mod runtime;
mod user;

pub use auth::Auth;
pub use journal::{ChainstateJournalConfig, ChainstateJournalOverrides};
pub use network::NetworkSelection;
pub use resolve::resolve;
pub use resolved::{
    IndexConfig, MiningConfig, NodeConfig, ObservabilityConfig, P2pConfig, RpcConfig,
    StorageConfig, ValidationConfig,
};
pub use runtime::RuntimeInputs;
pub use user::{
    IndexOverrides, MiningOverrides, NotificationConfig, ObservabilityOverrides, P2pOverrides,
    RpcOverrides, ScriptIndexMode, StorageOverrides, UserConfig, ValidationOverrides,
};

#[cfg(test)]
mod tests;
