//! Workspace release version surfaced for wire and RPC user-agent strings.

/// Current `bitcoin-rs` release version (from `[workspace.package].version`).
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Bitcoin P2P user-agent subversion string (`/bitcoin-rs:<version>/`).
pub const USER_AGENT: &str = concat!("/bitcoin-rs:", env!("CARGO_PKG_VERSION"), "/");
