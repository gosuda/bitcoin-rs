//! End-to-end harness for the `bitcoin-rs` daemon.
//!
//! Each file under `e2e/tests/` drives real child processes — the
//! `bitcoin-rs` binary under test and, where a scenario needs a peer, the
//! pinned Bitcoin Core build from `docs/api/core-compat.toml` — over their
//! public HTTP/RPC/P2P surfaces only. No crate internals are imported.
//!
//! Prerequisites:
//! - `cargo build --bin bitcoin-rs` (default dev profile is fine)
//! - `scripts/install-bitcoind.sh` for the P2P/reorg scenarios that need Core
//!
//! Evidence from every run (launch argv, captured stdout/stderr, the RPC
//! transcript) lands in `target/process-harness/e2e/run-*`, under the
//! artifact root CI uploads.

pub mod error;
pub mod helpers;
pub mod node;
pub mod rpc;

pub use error::{Error, Result, ValueExt};
pub use node::{HttpResponse, Kind, ProcessNode, SpawnOptions, mock_time};
