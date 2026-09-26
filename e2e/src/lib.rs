//! The one process-node harness: real child processes, public surfaces only.
//!
//! Every scenario test — the files under `e2e/tests/` and the `bitcoin-rs`
//! binary package's integration tests — drives spawned processes: the
//! `bitcoin-rs` binary under test, the pinned Bitcoin Core build named by
//! the compiled `core-compat.toml` manifest, and scripted loopback wire
//! peers. They speak only over the public HTTP/RPC/P2P surfaces; no crate
//! internals are imported.
//!
//! Prerequisites:
//! - `cargo build --bin bitcoin-rs` (default dev profile is fine)
//! - `scripts/install-bitcoind.sh` for the P2P/reorg scenarios that need Core
//!
//! Evidence from every run (launch argv, captured stdout/stderr, the RPC
//! and P2P transcripts) lands in `target/process-harness/e2e/run-*`, under
//! the artifact root CI uploads.

pub mod differential;
pub mod error;
pub mod helpers;
pub mod live_peer;
pub mod node;
pub mod process_peer;
pub mod rpc;

pub use error::{Error, Result, ValueExt};
pub use node::{ClockControl, HttpResponse, Kind, ProcessNode, SpawnOptions, mock_time};
