//! The one process-node harness: real child processes, public surfaces only.

pub mod differential;
pub mod error;
pub mod helpers;
pub mod live_peer;
pub mod node;
pub mod process_peer;
pub mod reference_set;
pub mod rpc;

pub use error::{Error, Result, ValueExt};
pub use node::{ClockControl, HttpResponse, Kind, ProcessNode, SpawnOptions, mock_time};
