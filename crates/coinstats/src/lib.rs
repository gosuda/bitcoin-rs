#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// `MuHash3072` accumulator.
pub mod muhash3072;
/// Persistent coinstats rows.
pub mod persist;
/// Running UTXO statistics.
pub mod stats;

pub use muhash3072::MuHash3072;
pub use persist::{CoinStatsPersistError, load_coin_stats, store_coin_stats};
pub use stats::{CoinStats, CoinStatsDecodeError, CoinStatsListener};
