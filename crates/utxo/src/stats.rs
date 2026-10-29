//! Running UTXO-set statistics over the live set.
//!
//! The checkpoint manifest records this component under the current codec
//! identifier `"bitcoin-rs-coinstats-v1"`. It is an on-disk value and changes
//! to it require a datadir schema epoch bump.

pub mod coin_stats;
mod muhash3072;

pub use coin_stats::{
    CoinStats, CoinStatsAccumulator, CoinStatsDecodeError, CoinStatsListener, CoinStatsRewindError,
    scan_coin_stats,
};
pub use muhash3072::MuHash3072;
