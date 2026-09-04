//! Running UTXO-set statistics over the live set.
//!
//! This is derived computation over the authoritative UTXO state that
//! [`crate::set`] owns, which is why it lives here rather than in a crate of
//! its own (issue #164). It reads the live set and folds it; it never decides
//! what the live set contains. The rewind accounts for
//! [`owed derived state`](../../../CONCEPTS.md#owed-derived-state) when a block
//! disconnects.
//!
//! [`MuHash3072`] is Bitcoin Core's 3072-bit `MuHash` as a running
//! numerator/denominator (`insert`, `remove`, `combine`, `finalize_hash`
//! yielding the Core-compatible `uint256`). [`CoinStats`] folds the live set --
//! `insert_utxo` and `remove_utxo` feed the accumulator and the scalar tallies
//! -- and serializes to a stable byte layout (`to_bytes`/`from_bytes`).
//! [`CoinStatsListener`] keeps stats behind a lock, applies the block-level
//! delta in `finish_block`, and exposes `rewind_block` as the explicit inverse
//! for disconnects. [`CoinStatsAccumulator`] serves checkpoint traversals:
//! `with_parallel_muhash` buffers exact coin preimages and combines ordered
//! insert-only partial `MuHash` values, while `without_muhash` skips hashing
//! entirely. [`scan_coin_stats`] recomputes stats on demand from a
//! [`crate::UtxoSetView`] (Core's on-demand model, no rolling listener
//! required), and [`store_coin_stats`]/[`load_coin_stats`] persist rows keyed
//! by little-endian height.
//!
//! The checkpoint manifest records this component under the current codec
//! identifier `"bitcoin-rs-coinstats-v1"`. It is an on-disk value and changes
//! to it require a datadir schema epoch bump.

/// Running UTXO statistics.
pub mod coin_stats;
/// `MuHash3072` accumulator.
pub mod muhash3072;
/// Persistent coinstats rows.
pub mod persist;

pub use coin_stats::{
    CoinStats, CoinStatsAccumulator, CoinStatsDecodeError, CoinStatsListener, CoinStatsRewindError,
    scan_coin_stats,
};
pub use muhash3072::MuHash3072;
pub use persist::{CoinStatsPersistError, load_coin_stats, store_coin_stats};
