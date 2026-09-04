#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Append-only flat files for immutable block bodies.
pub mod block_file;
/// Process cache-budget division shared by the storage backends.
pub mod cache_budget;
/// Logical column-family names shared by all storage backends.
pub mod column_families;
/// Storage error type.
pub mod error;
/// Retention and deletion of block bodies and undo rows.
pub mod pruning;
/// Backend-neutral key-value store traits.
pub mod trait_;
/// Per-block UTXO undo records and the in-flight disconnect marker.
pub mod undo;

#[cfg(feature = "fjall")]
mod fjall_impl;
#[cfg(feature = "mdbx")]
mod mdbx_impl;
#[cfg(feature = "redb")]
mod redb_impl;
#[cfg(feature = "rocksdb")]
mod rocksdb_impl;

pub use block_file::{
    BLOCK_FILE_MAGIC, BLOCK_FILE_MAX_BYTES, BlockFilePosition, FlatFileBlockReader,
    FlatFileBlockStore, block_file_max_height_key, decode_block_file_max_height,
    encode_block_file_max_height,
};
pub use cache_budget::{CacheBudgetShare, clamp_dbcache_bytes, split_cache_budget};
pub use column_families::ColumnFamily;
pub use error::StorageError;
pub use trait_::{
    KvIter, KvPair, KvSnapshot, KvStore, PrefixScan, PrefixScanLimit, WriteBatch, WriteCondition,
};
pub use undo::{DisconnectMarker, DisconnectPhase, InMemoryUndoStore, KvUndoStore, UndoStore};

#[cfg(feature = "fjall")]
pub use fjall_impl::FjallStore;
#[cfg(feature = "mdbx")]
pub use mdbx_impl::MdbxStore;
#[cfg(feature = "redb")]
pub use redb_impl::{RedbStore, open_redb_tx_index_store, open_redb_tx_index_store_with_cache};
#[cfg(feature = "rocksdb")]
pub use rocksdb_impl::RocksDbStore;

/// Converts a `u64` byte count to an `f64` metric value.
///
/// Split the value into 32-bit limbs so the conversion uses only exact
/// `f64::from(u32)` operations and rounds like a direct `u64` conversion.
#[cfg(any(
    feature = "fjall",
    feature = "mdbx",
    feature = "redb",
    feature = "rocksdb"
))]
pub(crate) fn metric_f64(value: u64) -> f64 {
    const TWO32: f64 = 4_294_967_296.0;
    let [b0, b1, b2, b3, b4, b5, b6, b7] = value.to_le_bytes();
    let low = u32::from_le_bytes([b0, b1, b2, b3]);
    let high = u32::from_le_bytes([b4, b5, b6, b7]);
    f64::from(high).mul_add(TWO32, f64::from(low))
}

/// Converts a `usize` byte count to an `f64` metric value via `u64`.
#[cfg(any(
    feature = "fjall",
    feature = "mdbx",
    feature = "redb",
    feature = "rocksdb"
))]
pub(crate) fn metric_f64_from_usize(value: usize) -> f64 {
    metric_f64(u64::try_from(value).unwrap_or(u64::MAX))
}
