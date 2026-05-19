#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Logical column-family names shared by all storage backends.
pub mod column_families;
/// Storage error type.
pub mod error;
/// Backend-neutral key-value store traits.
pub mod trait_;

#[cfg(feature = "fjall")]
/// Fjall-backed [`KvStore`](trait_::KvStore) implementation.
pub mod fjall_impl;
#[cfg(feature = "mdbx")]
/// MDBX-backed [`KvStore`](trait_::KvStore) implementation.
pub mod mdbx_impl;
#[cfg(feature = "redb")]
/// redb-backed [`KvStore`](trait_::KvStore) implementation.
pub mod redb_impl;
#[cfg(feature = "rocksdb")]
/// RocksDB-backed [`KvStore`](trait_::KvStore) implementation.
pub mod rocksdb_impl;

pub use column_families::ColumnFamily;
pub use error::StorageError;
pub use trait_::{KvIter, KvPair, KvSnapshot, KvStore, WriteBatch};

#[cfg(feature = "fjall")]
pub use fjall_impl::FjallStore;
#[cfg(feature = "mdbx")]
pub use mdbx_impl::MdbxStore;
#[cfg(feature = "redb")]
pub use redb_impl::RedbStore;
#[cfg(feature = "rocksdb")]
pub use rocksdb_impl::RocksDbStore;
