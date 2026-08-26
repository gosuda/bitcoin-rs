#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Append-only flat files for immutable block bodies.
pub mod block_file;
/// Logical column-family names shared by all storage backends.
pub mod column_families;
/// Streaming length-prefixed Core frame reader and writer.
pub mod corpus;
/// Storage error type.
pub mod error;
/// Retention and deletion of block bodies and undo rows.
pub mod pruning;
/// Backend-neutral key-value store traits.
pub mod trait_;

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
pub use column_families::ColumnFamily;
pub use corpus::{
    CORE_FRAME_HEADER_LEN, CORE_FRAME_MAGIC_LEN, CoreFrameError, CoreFrameMetadata,
    CoreFrameReader, CoreFrameRecord, CoreFrameWriter,
};
pub use error::StorageError;
pub use trait_::{KvIter, KvPair, KvSnapshot, KvStore, PrefixScan, PrefixScanLimit, WriteBatch};

#[cfg(feature = "fjall")]
pub use fjall_impl::FjallStore;
#[cfg(feature = "mdbx")]
pub use mdbx_impl::MdbxStore;
#[cfg(feature = "redb")]
pub use redb_impl::{RedbStore, open_redb_tx_index_store};
#[cfg(feature = "rocksdb")]
pub use rocksdb_impl::RocksDbStore;
