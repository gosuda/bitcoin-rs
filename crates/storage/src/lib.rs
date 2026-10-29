#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::{fmt, str::FromStr};

pub use batch::{BatchOp, BufferedWriteBatch};

pub use block_file::{
    BlockFilePosition, FlatFileBlockStore, block_file_max_height_key, decode_block_file_max_height,
    encode_block_file_max_height,
};

pub use cache_budget::{CacheBudgetShare, clamp_dbcache_bytes, split_cache_budget};

pub use column_families::ColumnFamily;

pub use error::{BoundedReadError, StorageError};

#[cfg(any(test, feature = "test-seam"))]
pub use trait_::PersistFault;
pub use trait_::{
    KvIter, KvPair, KvSnapshot, KvStore, PrefixScan, PrefixScanLimit, WriteCondition,
};

pub use undo::{DisconnectMarker, DisconnectPhase, InMemoryUndoStore, KvUndoStore, UndoStore};

pub use pruning::{MandatoryRetention, RetentionError, RetentionLease, RetentionRegistry};

/// Opaque ownership token a store keeps until its engine handle is closed.
///
/// Each file-owning store carries it as its last field, so it drops only after the
/// engine (or file) handle has closed.
///
/// The node hands every store its data-directory lock this way: the lock then lives
/// exactly as long as the last handle that can still write the directory, whoever
/// retains that handle. Storage never inspects the token.
pub type StoreGuard = std::sync::Arc<dyn core::any::Any + Send + Sync>;

pub use durable_head::{
    BodyExtent, CommitRecords, DurableHead, DurableHeadStore, InMemoryDurableHeadStore,
    KvDurableHeadStore,
};

#[cfg(feature = "fjall")]
pub use fjall_impl::{FJALL_DEFAULT_CACHE_BYTES, FjallStore};

#[cfg(feature = "redb")]
pub use redb_impl::{
    REDB_DEFAULT_CACHE_BYTES, REDB_TXINDEX_DEFAULT_CACHE_BYTES, RedbStore,
    open_redb_tx_index_store, open_redb_tx_index_store_with_cache,
};

#[cfg(feature = "rocksdb")]
pub use rocksdb_impl::{ROCKSDB_DEFAULT_CACHE_BYTES, RocksDbStore};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StorageBackend {
    RocksDb,
    Fjall,
    Redb,
}

impl StorageBackend {
    /// Returns the stable configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RocksDb => "rocksdb",
            Self::Fjall => "fjall",
            Self::Redb => "redb",
        }
    }

    /// Whether this backend is compiled into the current crate.
    #[must_use]
    pub const fn is_compiled_in(self) -> bool {
        match self {
            Self::RocksDb => cfg!(feature = "rocksdb"),
            Self::Fjall => cfg!(feature = "fjall"),
            Self::Redb => cfg!(feature = "redb"),
        }
    }
}

impl FromStr for StorageBackend {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "rocksdb" => Ok(Self::RocksDb),
            "fjall" => Ok(Self::Fjall),
            "redb" => Ok(Self::Redb),
            _ => Err(format!("unsupported storage backend {value}")),
        }
    }
}

impl fmt::Display for StorageBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub mod assumeutxo;
mod batch;
pub mod block_body;
mod block_file;
pub mod cache_budget;
mod column_families;
pub mod durable_head;
mod error;
pub mod pruning;
pub mod recovery_evidence;
mod trait_;
pub mod undo;

#[cfg(feature = "fjall")]
mod fjall_impl;
#[cfg(feature = "redb")]
mod redb_impl;
#[cfg(feature = "rocksdb")]
mod rocksdb_impl;

pub mod chainstate_journal;
pub mod checkpoint;
