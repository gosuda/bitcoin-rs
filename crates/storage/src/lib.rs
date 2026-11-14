#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::{fmt, str::FromStr};

pub use batch::{BatchOp, BufferedWriteBatch};

pub use block_file::{
    BlockFilePosition, FlatFileBlockStore, block_file_max_height_key, decode_block_file_max_height,
    encode_block_file_max_height,
};

pub use cache_budget::{
    CacheBudgetShare, ChainstateCacheBudget, clamp_dbcache_bytes, split_cache_budget_with_txindex,
    split_cache_budget_without_txindex, split_chainstate_cache_budget,
};

pub use column_families::ColumnFamily;

pub mod committed_facts;
pub use coins::{COIN_KEY_LEN, CoinCache, CoinKey, CoinStatsFeed, CoinStore, WindowDelta};
#[cfg(any(test, feature = "test-seam"))]
pub use commit::CommitFault;
pub use commit::{AcceptedPrefix, CommitAuthority, CommitError, DurableReceipt};
pub use committed_facts::{CommittedBlock, CommittedFacts, CreatedOutput, SpentPrevout, TxFacts};

pub use bytes::Bytes;
pub use error::{BoundedReadError, StorageError};
pub use memory_kv::MemoryKvStore;
pub use snapshot_activation::{SNAPSHOT_ACTIVATION_KEY, SnapshotActivationMarker};

#[cfg(any(test, feature = "test-seam"))]
pub use trait_::PersistFault;
pub use trait_::{
    KvIter, KvPair, KvSnapshot, KvStore, PrefixScan, PrefixScanLimit, WriteCondition,
};

pub use undo::{
    DisconnectMarker, DisconnectPhase, InMemoryUndoStore, KvUndoStore, UndoStore, block_undo_key,
};

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
    KvDurableHeadStore, SCRIPT_ATTESTATION_KEY, ScriptAttestation,
};

pub use rocksdb_impl::{ROCKSDB_DEFAULT_CACHE_BYTES, RocksDbStore};
#[cfg(feature = "surrealkv")]
pub use surrealkv_impl::{SURREALKV_DEFAULT_CACHE_BYTES, SurrealKvStore};

#[cfg(feature = "mdbx")]
pub use mdbx_impl::{MAX_KEY_SIZE, MAX_VAL_SIZE, MdbxStore};

pub mod engine_detect;
pub use checkpoint::open_checkpoint_store;
pub use engine_detect::detect_engine;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StorageBackend {
    RocksDb,
    SurrealKv,
    Mdbx,
}

impl StorageBackend {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RocksDb => "rocksdb",
            Self::SurrealKv => "surrealkv",
            Self::Mdbx => "mdbx",
        }
    }

    #[must_use]
    pub const fn is_compiled_in(self) -> bool {
        match self {
            Self::RocksDb => true,
            Self::SurrealKv => cfg!(feature = "surrealkv"),
            Self::Mdbx => cfg!(feature = "mdbx"),
        }
    }
}

impl FromStr for StorageBackend {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "rocksdb" => Ok(Self::RocksDb),
            "surrealkv" => Ok(Self::SurrealKv),
            "mdbx" => Ok(Self::Mdbx),
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
pub mod budget;
pub mod cache_budget;
pub mod coins;
mod column_families;
pub mod commit;
pub mod durable_head;
mod error;
pub mod memory_kv;
pub mod pruning;
pub mod recovery_evidence;
pub mod snapshot_activation;
mod trait_;
pub mod undo;

#[cfg(feature = "mdbx")]
mod mdbx_impl;
mod rocksdb_impl;
#[cfg(feature = "surrealkv")]
mod surrealkv_impl;

pub mod checkpoint;
#[cfg(any(test, verification, kani))]
pub mod schema_model;
#[cfg(test)]
pub(crate) mod test_support;
pub mod utxo;
#[cfg(any(test, feature = "test-seam"))]
pub mod write_fault;
