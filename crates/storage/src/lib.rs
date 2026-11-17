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
pub use committed_facts::{
    CommittedBlock, CommittedFacts, CreatedOutput, FactsScript, SpentPrevout, TxFacts,
};

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
pub(crate) mod test_support {
    #[derive(Debug, thiserror::Error)]
    pub(crate) enum TestError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        TryFromInt(#[from] std::num::TryFromIntError),
        #[error(transparent)]
        Storage(#[from] crate::StorageError),
        #[error(transparent)]
        BoundedRead(#[from] crate::BoundedReadError),
        #[error(transparent)]
        Checkpoint(#[from] crate::checkpoint::CheckpointError),
        #[error(transparent)]
        CheckpointLoad(#[from] crate::checkpoint::CheckpointLoadError),
        #[error(transparent)]
        Sonic(#[from] sonic_rs::Error),
        #[error("missing: {0}")]
        Missing(&'static str),
        #[error("unexpected success: {0}")]
        UnexpectedSuccess(&'static str),
        #[error("worker panicked: {0}")]
        #[allow(dead_code)]
        WorkerPanicked(&'static str),
        #[error("blocked past the deadline: {0}")]
        #[allow(dead_code)]
        Blocked(&'static str),
    }

    pub(crate) type TestResult<T = ()> = Result<T, TestError>;
}
pub mod utxo;
#[cfg(any(test, feature = "test-seam"))]
pub mod write_fault {
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::{
        BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, PersistFault, PrefixScan,
        PrefixScanLimit, StorageError, WriteCondition,
    };

    pub struct WriteFaultStore {
        inner: Arc<dyn KvStore>,
        countdown: AtomicUsize,
        durable_batches: AtomicUsize,
        dead: AtomicBool,
    }

    impl WriteFaultStore {
        #[must_use]
        pub fn new(inner: Arc<dyn KvStore>) -> Self {
            Self {
                inner,
                countdown: AtomicUsize::new(0),
                durable_batches: AtomicUsize::new(0),
                dead: AtomicBool::new(false),
            }
        }

        pub fn fail_durable_batch(&self, nth: usize) {
            self.countdown.store(nth, Ordering::SeqCst);
        }

        #[must_use]
        pub fn durable_batches(&self) -> usize {
            self.durable_batches.load(Ordering::SeqCst)
        }

        #[must_use]
        pub fn is_dead(&self) -> bool {
            self.dead.load(Ordering::SeqCst)
        }

        fn injected() -> StorageError {
            StorageError::Io(std::io::Error::other("injected durable batch failure"))
        }

        fn live(&self) -> Result<(), StorageError> {
            if self.is_dead() {
                return Err(Self::injected());
            }
            Ok(())
        }
    }

    impl KvStore for WriteFaultStore {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(cf, key)
        }

        fn get_bounded(
            &self,
            cf: ColumnFamily,
            key: &[u8],
            max_bytes: usize,
        ) -> Result<Option<Vec<u8>>, crate::BoundedReadError> {
            self.inner.get_bounded(cf, key, max_bytes)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            self.inner.iter_prefix(cf, prefix)
        }

        fn scan_prefix_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            self.inner.scan_prefix_bounded(cf, prefix, limit)
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            self.inner
                .scan_prefix_from_bounded(cf, prefix, start, limit)
        }

        fn new_batch(&self) -> BufferedWriteBatch {
            self.inner.new_batch()
        }

        fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            self.live()?;
            self.inner.write(batch)
        }

        fn write_deferred(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            self.live()?;
            self.inner.write_deferred(batch)
        }

        fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            self.live()?;
            self.durable_batches.fetch_add(1, Ordering::SeqCst);
            if self
                .countdown
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                == Ok(1)
            {
                self.dead.store(true, Ordering::SeqCst);
                return Err(Self::injected());
            }
            self.inner.write_durable(batch)
        }

        fn write_durable_if(
            &self,
            conditions: &[WriteCondition<'_>],
            batch: BufferedWriteBatch,
        ) -> Result<bool, StorageError> {
            self.live()?;
            self.inner.write_durable_if(conditions, batch)
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.live()?;
            self.inner.flush()
        }

        fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
            self.inner.snapshot()
        }

        fn multi_get(
            &self,
            cf: ColumnFamily,
            keys: &[&[u8]],
        ) -> Result<Vec<Option<crate::Bytes>>, StorageError> {
            self.inner.multi_get(cf, keys)
        }

        fn ingest_sorted(
            &self,
            cf: ColumnFamily,
            rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
            scratch: &Path,
        ) -> Result<u64, StorageError> {
            self.live()?;
            self.inner.ingest_sorted(cf, rows, scratch)
        }

        fn delete_range(
            &self,
            cf: ColumnFamily,
            start: &[u8],
            end: &[u8],
        ) -> Result<(), StorageError> {
            self.live()?;
            self.inner.delete_range(cf, start, end)
        }

        fn checkpoint(&self, dir: &Path) -> Result<(), StorageError> {
            self.live()?;
            self.inner.checkpoint(dir)
        }

        fn engine_cache_bytes(&self) -> u64 {
            self.inner.engine_cache_bytes()
        }

        #[cfg(any(test, feature = "test-seam"))]
        fn arm_persist_fault(&self, fault: PersistFault) {
            self.inner.arm_persist_fault(fault);
        }
    }
}
