use std::path::Path;

use bytes::Bytes;
use rust_rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, Direction, IteratorMode,
    Options, ReadOptions, WriteBatch as RocksWriteBatch, WriteOptions,
};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition};

const BLOCK_SIZE: usize = 4 * 1024 * 1024;
/// `RocksDB`'s block-cache capacity for unbudgeted opens.
const BLOCK_CACHE_SIZE: u64 = 256 * 1024 * 1024;
const BLOOM_BITS_PER_KEY: f64 = 10.0;
const WRITE_BUFFER_SIZE: usize = 128 << 20;

/// `RocksDB`-backed key-value store.
pub struct RocksDbStore {
    db: rust_rocksdb::DB,
    // Non-reentrant: public mutators hold this lock while calling the lock-free batch helper.
    write_lock: parking_lot::Mutex<()>,
}

impl RocksDbStore {
    /// Opens or creates a `RocksDB` store at `path` with all column families.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_cache(path, BLOCK_CACHE_SIZE)
    }

    /// Opens or creates a `RocksDB` store with an explicit block-cache capacity.
    ///
    /// `cache_bytes` replaces the historical hardcoded 256 MiB `BLOCK_CACHE_SIZE`
    /// as the shared LRU block cache (index and filter blocks included through
    /// `set_cache_index_and_filter_blocks`) and is configured exactly: a
    /// budgeted share is never raised above its allocation. Zero selects the
    /// engine default for unbudgeted opens. The write-buffer size stays its own
    /// fixed setting.
    pub fn open_with_cache(path: impl AsRef<Path>, cache_bytes: u64) -> Result<Self, StorageError> {
        let cache_bytes = if cache_bytes == 0 {
            BLOCK_CACHE_SIZE
        } else {
            cache_bytes
        };
        let cache_bytes = usize::try_from(cache_bytes).unwrap_or(usize::MAX);
        metrics::gauge!("storage.cache_capacity_bytes", "backend" => "rocksdb")
            .set(crate::metric_f64_from_usize(cache_bytes));
        let mut db_options = Options::default();
        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);
        db_options.set_compression_type(DBCompressionType::Lz4);
        db_options.set_atomic_flush(false);

        let mut table_options = BlockBasedOptions::default();
        table_options.set_block_size(BLOCK_SIZE);
        table_options.set_block_cache(&Cache::new_lru_cache(cache_bytes));
        table_options.set_bloom_filter(BLOOM_BITS_PER_KEY, false);
        table_options.set_cache_index_and_filter_blocks(true);

        let mut cf_options = Options::default();
        cf_options.set_compression_type(DBCompressionType::Lz4);
        cf_options.set_write_buffer_size(WRITE_BUFFER_SIZE);
        cf_options.set_block_based_table_factory(&table_options);

        let descriptors = ColumnFamily::ALL
            .iter()
            .copied()
            .map(|cf| ColumnFamilyDescriptor::new(cf.name(), cf_options.clone()));
        let db = rust_rocksdb::DB::open_cf_descriptors(&db_options, path, descriptors)
            .map_err(StorageError::backend)?;
        Ok(Self {
            db,
            write_lock: parking_lot::Mutex::new(()),
        })
    }

    fn cf_handle(&self, cf: ColumnFamily) -> Result<&rust_rocksdb::ColumnFamily, StorageError> {
        self.db
            .cf_handle(cf.name())
            .ok_or(StorageError::UnknownColumnFamily(cf))
    }

    /// Translates a portable [`RocksDbWriteBatch`] into a native `RocksDB` write batch.
    fn rocks_batch(&self, batch: RocksDbWriteBatch) -> Result<RocksWriteBatch, StorageError> {
        let mut rocks_batch = RocksWriteBatch::default();
        let mut handles = [None; ColumnFamily::ALL.len()];
        for op in batch.ops {
            match op {
                BatchOp::Put { cf, key, value } => {
                    rocks_batch.put_cf(cached_cf_handle(self, &mut handles, cf)?, key, value);
                }
                BatchOp::Delete { cf, key } => {
                    rocks_batch.delete_cf(cached_cf_handle(self, &mut handles, cf)?, key);
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    rocks_batch.delete_range_cf(
                        cached_cf_handle(self, &mut handles, cf)?,
                        start,
                        end,
                    );
                }
            }
        }
        Ok(rocks_batch)
    }

    /// Applies one batch as a single logical write with the given durability
    /// label, so each write is counted exactly once.
    fn write_with_durability(
        &self,
        batch: RocksDbWriteBatch,
        durability: &'static str,
        sync: bool,
    ) -> Result<(), StorageError> {
        count_write(durability, batch.encoded_bytes);
        let rocks_batch = self.rocks_batch(batch)?;
        if sync {
            let mut write_options = WriteOptions::default();
            write_options.set_sync(true);
            return self
                .db
                .write_opt(&rocks_batch, &write_options)
                .map_err(StorageError::backend);
        }
        self.db.write(&rocks_batch).map_err(StorageError::backend)
    }
}

impl KvStore for RocksDbStore {
    type WriteBatch = RocksDbWriteBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.db
            .get_cf(self.cf_handle(cf)?, key)
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let handle = self.cf_handle(cf)?;
        let prefix = prefix.to_vec();
        let iterator = self.db.iterator_cf_opt(
            handle,
            ReadOptions::default(),
            IteratorMode::From(&prefix, Direction::Forward),
        );
        Ok(Box::new(
            iterator
                .map(|item| {
                    item.map(|(key, value)| (key.to_vec(), value.to_vec()))
                        .map_err(StorageError::backend)
                })
                .take_while(move |item| match item {
                    Ok((key, _)) => key.starts_with(&prefix),
                    Err(_) => true,
                }),
        ))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        RocksDbWriteBatch::default()
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.db
            .put_cf(self.cf_handle(cf)?, key, value)
            .map_err(StorageError::backend)
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.write_with_durability(batch, "default", false)
    }

    fn write_deferred(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.write_with_durability(batch, "deferred", false)
    }

    fn write_durable(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.write_with_durability(batch, "durable", true)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: RocksDbWriteBatch,
    ) -> Result<bool, StorageError> {
        let _guard = self.write_lock.lock();
        let mut handles = [None; ColumnFamily::ALL.len()];
        for condition in conditions {
            let (cf, key) = condition.location();
            let handle = cached_cf_handle(self, &mut handles, cf)?;
            let current = self.db.get_cf(handle, key).map_err(StorageError::backend)?;
            if !condition.matches(current.as_deref()) {
                return Ok(false);
            }
        }
        self.write_with_durability(batch, "durable", true)?;
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        metrics::counter!("storage.flushes_total", "backend" => "rocksdb").increment(1);
        self.db.flush_wal(true).map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(RocksDbSnapshot {
            db: self,
            snapshot: self.db.snapshot(),
        }))
    }
}

/// Records one backend-neutral write-path metric sample.
fn count_write(durability: &'static str, encoded_bytes: usize) {
    metrics::counter!("storage.writes_total", "backend" => "rocksdb", "durability" => durability)
        .increment(1);
    metrics::histogram!("storage.write_bytes", "backend" => "rocksdb")
        .record(crate::metric_f64_from_usize(encoded_bytes));
}

fn cached_cf_handle<'store>(
    store: &'store RocksDbStore,
    handles: &mut [Option<&'store rust_rocksdb::ColumnFamily>],
    cf: ColumnFamily,
) -> Result<&'store rust_rocksdb::ColumnFamily, StorageError> {
    let slot = handles
        .get_mut(cf.index())
        .ok_or(StorageError::UnknownColumnFamily(cf))?;
    if slot.is_none() {
        *slot = Some(store.cf_handle(cf)?);
    }
    slot.ok_or(StorageError::UnknownColumnFamily(cf))
}

/// `RocksDB` write-batch adapter.
#[derive(Default)]
pub struct RocksDbWriteBatch {
    ops: Vec<BatchOp>,
    /// Sum of key and value lengths across ops, for write-path metrics.
    encoded_bytes: usize,
}

impl WriteBatch for RocksDbWriteBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.put_value(cf, key, Bytes::copy_from_slice(value));
    }

    fn put_value(&mut self, cf: ColumnFamily, key: &[u8], value: Bytes) {
        self.encoded_bytes = self.encoded_bytes.saturating_add(key.len() + value.len());
        self.ops.push(BatchOp::Put {
            cf,
            key: key.to_vec(),
            value,
        });
    }

    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.encoded_bytes = self.encoded_bytes.saturating_add(key.len());
        self.ops.push(BatchOp::Delete {
            cf,
            key: key.to_vec(),
        });
    }

    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]) {
        self.ops.push(BatchOp::DeleteRange {
            cf,
            start: start.to_vec(),
            end: end.to_vec(),
        });
    }
}

enum BatchOp {
    Put {
        cf: ColumnFamily,
        key: Vec<u8>,
        value: Bytes,
    },
    Delete {
        cf: ColumnFamily,
        key: Vec<u8>,
    },
    DeleteRange {
        cf: ColumnFamily,
        start: Vec<u8>,
        end: Vec<u8>,
    },
}

struct RocksDbSnapshot<'a> {
    db: &'a RocksDbStore,
    snapshot: rust_rocksdb::Snapshot<'a>,
}

impl KvSnapshot for RocksDbSnapshot<'_> {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.snapshot
            .get_cf(self.db.cf_handle(cf)?, key)
            .map_err(StorageError::backend)
    }

    fn get_many_sorted(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StorageError> {
        if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(StorageError::InvalidOperation(
                "snapshot batch keys are not strictly ascending",
            ));
        }

        let mut read_options = ReadOptions::default();
        read_options.set_snapshot(&self.snapshot);
        self.db
            .db
            .batched_multi_get_cf_slice_opt(
                self.db.cf_handle(cf)?,
                keys.iter().copied(),
                true,
                &read_options,
            )
            .into_iter()
            .map(|result| {
                result
                    .map(|value| value.map(|pinned| pinned.as_ref().to_vec()))
                    .map_err(StorageError::backend)
            })
            .collect()
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let handle = self.db.cf_handle(cf)?;
        let prefix = prefix.to_vec();
        let iterator = self.snapshot.iterator_cf_opt(
            handle,
            ReadOptions::default(),
            IteratorMode::From(&prefix, Direction::Forward),
        );
        Ok(Box::new(
            iterator
                .map(|item| {
                    item.map(|(key, value)| (key.to_vec(), value.to_vec()))
                        .map_err(StorageError::backend)
                })
                .take_while(move |item| match item {
                    Ok((key, _)) => key.starts_with(&prefix),
                    Err(_) => true,
                }),
        ))
    }
}
