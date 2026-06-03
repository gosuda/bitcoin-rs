use std::path::Path;

use rust_rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, Direction, IteratorMode,
    Options, ReadOptions, WriteBatch as RocksWriteBatch,
};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteBatch};

const BLOCK_SIZE: usize = 4 * 1024 * 1024;
const BLOCK_CACHE_SIZE: usize = 256 * 1024 * 1024;
const BLOOM_BITS_PER_KEY: f64 = 10.0;

/// `RocksDB`-backed key-value store.
pub struct RocksDbStore {
    db: rust_rocksdb::DB,
}

impl RocksDbStore {
    /// Opens or creates a `RocksDB` store at `path` with all column families.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let mut db_options = Options::default();
        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);
        db_options.set_compression_type(DBCompressionType::Lz4);
        db_options.set_atomic_flush(true);

        let mut table_options = BlockBasedOptions::default();
        table_options.set_block_size(BLOCK_SIZE);
        table_options.set_block_cache(&Cache::new_lru_cache(BLOCK_CACHE_SIZE));
        table_options.set_bloom_filter(BLOOM_BITS_PER_KEY, false);
        table_options.set_cache_index_and_filter_blocks(true);

        let mut cf_options = Options::default();
        cf_options.set_compression_type(DBCompressionType::Lz4);
        cf_options.set_block_based_table_factory(&table_options);

        let descriptors = ColumnFamily::ALL
            .iter()
            .copied()
            .map(|cf| ColumnFamilyDescriptor::new(cf.name(), cf_options.clone()));
        let db = rust_rocksdb::DB::open_cf_descriptors(&db_options, path, descriptors)
            .map_err(StorageError::backend)?;
        Ok(Self { db })
    }

    fn cf_handle(&self, cf: ColumnFamily) -> Result<&rust_rocksdb::ColumnFamily, StorageError> {
        self.db
            .cf_handle(cf.name())
            .ok_or(StorageError::UnknownColumnFamily(cf))
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
        self.db
            .put_cf(self.cf_handle(cf)?, key, value)
            .map_err(StorageError::backend)
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let mut rocks_batch = RocksWriteBatch::default();
        let mut handles = vec![None; ColumnFamily::ALL.len()];
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
        self.db.write(&rocks_batch).map_err(StorageError::backend)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.db.flush().map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(RocksDbSnapshot {
            db: self,
            snapshot: self.db.snapshot(),
        }))
    }
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
}

impl WriteBatch for RocksDbWriteBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.ops.push(BatchOp::Put {
            cf,
            key: key.to_vec(),
            value: value.to_vec(),
        });
    }

    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
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
        value: Vec<u8>,
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
