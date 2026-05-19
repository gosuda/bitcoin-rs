use std::path::Path;

use fjall::{Config, PartitionCreateOptions, PersistMode};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteBatch};

/// Fjall-backed key-value store.
pub struct FjallStore {
    keyspace: fjall::Keyspace,
    partitions: Vec<fjall::Partition>,
}

impl FjallStore {
    /// Opens or creates a Fjall store at `path` with one partition per column family.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let keyspace = Config::new(path).open().map_err(StorageError::backend)?;
        let mut partitions = Vec::with_capacity(ColumnFamily::ALL.len());
        for cf in ColumnFamily::ALL.iter().copied() {
            partitions.push(
                keyspace
                    .open_partition(cf.name(), PartitionCreateOptions::default())
                    .map_err(StorageError::backend)?,
            );
        }
        Ok(Self {
            keyspace,
            partitions,
        })
    }

    fn partition(&self, cf: ColumnFamily) -> Result<&fjall::Partition, StorageError> {
        self.partitions
            .get(cf.index())
            .ok_or(StorageError::UnknownColumnFamily(cf))
    }
}

impl KvStore for FjallStore {
    type WriteBatch = FjallWriteBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.partition(cf)?
            .get(key)
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let iterator = self.partition(cf)?.prefix(prefix.to_vec()).map(|item| {
            item.map(|(key, value)| (key.to_vec(), value.to_vec()))
                .map_err(StorageError::backend)
        });
        Ok(Box::new(iterator))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        FjallWriteBatch::default()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let mut fjall_batch = self.keyspace.batch();
        for op in batch.ops {
            match op {
                BatchOp::Put { cf, key, value } => {
                    fjall_batch.insert(self.partition(cf)?, key, value);
                }
                BatchOp::Delete { cf, key } => {
                    fjall_batch.remove(self.partition(cf)?, key);
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    let partition = self.partition(cf)?;
                    let keys = partition
                        .range(start..end)
                        .map(|item| {
                            item.map(|(key, _)| key.to_vec())
                                .map_err(StorageError::backend)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    for key in keys {
                        fjall_batch.remove(partition, key);
                    }
                }
            }
        }
        fjall_batch.commit().map_err(StorageError::backend)
    }

    fn flush(&self) -> Result<(), StorageError> {
        // Fjall journals are crash-consistent before fsync; SyncAll requests full durability.
        self.keyspace
            .persist(PersistMode::SyncAll)
            .map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        let snapshots = self
            .partitions
            .iter()
            .map(fjall::Partition::snapshot)
            .collect();
        Ok(Box::new(FjallSnapshot { snapshots }))
    }
}

/// Fjall write-batch adapter.
#[derive(Default)]
pub struct FjallWriteBatch {
    ops: Vec<BatchOp>,
}

impl WriteBatch for FjallWriteBatch {
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

struct FjallSnapshot {
    snapshots: Vec<fjall::Snapshot>,
}

impl FjallSnapshot {
    fn snapshot(&self, cf: ColumnFamily) -> Result<&fjall::Snapshot, StorageError> {
        self.snapshots
            .get(cf.index())
            .ok_or(StorageError::UnknownColumnFamily(cf))
    }
}

impl KvSnapshot for FjallSnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.snapshot(cf)?
            .get(key)
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let iterator = self.snapshot(cf)?.prefix(prefix.to_vec()).map(|item| {
            item.map(|(key, value)| (key.to_vec(), value.to_vec()))
                .map_err(StorageError::backend)
        });
        Ok(Box::new(iterator))
    }
}
