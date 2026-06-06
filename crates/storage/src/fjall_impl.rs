use std::path::Path;

use bytes::Bytes;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteBatch};

/// Fjall-backed key-value store.
pub struct FjallStore {
    db: Database,
    keyspaces: Vec<Keyspace>,
}

impl FjallStore {
    /// Opens or creates a Fjall store at `path` with one keyspace per column family.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = Database::builder(path.as_ref())
            .open()
            .map_err(StorageError::backend)?;
        let mut keyspaces = Vec::with_capacity(ColumnFamily::ALL.len());
        for cf in ColumnFamily::ALL.iter().copied() {
            keyspaces.push(
                db.keyspace(cf.name(), KeyspaceCreateOptions::default)
                    .map_err(StorageError::backend)?,
            );
        }
        Ok(Self { db, keyspaces })
    }

    fn keyspace(&self, cf: ColumnFamily) -> Result<&Keyspace, StorageError> {
        self.keyspaces
            .get(cf.index())
            .ok_or(StorageError::UnknownColumnFamily(cf))
    }
}

impl KvStore for FjallStore {
    type WriteBatch = FjallWriteBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.keyspace(cf)?
            .get(key)
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let iterator = self.keyspace(cf)?.prefix(prefix).map(|guard| {
            guard
                .into_inner()
                .map(|(key, value)| (key.to_vec(), value.to_vec()))
                .map_err(StorageError::backend)
        });
        Ok(Box::new(iterator))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        FjallWriteBatch::default()
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.keyspace(cf)?
            .insert(key, value)
            .map_err(StorageError::backend)
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let mut fjall_batch = self.db.batch();
        let mut keyspaces = [None; ColumnFamily::ALL.len()];
        for op in batch.ops {
            match op {
                BatchOp::Put { cf, key, value } => {
                    fjall_batch.insert(
                        cached_keyspace(self, &mut keyspaces, cf)?,
                        key,
                        value.as_ref(),
                    );
                }
                BatchOp::Delete { cf, key } => {
                    fjall_batch.remove(cached_keyspace(self, &mut keyspaces, cf)?, key);
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    let keyspace = cached_keyspace(self, &mut keyspaces, cf)?;
                    let keys = keyspace
                        .range(start..end)
                        .map(|guard| {
                            guard
                                .key()
                                .map(|key| key.to_vec())
                                .map_err(StorageError::backend)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    for key in keys {
                        fjall_batch.remove(keyspace, key);
                    }
                }
            }
        }
        fjall_batch.commit().map_err(StorageError::backend)
    }

    fn flush(&self) -> Result<(), StorageError> {
        // Fjall journals are crash-consistent before fsync; SyncAll requests full durability.
        self.db
            .persist(PersistMode::SyncAll)
            .map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(FjallSnapshot {
            store: self,
            snapshot: self.db.snapshot(),
        }))
    }
}

fn cached_keyspace<'store>(
    store: &'store FjallStore,
    keyspaces: &mut [Option<&'store Keyspace>],
    cf: ColumnFamily,
) -> Result<&'store Keyspace, StorageError> {
    let slot = keyspaces
        .get_mut(cf.index())
        .ok_or(StorageError::UnknownColumnFamily(cf))?;
    if slot.is_none() {
        *slot = Some(store.keyspace(cf)?);
    }
    slot.ok_or(StorageError::UnknownColumnFamily(cf))
}

/// Fjall write-batch adapter.
#[derive(Default)]
pub struct FjallWriteBatch {
    ops: Vec<BatchOp>,
}

impl WriteBatch for FjallWriteBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.put_value(cf, key, Bytes::copy_from_slice(value));
    }

    fn put_value(&mut self, cf: ColumnFamily, key: &[u8], value: Bytes) {
        self.ops.push(BatchOp::Put {
            cf,
            key: key.to_vec(),
            value,
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

struct FjallSnapshot<'a> {
    store: &'a FjallStore,
    snapshot: fjall::Snapshot,
}

impl KvSnapshot for FjallSnapshot<'_> {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.snapshot
            .get(self.store.keyspace(cf)?, key)
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let iterator = self
            .snapshot
            .prefix(self.store.keyspace(cf)?, prefix)
            .map(|guard| {
                guard
                    .into_inner()
                    .map(|(key, value)| (key.to_vec(), value.to_vec()))
                    .map_err(StorageError::backend)
            });
        Ok(Box::new(iterator))
    }
}
