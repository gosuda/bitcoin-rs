use std::path::Path;

use signet_libmdbx::{
    Database, DatabaseFlags, Environment, Geometry, WriteFlags,
    tx::aliases::{RoTxSync, RwTxSync},
};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteBatch};

const MIB: usize = 1024 * 1024;
const GIB: usize = 1024 * MIB;
const TIB: usize = 1024 * GIB;

/// MDBX-backed key-value store.
pub struct MdbxStore {
    env: Environment,
    databases: Vec<Database>,
}

impl MdbxStore {
    /// Opens or creates an MDBX store at `path` with one named database per column family.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        std::fs::create_dir_all(path.as_ref())?;
        let env = Environment::builder()
            .set_max_dbs(ColumnFamily::ALL.len())
            .set_geometry(Geometry {
                size: Some(GIB..TIB),
                ..Default::default()
            })
            .open(path.as_ref())
            .map_err(StorageError::backend)?;

        let txn = env.begin_rw_sync().map_err(StorageError::backend)?;
        let mut databases = Vec::with_capacity(ColumnFamily::ALL.len());
        for cf in ColumnFamily::ALL.iter().copied() {
            databases.push(
                txn.create_db(Some(cf.name()), DatabaseFlags::empty())
                    .map_err(StorageError::backend)?,
            );
        }
        txn.commit().map_err(StorageError::backend)?;
        Ok(Self { env, databases })
    }

    fn database(&self, cf: ColumnFamily) -> Result<Database, StorageError> {
        self.databases
            .get(cf.index())
            .copied()
            .ok_or(StorageError::UnknownColumnFamily(cf))
    }
}

impl KvStore for MdbxStore {
    type WriteBatch = MdbxWriteBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let txn = self.env.begin_ro_sync().map_err(StorageError::backend)?;
        txn.get(self.database(cf)?.dbi(), key)
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let txn = self.env.begin_ro_sync().map_err(StorageError::backend)?;
        let rows = collect_prefix(&txn, self.database(cf)?, prefix)?;
        Ok(Box::new(rows.into_iter().map(Ok)))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        MdbxWriteBatch::default()
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let txn = self.env.begin_rw_sync().map_err(StorageError::backend)?;
        txn.put(self.database(cf)?, key, value, WriteFlags::empty())
            .map_err(StorageError::backend)?;
        txn.commit().map_err(StorageError::backend)
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let txn = self.env.begin_rw_sync().map_err(StorageError::backend)?;
        for op in batch.ops {
            match op {
                BatchOp::Put { cf, key, value } => {
                    txn.put(self.database(cf)?, key, value, WriteFlags::empty())
                        .map_err(StorageError::backend)?;
                }
                BatchOp::Delete { cf, key } => {
                    txn.del(self.database(cf)?, key, None)
                        .map_err(StorageError::backend)?;
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    let database = self.database(cf)?;
                    let keys = collect_range_keys(&txn, database, &start, &end)?;
                    for key in keys {
                        txn.del(database, key, None)
                            .map_err(StorageError::backend)?;
                    }
                }
            }
        }
        txn.commit().map_err(StorageError::backend)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.env
            .sync(true)
            .map(|_| ())
            .map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(MdbxSnapshot {
            txn: self.env.begin_ro_sync().map_err(StorageError::backend)?,
            databases: self.databases.clone(),
        }))
    }
}

/// MDBX write-batch adapter.
#[derive(Default)]
pub struct MdbxWriteBatch {
    ops: Vec<BatchOp>,
}

impl WriteBatch for MdbxWriteBatch {
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

struct MdbxSnapshot {
    txn: RoTxSync,
    databases: Vec<Database>,
}

impl MdbxSnapshot {
    fn database(&self, cf: ColumnFamily) -> Result<Database, StorageError> {
        self.databases
            .get(cf.index())
            .copied()
            .ok_or(StorageError::UnknownColumnFamily(cf))
    }
}

impl KvSnapshot for MdbxSnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.txn
            .get(self.database(cf)?.dbi(), key)
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let rows = collect_prefix(&self.txn, self.database(cf)?, prefix)?;
        Ok(Box::new(rows.into_iter().map(Ok)))
    }
}

fn collect_prefix(
    txn: &RoTxSync,
    database: Database,
    prefix: &[u8],
) -> Result<Vec<crate::trait_::KvPair>, StorageError> {
    let mut cursor = txn.cursor(database).map_err(StorageError::backend)?;
    let mut rows = Vec::new();
    let iter = cursor
        .iter_from::<Vec<u8>, Vec<u8>>(prefix)
        .map_err(StorageError::backend)?;
    for item in iter {
        let (key, value) = item.map_err(StorageError::backend)?;
        if !key.starts_with(prefix) {
            break;
        }
        rows.push((key, value));
    }
    Ok(rows)
}

fn collect_range_keys(
    txn: &RwTxSync,
    database: Database,
    start: &[u8],
    end: &[u8],
) -> Result<Vec<Vec<u8>>, StorageError> {
    let mut cursor = txn.cursor(database).map_err(StorageError::backend)?;
    let mut keys = Vec::new();
    let iter = cursor
        .iter_from::<Vec<u8>, Vec<u8>>(start)
        .map_err(StorageError::backend)?;
    for item in iter {
        let (key, _) = item.map_err(StorageError::backend)?;
        if key.as_slice() >= end {
            break;
        }
        keys.push(key);
    }
    Ok(keys)
}
