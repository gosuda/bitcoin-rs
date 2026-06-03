use std::path::{Path, PathBuf};

use redb::{Database, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteBatch};

type ByteTable = TableDefinition<'static, &'static [u8], &'static [u8]>;

/// redb-backed key-value store.
pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    /// Opens or creates a redb store at `path` with one table per column family.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db_path = database_path(path.as_ref())?;
        let db = Database::create(db_path).map_err(StorageError::backend)?;
        let write_txn = db.begin_write().map_err(StorageError::backend)?;
        for cf in ColumnFamily::ALL.iter().copied() {
            let table = write_txn
                .open_table(table_for(cf))
                .map_err(StorageError::backend)?;
            drop(table);
        }
        write_txn.commit().map_err(StorageError::backend)?;
        Ok(Self { db })
    }
}

impl KvStore for RedbStore {
    type WriteBatch = RedbWriteBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let read_txn = self.db.begin_read().map_err(StorageError::backend)?;
        let table = read_txn
            .open_table(table_for(cf))
            .map_err(StorageError::backend)?;
        table
            .get(key)
            .map(|value| value.map(|bytes| bytes.value().to_vec()))
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let read_txn = self.db.begin_read().map_err(StorageError::backend)?;
        let rows = collect_prefix(&read_txn, cf, prefix)?;
        Ok(Box::new(rows.into_iter().map(Ok)))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        RedbWriteBatch::default()
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write().map_err(StorageError::backend)?;
        {
            let mut table = write_txn
                .open_table(table_for(cf))
                .map_err(StorageError::backend)?;
            table.insert(key, value).map_err(StorageError::backend)?;
        }
        write_txn.commit().map_err(StorageError::backend)
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write().map_err(StorageError::backend)?;
        for op in batch.ops {
            match op {
                BatchOp::Put { cf, key, value } => {
                    let mut table = write_txn
                        .open_table(table_for(cf))
                        .map_err(StorageError::backend)?;
                    table
                        .insert(key.as_slice(), value.as_slice())
                        .map_err(StorageError::backend)?;
                }
                BatchOp::Delete { cf, key } => {
                    let mut table = write_txn
                        .open_table(table_for(cf))
                        .map_err(StorageError::backend)?;
                    table
                        .remove(key.as_slice())
                        .map_err(StorageError::backend)?;
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    let mut table = write_txn
                        .open_table(table_for(cf))
                        .map_err(StorageError::backend)?;
                    let keys = table
                        .range(start.as_slice()..end.as_slice())
                        .map_err(StorageError::backend)?
                        .map(|item| {
                            item.map(|(key, _)| key.value().to_vec())
                                .map_err(StorageError::backend)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    for key in keys {
                        table
                            .remove(key.as_slice())
                            .map_err(StorageError::backend)?;
                    }
                }
            }
        }
        write_txn.commit().map_err(StorageError::backend)
    }

    fn flush(&self) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write().map_err(StorageError::backend)?;
        write_txn.commit().map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(RedbSnapshot {
            read_txn: self.db.begin_read().map_err(StorageError::backend)?,
        }))
    }
}

/// redb write-batch adapter.
#[derive(Default)]
pub struct RedbWriteBatch {
    ops: Vec<BatchOp>,
}

impl WriteBatch for RedbWriteBatch {
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

struct RedbSnapshot {
    read_txn: ReadTransaction,
}

impl KvSnapshot for RedbSnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let table = self
            .read_txn
            .open_table(table_for(cf))
            .map_err(StorageError::backend)?;
        table
            .get(key)
            .map(|value| value.map(|bytes| bytes.value().to_vec()))
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let rows = collect_prefix(&self.read_txn, cf, prefix)?;
        Ok(Box::new(rows.into_iter().map(Ok)))
    }
}

fn database_path(path: &Path) -> Result<PathBuf, StorageError> {
    if path.extension().is_some() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(path.to_path_buf())
    } else {
        std::fs::create_dir_all(path)?;
        Ok(path.join("redb.db"))
    }
}

const fn table_for(cf: ColumnFamily) -> ByteTable {
    match cf {
        ColumnFamily::TxConfirmed => TableDefinition::new("tx_confirmed"),
        ColumnFamily::TxMempool => TableDefinition::new("tx_mempool"),
        ColumnFamily::BlockHeaders => TableDefinition::new("block_headers"),
        ColumnFamily::Funding => TableDefinition::new("funding"),
        ColumnFamily::Spending => TableDefinition::new("spending"),
        ColumnFamily::Filters => TableDefinition::new("filters"),
        ColumnFamily::FilterHeaders => TableDefinition::new("filter_headers"),
        ColumnFamily::Coinstats => TableDefinition::new("coinstats"),
        ColumnFamily::BlockTree => TableDefinition::new("block_tree"),
        ColumnFamily::UtxoMeta => TableDefinition::new("utxo_meta"),
        ColumnFamily::BlockBodies => TableDefinition::new("block_bodies"),
    }
}

fn collect_prefix(
    read_txn: &ReadTransaction,
    cf: ColumnFamily,
    prefix: &[u8],
) -> Result<Vec<crate::trait_::KvPair>, StorageError> {
    let table = read_txn
        .open_table(table_for(cf))
        .map_err(StorageError::backend)?;
    let mut rows = Vec::new();
    match prefix_end(prefix) {
        Some(end) => {
            for item in table
                .range(prefix..end.as_slice())
                .map_err(StorageError::backend)?
            {
                let (key, value) = item.map_err(StorageError::backend)?;
                rows.push((key.value().to_vec(), value.value().to_vec()));
            }
        }
        None => {
            for item in table.range(prefix..).map_err(StorageError::backend)? {
                let (key, value) = item.map_err(StorageError::backend)?;
                if !key.value().starts_with(prefix) {
                    break;
                }
                rows.push((key.value().to_vec(), value.value().to_vec()));
            }
        }
    }
    Ok(rows)
}

fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(byte) = end.last_mut() {
        if *byte == u8::MAX {
            end.pop();
        } else {
            *byte = byte.saturating_add(1);
            return Some(end);
        }
    }
    None
}
