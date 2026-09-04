use std::path::{Path, PathBuf};

use bytes::Bytes;
use redb::{
    Database, Durability, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition,
};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition};

type ByteTable = TableDefinition<'static, &'static [u8], &'static [u8]>;
type FixedTable<const N: usize> = TableDefinition<'static, &'static [u8; N], ()>;
type TxIndexValueTable = TableDefinition<'static, &'static [u8; 12], &'static [u8]>;
/// `ScriptLive` key width: `prefix(8) || txid(32) || vout(4)`.
const SCRIPT_LIVE_KEY_LEN: usize = 44;

const TXINDEX_TX_CONFIRMED: FixedTable<12> = TableDefinition::new("txindex_v1_tx_confirmed");
const TXINDEX_TX_CONFIRMED_VALUES: TxIndexValueTable =
    TableDefinition::new("txindex_v1_tx_confirmed_values");
const TXINDEX_FUNDING: FixedTable<12> = TableDefinition::new("txindex_v1_funding");
const TXINDEX_FUNDING_VALUES: TxIndexValueTable = TableDefinition::new("txindex_v1_funding_values");
const TXINDEX_SPENDING: FixedTable<12> = TableDefinition::new("txindex_v1_spending");
const TXINDEX_SPENDING_VALUES: TxIndexValueTable =
    TableDefinition::new("txindex_v1_spending_values");
const TXINDEX_BLOCK_HEADERS: FixedTable<80> = TableDefinition::new("txindex_v1_block_headers");
const TXINDEX_SCRIPT_LIVE: FixedTable<SCRIPT_LIVE_KEY_LEN> =
    TableDefinition::new("txindex_v1_script_live");
const TXINDEX_META: ByteTable = TableDefinition::new("txindex_v1_meta");

/// redb's builder-default page-cache capacity for the transaction index.
const REDB_TXINDEX_DEFAULT_CACHE_BYTES: u64 = 1024 * 1024 * 1024;

/// redb's builder-default page-cache capacity for unbudgeted opens.
const REDB_DEFAULT_CACHE_BYTES: u64 = 1024 * 1024 * 1024;

/// redb-backed key-value store.
pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    /// Opens or creates a redb store at `path` with one table per column family.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_cache(path, REDB_DEFAULT_CACHE_BYTES)
    }

    /// Opens or creates a redb store with an explicit page-cache capacity.
    ///
    /// `cache_bytes` bounds redb's in-memory page cache and is configured
    /// exactly: a budgeted share is never raised above its allocation. Zero
    /// selects the engine default for unbudgeted opens.
    pub fn open_with_cache(path: impl AsRef<Path>, cache_bytes: u64) -> Result<Self, StorageError> {
        let cache_bytes = if cache_bytes == 0 {
            REDB_DEFAULT_CACHE_BYTES
        } else {
            cache_bytes
        };
        metrics::gauge!("storage.cache_capacity_bytes", "backend" => "redb")
            .set(crate::metric_f64(cache_bytes));
        let db_path = database_path(path.as_ref())?;
        let db = Database::builder()
            .set_cache_size(usize::try_from(cache_bytes).unwrap_or(usize::MAX))
            .create(db_path)
            .map_err(StorageError::backend)?;
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

    fn write_with_durability(
        &self,
        batch: RedbWriteBatch,
        durability: Durability,
    ) -> Result<(), StorageError> {
        validate_redb_store_batch(&batch)?;
        let durability_label = match durability {
            Durability::Immediate => "durable",
            Durability::None => "deferred",
            _ => "other",
        };
        metrics::counter!("storage.writes_total", "backend" => "redb", "durability" => durability_label)
            .increment(1);
        metrics::histogram!("storage.write_bytes", "backend" => "redb")
            .record(crate::metric_f64_from_usize(batch.encoded_bytes));
        let mut write_txn = self.db.begin_write().map_err(StorageError::backend)?;
        write_txn
            .set_durability(durability)
            .map_err(StorageError::backend)?;
        apply_redb_ops(&write_txn, batch.ops.into_iter())?;
        write_txn.commit().map_err(StorageError::backend)
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
        let rows = collect_prefix(&read_txn, table_for(cf), prefix)?;
        Ok(Box::new(rows.into_iter().map(Ok)))
    }

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        let read_txn = self.db.begin_read().map_err(StorageError::backend)?;
        scan_prefix(&read_txn, table_for(cf), prefix, limit)
    }

    fn new_batch(&self) -> Self::WriteBatch {
        RedbWriteBatch::default()
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        if cf == ColumnFamily::ScriptLive {
            validate_script_live_put(key, value)?;
        }
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
        self.write_with_durability(batch, Durability::Immediate)
    }

    fn write_deferred(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write_with_durability(batch, Durability::None)
    }

    fn write_durable(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write_with_durability(batch, Durability::Immediate)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: RedbWriteBatch,
    ) -> Result<bool, StorageError> {
        validate_redb_store_batch(&batch)?;
        let mut write_txn = self.db.begin_write().map_err(StorageError::backend)?;
        write_txn
            .set_durability(Durability::Immediate)
            .map_err(StorageError::backend)?;
        for condition in conditions {
            let (cf, key) = condition.location();
            let table = write_txn
                .open_table(table_for(cf))
                .map_err(StorageError::backend)?;
            let guard = table.get(key).map_err(StorageError::backend)?;
            let matched = match condition {
                WriteCondition::Absent { .. } => guard.is_none(),
                WriteCondition::Equals { expected, .. } => match &guard {
                    Some(g) => g.value() == *expected,
                    None => false,
                },
            };
            if !matched {
                // Dropping the transaction aborts it, so no batch operation is applied.
                return Ok(false);
            }
        }
        apply_redb_ops(&write_txn, batch.ops.into_iter())?;
        write_txn.commit().map_err(StorageError::backend)?;
        metrics::counter!("storage.writes_total", "backend" => "redb", "durability" => "durable")
            .increment(1);
        metrics::histogram!("storage.write_bytes", "backend" => "redb")
            .record(crate::metric_f64_from_usize(batch.encoded_bytes));
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        metrics::counter!("storage.flushes_total", "backend" => "redb").increment(1);
        let mut write_txn = self.db.begin_write().map_err(StorageError::backend)?;
        // An empty Immediate commit makes all earlier None commits durable.
        write_txn
            .set_durability(Durability::Immediate)
            .map_err(StorageError::backend)?;
        write_txn.commit().map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(RedbSnapshot {
            read_txn: self.db.begin_read().map_err(StorageError::backend)?,
        }))
    }
}

/// redb-backed transaction-index store using fixed-width physical tables.
struct RedbTxIndexStore {
    db: Database,
}

impl RedbTxIndexStore {
    /// Opens or creates a transaction-index store at `path`.
    fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_cache(path, REDB_TXINDEX_DEFAULT_CACHE_BYTES)
    }

    /// Opens or creates a transaction-index store with an explicit page-cache
    /// capacity, configured exactly.
    fn open_with_cache(path: impl AsRef<Path>, cache_bytes: u64) -> Result<Self, StorageError> {
        let db_path = database_path(path.as_ref())?;
        let db = Database::builder()
            .set_cache_size(usize::try_from(cache_bytes).unwrap_or(usize::MAX))
            .create(db_path)
            .map_err(StorageError::backend)?;
        let write_txn = db.begin_write().map_err(StorageError::backend)?;
        drop(
            write_txn
                .open_table(TXINDEX_TX_CONFIRMED)
                .map_err(StorageError::backend)?,
        );
        drop(
            write_txn
                .open_table(TXINDEX_TX_CONFIRMED_VALUES)
                .map_err(StorageError::backend)?,
        );
        drop(
            write_txn
                .open_table(TXINDEX_FUNDING)
                .map_err(StorageError::backend)?,
        );
        drop(
            write_txn
                .open_table(TXINDEX_FUNDING_VALUES)
                .map_err(StorageError::backend)?,
        );
        drop(
            write_txn
                .open_table(TXINDEX_SPENDING)
                .map_err(StorageError::backend)?,
        );
        drop(
            write_txn
                .open_table(TXINDEX_SPENDING_VALUES)
                .map_err(StorageError::backend)?,
        );
        drop(
            write_txn
                .open_table(TXINDEX_BLOCK_HEADERS)
                .map_err(StorageError::backend)?,
        );
        drop(
            write_txn
                .open_table(TXINDEX_SCRIPT_LIVE)
                .map_err(StorageError::backend)?,
        );
        drop(
            write_txn
                .open_table(TXINDEX_META)
                .map_err(StorageError::backend)?,
        );
        write_txn.commit().map_err(StorageError::backend)?;
        Ok(Self { db })
    }

    fn write_with_durability(
        &self,
        batch: RedbWriteBatch,
        durability: Durability,
    ) -> Result<(), StorageError> {
        let durability_label = match durability {
            Durability::Immediate => "durable",
            Durability::None => "deferred",
            _ => "other",
        };
        metrics::counter!("storage.writes_total", "backend" => "redb", "durability" => durability_label)
            .increment(1);
        metrics::histogram!("storage.write_bytes", "backend" => "redb")
            .record(crate::metric_f64_from_usize(batch.encoded_bytes));
        let mut write_txn = self.db.begin_write().map_err(StorageError::backend)?;
        write_txn
            .set_durability(durability)
            .map_err(StorageError::backend)?;
        apply_txindex_ops(&write_txn, batch.ops.into_iter())?;
        write_txn.commit().map_err(StorageError::backend)
    }
}

impl KvStore for RedbTxIndexStore {
    type WriteBatch = RedbWriteBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let read_txn = self.db.begin_read().map_err(StorageError::backend)?;
        match cf {
            ColumnFamily::TxConfirmed => fixed_value_get(
                &read_txn,
                TXINDEX_TX_CONFIRMED,
                TXINDEX_TX_CONFIRMED_VALUES,
                key,
            ),
            ColumnFamily::Funding => {
                fixed_value_get(&read_txn, TXINDEX_FUNDING, TXINDEX_FUNDING_VALUES, key)
            }
            ColumnFamily::Spending => {
                fixed_value_get(&read_txn, TXINDEX_SPENDING, TXINDEX_SPENDING_VALUES, key)
            }
            ColumnFamily::BlockHeaders => fixed_get(&read_txn, TXINDEX_BLOCK_HEADERS, key),
            ColumnFamily::ScriptLive => fixed_get(&read_txn, TXINDEX_SCRIPT_LIVE, key),
            ColumnFamily::UtxoMeta => byte_get(&read_txn, TXINDEX_META, key),
            _ => Err(invalid_txindex_cf()),
        }
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let read_txn = self.db.begin_read().map_err(StorageError::backend)?;
        let rows = collect_txindex_prefix(&read_txn, cf, prefix)?;
        Ok(Box::new(rows.into_iter().map(Ok)))
    }

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        let read_txn = self.db.begin_read().map_err(StorageError::backend)?;
        scan_txindex_prefix(&read_txn, cf, prefix, limit)
    }

    fn new_batch(&self) -> Self::WriteBatch {
        RedbWriteBatch::default()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write_with_durability(batch, Durability::Immediate)
    }

    fn write_deferred(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write_with_durability(batch, Durability::None)
    }

    fn write_durable(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write_with_durability(batch, Durability::Immediate)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: RedbWriteBatch,
    ) -> Result<bool, StorageError> {
        // Width and family validation happens before any transaction begins so an
        // invalid request never opens (and aborts) a write transaction. Every
        // condition is validated, not only the first.
        validate_txindex_batch(&batch)?;
        for condition in conditions {
            let (cf, key) = condition.location();
            validate_txindex_key(cf, key)?;
        }
        let mut write_txn = self.db.begin_write().map_err(StorageError::backend)?;
        write_txn
            .set_durability(Durability::Immediate)
            .map_err(StorageError::backend)?;
        for condition in conditions {
            if !txindex_condition_matches(&write_txn, condition)? {
                // Dropping the transaction aborts it, so no batch operation is applied.
                return Ok(false);
            }
        }
        apply_txindex_ops(&write_txn, batch.ops.into_iter())?;
        write_txn.commit().map_err(StorageError::backend)?;
        metrics::counter!("storage.writes_total", "backend" => "redb", "durability" => "durable")
            .increment(1);
        metrics::histogram!("storage.write_bytes", "backend" => "redb")
            .record(crate::metric_f64_from_usize(batch.encoded_bytes));
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        metrics::counter!("storage.flushes_total", "backend" => "redb-txindex").increment(1);
        let mut write_txn = self.db.begin_write().map_err(StorageError::backend)?;
        write_txn
            .set_durability(Durability::Immediate)
            .map_err(StorageError::backend)?;
        write_txn.commit().map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(RedbTxIndexSnapshot {
            read_txn: self.db.begin_read().map_err(StorageError::backend)?,
        }))
    }
}

/// Opens the fixed-width redb transaction-index store at `path` behind an
/// opaque [`KvStore`].
///
/// The concrete store type is an implementation detail. The store serves
/// [`ColumnFamily::TxConfirmed`], [`ColumnFamily::Funding`],
/// [`ColumnFamily::Spending`], [`ColumnFamily::BlockHeaders`],
/// [`ColumnFamily::ScriptLive`], and [`ColumnFamily::UtxoMeta`]; every other
/// family returns [`StorageError::InvalidOperation`].
pub fn open_redb_tx_index_store(path: &Path) -> Result<impl KvStore, StorageError> {
    RedbTxIndexStore::open(path)
}

/// Opens the fixed-width redb transaction-index store with an explicit
/// page-cache capacity.
///
/// The tables and layout are unchanged. `cache_bytes` configures only the
/// cache window; zero selects the store default.
pub fn open_redb_tx_index_store_with_cache(
    path: &Path,
    cache_bytes: u64,
) -> Result<impl KvStore, StorageError> {
    let cache_bytes = if cache_bytes == 0 {
        REDB_TXINDEX_DEFAULT_CACHE_BYTES
    } else {
        cache_bytes
    };
    metrics::gauge!("storage.cache_capacity_bytes", "backend" => "redb-txindex")
        .set(crate::metric_f64(cache_bytes));
    RedbTxIndexStore::open_with_cache(path, cache_bytes)
}

/// redb write-batch adapter.
#[derive(Default)]
pub struct RedbWriteBatch {
    ops: Vec<BatchOp>,
    /// Sum of key and value lengths across ops, for write-path metrics.
    encoded_bytes: usize,
}

impl WriteBatch for RedbWriteBatch {
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

impl BatchOp {
    const fn cf(&self) -> ColumnFamily {
        match self {
            Self::Put { cf, .. } | Self::Delete { cf, .. } | Self::DeleteRange { cf, .. } => *cf,
        }
    }
}

fn apply_redb_batch_op(
    table: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    op: BatchOp,
) -> Result<(), StorageError> {
    match op {
        BatchOp::Put { cf, key, value } => {
            if cf == ColumnFamily::ScriptLive {
                validate_script_live_put(&key, &value)?;
            }
            table
                .insert(key.as_slice(), value.as_ref())
                .map(|_| ())
                .map_err(StorageError::backend)
        }
        BatchOp::Delete { key, .. } => table
            .remove(key.as_slice())
            .map(|_| ())
            .map_err(StorageError::backend),
        BatchOp::DeleteRange { start, end, .. } => {
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
            Ok(())
        }
    }
}

/// Applies every ordered batch operation inside one open write transaction,
/// opening each column family's table only once per consecutive run.
fn apply_redb_ops(
    write_txn: &redb::WriteTransaction,
    ops: std::vec::IntoIter<BatchOp>,
) -> Result<(), StorageError> {
    let mut ops = ops.peekable();
    while let Some(op) = ops.next() {
        let cf = op.cf();
        let mut table = write_txn
            .open_table(table_for(cf))
            .map_err(StorageError::backend)?;
        apply_redb_batch_op(&mut table, op)?;
        while ops.peek().is_some_and(|next| next.cf() == cf) {
            let Some(op) = ops.next() else { break };
            apply_redb_batch_op(&mut table, op)?;
        }
    }
    Ok(())
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
        let rows = collect_prefix(&self.read_txn, table_for(cf), prefix)?;
        Ok(Box::new(rows.into_iter().map(Ok)))
    }

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        scan_prefix(&self.read_txn, table_for(cf), prefix, limit)
    }
}

struct RedbTxIndexSnapshot {
    read_txn: ReadTransaction,
}

impl KvSnapshot for RedbTxIndexSnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        match cf {
            ColumnFamily::TxConfirmed => fixed_value_get(
                &self.read_txn,
                TXINDEX_TX_CONFIRMED,
                TXINDEX_TX_CONFIRMED_VALUES,
                key,
            ),
            ColumnFamily::Funding => {
                fixed_value_get(&self.read_txn, TXINDEX_FUNDING, TXINDEX_FUNDING_VALUES, key)
            }
            ColumnFamily::Spending => fixed_value_get(
                &self.read_txn,
                TXINDEX_SPENDING,
                TXINDEX_SPENDING_VALUES,
                key,
            ),
            ColumnFamily::BlockHeaders => fixed_get(&self.read_txn, TXINDEX_BLOCK_HEADERS, key),
            ColumnFamily::ScriptLive => fixed_get(&self.read_txn, TXINDEX_SCRIPT_LIVE, key),
            ColumnFamily::UtxoMeta => byte_get(&self.read_txn, TXINDEX_META, key),
            _ => Err(invalid_txindex_cf()),
        }
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let rows = collect_txindex_prefix(&self.read_txn, cf, prefix)?;
        Ok(Box::new(rows.into_iter().map(Ok)))
    }

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        scan_txindex_prefix(&self.read_txn, cf, prefix, limit)
    }
}

fn scan_prefix(
    read_txn: &redb::ReadTransaction,
    table_def: ByteTable,
    prefix: &[u8],
    limit: crate::PrefixScanLimit,
) -> Result<crate::PrefixScan, StorageError> {
    let table = read_txn
        .open_table(table_def)
        .map_err(StorageError::backend)?;
    let mut rows = Vec::new();
    let mut bytes = 0;
    match prefix_end(prefix) {
        Some(end) => {
            for item in table
                .range(prefix..end.as_slice())
                .map_err(StorageError::backend)?
            {
                let (key, value) = item.map_err(StorageError::backend)?;
                if !crate::trait_::push_bounded_row(
                    &mut rows,
                    &mut bytes,
                    key.value(),
                    value.value(),
                    limit,
                ) {
                    // Stop before copying the first row that exceeds limits.
                    return Ok(crate::PrefixScan {
                        rows,
                        complete: false,
                    });
                }
            }
        }
        None => {
            for item in table.range(prefix..).map_err(StorageError::backend)? {
                let (key, value) = item.map_err(StorageError::backend)?;
                if !key.value().starts_with(prefix) {
                    break;
                }
                if !crate::trait_::push_bounded_row(
                    &mut rows,
                    &mut bytes,
                    key.value(),
                    value.value(),
                    limit,
                ) {
                    return Ok(crate::PrefixScan {
                        rows,
                        complete: false,
                    });
                }
            }
        }
    }
    Ok(crate::PrefixScan {
        rows,
        complete: true,
    })
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
        ColumnFamily::Coinstats => TableDefinition::new("coinstats"),
        ColumnFamily::BlockTree => TableDefinition::new("block_tree"),
        ColumnFamily::UtxoMeta => TableDefinition::new("utxo_meta"),
        ColumnFamily::BlockBodies => TableDefinition::new("block_bodies"),
        ColumnFamily::UndoData => TableDefinition::new("undo_data"),
        ColumnFamily::ScriptLive => TableDefinition::new("script_live"),
    }
}

fn collect_prefix(
    read_txn: &ReadTransaction,
    table_def: ByteTable,
    prefix: &[u8],
) -> Result<Vec<crate::trait_::KvPair>, StorageError> {
    let table = read_txn
        .open_table(table_def)
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

/// Rejects a `ScriptLive` write that is not a 44-byte key with an empty value.
///
/// The dedicated txindex store enforces this with a fixed-width table. The
/// generic [`RedbStore`] path uses variable-width tables, so the same
/// `ScriptLiveRow` contract is checked here before any write is persisted.
fn validate_script_live_put(key: &[u8], value: &[u8]) -> Result<(), StorageError> {
    fixed_key::<SCRIPT_LIVE_KEY_LEN>(key).map(|_| ())?;
    if !value.is_empty() {
        return Err(fixed_value_error());
    }
    Ok(())
}

/// Validates `ScriptLive` puts in a generic [`RedbStore`] batch before a
/// transaction begins, matching the dedicated txindex store's reject-first
/// contract.
fn validate_redb_store_batch(batch: &RedbWriteBatch) -> Result<(), StorageError> {
    batch.ops.iter().try_for_each(|op| match op {
        BatchOp::Put { cf, key, value } if *cf == ColumnFamily::ScriptLive => {
            validate_script_live_put(key, value)
        }
        _ => Ok(()),
    })
}

fn invalid_txindex_cf() -> StorageError {
    StorageError::InvalidOperation("column family not supported by RedbTxIndexStore")
}

fn fixed_key_error() -> StorageError {
    StorageError::InvalidOperation("fixed-width key length mismatch")
}

fn fixed_value_error() -> StorageError {
    StorageError::InvalidOperation("fixed-width value must be empty")
}

fn fixed_prefix_error() -> StorageError {
    StorageError::InvalidOperation("fixed-width prefix exceeds key width")
}

fn fixed_key<const N: usize>(key: &[u8]) -> Result<[u8; N], StorageError> {
    if key.len() != N {
        return Err(fixed_key_error());
    }
    let mut array = [0u8; N];
    array.copy_from_slice(key);
    Ok(array)
}

fn fixed_prefix_bounds<const N: usize>(prefix: &[u8]) -> Result<([u8; N], [u8; N]), StorageError> {
    if prefix.len() > N {
        return Err(fixed_prefix_error());
    }
    let mut start = [0u8; N];
    let mut end = [0xffu8; N];
    start[..prefix.len()].copy_from_slice(prefix);
    end[..prefix.len()].copy_from_slice(prefix);
    Ok((start, end))
}

fn fixed_get<const N: usize>(
    read_txn: &ReadTransaction,
    table_def: FixedTable<N>,
    key: &[u8],
) -> Result<Option<Vec<u8>>, StorageError> {
    let array = fixed_key::<N>(key)?;
    let table = read_txn
        .open_table(table_def)
        .map_err(StorageError::backend)?;
    table
        .get(&array)
        .map(|value| value.map(|_| Vec::new()))
        .map_err(StorageError::backend)
}

fn fixed_value_get(
    read_txn: &ReadTransaction,
    main_def: FixedTable<12>,
    value_def: TxIndexValueTable,
    key: &[u8],
) -> Result<Option<Vec<u8>>, StorageError> {
    let key = fixed_key::<12>(key)?;
    let main = read_txn
        .open_table(main_def)
        .map_err(StorageError::backend)?;
    if main.get(&key).map_err(StorageError::backend)?.is_none() {
        return Ok(None);
    }
    let values = read_txn
        .open_table(value_def)
        .map_err(StorageError::backend)?;
    values
        .get(&key)
        .map(|value| value.map_or_else(Vec::new, |bytes| bytes.value().to_vec()))
        .map(Some)
        .map_err(StorageError::backend)
}

fn byte_get(
    read_txn: &ReadTransaction,
    table_def: ByteTable,
    key: &[u8],
) -> Result<Option<Vec<u8>>, StorageError> {
    let table = read_txn
        .open_table(table_def)
        .map_err(StorageError::backend)?;
    table
        .get(key)
        .map(|value| value.map(|bytes| bytes.value().to_vec()))
        .map_err(StorageError::backend)
}

fn fixed_prefix_collect<const N: usize>(
    read_txn: &ReadTransaction,
    table_def: FixedTable<N>,
    prefix: &[u8],
) -> Result<Vec<crate::trait_::KvPair>, StorageError> {
    let (start, end) = fixed_prefix_bounds::<N>(prefix)?;
    let table = read_txn
        .open_table(table_def)
        .map_err(StorageError::backend)?;
    let mut rows = Vec::new();
    for item in table
        .range::<&[u8; N]>(&start..=&end)
        .map_err(StorageError::backend)?
    {
        let (key, _) = item.map_err(StorageError::backend)?;
        rows.push((key.value().to_vec(), Vec::new()));
    }
    Ok(rows)
}

fn fixed_value_prefix_collect(
    read_txn: &ReadTransaction,
    main_def: FixedTable<12>,
    value_def: TxIndexValueTable,
    prefix: &[u8],
) -> Result<Vec<crate::trait_::KvPair>, StorageError> {
    let (start, end) = fixed_prefix_bounds::<12>(prefix)?;
    let main = read_txn
        .open_table(main_def)
        .map_err(StorageError::backend)?;
    let values = read_txn
        .open_table(value_def)
        .map_err(StorageError::backend)?;
    let mut rows = Vec::new();
    for item in main
        .range::<&[u8; 12]>(&start..=&end)
        .map_err(StorageError::backend)?
    {
        let (key, _) = item.map_err(StorageError::backend)?;
        let key = key.value();
        let value = values
            .get(key)
            .map_err(StorageError::backend)?
            .map_or_else(Vec::new, |bytes| bytes.value().to_vec());
        rows.push((key.to_vec(), value));
    }
    Ok(rows)
}

fn fixed_prefix_scan<const N: usize>(
    read_txn: &ReadTransaction,
    table_def: FixedTable<N>,
    prefix: &[u8],
    limit: crate::PrefixScanLimit,
) -> Result<crate::PrefixScan, StorageError> {
    let (start, end) = fixed_prefix_bounds::<N>(prefix)?;
    let table = read_txn
        .open_table(table_def)
        .map_err(StorageError::backend)?;
    let mut rows = Vec::new();
    let mut bytes = 0;
    for item in table
        .range::<&[u8; N]>(&start..=&end)
        .map_err(StorageError::backend)?
    {
        let (key, _) = item.map_err(StorageError::backend)?;
        if !crate::trait_::push_bounded_row(&mut rows, &mut bytes, key.value(), &[], limit) {
            return Ok(crate::PrefixScan {
                rows,
                complete: false,
            });
        }
    }
    Ok(crate::PrefixScan {
        rows,
        complete: true,
    })
}

fn fixed_value_prefix_scan(
    read_txn: &ReadTransaction,
    main_def: FixedTable<12>,
    value_def: TxIndexValueTable,
    prefix: &[u8],
    limit: crate::PrefixScanLimit,
) -> Result<crate::PrefixScan, StorageError> {
    let (start, end) = fixed_prefix_bounds::<12>(prefix)?;
    let main = read_txn
        .open_table(main_def)
        .map_err(StorageError::backend)?;
    let values = read_txn
        .open_table(value_def)
        .map_err(StorageError::backend)?;
    let mut rows = Vec::new();
    let mut bytes = 0;
    for item in main
        .range::<&[u8; 12]>(&start..=&end)
        .map_err(StorageError::backend)?
    {
        let (key, _) = item.map_err(StorageError::backend)?;
        let key = key.value();
        let value = values
            .get(key)
            .map_err(StorageError::backend)?
            .map_or_else(Vec::new, |bytes| bytes.value().to_vec());
        if !crate::trait_::push_bounded_row(&mut rows, &mut bytes, key, &value, limit) {
            return Ok(crate::PrefixScan {
                rows,
                complete: false,
            });
        }
    }
    Ok(crate::PrefixScan {
        rows,
        complete: true,
    })
}

fn collect_txindex_prefix(
    read_txn: &ReadTransaction,
    cf: ColumnFamily,
    prefix: &[u8],
) -> Result<Vec<crate::trait_::KvPair>, StorageError> {
    match cf {
        ColumnFamily::TxConfirmed => fixed_value_prefix_collect(
            read_txn,
            TXINDEX_TX_CONFIRMED,
            TXINDEX_TX_CONFIRMED_VALUES,
            prefix,
        ),
        ColumnFamily::Funding => {
            fixed_value_prefix_collect(read_txn, TXINDEX_FUNDING, TXINDEX_FUNDING_VALUES, prefix)
        }
        ColumnFamily::Spending => {
            fixed_value_prefix_collect(read_txn, TXINDEX_SPENDING, TXINDEX_SPENDING_VALUES, prefix)
        }
        ColumnFamily::BlockHeaders => {
            fixed_prefix_collect::<80>(read_txn, TXINDEX_BLOCK_HEADERS, prefix)
        }
        ColumnFamily::ScriptLive => {
            fixed_prefix_collect::<SCRIPT_LIVE_KEY_LEN>(read_txn, TXINDEX_SCRIPT_LIVE, prefix)
        }
        ColumnFamily::UtxoMeta => collect_prefix(read_txn, TXINDEX_META, prefix),
        _ => Err(invalid_txindex_cf()),
    }
}

fn scan_txindex_prefix(
    read_txn: &ReadTransaction,
    cf: ColumnFamily,
    prefix: &[u8],
    limit: crate::PrefixScanLimit,
) -> Result<crate::PrefixScan, StorageError> {
    match cf {
        ColumnFamily::TxConfirmed => fixed_value_prefix_scan(
            read_txn,
            TXINDEX_TX_CONFIRMED,
            TXINDEX_TX_CONFIRMED_VALUES,
            prefix,
            limit,
        ),
        ColumnFamily::Funding => fixed_value_prefix_scan(
            read_txn,
            TXINDEX_FUNDING,
            TXINDEX_FUNDING_VALUES,
            prefix,
            limit,
        ),
        ColumnFamily::Spending => fixed_value_prefix_scan(
            read_txn,
            TXINDEX_SPENDING,
            TXINDEX_SPENDING_VALUES,
            prefix,
            limit,
        ),
        ColumnFamily::BlockHeaders => {
            fixed_prefix_scan::<80>(read_txn, TXINDEX_BLOCK_HEADERS, prefix, limit)
        }
        ColumnFamily::ScriptLive => {
            fixed_prefix_scan::<SCRIPT_LIVE_KEY_LEN>(read_txn, TXINDEX_SCRIPT_LIVE, prefix, limit)
        }
        ColumnFamily::UtxoMeta => scan_prefix(read_txn, TXINDEX_META, prefix, limit),
        _ => Err(invalid_txindex_cf()),
    }
}

fn apply_fixed_op<const N: usize>(
    table: &mut redb::Table<'_, &'static [u8; N], ()>,
    op: BatchOp,
) -> Result<(), StorageError> {
    match op {
        BatchOp::Put { key, value, .. } => {
            if !value.is_empty() {
                return Err(fixed_value_error());
            }
            let key = fixed_key::<N>(&key)?;
            table
                .insert(&key, ())
                .map(|_| ())
                .map_err(StorageError::backend)
        }
        BatchOp::Delete { key, .. } => {
            let key = fixed_key::<N>(&key)?;
            table
                .remove(&key)
                .map(|_| ())
                .map_err(StorageError::backend)
        }
        BatchOp::DeleteRange { start, end, .. } => {
            let start = fixed_key::<N>(&start)?;
            let end = fixed_key::<N>(&end)?;
            table
                .retain_in::<&[u8; N], _>(&start..&end, |_, ()| false)
                .map_err(StorageError::backend)
        }
    }
}

fn apply_fixed_value_op(
    main: &mut redb::Table<'_, &'static [u8; 12], ()>,
    values: &mut redb::Table<'_, &'static [u8; 12], &'static [u8]>,
    op: BatchOp,
) -> Result<(), StorageError> {
    match op {
        BatchOp::Put { key, value, .. } => {
            let key = fixed_key::<12>(&key)?;
            main.insert(&key, ()).map_err(StorageError::backend)?;
            if value.is_empty() {
                values.remove(&key).map_err(StorageError::backend)?;
            } else {
                values
                    .insert(&key, value.as_ref())
                    .map_err(StorageError::backend)?;
            }
            Ok(())
        }
        BatchOp::Delete { key, .. } => {
            let key = fixed_key::<12>(&key)?;
            main.remove(&key).map_err(StorageError::backend)?;
            values.remove(&key).map_err(StorageError::backend)?;
            Ok(())
        }
        BatchOp::DeleteRange { start, end, .. } => {
            let start = fixed_key::<12>(&start)?;
            let end = fixed_key::<12>(&end)?;
            main.retain_in::<&[u8; 12], _>(&start..&end, |_, ()| false)
                .map_err(StorageError::backend)?;
            values
                .retain_in::<&[u8; 12], _>(&start..&end, |_, _| false)
                .map_err(StorageError::backend)
        }
    }
}

fn apply_fixed_value_run(
    write_txn: &redb::WriteTransaction,
    main_def: FixedTable<12>,
    value_def: TxIndexValueTable,
    first: BatchOp,
    ops: &mut std::iter::Peekable<std::vec::IntoIter<BatchOp>>,
) -> Result<(), StorageError> {
    let cf = first.cf();
    let mut main = write_txn
        .open_table(main_def)
        .map_err(StorageError::backend)?;
    let mut values = write_txn
        .open_table(value_def)
        .map_err(StorageError::backend)?;
    apply_fixed_value_op(&mut main, &mut values, first)?;
    while ops.peek().is_some_and(|next| next.cf() == cf) {
        let Some(op) = ops.next() else { break };
        apply_fixed_value_op(&mut main, &mut values, op)?;
    }
    Ok(())
}

fn apply_fixed_run<const N: usize>(
    write_txn: &redb::WriteTransaction,
    table_def: FixedTable<N>,
    first: BatchOp,
    ops: &mut std::iter::Peekable<std::vec::IntoIter<BatchOp>>,
) -> Result<(), StorageError> {
    let cf = first.cf();
    let mut table = write_txn
        .open_table(table_def)
        .map_err(StorageError::backend)?;
    apply_fixed_op(&mut table, first)?;
    while ops.peek().is_some_and(|next| next.cf() == cf) {
        let Some(op) = ops.next() else { break };
        apply_fixed_op(&mut table, op)?;
    }
    Ok(())
}

fn apply_byte_run(
    write_txn: &redb::WriteTransaction,
    table_def: ByteTable,
    first: BatchOp,
    ops: &mut std::iter::Peekable<std::vec::IntoIter<BatchOp>>,
) -> Result<(), StorageError> {
    let cf = first.cf();
    let mut table = write_txn
        .open_table(table_def)
        .map_err(StorageError::backend)?;
    apply_redb_batch_op(&mut table, first)?;
    while ops.peek().is_some_and(|next| next.cf() == cf) {
        let Some(op) = ops.next() else { break };
        apply_redb_batch_op(&mut table, op)?;
    }
    Ok(())
}

/// Validates every batch operation's family and widths before any transaction
/// begins, mirroring exactly what the apply path would reject mid-transaction.
fn validate_txindex_batch(batch: &RedbWriteBatch) -> Result<(), StorageError> {
    batch.ops.iter().try_for_each(|op| match op {
        BatchOp::Put { cf, key, value } => {
            if matches!(cf, ColumnFamily::BlockHeaders | ColumnFamily::ScriptLive)
                && !value.is_empty()
            {
                return Err(fixed_value_error());
            }
            validate_txindex_key(*cf, key)
        }
        BatchOp::Delete { cf, key } => validate_txindex_key(*cf, key),
        BatchOp::DeleteRange { cf, start, end } => {
            validate_txindex_key(*cf, start)?;
            validate_txindex_key(*cf, end)
        }
    })
}

/// Validates one txindex family/key pair; rejects unsupported families and
/// fixed-width keys of the wrong length before any transaction begins.
fn validate_txindex_key(cf: ColumnFamily, key: &[u8]) -> Result<(), StorageError> {
    match cf {
        ColumnFamily::TxConfirmed | ColumnFamily::Funding | ColumnFamily::Spending => {
            fixed_key::<12>(key).map(|_| ())
        }
        ColumnFamily::BlockHeaders => fixed_key::<80>(key).map(|_| ()),
        ColumnFamily::ScriptLive => fixed_key::<SCRIPT_LIVE_KEY_LEN>(key).map(|_| ()),
        ColumnFamily::UtxoMeta => Ok(()),
        _ => Err(invalid_txindex_cf()),
    }
}

/// Applies every ordered batch operation inside one open write transaction.
fn apply_txindex_ops(
    write_txn: &redb::WriteTransaction,
    ops: std::vec::IntoIter<BatchOp>,
) -> Result<(), StorageError> {
    let mut ops = ops.peekable();
    while let Some(op) = ops.next() {
        match op.cf() {
            ColumnFamily::TxConfirmed => apply_fixed_value_run(
                write_txn,
                TXINDEX_TX_CONFIRMED,
                TXINDEX_TX_CONFIRMED_VALUES,
                op,
                &mut ops,
            )?,
            ColumnFamily::Funding => apply_fixed_value_run(
                write_txn,
                TXINDEX_FUNDING,
                TXINDEX_FUNDING_VALUES,
                op,
                &mut ops,
            )?,
            ColumnFamily::Spending => apply_fixed_value_run(
                write_txn,
                TXINDEX_SPENDING,
                TXINDEX_SPENDING_VALUES,
                op,
                &mut ops,
            )?,
            ColumnFamily::BlockHeaders => {
                apply_fixed_run(write_txn, TXINDEX_BLOCK_HEADERS, op, &mut ops)?;
            }
            ColumnFamily::ScriptLive => {
                apply_fixed_run(write_txn, TXINDEX_SCRIPT_LIVE, op, &mut ops)?;
            }
            ColumnFamily::UtxoMeta => apply_byte_run(write_txn, TXINDEX_META, op, &mut ops)?,
            _ => return Err(invalid_txindex_cf()),
        }
    }
    Ok(())
}

fn txindex_condition_matches(
    write_txn: &redb::WriteTransaction,
    condition: &WriteCondition<'_>,
) -> Result<bool, StorageError> {
    let (cf, key) = condition.location();
    match cf {
        ColumnFamily::TxConfirmed => txindex_fixed_value_condition_matches(
            write_txn,
            TXINDEX_TX_CONFIRMED,
            TXINDEX_TX_CONFIRMED_VALUES,
            key,
            condition,
        ),
        ColumnFamily::Funding => txindex_fixed_value_condition_matches(
            write_txn,
            TXINDEX_FUNDING,
            TXINDEX_FUNDING_VALUES,
            key,
            condition,
        ),
        ColumnFamily::Spending => txindex_fixed_value_condition_matches(
            write_txn,
            TXINDEX_SPENDING,
            TXINDEX_SPENDING_VALUES,
            key,
            condition,
        ),
        ColumnFamily::BlockHeaders => {
            txindex_fixed_condition_matches(write_txn, TXINDEX_BLOCK_HEADERS, key, condition)
        }
        ColumnFamily::ScriptLive => {
            txindex_fixed_condition_matches(write_txn, TXINDEX_SCRIPT_LIVE, key, condition)
        }
        ColumnFamily::UtxoMeta => {
            let table = write_txn
                .open_table(TXINDEX_META)
                .map_err(StorageError::backend)?;
            let guard = table.get(key).map_err(StorageError::backend)?;
            Ok(match condition {
                WriteCondition::Absent { .. } => guard.is_none(),
                WriteCondition::Equals { expected, .. } => match &guard {
                    Some(g) => g.value() == *expected,
                    None => false,
                },
            })
        }
        _ => Err(invalid_txindex_cf()),
    }
}

fn txindex_fixed_value_condition_matches(
    write_txn: &redb::WriteTransaction,
    main_def: FixedTable<12>,
    value_def: TxIndexValueTable,
    key: &[u8],
    condition: &WriteCondition<'_>,
) -> Result<bool, StorageError> {
    let key = fixed_key::<12>(key)?;
    let main = write_txn
        .open_table(main_def)
        .map_err(StorageError::backend)?;
    let exists = main.get(&key).map_err(StorageError::backend)?.is_some();
    match condition {
        WriteCondition::Absent { .. } => Ok(!exists),
        WriteCondition::Equals { expected, .. } => {
            if !exists {
                return Ok(false);
            }
            let values = write_txn
                .open_table(value_def)
                .map_err(StorageError::backend)?;
            let guard = values.get(&key).map_err(StorageError::backend)?;
            Ok(match &guard {
                Some(g) => g.value() == *expected,
                None => expected.is_empty(),
            })
        }
    }
}

fn txindex_fixed_condition_matches<const N: usize>(
    write_txn: &redb::WriteTransaction,
    table_def: FixedTable<N>,
    key: &[u8],
    condition: &WriteCondition<'_>,
) -> Result<bool, StorageError> {
    let key = fixed_key::<N>(key)?;
    let table = write_txn
        .open_table(table_def)
        .map_err(StorageError::backend)?;
    let exists = table.get(&key).map_err(StorageError::backend)?.is_some();
    Ok(match condition {
        WriteCondition::Absent { .. } => !exists,
        WriteCondition::Equals { expected, .. } => exists && expected.is_empty(),
    })
}
