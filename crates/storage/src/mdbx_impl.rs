use std::borrow::Cow;
use std::path::Path;

use bytes::Bytes;
use signet_libmdbx::{
    Database, DatabaseFlags, Environment, Geometry, WriteFlags,
    tx::aliases::{RoTxSync, RwTxSync},
};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition};

const MIB: usize = 1024 * 1024;
const GIB: usize = 1024 * MIB;
const TIB: usize = 1024 * GIB;

/// MDBX's default page size, used to turn cache bytes into page counts.
const MDBX_PAGE_BYTES: u64 = 4 * 1024;
/// MDBX's default dirty-page reserve for unbudgeted opens.
const MDBX_DEFAULT_DIRTY_RESERVE_BYTES: u64 = 64 * 1024 * 1024;
/// Engine ceiling for the reserved dirty-page pool (MDBX caps at 32-bit).
const MDBX_MAX_RESERVE_PAGES: u64 = 1 << 20;
/// Engine ceiling for the loose-page reuse pool.
const MDBX_MAX_LOOSE_PAGES: u64 = 255;

/// MDBX-backed key-value store.
pub struct MdbxStore {
    env: Environment,
    databases: Vec<Database>,
}

impl MdbxStore {
    /// Opens or creates an MDBX store at `path` with one named database per column family.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_cache(path, MDBX_DEFAULT_DIRTY_RESERVE_BYTES)
    }

    /// Opens or creates an MDBX store with an explicit write-cache capacity.
    ///
    /// MDBX reads through the OS page cache over its memory map, which no
    /// in-process knob bounds; the budget therefore applies to the write side:
    /// the reserved dirty-page pool (`dp_reserve_limit`, pages) and the
    /// loose-page reuse pool (`loose_limit`, pages) are derived from
    /// `cache_bytes` at MDBX's 4 KiB default page size and clamped to their
    /// engine ceilings. `cache_bytes` itself is configured exactly: a budgeted
    /// share is never raised above its allocation. Zero selects the engine
    /// default for unbudgeted opens. Reads stay OS-cached regardless of the
    /// budget.
    pub fn open_with_cache(path: impl AsRef<Path>, cache_bytes: u64) -> Result<Self, StorageError> {
        let cache_bytes = if cache_bytes == 0 {
            MDBX_DEFAULT_DIRTY_RESERVE_BYTES
        } else {
            cache_bytes
        };
        let reserve_pages = (cache_bytes / MDBX_PAGE_BYTES).min(MDBX_MAX_RESERVE_PAGES);
        let loose_pages = (cache_bytes / MDBX_PAGE_BYTES / 4).clamp(16, MDBX_MAX_LOOSE_PAGES);
        metrics::gauge!("storage.cache_capacity_bytes", "backend" => "mdbx")
            .set(crate::metric_f64(cache_bytes));
        std::fs::create_dir_all(path.as_ref())?;
        let env = Environment::builder()
            .set_max_dbs(ColumnFamily::ALL.len())
            .set_dp_reserve_limit(reserve_pages)
            .set_loose_limit(loose_pages)
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

    /// Applies one batch as a single logical write with the given durability
    /// label, so each write is counted exactly once.
    fn write_with_durability(
        &self,
        batch: MdbxWriteBatch,
        durability: &'static str,
    ) -> Result<(), StorageError> {
        count_write(durability, batch.encoded_bytes);
        let txn = self.env.begin_rw_sync().map_err(StorageError::backend)?;
        apply_mdbx_ops(self, &txn, batch)?;
        txn.commit().map_err(StorageError::backend)
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

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        let txn = self.env.begin_ro_sync().map_err(StorageError::backend)?;
        scan_prefix(&txn, self.database(cf)?, prefix, limit)
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
        self.write_with_durability(batch, "default")
    }

    fn write_durable(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        // MDBX environments are opened with default durable sync flags, so a normal
        // synchronous write transaction already returns after the data is fsynced.
        self.write_with_durability(batch, "durable")
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: MdbxWriteBatch,
    ) -> Result<bool, StorageError> {
        let encoded_bytes = batch.encoded_bytes;
        let txn = self.env.begin_rw_sync().map_err(StorageError::backend)?;
        for condition in conditions {
            let (cf, key) = condition.location();
            let current: Option<Cow<'_, [u8]>> = txn
                .get(self.database(cf)?.dbi(), key)
                .map_err(StorageError::backend)?;
            if !condition.matches(current.as_deref()) {
                // Dropping the transaction aborts it, so no batch operation is applied.
                return Ok(false);
            }
        }
        apply_mdbx_ops(self, &txn, batch)?;
        txn.commit().map_err(StorageError::backend)?;
        count_write("durable", encoded_bytes);
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        metrics::counter!("storage.flushes_total", "backend" => "mdbx").increment(1);
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

/// Records one backend-neutral write-path metric sample.
fn count_write(durability: &'static str, encoded_bytes: usize) {
    metrics::counter!("storage.writes_total", "backend" => "mdbx", "durability" => durability)
        .increment(1);
    metrics::histogram!("storage.write_bytes", "backend" => "mdbx")
        .record(crate::metric_f64_from_usize(encoded_bytes));
}

/// Applies every ordered batch operation inside one open write transaction.
fn apply_mdbx_ops(
    store: &MdbxStore,
    txn: &RwTxSync,
    batch: MdbxWriteBatch,
) -> Result<(), StorageError> {
    let mut databases = [None; ColumnFamily::ALL.len()];
    for op in batch.ops {
        match op {
            BatchOp::Put { cf, key, value } => {
                txn.put(
                    cached_database(store, &mut databases, cf)?,
                    &key,
                    &value,
                    WriteFlags::empty(),
                )
                .map_err(StorageError::backend)?;
            }
            BatchOp::Delete { cf, key } => {
                txn.del(cached_database(store, &mut databases, cf)?, &key, None)
                    .map_err(StorageError::backend)?;
            }
            BatchOp::DeleteRange { cf, start, end } => {
                let database = cached_database(store, &mut databases, cf)?;
                for key in collect_range_keys(txn, database, &start, &end)? {
                    txn.del(database, &key, None)
                        .map_err(StorageError::backend)?;
                }
            }
        }
    }
    Ok(())
}

fn cached_database(
    store: &MdbxStore,
    databases: &mut [Option<Database>],
    cf: ColumnFamily,
) -> Result<Database, StorageError> {
    let slot = databases
        .get_mut(cf.index())
        .ok_or(StorageError::UnknownColumnFamily(cf))?;
    if slot.is_none() {
        *slot = Some(store.database(cf)?);
    }
    slot.ok_or(StorageError::UnknownColumnFamily(cf))
}

/// MDBX write-batch adapter.
#[derive(Default)]
pub struct MdbxWriteBatch {
    ops: Vec<BatchOp>,
    /// Sum of key and value lengths across ops, for write-path metrics.
    encoded_bytes: usize,
}

impl WriteBatch for MdbxWriteBatch {
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

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        scan_prefix(&self.txn, self.database(cf)?, prefix, limit)
    }
}

fn scan_prefix<'tx>(
    txn: &'tx RoTxSync,
    database: Database,
    prefix: &[u8],
    limit: crate::PrefixScanLimit,
) -> Result<crate::PrefixScan, StorageError> {
    use std::borrow::Cow;

    let mut cursor = txn.cursor(database).map_err(StorageError::backend)?;
    let mut iter = cursor
        .iter_from::<Cow<'tx, [u8]>, Cow<'tx, [u8]>>(prefix)
        .map_err(StorageError::backend)?;
    let mut rows = Vec::new();
    let mut bytes = 0;
    while let Some((key, value)) = iter.borrow_next().map_err(StorageError::backend)? {
        if !key.starts_with(prefix) {
            // Native forward ordering means no later key can match.
            return Ok(crate::PrefixScan {
                rows,
                complete: true,
            });
        }
        if !crate::trait_::push_bounded_row(&mut rows, &mut bytes, &key, &value, limit) {
            // Stop before copying the first row that exceeds limits.
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
