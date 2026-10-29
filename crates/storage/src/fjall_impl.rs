#[cfg(any(test, feature = "test-seam"))]
use crate::batch::prefix_ops;
use crate::batch::{BatchOp, BufferedWriteBatch};
use std::collections::BTreeSet;
use std::path::Path;

use fjall::config::CompressionPolicy;
use fjall::{CompressionType, Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteCondition};

/// Fjall's default block-cache capacity for unbudgeted opens.
pub const FJALL_DEFAULT_CACHE_BYTES: u64 = 32 * 1024 * 1024;

pub struct FjallStore {
    db: Database,
    keyspaces: Vec<Keyspace>,
    write_lock: parking_lot::Mutex<()>,
    #[cfg(any(test, feature = "test-seam"))]
    faults: crate::trait_::PersistFaultSlot,
    /// Last field: drops after the engine handles above have closed.
    guard: Option<crate::StoreGuard>,
}

impl FjallStore {
    /// Keeps `guard` alive until this store's engine handle is closed.
    /// Panics when a guard is already installed: replacing it would release
    /// the first guard while the engine handle it protects is still open.
    #[must_use]
    pub fn guarded_by(self, guard: crate::StoreGuard) -> Self {
        assert!(
            self.guard.is_none(),
            "a Fjall store takes exactly one lifetime guard"
        );
        Self {
            guard: Some(guard),
            ..self
        }
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_cache(path, FJALL_DEFAULT_CACHE_BYTES)
    }

    /// Opens or creates a Fjall store with an explicit block-cache capacity.
    ///
    /// `cache_bytes` sizes fjall's shared block cache and is configured exactly: a
    /// budgeted share is never raised above its allocation. Zero selects the engine
    /// default for unbudgeted opens.
    pub fn open_with_cache(path: impl AsRef<Path>, cache_bytes: u64) -> Result<Self, StorageError> {
        let cache_bytes = if cache_bytes == 0 {
            FJALL_DEFAULT_CACHE_BYTES
        } else {
            cache_bytes
        };
        metrics::gauge!("storage.cache_capacity_bytes", "backend" => "fjall")
            .set(bitcoin_rs_primitives::u64_to_f64(cache_bytes));
        let db = Database::builder(path.as_ref())
            .cache_size(cache_bytes)
            .open()
            .map_err(StorageError::backend)?;
        let mut keyspaces = Vec::with_capacity(ColumnFamily::ALL.len());
        for cf in ColumnFamily::ALL.iter().copied() {
            let opts = KeyspaceCreateOptions::default()
                .data_block_compression_policy(CompressionPolicy::all(CompressionType::Lz4));
            keyspaces.push(
                db.keyspace(cf.name(), || opts)
                    .map_err(StorageError::backend)?,
            );
        }
        Ok(Self {
            db,
            keyspaces,
            write_lock: parking_lot::Mutex::new(()),
            #[cfg(any(test, feature = "test-seam"))]
            faults: crate::trait_::PersistFaultSlot::default(),
            guard: None,
        })
    }

    fn keyspace(&self, cf: ColumnFamily) -> Result<&Keyspace, StorageError> {
        self.keyspaces
            .get(cf.index())
            .ok_or(StorageError::UnknownColumnFamily(cf))
    }

    fn write_with_durability(
        &self,
        batch: BufferedWriteBatch,
        durability: Option<PersistMode>,
    ) -> Result<(), StorageError> {
        let durability_label = match durability {
            Some(PersistMode::SyncAll) => "durable",
            Some(_) => "deferred",
            None => "default",
        };
        metrics::counter!("storage.writes_total", "backend" => "fjall", "durability" => durability_label)
            .increment(1);
        metrics::histogram!("storage.write_bytes", "backend" => "fjall").record(
            bitcoin_rs_primitives::u64_to_f64(
                u64::try_from(batch.encoded_bytes).unwrap_or(u64::MAX),
            ),
        );

        #[cfg(any(test, feature = "test-seam"))]
        {
            if let Some(fault) = self.faults.take_at(crate::trait_::PersistBoundary::Apply) {
                if fault == crate::PersistFault::PartialApply {
                    let mut fjall_batch = self.db.batch();
                    self.stage_ops(&mut fjall_batch, prefix_ops(batch.ops).collect())?;
                }
                return Err(fault.injected_error());
            }

            if durability == Some(PersistMode::SyncAll) {
                if let Some(fault) = self.faults.take_at(crate::trait_::PersistBoundary::Sync) {
                    let mut fjall_batch = self.db.batch();
                    self.stage_ops(&mut fjall_batch, batch.ops)?;
                    fjall_batch.commit().map_err(StorageError::backend)?;
                    return Err(fault.injected_error());
                }
            }
        }

        let mut fjall_batch = self.db.batch();
        if let Some(durability) = durability {
            fjall_batch = fjall_batch.durability(Some(durability));
        }
        self.stage_ops(&mut fjall_batch, batch.ops)?;
        if fjall_batch.is_empty() && durability == Some(PersistMode::SyncAll) {
            return self
                .db
                .persist(PersistMode::SyncAll)
                .map_err(StorageError::backend);
        }
        fjall_batch.commit().map_err(StorageError::backend)
    }

    /// Stages `ops` into `fjall_batch` without committing.
    fn stage_ops(
        &self,
        fjall_batch: &mut fjall::OwnedWriteBatch,
        ops: Vec<BatchOp>,
    ) -> Result<(), StorageError> {
        let mut keyspaces = [None; ColumnFamily::ALL.len()];
        let mut last_range = [None; ColumnFamily::ALL.len()];
        for (index, op) in ops.iter().enumerate() {
            if let BatchOp::DeleteRange { cf, .. } = op {
                last_range[cf.index()] = Some(index);
            }
        }
        let mut staged_puts: [BTreeSet<Vec<u8>>; ColumnFamily::ALL.len()] =
            std::array::from_fn(|_| BTreeSet::new());
        for (index, op) in ops.into_iter().enumerate() {
            match op {
                BatchOp::Put { cf, key, value } => {
                    if last_range[cf.index()].is_some_and(|last| index < last) {
                        staged_puts[cf.index()].insert(key.clone());
                    }
                    fjall_batch.insert(
                        cached_keyspace(self, &mut keyspaces, cf)?,
                        key,
                        value.as_ref(),
                    );
                }
                BatchOp::Delete { cf, key } => {
                    staged_puts[cf.index()].remove(&key);
                    fjall_batch.remove(cached_keyspace(self, &mut keyspaces, cf)?, key);
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    let keyspace = cached_keyspace(self, &mut keyspaces, cf)?;
                    let keys = keyspace
                        .range(start.as_slice()..end.as_slice())
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
                    staged_puts[cf.index()].retain(|key| {
                        if start <= *key && *key < end {
                            fjall_batch.remove(keyspace, key.as_slice());
                            false
                        } else {
                            true
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

impl KvStore for FjallStore {
    fn get_bounded(
        &self,
        cf: ColumnFamily,
        key: &[u8],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, crate::BoundedReadError> {
        self.keyspace(cf)?
            .get(key)
            .map_err(StorageError::backend)?
            .map(|value| crate::error::copy_bounded(&value, max_bytes))
            .transpose()
    }

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

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        let rows = self
            .keyspace(cf)?
            .range::<&[u8], _>(core::cmp::max(start, prefix)..)
            .map(|guard| guard.into_inner().map_err(StorageError::backend));
        crate::trait_::collect_bounded_prefix(rows, prefix, limit)
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        BufferedWriteBatch::default()
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.keyspace(cf)?
            .insert(key, value)
            .map_err(StorageError::backend)
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.write_with_durability(batch, None)
    }

    fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.write_with_durability(batch, Some(PersistMode::SyncAll))
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        let _guard = self.write_lock.lock();
        let mut keyspaces = [None; ColumnFamily::ALL.len()];
        for condition in conditions {
            let (cf, key) = condition.location();
            let keyspace = cached_keyspace(self, &mut keyspaces, cf)?;
            let current = keyspace.get(key).map_err(StorageError::backend)?;
            if !condition.matches(current.as_ref().map(std::convert::AsRef::as_ref)) {
                return Ok(false);
            }
        }
        self.write_with_durability(batch, Some(PersistMode::SyncAll))?;
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        metrics::counter!("storage.flushes_total", "backend" => "fjall").increment(1);
        #[cfg(any(test, feature = "test-seam"))]
        if let Some(fault) = self.faults.take_at(crate::trait_::PersistBoundary::Flush) {
            return Err(fault.injected_error());
        }
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

    #[cfg(any(test, feature = "test-seam"))]
    fn arm_persist_fault(&self, fault: crate::PersistFault) {
        self.faults.arm(fault);
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

    fn last_prefix(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Option<crate::KvPair>, StorageError> {
        let keyspace = self.store.keyspace(cf)?;
        let mut range = match prefix_end(prefix) {
            Some(end) => self.snapshot.range(keyspace, prefix.to_vec()..end),
            None => self.snapshot.range(keyspace, prefix.to_vec()..),
        };
        range
            .next_back()
            .map(|guard| {
                guard
                    .into_inner()
                    .map(|(key, value)| (key.to_vec(), value.to_vec()))
                    .map_err(StorageError::backend)
            })
            .transpose()
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        let rows = self
            .snapshot
            .range::<&[u8], _>(self.store.keyspace(cf)?, core::cmp::max(start, prefix)..)
            .map(|guard| guard.into_inner().map_err(StorageError::backend));
        crate::trait_::collect_bounded_prefix(rows, prefix, limit)
    }
}

/// Exclusive upper bound of a prefix range, if the prefix is not all `0xFF`.
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
