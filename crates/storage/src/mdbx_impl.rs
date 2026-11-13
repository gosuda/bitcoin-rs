use crate::batch::{BatchOp, BufferedWriteBatch};
use crate::trait_::{
    KvIter, KvPair, KvSnapshot, KvStore, PrefixScan, PrefixScanLimit, WriteCondition,
};
use crate::{BoundedReadError, ColumnFamily, StorageError};
use bytes::Bytes;
use signet_libmdbx::{
    Database, DatabaseFlags, Environment, EnvironmentFlags, Geometry, Mode, SyncMode, WriteFlags,
};
use std::path::Path;

pub(crate) const MDBX_MARKER: &str = "mdbx.dat";
pub const MAX_KEY_SIZE: usize = 1024;
pub const MAX_VAL_SIZE: usize = 2_146_435_072;
const INGEST_BATCH_TARGET_BYTES: usize = 64 * 1024 * 1024;

fn check_key(key: &[u8]) -> Result<(), StorageError> {
    if key.len() > MAX_KEY_SIZE {
        return Err(StorageError::InvalidOperation("key exceeds 1024 bytes"));
    }
    Ok(())
}

fn check_value(value: &[u8]) -> Result<(), StorageError> {
    if value.len() > MAX_VAL_SIZE {
        return Err(StorageError::InvalidOperation(
            "value exceeds backend limit",
        ));
    }
    Ok(())
}

fn validate_batch_op(op: &BatchOp) -> Result<(), StorageError> {
    match op {
        BatchOp::Put { key, value, .. } => {
            check_key(key)?;
            check_value(value)?;
        }
        BatchOp::Delete { key, .. } => {
            check_key(key)?;
        }
        BatchOp::DeleteRange { start, end, .. } => {
            check_key(start)?;
            check_key(end)?;
        }
    }
    Ok(())
}

fn validate_condition(condition: &WriteCondition<'_>) -> Result<(), StorageError> {
    let (_, key) = condition.location();
    check_key(key)?;
    if let WriteCondition::Equals { expected, .. } = condition {
        check_value(expected)?;
    }
    Ok(())
}

fn delete_range_cursor(
    cursor: &mut signet_libmdbx::Cursor<'_, signet_libmdbx::RwSync>,
    start: &[u8],
    end: &[u8],
) -> Result<(), StorageError> {
    let mut current_key = match cursor
        .set_range::<Vec<u8>, ()>(start)
        .map_err(StorageError::backend)?
    {
        Some((k, _)) => k,
        None => return Ok(()),
    };
    while current_key.as_slice() < end {
        cursor.del().map_err(StorageError::backend)?;
        match cursor
            .get_current::<Vec<u8>, ()>()
            .map_err(StorageError::backend)?
        {
            Some((next_k, _)) => current_key = next_k,
            None => break,
        }
    }
    Ok(())
}

fn apply_batch_op(
    store: &MdbxStore,
    tx: &signet_libmdbx::TxSync<signet_libmdbx::RwSync>,
    op: BatchOp,
) -> Result<(), StorageError> {
    match op {
        BatchOp::Put { cf, key, value } => {
            let db = store.db_for_cf(cf)?;
            tx.put(db, &key, &value, WriteFlags::empty())
                .map_err(StorageError::backend)?;
        }
        BatchOp::Delete { cf, key } => {
            let db = store.db_for_cf(cf)?;
            tx.del(db, &key, None).map_err(StorageError::backend)?;
        }
        BatchOp::DeleteRange { cf, start, end } => {
            if start < end {
                let db = store.db_for_cf(cf)?;
                let mut cursor = tx.cursor(db).map_err(StorageError::backend)?;
                delete_range_cursor(&mut cursor, &start, &end)?;
            }
        }
    }
    Ok(())
}

fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut next = prefix.to_vec();
    while let Some(last) = next.pop() {
        if last < 0xff {
            next.push(last + 1);
            return Some(next);
        }
    }
    None
}

fn collect_bounded_prefix<K, V>(
    rows: impl Iterator<Item = Result<(K, V), StorageError>>,
    prefix: &[u8],
    limit: PrefixScanLimit,
) -> Result<PrefixScan, StorageError>
where
    K: AsRef<[u8]>,
    V: Into<Vec<u8>>,
{
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for item in rows {
        let (key, value) = item?;
        let key_ref = key.as_ref();
        if !key_ref.starts_with(prefix) {
            break;
        }
        let val_vec = value.into();
        let row_bytes = key_ref.len().saturating_add(val_vec.len());
        let next_bytes = bytes.saturating_add(row_bytes);
        if out.len() >= limit.max_rows || (!out.is_empty() && next_bytes > limit.max_bytes) {
            return Ok(PrefixScan {
                rows: out,
                complete: false,
            });
        }
        out.push((key_ref.to_vec(), val_vec));
        bytes = next_bytes;
    }
    Ok(PrefixScan {
        rows: out,
        complete: true,
    })
}

#[cfg(any(test, feature = "test-seam"))]
fn fault_injected_error(
    fault: crate::PersistFault,
    boundary: crate::trait_::PersistBoundary,
) -> StorageError {
    StorageError::Io(std::io::Error::other(format!(
        "injected persistence fault {fault:?} at the {boundary:?} boundary"
    )))
}

pub struct MdbxStore {
    env: Environment,
    dbs: [Database; ColumnFamily::ALL.len()],
    write_lock: parking_lot::Mutex<()>,
    #[cfg(any(test, feature = "test-seam"))]
    faults: crate::trait_::PersistFaultSlot,
    guard: Option<crate::StoreGuard>,
}

impl MdbxStore {
    #[must_use]
    pub fn guarded_by(self, guard: crate::StoreGuard) -> Self {
        assert!(
            self.guard.is_none(),
            "an MDBX store takes exactly one lifetime guard"
        );
        Self {
            guard: Some(guard),
            ..self
        }
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_cache(path, 0)
    }

    pub fn open_with_cache(
        path: impl AsRef<Path>,
        _cache_bytes: u64,
    ) -> Result<Self, StorageError> {
        std::fs::create_dir_all(path.as_ref()).map_err(StorageError::Io)?;
        let mut builder = Environment::builder();
        builder.set_max_dbs(32);
        builder.set_geometry(Geometry {
            size: Some(0..(1024 * 1024 * 1024 * 1024)),
            ..Default::default()
        });
        builder.set_flags(EnvironmentFlags {
            mode: Mode::ReadWrite {
                sync_mode: SyncMode::Durable,
            },
            ..Default::default()
        });
        let env = builder.open(path.as_ref()).map_err(StorageError::backend)?;
        let tx = env.begin_rw_sync().map_err(StorageError::backend)?;
        let mut dbs_vec = Vec::with_capacity(ColumnFamily::ALL.len());
        for cf in ColumnFamily::ALL {
            let db = tx
                .create_db(Some(cf.name()), DatabaseFlags::empty())
                .map_err(StorageError::backend)?;
            dbs_vec.push(db);
        }
        tx.commit().map_err(StorageError::backend)?;
        let dbs: [Database; ColumnFamily::ALL.len()] = dbs_vec.try_into().map_err(|_| {
            StorageError::Backend("failed to initialize all column families".into())
        })?;
        Ok(Self {
            env,
            dbs,
            write_lock: parking_lot::Mutex::new(()),
            #[cfg(any(test, feature = "test-seam"))]
            faults: crate::trait_::PersistFaultSlot::default(),
            guard: None,
        })
    }

    fn db_for_cf(&self, cf: ColumnFamily) -> Result<Database, StorageError> {
        self.dbs
            .get(cf.index())
            .copied()
            .ok_or(StorageError::UnknownColumnFamily(cf))
    }

    fn open_iter<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
    ) -> Result<MdbxStoreIter<'a>, StorageError> {
        let db = self.db_for_cf(cf)?;
        let tx = Box::new(self.env.begin_ro_sync().map_err(StorageError::backend)?);
        // SAFETY: tx is heap-allocated with a stable address that outlives cursor in MdbxStoreIter.
        let tx_ref: &'a signet_libmdbx::TxSync<signet_libmdbx::RoSync> =
            unsafe { &*std::ptr::from_ref(&*tx) };
        let cursor = tx_ref.cursor(db).map_err(StorageError::backend)?;
        Ok(MdbxStoreIter {
            cursor,
            _tx: tx,
            prefix: prefix.to_vec(),
            start: start.to_vec(),
            first: true,
        })
    }

    fn write_batch(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        let ops = batch.into_ops();
        for op in &ops {
            validate_batch_op(op)?;
        }
        let _guard = self.write_lock.lock();
        let tx = self.env.begin_rw_sync().map_err(StorageError::backend)?;
        for op in ops {
            apply_batch_op(self, &tx, op)?;
        }
        tx.commit().map_err(StorageError::backend)?;
        Ok(())
    }

    pub fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Bytes>>, StorageError> {
        for k in keys {
            check_key(k)?;
        }
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut indices: Vec<usize> = (0..keys.len()).collect();
        indices.sort_unstable_by(|&a, &b| keys[a].cmp(keys[b]));

        let db = self.db_for_cf(cf)?;
        let tx = self.env.begin_ro_sync().map_err(StorageError::backend)?;
        let mut results: Vec<Option<Bytes>> = vec![None; keys.len()];
        for idx in indices {
            let key = keys[idx];
            let val: Option<Vec<u8>> = tx.get(db.dbi(), key).map_err(StorageError::backend)?;
            results[idx] = val.map(Bytes::from);
        }
        Ok(results)
    }

    pub fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        _scratch: &Path,
    ) -> Result<u64, StorageError> {
        let _guard = self.write_lock.lock();
        let db = self.db_for_cf(cf)?;
        let mut count = 0u64;
        let mut batch_bytes = 0usize;
        let mut prev_key: Option<Vec<u8>> = None;
        let mut tx: Option<signet_libmdbx::TxSync<signet_libmdbx::RwSync>> = None;

        for (k, v) in rows {
            check_key(&k)?;
            check_value(&v)?;
            if let Some(prev) = &prev_key {
                if k.as_slice() <= prev.as_slice() {
                    return Err(StorageError::InvalidOperation(
                        "keys not strictly ascending",
                    ));
                }
            }
            let row_bytes = k.len().saturating_add(v.len());
            let is_oversized = row_bytes >= INGEST_BATCH_TARGET_BYTES;

            if batch_bytes > 0
                && (batch_bytes.saturating_add(row_bytes) > INGEST_BATCH_TARGET_BYTES
                    || is_oversized)
            {
                if let Some(t) = tx.take() {
                    t.commit().map_err(StorageError::backend)?;
                }
                batch_bytes = 0;
            }

            if tx.is_none() {
                tx = Some(self.env.begin_rw_sync().map_err(StorageError::backend)?);
            }

            let Some(active_tx) = tx.as_ref() else {
                return Err(StorageError::Backend("transaction missing".into()));
            };
            active_tx
                .append(db, &k, &v)
                .map_err(StorageError::backend)?;
            count += 1;
            prev_key = Some(k);

            if is_oversized {
                if let Some(t) = tx.take() {
                    t.commit().map_err(StorageError::backend)?;
                }
                batch_bytes = 0;
            } else {
                batch_bytes += row_bytes;
            }
        }

        if let Some(t) = tx.take() {
            t.commit().map_err(StorageError::backend)?;
        }

        Ok(count)
    }

    pub fn delete_range(
        &self,
        cf: ColumnFamily,
        start: &[u8],
        end: &[u8],
    ) -> Result<(), StorageError> {
        check_key(start)?;
        check_key(end)?;
        if start >= end {
            return Ok(());
        }
        let _guard = self.write_lock.lock();
        let db = self.db_for_cf(cf)?;
        let tx = self.env.begin_rw_sync().map_err(StorageError::backend)?;
        let mut cursor = tx.cursor(db).map_err(StorageError::backend)?;
        delete_range_cursor(&mut cursor, start, end)?;
        drop(cursor);
        tx.commit().map_err(StorageError::backend)?;
        Ok(())
    }

    pub fn checkpoint(&self, dir: &Path) -> Result<(), StorageError> {
        std::fs::create_dir_all(dir).map_err(StorageError::Io)?;
        let dest_file = dir.join(MDBX_MARKER);
        if dest_file.exists() {
            return Err(StorageError::IncompatibleData(
                "checkpoint destination file already exists".to_string(),
            ));
        }
        let path_str = dest_file
            .to_str()
            .ok_or(StorageError::InvalidOperation("invalid utf-8 path"))?;
        let c_dest = std::ffi::CString::new(path_str)
            .map_err(|_| StorageError::InvalidOperation("null byte in path"))?;
        self.env.with_raw_env_ptr(|env_ptr| {
            // SAFETY: env_ptr is a valid open MDBX environment pointer and c_dest is a valid null-terminated path.
            let rc = unsafe {
                signet_libmdbx::ffi::mdbx_env_copy(
                    env_ptr,
                    c_dest.as_ptr(),
                    signet_libmdbx::ffi::MDBX_CP_COMPACT,
                )
            };
            if rc != signet_libmdbx::ffi::MDBX_SUCCESS {
                return Err(StorageError::Backend(format!("mdbx_env_copy failed: {rc}")));
            }
            Ok(())
        })?;
        let directory = cap_std::fs::Dir::open_ambient_dir(dir, cap_std::ambient_authority())
            .map_err(StorageError::Io)?;
        crate::checkpoint::fs::sync_dir(&directory).map_err(StorageError::Io)?;
        Ok(())
    }

    pub fn engine_cache_bytes(&self) -> u64 {
        0
    }
}

impl KvStore for MdbxStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        check_key(key)?;
        let db = self.db_for_cf(cf)?;
        let tx = self.env.begin_ro_sync().map_err(StorageError::backend)?;
        tx.get(db.dbi(), key).map_err(StorageError::backend)
    }

    fn get_bounded(
        &self,
        cf: ColumnFamily,
        key: &[u8],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, BoundedReadError> {
        check_key(key)?;
        let db = self.db_for_cf(cf)?;
        let tx = self.env.begin_ro_sync().map_err(StorageError::backend)?;
        let val: Option<std::borrow::Cow<'_, [u8]>> =
            tx.get(db.dbi(), key).map_err(StorageError::backend)?;
        val.map(|value| crate::error::copy_bounded(&value, max_bytes))
            .transpose()
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        check_key(prefix)?;
        let iter = self.open_iter(cf, prefix, prefix)?;
        Ok(Box::new(iter))
    }

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        check_key(prefix)?;
        let iter = self.open_iter(cf, prefix, prefix)?;
        collect_bounded_prefix(iter, prefix, limit)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        check_key(prefix)?;
        check_key(start)?;
        let start_key = core::cmp::max(start, prefix);
        let iter = self.open_iter(cf, prefix, start_key)?;
        collect_bounded_prefix(iter, prefix, limit)
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        BufferedWriteBatch::default()
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        check_key(key)?;
        check_value(value)?;
        let _guard = self.write_lock.lock();
        let db = self.db_for_cf(cf)?;
        let tx = self.env.begin_rw_sync().map_err(StorageError::backend)?;
        tx.put(db, key, value, WriteFlags::empty())
            .map_err(StorageError::backend)?;
        tx.commit().map_err(StorageError::backend)?;
        Ok(())
    }

    fn put_value(&self, cf: ColumnFamily, key: &[u8], value: Bytes) -> Result<(), StorageError> {
        self.put(cf, key, &value)
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.write_batch(batch)
    }

    fn write_deferred(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.write_batch(batch)
    }

    fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.write_batch(batch)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        for condition in conditions {
            validate_condition(condition)?;
        }
        let ops = batch.into_ops();
        for op in &ops {
            validate_batch_op(op)?;
        }
        let _guard = self.write_lock.lock();
        let tx = self.env.begin_rw_sync().map_err(StorageError::backend)?;
        for condition in conditions {
            let (cf, key) = condition.location();
            let db = self.db_for_cf(cf)?;
            let current: Option<Vec<u8>> = tx.get(db.dbi(), key).map_err(StorageError::backend)?;
            if !condition.matches(current.as_deref()) {
                return Ok(false);
            }
        }
        for op in ops {
            apply_batch_op(self, &tx, op)?;
        }
        tx.commit().map_err(StorageError::backend)?;
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        #[cfg(any(test, feature = "test-seam"))]
        if let Some(fault) = self.faults.take_at(crate::trait_::PersistBoundary::Flush) {
            return Err(fault_injected_error(
                fault,
                crate::trait_::PersistBoundary::Flush,
            ));
        }
        self.env.sync(true).map_err(StorageError::backend)?;
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        let tx = self.env.begin_ro_sync().map_err(StorageError::backend)?;
        Ok(Box::new(MdbxSnapshot { store: self, tx }))
    }

    fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Bytes>>, StorageError> {
        self.multi_get(cf, keys)
    }

    fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        scratch: &Path,
    ) -> Result<u64, StorageError> {
        self.ingest_sorted(cf, rows, scratch)
    }

    fn delete_range(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<(), StorageError> {
        self.delete_range(cf, start, end)
    }

    fn checkpoint(&self, dir: &Path) -> Result<(), StorageError> {
        self.checkpoint(dir)
    }

    fn engine_cache_bytes(&self) -> u64 {
        self.engine_cache_bytes()
    }

    #[cfg(any(test, feature = "test-seam"))]
    fn arm_persist_fault(&self, fault: crate::PersistFault) {
        self.faults.arm(fault);
    }
}

pub(crate) struct MdbxSnapshot<'a> {
    store: &'a MdbxStore,
    tx: signet_libmdbx::TxSync<signet_libmdbx::RoSync>,
}

impl KvSnapshot for MdbxSnapshot<'_> {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        check_key(key)?;
        let db = self.store.db_for_cf(cf)?;
        self.tx.get(db.dbi(), key).map_err(StorageError::backend)
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
        for k in keys {
            check_key(k)?;
        }
        let db = self.store.db_for_cf(cf)?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let val = self.tx.get(db.dbi(), k).map_err(StorageError::backend)?;
            out.push(val);
        }
        Ok(out)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        check_key(prefix)?;
        let db = self.store.db_for_cf(cf)?;
        let cursor = self.tx.cursor(db).map_err(StorageError::backend)?;
        Ok(Box::new(MdbxCursorIter {
            cursor,
            prefix: prefix.to_vec(),
            start: prefix.to_vec(),
            first: true,
        }))
    }

    fn last_prefix(&self, cf: ColumnFamily, prefix: &[u8]) -> Result<Option<KvPair>, StorageError> {
        check_key(prefix)?;
        let db = self.store.db_for_cf(cf)?;
        let mut cursor = self.tx.cursor(db).map_err(StorageError::backend)?;
        let succ = prefix_successor(prefix);
        let found = match &succ {
            Some(s) => cursor
                .set_range::<Vec<u8>, Vec<u8>>(s)
                .map_err(StorageError::backend)?,
            None => None,
        };
        let candidate = if found.is_some() {
            cursor
                .prev::<Vec<u8>, Vec<u8>>()
                .map_err(StorageError::backend)?
        } else {
            cursor
                .last::<Vec<u8>, Vec<u8>>()
                .map_err(StorageError::backend)?
        };
        if let Some((k, v)) = candidate {
            if k.starts_with(prefix) {
                return Ok(Some((k, v)));
            }
        }
        Ok(None)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        check_key(prefix)?;
        check_key(start)?;
        let start_key = core::cmp::max(start, prefix);
        let db = self.store.db_for_cf(cf)?;
        let cursor = self.tx.cursor(db).map_err(StorageError::backend)?;
        let iter = MdbxCursorIter {
            cursor,
            prefix: prefix.to_vec(),
            start: start_key.to_vec(),
            first: true,
        };
        collect_bounded_prefix(iter, prefix, limit)
    }
}

struct MdbxStoreIter<'a> {
    cursor: signet_libmdbx::Cursor<'a, signet_libmdbx::RoSync>,
    _tx: Box<signet_libmdbx::TxSync<signet_libmdbx::RoSync>>,
    prefix: Vec<u8>,
    start: Vec<u8>,
    first: bool,
}

impl Iterator for MdbxStoreIter<'_> {
    type Item = Result<KvPair, StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let res = if self.first {
            self.first = false;
            self.cursor.set_range::<Vec<u8>, Vec<u8>>(&self.start)
        } else {
            self.cursor.next::<Vec<u8>, Vec<u8>>()
        };

        match res {
            Ok(Some((k, v))) => {
                if k.starts_with(&self.prefix) {
                    Some(Ok((k, v)))
                } else {
                    None
                }
            }
            Ok(None) => None,
            Err(e) => Some(Err(StorageError::backend(e))),
        }
    }
}

struct MdbxCursorIter<'a> {
    cursor: signet_libmdbx::Cursor<'a, signet_libmdbx::RoSync>,
    prefix: Vec<u8>,
    start: Vec<u8>,
    first: bool,
}

impl Iterator for MdbxCursorIter<'_> {
    type Item = Result<KvPair, StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let res = if self.first {
            self.first = false;
            self.cursor.set_range::<Vec<u8>, Vec<u8>>(&self.start)
        } else {
            self.cursor.next::<Vec<u8>, Vec<u8>>()
        };

        match res {
            Ok(Some((k, v))) => {
                if k.starts_with(&self.prefix) {
                    Some(Ok((k, v)))
                } else {
                    None
                }
            }
            Ok(None) => None,
            Err(e) => Some(Err(StorageError::backend(e))),
        }
    }
}
