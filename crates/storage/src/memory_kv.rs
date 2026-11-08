//! In-memory [`KvStore`] for tests that need a real store without an engine.
//!
//! Only compiled under `test` or `test-seam`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::RwLock;

use crate::Bytes;
#[cfg(any(test, feature = "test-seam"))]
use crate::PersistFault;
use crate::batch::{BatchOp, BufferedWriteBatch};
use crate::coins::CoinStore;
use crate::column_families::ColumnFamily;
use crate::commit::CommitAuthority;
use crate::error::StorageError;
use crate::trait_::{KvIter, KvSnapshot, KvStore, PrefixScan, PrefixScanLimit, WriteCondition};

type Families = [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()];
pub const MEMORY_KV_FILE: &str = "memory_kv.bin";

#[derive(Default)]
pub struct MemoryKvStore {
    cfs: RwLock<Families>,
    fail_next_fenced_write: AtomicBool,
}

impl MemoryKvStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open_checkpoint(dir: &std::path::Path) -> Result<Self, StorageError> {
        let file_path = dir.join(MEMORY_KV_FILE);
        let bytes = std::fs::read(&file_path).map_err(StorageError::Io)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() < 12 || &bytes[..8] != b"MEMKV01\0" {
            return Err(StorageError::IncompatibleData(
                "corrupt memory_kv checkpoint".into(),
            ));
        }
        let raw_cf_count = u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| StorageError::IncompatibleData("corrupt cf count".into()))?,
        );
        let cf_count = usize::try_from(raw_cf_count)
            .map_err(|_| StorageError::IncompatibleData("cf count exceeds usize".into()))?;
        let mut cursor = 12;
        let mut cfs: Families = std::array::from_fn(|_| BTreeMap::new());
        for i in 0..cf_count.min(cfs.len()) {
            if cursor + 4 > bytes.len() {
                return Err(StorageError::IncompatibleData("unexpected EOF".into()));
            }
            let raw_entry_count = u32::from_le_bytes(
                bytes[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| StorageError::IncompatibleData("corrupt entry count".into()))?,
            );
            let entry_count = usize::try_from(raw_entry_count)
                .map_err(|_| StorageError::IncompatibleData("entry count exceeds usize".into()))?;
            cursor += 4;
            for _ in 0..entry_count {
                if cursor + 4 > bytes.len() {
                    return Err(StorageError::IncompatibleData("unexpected EOF".into()));
                }
                let raw_k_len = u32::from_le_bytes(
                    bytes[cursor..cursor + 4]
                        .try_into()
                        .map_err(|_| StorageError::IncompatibleData("corrupt key len".into()))?,
                );
                let k_len = usize::try_from(raw_k_len)
                    .map_err(|_| StorageError::IncompatibleData("key len exceeds usize".into()))?;
                cursor += 4;
                if cursor + k_len > bytes.len() {
                    return Err(StorageError::IncompatibleData("unexpected EOF".into()));
                }
                let k = bytes[cursor..cursor + k_len].to_vec();
                cursor += k_len;

                if cursor + 4 > bytes.len() {
                    return Err(StorageError::IncompatibleData("unexpected EOF".into()));
                }
                let raw_v_len = u32::from_le_bytes(
                    bytes[cursor..cursor + 4]
                        .try_into()
                        .map_err(|_| StorageError::IncompatibleData("corrupt val len".into()))?,
                );
                let v_len = usize::try_from(raw_v_len)
                    .map_err(|_| StorageError::IncompatibleData("val len exceeds usize".into()))?;
                cursor += 4;
                if cursor + v_len > bytes.len() {
                    return Err(StorageError::IncompatibleData("unexpected EOF".into()));
                }
                let v = bytes[cursor..cursor + v_len].to_vec();
                cursor += v_len;
                cfs[i].insert(k, v);
            }
        }
        Ok(Self {
            cfs: RwLock::new(cfs),
            fail_next_fenced_write: AtomicBool::new(false),
        })
    }
}

fn apply_ops(cfs: &mut Families, ops: Vec<BatchOp>) {
    for op in ops {
        match op {
            BatchOp::Put { cf, key, value } => {
                cfs[cf.index()].insert(key.to_vec(), value.to_vec());
            }
            BatchOp::Delete { cf, key } => {
                cfs[cf.index()].remove(&key);
            }
            BatchOp::DeleteRange { cf, start, end } => {
                let doomed: Vec<Vec<u8>> = cfs[cf.index()]
                    .range(start.to_vec()..end.to_vec())
                    .map(|(key, _value)| key.clone())
                    .collect();
                for key in doomed {
                    cfs[cf.index()].remove(&key);
                }
            }
        }
    }
}

fn scan_prefix_from(
    map: &BTreeMap<Vec<u8>, Vec<u8>>,
    prefix: &[u8],
    start: &[u8],
    limit: PrefixScanLimit,
) -> PrefixScan {
    let mut rows = Vec::new();
    let mut bytes = 0_usize;
    for (key, value) in map.range(start.to_vec()..) {
        if !key.starts_with(prefix) {
            break;
        }
        let row_bytes = key.len() + value.len();
        if rows.len() >= limit.max_rows || (!rows.is_empty() && bytes + row_bytes > limit.max_bytes)
        {
            return PrefixScan {
                rows,
                complete: false,
            };
        }
        bytes += row_bytes;
        rows.push((key.clone(), value.clone()));
    }
    PrefixScan {
        rows,
        complete: true,
    }
}

#[derive(Clone)]
struct MemorySnapshot {
    cfs: Arc<Families>,
}

impl KvSnapshot for MemorySnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.cfs[cf.index()].get(key).cloned())
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let rows: Result<Vec<_>, StorageError> = self.cfs[cf.index()]
            .iter()
            .filter(|(key, _value)| key.starts_with(prefix))
            .map(|(key, value)| Ok((key.clone(), value.clone())))
            .collect();
        Ok(Box::new(rows?.into_iter().map(Ok)))
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        Ok(scan_prefix_from(
            &self.cfs[cf.index()],
            prefix,
            start,
            limit,
        ))
    }
}

impl KvStore for MemoryKvStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let guard = self.cfs.read();
        Ok(guard[cf.index()].get(key).cloned())
    }

    fn get_bounded(
        &self,
        cf: ColumnFamily,
        key: &[u8],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, crate::BoundedReadError> {
        let guard = self.cfs.read();
        guard[cf.index()]
            .get(key)
            .map(|value| crate::error::copy_bounded(value, max_bytes))
            .transpose()
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let guard = self.cfs.read();
        let rows: Result<Vec<_>, StorageError> = guard[cf.index()]
            .iter()
            .filter(|(key, _value)| key.starts_with(prefix))
            .map(|(key, value)| Ok((key.clone(), value.clone())))
            .collect();
        drop(guard);
        Ok(Box::new(rows?.into_iter().map(Ok)))
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        let guard = self.cfs.read();
        Ok(scan_prefix_from(&guard[cf.index()], prefix, start, limit))
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        BufferedWriteBatch::default()
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        let mut guard = self.cfs.write();
        apply_ops(&mut guard, batch.into_ops());
        Ok(())
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        if self.fail_next_fenced_write.swap(false, Ordering::SeqCst) {
            return Err(StorageError::Backend(
                "injected fenced write failure".into(),
            ));
        }
        let mut guard = self.cfs.write();
        let matched = conditions.iter().all(|condition| {
            let (cf, key) = condition.location();
            condition.matches(guard[cf.index()].get(key).map(Vec::as_slice))
        });
        if !matched {
            return Ok(false);
        }
        apply_ops(&mut guard, batch.into_ops());
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(MemorySnapshot {
            cfs: Arc::new(self.cfs.read().clone()),
        }))
    }

    #[cfg(any(test, feature = "test-seam"))]
    fn arm_persist_fault(&self, _fault: PersistFault) {
        self.fail_next_fenced_write.store(true, Ordering::SeqCst);
    }

    fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Bytes>>, StorageError> {
        let guard = self.cfs.read();
        let map = &guard[cf.index()];
        Ok(keys
            .iter()
            .map(|key| map.get(*key).map(|value| Bytes::copy_from_slice(value)))
            .collect())
    }

    fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        _scratch: &std::path::Path,
    ) -> Result<u64, StorageError> {
        let mut count = 0_u64;
        let mut guard = self.cfs.write();
        for (key, value) in rows {
            guard[cf.index()].insert(key, value);
            count += 1;
        }
        Ok(count)
    }

    fn delete_range(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<(), StorageError> {
        let mut guard = self.cfs.write();
        let doomed: Vec<Vec<u8>> = guard[cf.index()]
            .range(start.to_vec()..end.to_vec())
            .map(|(key, _)| key.clone())
            .collect();
        for key in doomed {
            guard[cf.index()].remove(&key);
        }
        Ok(())
    }

    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
        std::fs::create_dir_all(dir).map_err(StorageError::Io)?;
        let guard = self.cfs.read();
        let file_path = dir.join(MEMORY_KV_FILE);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"MEMKV01\0");
        let cf_len = u32::try_from(guard.len())
            .map_err(|_| StorageError::InvalidOperation("too many column families"))?;
        bytes.extend_from_slice(&cf_len.to_le_bytes());
        for map in guard.iter() {
            let map_len = u32::try_from(map.len())
                .map_err(|_| StorageError::InvalidOperation("too many entries"))?;
            bytes.extend_from_slice(&map_len.to_le_bytes());
            for (k, v) in map.iter() {
                let k_len = u32::try_from(k.len())
                    .map_err(|_| StorageError::InvalidOperation("key too long"))?;
                bytes.extend_from_slice(&k_len.to_le_bytes());
                bytes.extend_from_slice(k);
                let v_len = u32::try_from(v.len())
                    .map_err(|_| StorageError::InvalidOperation("value too long"))?;
                bytes.extend_from_slice(&v_len.to_le_bytes());
                bytes.extend_from_slice(v);
            }
        }
        std::fs::write(&file_path, &bytes).map_err(StorageError::Io)?;
        Ok(())
    }

    fn engine_cache_bytes(&self) -> u64 {
        0
    }
}

#[must_use]
pub fn memory_coin_store(budget_bytes: u64) -> Arc<CoinStore> {
    Arc::new(CoinStore::open(
        Arc::new(MemoryKvStore::default()),
        budget_bytes,
    ))
}

#[must_use]
pub fn memory_commit_authority(budget_bytes: u64) -> Arc<CommitAuthority> {
    let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::default());
    let coins = Arc::new(CoinStore::open(Arc::clone(&store), budget_bytes));
    Arc::new(CommitAuthority::new(store, coins))
}
