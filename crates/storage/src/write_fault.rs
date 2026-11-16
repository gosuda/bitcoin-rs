use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::{
    BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, PersistFault, PrefixScan,
    PrefixScanLimit, StorageError, WriteCondition,
};

pub struct WriteFaultStore {
    inner: Arc<dyn KvStore>,
    countdown: AtomicUsize,
    durable_batches: AtomicUsize,
    dead: AtomicBool,
}

impl WriteFaultStore {
    #[must_use]
    pub fn new(inner: Arc<dyn KvStore>) -> Self {
        Self {
            inner,
            countdown: AtomicUsize::new(0),
            durable_batches: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
        }
    }

    pub fn fail_durable_batch(&self, nth: usize) {
        self.countdown.store(nth, Ordering::SeqCst);
    }

    #[must_use]
    pub fn durable_batches(&self) -> usize {
        self.durable_batches.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    fn injected() -> StorageError {
        StorageError::Io(std::io::Error::other("injected durable batch failure"))
    }

    fn live(&self) -> Result<(), StorageError> {
        if self.is_dead() {
            return Err(Self::injected());
        }
        Ok(())
    }
}

impl KvStore for WriteFaultStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(cf, key)
    }

    fn get_bounded(
        &self,
        cf: ColumnFamily,
        key: &[u8],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, crate::BoundedReadError> {
        self.inner.get_bounded(cf, key, max_bytes)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.inner.iter_prefix(cf, prefix)
    }

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        self.inner.scan_prefix_bounded(cf, prefix, limit)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        self.inner
            .scan_prefix_from_bounded(cf, prefix, start, limit)
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        self.inner.new_batch()
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.live()?;
        self.inner.write(batch)
    }

    fn write_deferred(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.live()?;
        self.inner.write_deferred(batch)
    }

    fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.live()?;
        self.durable_batches.fetch_add(1, Ordering::SeqCst);
        if self
            .countdown
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            == Ok(1)
        {
            self.dead.store(true, Ordering::SeqCst);
            return Err(Self::injected());
        }
        self.inner.write_durable(batch)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        self.live()?;
        self.inner.write_durable_if(conditions, batch)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.live()?;
        self.inner.flush()
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        self.inner.snapshot()
    }

    fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<crate::Bytes>>, StorageError> {
        self.inner.multi_get(cf, keys)
    }

    fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        scratch: &Path,
    ) -> Result<u64, StorageError> {
        self.live()?;
        self.inner.ingest_sorted(cf, rows, scratch)
    }

    fn delete_range(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<(), StorageError> {
        self.live()?;
        self.inner.delete_range(cf, start, end)
    }

    fn checkpoint(&self, dir: &Path) -> Result<(), StorageError> {
        self.live()?;
        self.inner.checkpoint(dir)
    }

    fn engine_cache_bytes(&self) -> u64 {
        self.inner.engine_cache_bytes()
    }

    #[cfg(any(test, feature = "test-seam"))]
    fn arm_persist_fault(&self, fault: PersistFault) {
        self.inner.arm_persist_fault(fault);
    }
}
