use crate::{ColumnFamily, StorageError};

/// Owned key-value pair returned by portable iterators.
pub type KvPair = (Vec<u8>, Vec<u8>);

/// Boxed portable key-value iterator.
pub type KvIter<'a> = Box<dyn Iterator<Item = Result<KvPair, StorageError>> + 'a>;

/// Backend-neutral key-value store over named column families.
pub trait KvStore: Send + Sync + 'static {
    /// Backend-specific atomic write-batch type.
    type WriteBatch: WriteBatch;

    /// Returns the value for `key` in `cf`, if present.
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Iterates key-value pairs in `cf` whose keys begin with `prefix`, in key order.
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError>;

    /// Creates a backend-specific write batch.
    fn new_batch(&self) -> Self::WriteBatch;

    /// Inserts or replaces one `key` with `value` in `cf`.
    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut batch = self.new_batch();
        batch.put(cf, key, value);
        self.write(batch)
    }

    /// Atomically applies `batch`.
    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError>;

    /// Flushes pending durable state according to backend semantics.
    fn flush(&self) -> Result<(), StorageError>;

    /// Captures a point-in-time read snapshot.
    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError>;
}

/// Backend-neutral atomic write batch.
pub trait WriteBatch: Send {
    /// Inserts or replaces `key` with `value` in `cf`.
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]);

    /// Deletes `key` from `cf`.
    fn delete(&mut self, cf: ColumnFamily, key: &[u8]);

    /// Deletes keys in the half-open range `[start, end)` from `cf`.
    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]);
}

/// Point-in-time read view over a [`KvStore`].
pub trait KvSnapshot: Send + Sync {
    /// Returns the snapshot value for `key` in `cf`, if present.
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Iterates snapshot key-value pairs in `cf` whose keys begin with `prefix`, in key order.
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError>;
}
