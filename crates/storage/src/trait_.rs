use crate::{ColumnFamily, StorageError};
use bytes::Bytes;

/// Owned key-value pair returned by portable iterators.
pub type KvPair = (Vec<u8>, Vec<u8>);

/// Boxed portable key-value iterator.
pub type KvIter<'a> = Box<dyn Iterator<Item = Result<KvPair, StorageError>> + 'a>;

/// Resource limits for one bounded prefix scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefixScanLimit {
    /// Maximum number of rows to return. Hard: scanning stops once this many
    /// rows have been collected. `0` produces an empty, incomplete scan.
    pub max_rows: usize,
    /// Maximum sum of returned key and value lengths. Soft for the first row:
    /// when `max_rows > 0` the first matching row is always admitted even if it
    /// alone exceeds `max_bytes`. The limit is hard for every subsequent row.
    pub max_bytes: usize,
}

/// Rows returned by a bounded prefix scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixScan {
    /// Matching rows in key order.
    pub rows: Vec<KvPair>,
    /// Whether every matching row fit within the limits.
    ///
    /// `false` when the scan stopped early because a row or byte limit was
    /// reached. Because the first row is always admitted when `max_rows > 0`
    /// (see [`PrefixScanLimit`]), an incomplete scan contains at least one row
    /// whenever any matching rows exist.
    pub complete: bool,
}
/// Precondition evaluated against a store's state before a conditional batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteCondition<'a> {
    /// The key must not exist.
    Absent {
        /// Logical column family containing the key.
        cf: ColumnFamily,
        /// Key whose absence is required.
        key: &'a [u8],
    },
    /// The key's value must equal `expected` byte for byte.
    Equals {
        /// Logical column family containing the key.
        cf: ColumnFamily,
        /// Key whose value is compared.
        key: &'a [u8],
        /// Required pre-batch value.
        expected: &'a [u8],
    },
}

impl WriteCondition<'_> {
    /// Returns the condition's logical column family and key.
    pub const fn location(&self) -> (ColumnFamily, &[u8]) {
        match self {
            Self::Absent { cf, key } | Self::Equals { cf, key, .. } => (*cf, key),
        }
    }

    /// Tests a logical pre-batch value.
    pub fn matches(&self, current: Option<&[u8]>) -> bool {
        match self {
            Self::Absent { .. } => current.is_none(),
            Self::Equals { expected, .. } => current == Some(*expected),
        }
    }
}

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

    /// Collects matching rows until a limit is reached.
    ///
    /// The first matching row is always admitted when `max_rows > 0`, even if
    /// it exceeds `max_bytes`; `max_bytes` is enforced only for subsequent rows.
    /// See [`PrefixScanLimit`].
    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        collect_bounded(self.iter_prefix(cf, prefix)?, limit)
    }

    /// Creates a backend-specific write batch.
    fn new_batch(&self) -> Self::WriteBatch;

    /// Inserts or replaces one `key` with `value` in `cf`.
    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut batch = self.new_batch();
        batch.put(cf, key, value);
        self.write(batch)
    }

    /// Inserts or replaces one `key` with an owned `value` in `cf`.
    fn put_value(&self, cf: ColumnFamily, key: &[u8], value: Bytes) -> Result<(), StorageError> {
        let mut batch = self.new_batch();
        batch.put_value(cf, key, value);
        self.write(batch)
    }

    /// Atomically applies `batch`.
    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError>;

    /// Atomically applies `batch`, but may defer crash durability until [`Self::flush`].
    ///
    /// Completed writes must be visible to later reads in the current process. Backends that do
    /// not support deferred durability may use the regular [`Self::write`] path.
    fn write_deferred(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write(batch)
    }

    /// Atomically applies `batch` and returns only after the write is durable.
    ///
    /// The default implementation applies the batch via [`Self::write_deferred`] and then
    /// calls [`Self::flush`]. Backends may override this with a single synchronous atomic
    /// commit that is both applied and durable before returning.
    fn write_durable(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write_deferred(batch)?;
        self.flush()
    }

    /// Durably applies the entire ordered `batch` only when every condition in
    /// `conditions` matches the pre-batch state.
    ///
    /// Every supplied condition observes the pre-batch state, even when the batch puts or
    /// deletes a condition key; conditions never observe batch effects, including from
    /// earlier conditions on the same key. The empty slice is an all-true conjunction:
    /// the batch commits unconditionally. `Ok(true)` means the whole batch committed
    /// atomically and is durable before return. `Ok(false)` means at least one condition
    /// did not match and no batch operation was applied. An unknown family, failed
    /// lookup, or backend error while evaluating any condition propagates as `Err` and
    /// is never reported as a mismatch. Evaluation and commit are atomic with respect
    /// to every writer the backend permits to coexist on the same database: the backend
    /// holds one write boundary across all condition reads and the commit.
    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError>;

    /// Makes every earlier completed write durable before returning.
    fn flush(&self) -> Result<(), StorageError>;

    /// Captures a point-in-time read snapshot.
    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError>;
}

/// Backend-neutral atomic write batch.
pub trait WriteBatch: Send {
    /// Inserts or replaces `key` with `value` in `cf`.
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]);

    /// Inserts or replaces `key` with an owned `value` in `cf`.
    fn put_value(&mut self, cf: ColumnFamily, key: &[u8], value: Bytes) {
        self.put(cf, key, &value);
    }

    /// Deletes `key` from `cf`.
    fn delete(&mut self, cf: ColumnFamily, key: &[u8]);

    /// Deletes keys in the half-open range `[start, end)` from `cf`.
    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]);
}

/// Point-in-time read view over a [`KvStore`].
pub trait KvSnapshot: Send + Sync {
    /// Returns the snapshot value for `key` in `cf`, if present.
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Returns one snapshot value per key, in input order.
    ///
    /// `keys` must be in strictly ascending byte order. Backends can use this
    /// invariant to select an ordered batch-read path.
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
        keys.iter().map(|key| self.get(cf, key)).collect()
    }

    /// Iterates snapshot key-value pairs in `cf` whose keys begin with `prefix`, in key order.
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError>;

    /// Collects matching snapshot rows until a limit is reached.
    ///
    /// The first matching row is always admitted when `max_rows > 0`, even if
    /// it exceeds `max_bytes`; `max_bytes` is enforced only for subsequent rows.
    /// See [`PrefixScanLimit`].
    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        collect_bounded(self.iter_prefix(cf, prefix)?, limit)
    }
}

pub(crate) fn push_bounded_row(
    rows: &mut Vec<KvPair>,
    bytes: &mut usize,
    key: &[u8],
    value: &[u8],
    limit: PrefixScanLimit,
) -> bool {
    let Some(row_bytes) = key.len().checked_add(value.len()) else {
        return false;
    };
    let Some(next_bytes) = bytes.checked_add(row_bytes) else {
        return false;
    };
    if rows.len() >= limit.max_rows {
        return false;
    }
    // The first row is admitted regardless of max_bytes when at least one row
    // is requested, so a single oversized row never produces an empty scan.
    // max_bytes is honored as a hard limit for every subsequent row.
    if !rows.is_empty() && next_bytes > limit.max_bytes {
        return false;
    }
    rows.push((key.to_vec(), value.to_vec()));
    *bytes = next_bytes;
    true
}

fn collect_bounded(iter: KvIter<'_>, limit: PrefixScanLimit) -> Result<PrefixScan, StorageError> {
    let mut rows = Vec::new();
    let mut bytes = 0;
    for item in iter {
        let (key, value) = item?;
        if !push_bounded_row(&mut rows, &mut bytes, &key, &value, limit) {
            return Ok(PrefixScan {
                rows,
                complete: false,
            });
        }
    }
    Ok(PrefixScan {
        rows,
        complete: true,
    })
}
