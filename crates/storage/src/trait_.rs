use crate::{ColumnFamily, StorageError};
use bytes::Bytes;

/// Owned key-value pair returned by portable iterators.
pub type KvPair = (Vec<u8>, Vec<u8>);

/// Boxed portable key-value iterator.
pub type KvIter<'a> = Box<dyn Iterator<Item = Result<KvPair, StorageError>> + 'a>;

/// Limits for one bounded prefix scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefixScanLimit {
    /// Maximum rows returned. Zero returns no rows.
    pub max_rows: usize,
    /// Maximum returned key-plus-value bytes after the first row.
    pub max_bytes: usize,
}

/// Result of a bounded prefix scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixScan {
    /// Matching rows in key order.
    pub rows: Vec<KvPair>,
    /// Whether all matching rows fit within the limits.
    pub complete: bool,
}

/// Precondition evaluated against the pre-batch store state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteCondition<'a> {
    /// Requires a missing key.
    Absent {
        /// Column family containing the key.
        cf: ColumnFamily,
        /// Key that must be absent.
        key: &'a [u8],
    },
    /// Requires an exact value.
    Equals {
        /// Column family containing the key.
        cf: ColumnFamily,
        /// Key whose value is compared.
        key: &'a [u8],
        /// Required value.
        expected: &'a [u8],
    },
}

impl WriteCondition<'_> {
    /// Returns the condition's column family and key.
    pub const fn location(&self) -> (ColumnFamily, &[u8]) {
        match self {
            Self::Absent { cf, key } | Self::Equals { cf, key, .. } => (*cf, key),
        }
    }

    /// Tests a pre-batch value against this condition.
    pub fn matches(&self, current: Option<&[u8]>) -> bool {
        match self {
            Self::Absent { .. } => current.is_none(),
            Self::Equals { expected, .. } => current == Some(*expected),
        }
    }
}

/// Persistence boundary used by fault-injection tests.
#[doc(hidden)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PersistBoundary {
    /// Atomic batch application.
    Apply,
    /// Durability synchronization.
    Sync,
    /// Deferred-write flush.
    Flush,
}

/// One-shot persistence fault used by storage proof tests.
#[doc(hidden)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PersistFault {
    /// Fail before applying the batch.
    FailApply,
    /// Drop the apply step.
    LostApply,
    /// Attempt a partial apply; the backend must expose no partial batch.
    PartialApply,
    /// Fail after apply while completing durability.
    FailSync,
    /// Drop durability completion after apply.
    LostSync,
    /// Fail while flushing deferred writes.
    FailFlush,
    /// Lose flush completion and return an error without confirming durability.
    LostFlush,
}

impl PersistFault {
    /// Returns the boundary at which this fault fires.
    pub const fn boundary(self) -> PersistBoundary {
        match self {
            Self::FailApply | Self::LostApply | Self::PartialApply => PersistBoundary::Apply,
            Self::FailSync | Self::LostSync => PersistBoundary::Sync,
            Self::FailFlush | Self::LostFlush => PersistBoundary::Flush,
        }
    }

    /// Builds the storage error surfaced by this injected fault.
    pub fn injected_error(self) -> StorageError {
        let boundary = self.boundary();
        StorageError::Io(std::io::Error::other(format!(
            "injected persistence fault {self:?} at the {boundary:?} boundary"
        )))
    }
}

/// One-shot persistence fault slot used by storage backends.
#[doc(hidden)]
#[derive(Default)]
pub struct PersistFaultSlot(parking_lot::Mutex<Option<PersistFault>>);

impl PersistFaultSlot {
    /// Arms one fault, replacing any previously armed fault.
    pub fn arm(&self, fault: PersistFault) {
        *self.0.lock() = Some(fault);
    }

    #[cfg_attr(
        not(any(
            feature = "fjall",
            feature = "redb",
            feature = "rocksdb",
            feature = "mdbx"
        )),
        allow(dead_code)
    )]
    pub(crate) fn take_at(&self, boundary: PersistBoundary) -> Option<PersistFault> {
        let mut guard = self.0.lock();
        match *guard {
            Some(fault) if fault.boundary() == boundary => {
                *guard = None;
                Some(fault)
            }
            _ => None,
        }
    }
}

/// Backend-neutral key-value store over named column families.
///
/// Every batch is atomic across all column families it touches. `write` and
/// `write_deferred` need not survive a crash; `write_durable`,
/// `write_durable_if`, and successful `flush` complete durability. Atomicity
/// prevents partial batches, but an error from a durability API is not a
/// rollback receipt: application may already have completed before the
/// durability completion failed or was lost. Snapshots are coherent across
/// families.
pub trait KvStore: Send + Sync + 'static {
    /// Backend-specific atomic write-batch type.
    type WriteBatch: WriteBatch;

    /// Returns the value for `key` in `cf`, if present.
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Iterates matching key-value pairs in key order.
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError>;

    /// Collects matching rows within `limit`.
    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        collect_bounded(self.iter_prefix(cf, prefix)?, limit)
    }

    /// Creates an empty backend-specific batch.
    fn new_batch(&self) -> Self::WriteBatch;

    /// Inserts or replaces one value through the regular write path.
    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut batch = self.new_batch();
        batch.put(cf, key, value);
        self.write(batch)
    }

    /// Inserts or replaces one owned value through the regular write path.
    fn put_value(&self, cf: ColumnFamily, key: &[u8], value: Bytes) -> Result<(), StorageError> {
        let mut batch = self.new_batch();
        batch.put_value(cf, key, value);
        self.write(batch)
    }

    /// Atomically applies a batch without a crash-durability guarantee.
    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError>;

    /// Atomically applies a batch whose durability may wait for `flush`.
    fn write_deferred(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write(batch)
    }

    /// Atomically applies a batch and completes its durability before success.
    ///
    /// `Ok(())` is the durability receipt. `Err` is not a rollback receipt:
    /// the failure may occur before application, or after the whole atomic
    /// batch became visible while durability completion failed or was lost.
    /// [`StorageError`] does not classify that phase. A caller must therefore
    /// not blindly retry a non-idempotent batch after `Err`; it must reconcile
    /// through the state owner's recovery protocol, or independently prove
    /// that the batch did not apply before retrying.
    ///
    /// The default implementation makes the ambiguous post-application case
    /// explicit: it applies through [`Self::write_deferred`] and then calls
    /// [`Self::flush`]. Backend overrides must preserve the same receipt and
    /// error semantics even when they use one synchronous commit.
    fn write_durable(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write_deferred(batch)?;
        self.flush()
    }

    /// Durably commits `batch` iff every condition matches the pre-batch state.
    ///
    /// Conditions and commit form one write boundary. `Ok(true)` means the
    /// whole batch is durable; `Ok(false)` is the only result that proves the
    /// conditions did not match and no operation applied. Lookup, backend, or
    /// persistence failures return `Err` rather than a mismatch or false
    /// durability confirmation. After conditions matched, an `Err` may occur
    /// after the atomic batch applied but before durability was confirmed, so
    /// it must not be treated as `Ok(false)` or as permission to blindly retry
    /// a non-idempotent batch. The state owner must reconcile the outcome.
    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError>;

    /// Makes every earlier completed write durable before success.
    ///
    /// `Ok(())` is the receipt covering those writes. `Err` provides no such
    /// receipt, but also does not prove that earlier writes were unapplied or
    /// non-durable: synchronization can fail or its completion can be lost
    /// after writes became visible. Callers that track pending durability must
    /// retain that bookkeeping until a successful receipt or owner-specific
    /// recovery establishes the durable state.
    fn flush(&self) -> Result<(), StorageError>;

    /// Captures a coherent point-in-time view across column families.
    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError>;

    /// Arms a one-shot persistence fault for storage proof tests.
    #[doc(hidden)]
    fn arm_persist_fault(&self, fault: PersistFault);
}

/// Backend-neutral atomic write batch.
pub trait WriteBatch: Send {
    /// Inserts or replaces `key` with `value` in `cf`.
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]);

    /// Inserts or replaces `key` with an owned value in `cf`.
    fn put_value(&mut self, cf: ColumnFamily, key: &[u8], value: Bytes) {
        self.put(cf, key, &value);
    }

    /// Deletes `key` from `cf`.
    fn delete(&mut self, cf: ColumnFamily, key: &[u8]);

    /// Deletes keys in `[start, end)` from `cf`.
    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]);
}

/// Point-in-time read view over a [`KvStore`].
pub trait KvSnapshot: Send + Sync {
    /// Returns the snapshot value for `key` in `cf`, if present.
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Returns one value per strictly ascending input key.
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

    /// Iterates matching snapshot key-value pairs in key order.
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError>;

    /// Collects matching snapshot rows within `limit`.
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
    if rows.len() >= limit.max_rows || (!rows.is_empty() && next_bytes > limit.max_bytes) {
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
