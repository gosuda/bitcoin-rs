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
/// Persistence boundary that a [`PersistFault`] is armed against.
///
/// Test-only fault-injection control for the atomic-durability proof suite;
/// not part of the storage contract. `Apply` is the engine boundary that
/// atomically commits a batch, `Sync` is the durability step that makes an
/// applied batch crash-safe, and `Flush` is the [`KvStore::flush`] completion
/// of deferred writes.
#[doc(hidden)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PersistBoundary {
    /// The engine boundary that applies a batch atomically.
    Apply,
    /// The durability boundary that persists an applied batch.
    Sync,
    /// The `flush` boundary that completes deferred durability.
    Flush,
}

/// One injected persistence fault for the atomic-durability proofs.
///
/// Test-only seam, hidden from the documented API: when armed on a backend,
/// the next write path that reaches the fault's boundary fires the fault once
/// and consumes it. Unarmed stores never consult the seam, and a fault armed
/// at a boundary a path does not cross stays armed for a later path. The
/// observable contract under every fault is fixed by [`KvStore`]: a
/// multi-family batch recovers as the complete old or the complete new state
/// across every column family, and a durability completion never precedes the
/// persisted writes it vouches for.
#[doc(hidden)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PersistFault {
    /// Persistence faults before any batch byte is applied: the call returns
    /// `Err` and no operation lands in any family.
    FailApply,
    /// The engine write is dropped before apply. The call returns `Err`:
    /// even a deferred write must not acknowledge bytes that are not visible.
    LostApply,
    /// Partial write at the apply boundary: a strict prefix of the batch
    /// reaches the engine and the boundary then faults. The engine discards
    /// or aborts the prefix atomically: the call returns `Err` and no family
    /// observes a partial batch.
    PartialApply,
    /// Durability completion faults after the batch applied: the batch is
    /// visible but not confirmed durable, and the call returns `Err` rather
    /// than reporting completion.
    FailSync,
    /// Durability completion is lost after apply. The call returns `Err`;
    /// recovery may observe the whole batch or none, never a cross-family mix.
    LostSync,
    /// `flush` faults without completing deferred durability: the call
    /// returns `Err`.
    FailFlush,
    /// The flush sync is dropped. The call returns `Err` rather than
    /// acknowledging deferred durability that has not completed.
    LostFlush,
}

impl PersistFault {
    /// The persistence boundary this fault fires at.
    pub const fn boundary(self) -> PersistBoundary {
        match self {
            Self::FailApply | Self::LostApply | Self::PartialApply => PersistBoundary::Apply,
            Self::FailSync | Self::LostSync => PersistBoundary::Sync,
            Self::FailFlush | Self::LostFlush => PersistBoundary::Flush,
        }
    }

    /// The storage error an injected fault surfaces as.
    pub fn injected_error(self) -> StorageError {
        StorageError::Io(std::io::Error::other(format!(
            "injected persistence fault {:?} at the {:?} boundary",
            self,
            self.boundary()
        )))
    }
}

/// Armed persistence-fault slot backing the backend seam.
///
/// Test-only; hidden from the documented API. Backends hold one slot and
/// consult it when a write path reaches a persistence boundary.
#[doc(hidden)]
#[derive(Default)]
pub struct PersistFaultSlot(parking_lot::Mutex<Option<PersistFault>>);

impl PersistFaultSlot {
    /// Arms `fault`; a later path crossing its boundary fires it once.
    pub fn arm(&self, fault: PersistFault) {
        *self.0.lock() = Some(fault);
    }

    /// Consumes the armed fault when it fires at `boundary`.
    ///
    /// A fault armed at a boundary this path does not cross stays armed.
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
/// # Atomicity and durability contract
///
/// Every mutation route applies a *named-family atomic batch*: the batch's
/// operations across every [`ColumnFamily`] it touches land as one unit.
/// After any fault at a persistence boundary — a lost write, a partial
/// write, or a faulted or lost durability completion — and a reopen, each
/// column family reflects either the complete pre-batch state or the
/// complete post-batch state. A batch is never half-landed: a reopened
/// store never mixes the new head with old coins, or any other cross-family
/// combination of old and new rows from one batch.
///
/// Atomic visibility is not crash durability. [`Self::write`] and
/// [`Self::write_deferred`] make a batch visible without promising it
/// survived a crash; only [`Self::write_durable`], [`Self::write_durable_if`],
/// and a successful [`Self::flush`] complete durability. A durability
/// completion never precedes the persisted writes it vouches for: when the
/// persistence step is lost or faults, the call surfaces `Err` instead of
/// reporting completion.
///
/// [`Self::snapshot`] captures one point-in-time view across families and
/// never mixes pre-batch and post-batch state. [`Self::snapshot`] plus
/// [`Self::write_durable_if`] form the receipt contract for compare-and-swap
/// durability; there is no separate snapshot or receipt trait.
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

    /// Atomically applies `batch` across every column family it touches.
    ///
    /// The batch lands as one unit: readers observe either none or all of
    /// its operations. A persistence-boundary fault surfaces as `Err`; the
    /// store then holds the batch atomically or not at all across families,
    /// never a mix. This route alone gives no crash-durability promise.
    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError>;

    /// Atomically applies `batch`, but may defer crash durability until [`Self::flush`].
    ///
    /// Completed writes must be visible to later reads in the current process. Backends that do
    /// not support deferred durability may use the regular [`Self::write`] path. A crash before
    /// [`Self::flush`] may lose the whole batch, never a cross-family part of it.
    fn write_deferred(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write(batch)
    }

    /// Atomically applies `batch` and returns only after the write is durable.
    ///
    /// The default implementation applies the batch via [`Self::write_deferred`] and then
    /// calls [`Self::flush`]. Backends may override this with a single synchronous atomic
    /// commit that is both applied and durable before returning. `Ok(())` vouches that the
    /// required bytes are persisted: a lost or faulted persistence step surfaces as `Err`,
    /// so completion never precedes the persisted write.
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
    /// did not match and no batch operation was applied — no family, not even one no
    /// condition names, observes any batch effect, and the durable pre-batch state
    /// survives reopen unchanged. An unknown family, failed lookup, or backend error
    /// while evaluating any condition propagates as `Err` and is never reported as a
    /// mismatch; a fault at the persistence boundary likewise surfaces as `Err`, never
    /// as `Ok(true)`. Evaluation and commit are atomic with respect to every writer the
    /// backend permits to coexist on the same database: the backend holds one write
    /// boundary across all condition reads and the commit.
    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError>;

    /// Makes every earlier completed write durable before returning.
    ///
    /// `Err` means durability completion was not established: the affected
    /// writes stay visible in-process and each recovers whole or not at all
    /// across families after a reopen, never as a cross-family mix.
    fn flush(&self) -> Result<(), StorageError>;

    /// Captures a point-in-time read snapshot.
    ///
    /// The view is coherent across column families: it never mixes rows from
    /// before and after any single batch, including for batches that commit
    /// while the snapshot is held.
    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError>;

    /// Arms `fault` to fire once at its persistence boundary.
    ///
    /// Test seam for the atomic-durability proofs: not part of the storage
    /// contract, hidden from the documented API. Unarmed stores never
    /// consult the slot.
    #[doc(hidden)]
    fn arm_persist_fault(&self, fault: PersistFault);
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
