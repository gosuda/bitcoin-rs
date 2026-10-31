use crate::batch::BufferedWriteBatch;
use crate::{ColumnFamily, StorageError};
use bytes::Bytes;

pub type KvPair = (Vec<u8>, Vec<u8>);

pub type KvIter<'a> = Box<dyn Iterator<Item = Result<KvPair, StorageError>> + 'a>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefixScanLimit {
    pub max_rows: usize,
    pub max_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixScan {
    pub rows: Vec<KvPair>,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteCondition<'a> {
    Absent {
        cf: ColumnFamily,
        key: &'a [u8],
    },
    Equals {
        cf: ColumnFamily,
        key: &'a [u8],
        expected: &'a [u8],
    },
}

impl WriteCondition<'_> {
    pub const fn location(&self) -> (ColumnFamily, &[u8]) {
        match self {
            Self::Absent { cf, key } | Self::Equals { cf, key, .. } => (*cf, key),
        }
    }

    pub fn matches(&self, current: Option<&[u8]>) -> bool {
        match self {
            Self::Absent { .. } => current.is_none(),
            Self::Equals { expected, .. } => current == Some(*expected),
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
#[doc(hidden)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PersistBoundary {
    Apply,
    Sync,
    Flush,
}

#[cfg(any(test, feature = "test-seam"))]
#[doc(hidden)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PersistFault {
    FailApply,
    LostApply,
    PartialApply,
    FailSync,
    LostSync,
    FailFlush,
    LostFlush,
}

#[cfg(any(test, feature = "test-seam"))]
impl PersistFault {
    pub(crate) const fn boundary(self) -> PersistBoundary {
        match self {
            Self::FailApply | Self::LostApply | Self::PartialApply => PersistBoundary::Apply,
            Self::FailSync | Self::LostSync => PersistBoundary::Sync,
            Self::FailFlush | Self::LostFlush => PersistBoundary::Flush,
        }
    }

    #[cfg_attr(
        not(any(feature = "fjall", feature = "redb", feature = "rocksdb")),
        allow(dead_code)
    )]
    pub(crate) fn injected_error(self) -> StorageError {
        let boundary = self.boundary();
        StorageError::Io(std::io::Error::other(format!(
            "injected persistence fault {self:?} at the {boundary:?} boundary"
        )))
    }
}

#[cfg(any(test, feature = "test-seam"))]
#[doc(hidden)]
#[derive(Default)]
pub(crate) struct PersistFaultSlot(parking_lot::Mutex<Option<PersistFault>>);

#[cfg(any(test, feature = "test-seam"))]
impl PersistFaultSlot {
    #[cfg_attr(
        not(any(feature = "fjall", feature = "redb", feature = "rocksdb")),
        allow(dead_code)
    )]
    pub(crate) fn arm(&self, fault: PersistFault) {
        *self.0.lock() = Some(fault);
    }

    #[cfg_attr(
        not(any(feature = "fjall", feature = "redb", feature = "rocksdb")),
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

pub trait KvStore: Send + Sync + 'static {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    fn get_bounded(
        &self,
        _cf: ColumnFamily,
        _key: &[u8],
        _max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, crate::BoundedReadError> {
        Err(crate::BoundedReadError::Unsupported)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError>;

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        collect_bounded_prefix(self.iter_prefix(cf, prefix)?, &[], limit)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError>;

    fn new_batch(&self) -> BufferedWriteBatch;

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut batch = self.new_batch();
        batch.put(cf, key, value);
        self.write(batch)
    }

    fn put_value(&self, cf: ColumnFamily, key: &[u8], value: Bytes) -> Result<(), StorageError> {
        let mut batch = self.new_batch();
        batch.put_value(cf, key, value);
        self.write(batch)
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError>;

    fn write_deferred(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.write(batch)
    }

    fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.write_deferred(batch)?;
        self.flush()
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError>;

    fn flush(&self) -> Result<(), StorageError>;

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError>;

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-seam"))]
    fn arm_persist_fault(&self, fault: PersistFault);
}

fn _kv_store_is_dyn_compatible(_: &dyn KvStore) {}

pub trait KvSnapshot: Send + Sync {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

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

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError>;

    fn last_prefix(&self, cf: ColumnFamily, prefix: &[u8]) -> Result<Option<KvPair>, StorageError> {
        let mut last = None;
        for item in self.iter_prefix(cf, prefix)? {
            last = Some(item?);
        }
        Ok(last)
    }

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        collect_bounded_prefix(self.iter_prefix(cf, prefix)?, &[], limit)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError>;
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

pub(crate) fn collect_bounded_prefix<K, V>(
    rows: impl Iterator<Item = Result<(K, V), StorageError>>,
    prefix: &[u8],
    limit: PrefixScanLimit,
) -> Result<PrefixScan, StorageError>
where
    K: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    let mut out = Vec::new();
    let mut bytes = 0;
    for item in rows {
        let (key, value) = item?;
        let key = key.as_ref();
        if !key.starts_with(prefix) {
            break;
        }
        if !push_bounded_row(&mut out, &mut bytes, key, value.as_ref(), limit) {
            return Ok(PrefixScan {
                rows: out,
                complete: false,
            });
        }
    }
    Ok(PrefixScan {
        rows: out,
        complete: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_condition_matches_pre_batch_value() {
        let absent = WriteCondition::Absent {
            cf: ColumnFamily::TxConfirmed,
            key: b"k",
        };
        assert!(absent.matches(None));
        assert!(!absent.matches(Some(b"v")));

        let equals = WriteCondition::Equals {
            cf: ColumnFamily::TxConfirmed,
            key: b"k",
            expected: b"v",
        };
        assert!(!equals.matches(None));
        assert!(equals.matches(Some(b"v")));
        assert!(!equals.matches(Some(b"w")));
    }
}
