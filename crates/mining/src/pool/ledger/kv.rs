//! Snapshot-backed logical tables and a single revision-guarded durable commit.
use super::LedgerError;
use bitcoin_rs_storage::{ColumnFamily, KvSnapshot, KvStore, PrefixScanLimit, WriteCondition};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ops::{Bound, RangeBounds};
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(test)]
#[path = "../../../tests/support/kv_transactions.rs"]
mod tests;

const PREFIX: &[u8] = b"pool-ledger/v1/";
const REVISION: &[u8] = b"pool-ledger/v1/\0revision";
const CF: ColumnFamily = ColumnFamily::PoolLedger;

pub(crate) struct Database {
    store: Arc<dyn KvStore>,
    writer: Mutex<()>,
}
impl Database {
    pub(crate) fn new(store: Arc<dyn KvStore>) -> Self {
        Self {
            store,
            writer: Mutex::new(()),
        }
    }
    pub(crate) fn begin_write(&self) -> Result<WriteTransaction<'_>, LedgerError> {
        let guard = self
            .writer
            .lock()
            .map_err(|_| LedgerError::Invariant("ledger writer poisoned".into()))?;
        self.transaction(Some(guard))
    }
    pub(crate) fn begin_read(&self) -> Result<WriteTransaction<'_>, LedgerError> {
        self.transaction(None)
    }
    fn transaction<'a>(
        &'a self,
        guard: Option<MutexGuard<'a, ()>>,
    ) -> Result<WriteTransaction<'a>, LedgerError> {
        let snapshot = self.store.snapshot()?;
        let revision = snapshot.get(CF, REVISION)?;
        Ok(WriteTransaction {
            db: self,
            snapshot,
            revision,
            changes: RefCell::new(BTreeMap::new()),
            guard,
        })
    }
}
pub(crate) struct WriteTransaction<'a> {
    db: &'a Database,
    snapshot: Box<dyn KvSnapshot + 'a>,
    revision: Option<Vec<u8>>,
    changes: RefCell<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
    guard: Option<MutexGuard<'a, ()>>,
}
impl WriteTransaction<'_> {
    pub(crate) fn open_table<K: Value, V: Value>(
        &self,
        definition: TableDefinition<'_, K, V>,
    ) -> Result<Table<'_, K, V>, LedgerError> {
        Ok(Table {
            snapshot: self.snapshot.as_ref(),
            changes: &self.changes,
            prefix: definition.prefix()?,
            marker: PhantomData,
        })
    }
    pub(crate) fn has_revision(&self) -> bool {
        self.revision.as_ref().is_some_and(|bytes| bytes.len() == 8)
    }
    pub(crate) fn namespace_is_empty(&self) -> Result<bool, LedgerError> {
        Ok(self
            .snapshot
            .iter_prefix(CF, PREFIX)?
            .next()
            .transpose()?
            .is_none())
    }
    pub(crate) fn commit(self) -> Result<(), LedgerError> {
        if self.guard.is_none() {
            return Err(LedgerError::Invariant(
                "read transaction cannot commit".into(),
            ));
        }
        let revision = match self.revision.as_deref() {
            Some(bytes) => u64::from_be_bytes(
                bytes
                    .try_into()
                    .map_err(|_| LedgerError::Invariant("invalid ledger revision".into()))?,
            ),
            None => 0,
        };
        let next = revision
            .checked_add(1)
            .ok_or(LedgerError::Overflow("ledger revision"))?;
        let mut batch = self.db.store.new_batch();
        for (key, value) in self.changes.into_inner() {
            match value {
                Some(value) => batch.put(CF, &key, &value),
                None => batch.delete(CF, &key),
            }
        }
        batch.put(CF, REVISION, &next.to_be_bytes());
        let condition = match self.revision.as_deref() {
            Some(expected) => WriteCondition::Equals {
                cf: CF,
                key: REVISION,
                expected,
            },
            None => WriteCondition::Absent {
                cf: CF,
                key: REVISION,
            },
        };
        if !self.db.store.write_durable_if(&[condition], batch)? {
            return Err(LedgerError::Conflict);
        }
        Ok(())
    }
}

pub(crate) trait Value: 'static {
    type Owned: 'static;
    type View<'a>
    where
        Self: 'a;
    fn decode(bytes: Vec<u8>) -> Result<Self::Owned, LedgerError>;
    fn view(value: &Self::Owned) -> Self::View<'_>;
}
pub(crate) trait Encode<K: Value> {
    fn encode(self) -> Vec<u8>;
}
macro_rules! integer {
    ($t:ty) => {
        impl Value for $t {
            type Owned = $t;
            type View<'a> = $t;
            fn decode(bytes: Vec<u8>) -> Result<$t, LedgerError> {
                Ok(<$t>::from_be_bytes(bytes.as_slice().try_into().map_err(
                    |_| LedgerError::Invariant("invalid integer table value".into()),
                )?))
            }
            fn view(value: &$t) -> $t {
                *value
            }
        }
        impl Encode<$t> for $t {
            fn encode(self) -> Vec<u8> {
                self.to_be_bytes().to_vec()
            }
        }
    };
}
integer!(u64);
integer!(u128);
impl Value for &'static [u8] {
    type Owned = Vec<u8>;
    type View<'a> = &'a [u8];
    fn decode(bytes: Vec<u8>) -> Result<Vec<u8>, LedgerError> {
        Ok(bytes)
    }
    fn view(value: &Vec<u8>) -> &[u8] {
        value
    }
}
impl Encode<&'static [u8]> for &[u8] {
    fn encode(self) -> Vec<u8> {
        self.to_vec()
    }
}
impl Value for &'static str {
    type Owned = String;
    type View<'a> = &'a str;
    fn decode(bytes: Vec<u8>) -> Result<String, LedgerError> {
        String::from_utf8(bytes).map_err(|_| LedgerError::Invariant("invalid metadata key".into()))
    }
    fn view(value: &String) -> &str {
        value
    }
}
impl Encode<&'static str> for &str {
    fn encode(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}
impl Value for () {
    type Owned = ();
    type View<'a> = ();
    fn decode(bytes: Vec<u8>) -> Result<(), LedgerError> {
        if bytes.is_empty() {
            Ok(())
        } else {
            Err(LedgerError::Invariant("invalid unit table value".into()))
        }
    }
    fn view((): &()) {}
}
impl Encode<()> for () {
    fn encode(self) -> Vec<u8> {
        Vec::new()
    }
}
pub(crate) struct Guard<V: Value>(V::Owned);
impl<V: Value> Guard<V> {
    pub(crate) fn value(&self) -> V::View<'_> {
        V::view(&self.0)
    }
}
pub(crate) struct TableDefinition<'a, K, V> {
    name: &'a str,
    marker: PhantomData<(K, V)>,
}
impl<K, V> Copy for TableDefinition<'_, K, V> {}
impl<K, V> Clone for TableDefinition<'_, K, V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, K, V> TableDefinition<'a, K, V> {
    pub(crate) const fn new(name: &'a str) -> Self {
        Self {
            name,
            marker: PhantomData,
        }
    }
    fn prefix(&self) -> Result<Vec<u8>, LedgerError> {
        let tag = match self.name {
            "pplns_meta_u64_v1" => 1,
            "pplns_meta_bytes_v1" => 2,
            "pplns_shares_v1" => 3,
            "pplns_share_hashes_v1" => 4,
            "pplns_share_tuples_v1" => 5,
            "pplns_retired_jobs_v1" => 6,
            "pplns_rounds_v1" => 7,
            "pplns_round_by_block_v1" => 8,
            "pplns_round_weights_v1" => 9,
            "pplns_round_allocs_v1" => 10,
            "pplns_open_rounds_v1" => 11,
            "pplns_balances_v1" => 12,
            "pplns_scripts_v1" => 13,
            "pplns_batches_v1" => 14,
            "pplns_active_batches_v1" => 15,
            "pplns_batch_idem_v1" => 16,
            "pplns_batch_txids_v1" => 17,
            "pplns_audit_v1" => 18,
            "pplns_retired_hashes_v1" => 19,
            _ => {
                return Err(LedgerError::Invariant(
                    "unknown logical ledger table".into(),
                ));
            }
        };
        Ok([PREFIX, &[tag]].concat())
    }
}
type GuardPair<K, V> = (Guard<K>, Guard<V>);
type Row<K, V> = Result<GuardPair<K, V>, LedgerError>;
type Rows<K, V> = std::vec::IntoIter<Row<K, V>>;
type EncodedBound = Option<(Vec<u8>, bool)>;
pub(crate) struct Table<'a, K: Value, V: Value> {
    snapshot: &'a dyn KvSnapshot,
    changes: &'a RefCell<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
    prefix: Vec<u8>,
    marker: PhantomData<(K, V)>,
}
impl<K: Value, V: Value> Table<'_, K, V> {
    fn key(&self, key: impl Encode<K>) -> Result<Vec<u8>, LedgerError> {
        let encoded = key.encode();
        self.prefix
            .len()
            .checked_add(encoded.len())
            .ok_or(LedgerError::Overflow("ledger key length"))?;
        let mut full = self.prefix.clone();
        full.extend(encoded);
        Ok(full)
    }
    pub(crate) fn get(&self, key: impl Encode<K>) -> Result<Option<Guard<V>>, LedgerError> {
        let key = self.key(key)?;
        let bytes = match self.changes.borrow().get(&key) {
            Some(value) => value.clone(),
            None => self.snapshot.get(CF, &key)?,
        };
        bytes.map(|bytes| V::decode(bytes).map(Guard)).transpose()
    }
    pub(crate) fn insert(
        &self,
        key: impl Encode<K>,
        value: impl Encode<V>,
    ) -> Result<(), LedgerError> {
        let key = self.key(key)?;
        self.changes.borrow_mut().insert(key, Some(value.encode()));
        Ok(())
    }
    pub(crate) fn remove(&self, key: impl Encode<K>) -> Result<(), LedgerError> {
        let key = self.key(key)?;
        self.changes.borrow_mut().insert(key, None);
        Ok(())
    }
    pub(crate) fn rows_iter(&self) -> Result<Rows<K, V>, LedgerError> {
        self.rows(&None, &None)
    }
    pub(crate) fn range<I: Encode<K> + Clone, R: RangeBounds<I>>(
        &self,
        range: R,
    ) -> Result<Rows<K, V>, LedgerError> {
        let bound = |b: Bound<&I>| match b {
            Bound::Included(v) => Some((v.clone().encode(), true)),
            Bound::Excluded(v) => Some((v.clone().encode(), false)),
            Bound::Unbounded => None,
        };
        let start = bound(range.start_bound());
        let end = bound(range.end_bound());
        self.rows(&start, &end)
    }

    fn rows(&self, start: &EncodedBound, end: &EncodedBound) -> Result<Rows<K, V>, LedgerError> {
        let within = |key: &[u8]| {
            !start.as_ref().is_some_and(|(b, inclusive)| {
                key < b.as_slice() || (!inclusive && key == b.as_slice())
            }) && !end.as_ref().is_some_and(|(b, inclusive)| {
                key > b.as_slice() || (!inclusive && key == b.as_slice())
            })
        };
        let mut rows = BTreeMap::new();
        for item in self.snapshot.iter_prefix(CF, &self.prefix)? {
            let (key, value) = item?;
            let logical = &key[self.prefix.len()..];
            if end.as_ref().is_some_and(|(b, inclusive)| {
                logical > b.as_slice() || (!inclusive && logical == b.as_slice())
            }) {
                break;
            }
            if within(logical) {
                rows.insert(key, value);
            }
        }
        let mut overlay_start = self.prefix.clone();
        if let Some((key, _)) = &start {
            overlay_start.extend_from_slice(key);
        }
        for (key, value) in self.changes.borrow().range(overlay_start..) {
            if !key.starts_with(&self.prefix) {
                break;
            }
            let logical = &key[self.prefix.len()..];
            if !within(logical) {
                continue;
            }
            match value {
                Some(value) => {
                    rows.insert(key.clone(), value.clone());
                }
                None => {
                    rows.remove(key);
                }
            }
        }
        let mut result = Vec::new();
        for (key, value) in rows {
            let key = &key[self.prefix.len()..];
            result.push(Ok((
                Guard(K::decode(key.to_vec())?),
                Guard(V::decode(value)?),
            )));
        }
        Ok(result.into_iter())
    }
    pub(crate) fn last(&self) -> Result<Option<GuardPair<K, V>>, LedgerError> {
        let backend = self.snapshot.last_prefix(CF, &self.prefix)?;
        let changes = self.changes.borrow();
        let tombstoned = |key: &[u8]| changes.get(key).is_some_and(Option::is_none);
        if backend.as_ref().is_some_and(|(key, _)| tombstoned(key)) {
            drop(changes);
            return self.last_scanned();
        }
        let mut end = self.prefix.clone();
        match end.last_mut() {
            Some(tag) => {
                *tag = tag
                    .checked_add(1)
                    .ok_or_else(|| LedgerError::Invariant("ledger table prefix overflow".into()))?;
            }
            None => {
                return Err(LedgerError::Invariant("empty ledger table prefix".into()));
            }
        }
        let mut overlay: Option<(&[u8], &[u8])> = None;
        for (key, value) in changes.range(self.prefix.clone()..end).rev() {
            if let Some(put) = value {
                overlay = Some((key.as_slice(), put.as_slice()));
                break;
            }
        }
        let tail: Option<(Vec<u8>, Vec<u8>)> = match (backend, overlay) {
            (backend, None) => backend,
            (None, Some((key, value))) => Some((key.to_vec(), value.to_vec())),
            (Some((committed, stored)), Some((staged, put))) => {
                if staged < committed.as_slice() {
                    Some((committed, stored))
                } else {
                    Some((staged.to_vec(), put.to_vec()))
                }
            }
        };
        drop(changes);
        tail.map(|(key, value)| {
            let logical = key[self.prefix.len()..].to_vec();
            Ok((Guard(K::decode(logical)?), Guard(V::decode(value)?)))
        })
        .transpose()
    }
    fn last_scanned(&self) -> Result<Option<GuardPair<K, V>>, LedgerError> {
        let changes = self.changes.borrow();
        let deleted = |key: &[u8]| changes.get(key).is_some_and(Option::is_none);
        let mut last: Option<(Vec<u8>, Vec<u8>)> = None;
        for item in self.snapshot.iter_prefix(CF, &self.prefix)? {
            let (key, value) = item?;
            if deleted(&key) {
                continue;
            }
            last = Some((key, value));
        }
        for (key, value) in changes.iter().rev() {
            if !key.starts_with(&self.prefix) {
                continue;
            }
            if let Some(put) = value {
                if last
                    .as_ref()
                    .is_none_or(|(tail, _)| tail.as_slice() <= key.as_slice())
                {
                    last = Some((key.clone(), put.clone()));
                }
                break;
            }
        }
        drop(changes);
        last.map(|(key, value)| {
            let logical = key[self.prefix.len()..].to_vec();
            Ok((Guard(K::decode(logical)?), Guard(V::decode(value)?)))
        })
        .transpose()
    }
}

impl<V: Value> Table<'_, u64, V> {
    pub(crate) fn page_after(
        &self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<(Vec<GuardPair<u64, V>>, bool), LedgerError> {
        let mut start = self.prefix.clone();
        if let Some(cursor) = after {
            start.extend_from_slice(&cursor.encode());
            start.push(0x00);
        }
        let want = limit.saturating_add(1);
        let max_bytes = want.saturating_mul(128);
        let scan = self.snapshot.scan_prefix_from_bounded(
            CF,
            &self.prefix,
            &start,
            PrefixScanLimit {
                max_rows: want,
                max_bytes,
            },
        )?;
        let complete = scan.complete;
        let mut rows: Vec<GuardPair<u64, V>> = Vec::new();
        for (full_key, value) in scan.rows.into_iter() {
            if !full_key.starts_with(&self.prefix) {
                break;
            }
            if !self.changes.borrow().is_empty()
                && let Some(staged) = self.changes.borrow().get(&full_key)
            {
                if staged.is_none() {
                    continue;
                }
            }
            let logical = full_key[self.prefix.len()..].to_vec();
            let key_bytes: [u8; 8] = logical
                .as_slice()
                .try_into()
                .map_err(|_| LedgerError::Invariant("non-u64 key in u64 table page".into()))?;
            let key = u64::from_be_bytes(key_bytes);
            if let Some(cursor) = after
                && key <= cursor
            {
                continue;
            }
            let stored = if !self.changes.borrow().is_empty()
                && let Some(Some(put)) = self.changes.borrow().get(&full_key).cloned()
            {
                put
            } else {
                value
            };
            rows.push((Guard(key), Guard(V::decode(stored)?)));
            if rows.len() >= want {
                break;
            }
        }
        let more = !complete || rows.len() > limit;
        if rows.len() > limit {
            rows.truncate(limit);
        }
        Ok((rows, more))
    }
}
