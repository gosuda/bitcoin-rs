//! Shared test support: a backend-free `KvStore` over `BTreeMap`.
//!
//! Deliberately not behind a storage feature. Correctness tests that gate a
//! refactor must run on a plain `cargo test --workspace`; a test hidden behind
//! `required-features` is a test that silently does not run.
#![allow(dead_code)]

use std::collections::BTreeMap;

use bitcoin_rs_index::{ScriptHash, ScriptHashRow, SpendingPrefixRow};
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_storage::{
    BatchOp, BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError,
    WriteCondition,
};
use parking_lot::RwLock;

#[derive(Default)]
pub(crate) struct MemoryStore {
    cfs: RwLock<[BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()]>,
}

impl KvStore for MemoryStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let guard = self.cfs.read();
        Ok(guard[cf.index()].get(key).cloned())
    }

    #[allow(clippy::needless_collect)] // SPEC: returned KvIter must own cloned rows after the lock guard is dropped.
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let guard = self.cfs.read();
        let rows = guard[cf.index()]
            .iter()
            .filter(|(key, _value)| key.starts_with(prefix))
            .map(|(key, value)| Ok((key.clone(), value.clone())))
            .collect::<Vec<_>>();
        Ok(Box::new(rows.into_iter()))
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        BufferedWriteBatch::default()
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        let mut guard = self.cfs.write();
        for op in batch.into_ops() {
            match op {
                BatchOp::Put { cf, key, value } => {
                    guard[cf.index()].insert(key, value.into());
                }
                BatchOp::Delete { cf, key } => {
                    guard[cf.index()].remove(&key);
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    let doomed: Vec<Vec<u8>> = guard[cf.index()]
                        .range(start..end)
                        .map(|(key, _value)| key.clone())
                        .collect();
                    for key in doomed {
                        guard[cf.index()].remove(&key);
                    }
                }
            }
        }
        Ok(())
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        // Every condition observes pre-batch state; the batch is allowed to
        // put or delete a condition key itself.
        let matched = {
            let guard = self.cfs.read();
            conditions.iter().all(|condition| {
                let (cf, key) = condition.location();
                condition.matches(guard[cf.index()].get(key).map(Vec::as_slice))
            })
        };
        if !matched {
            return Ok(false);
        }
        self.write(batch).map(|()| true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        let guard = self.cfs.read();
        Ok(Box::new(MemorySnapshot { cfs: guard.clone() }))
    }

    fn arm_persist_fault(&self, _fault: bitcoin_rs_storage::PersistFault) {
        // In-memory double: no persistence boundary exists to fault.
    }
}

pub(crate) struct MemorySnapshot {
    cfs: [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()],
}

impl KvSnapshot for MemorySnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.cfs[cf.index()].get(key).cloned())
    }

    #[allow(clippy::needless_collect)] // SPEC: returned KvIter owns cloned rows to match backend iterator ownership.
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let rows = self.cfs[cf.index()]
            .iter()
            .filter(|(key, _value)| key.starts_with(prefix))
            .map(|(key, value)| Ok((key.clone(), value.clone())))
            .collect::<Vec<_>>();
        Ok(Box::new(rows.into_iter()))
    }
}

/// Writes one funding-row key at `height` with an empty value.
///
/// Empty values take the scan-fallback resolver path. Tests that pin
/// little-endian key order, not watermark contiguity, use this instead of
/// [`bitcoin_rs_index::IndexWriter::commit_block`].
pub(crate) fn put_funding_row(
    store: &MemoryStore,
    scripthash: ScriptHash,
    height: u32,
) -> Result<(), StorageError> {
    store.put(
        ColumnFamily::Funding,
        &ScriptHashRow::row(scripthash, height).to_db_row(),
        &[],
    )
}

/// Writes one spending-row key at `height` with an empty value.
pub(crate) fn put_spending_row(
    store: &MemoryStore,
    outpoint: &OutPoint,
    height: u32,
) -> Result<(), StorageError> {
    store.put(
        ColumnFamily::Spending,
        &SpendingPrefixRow::row(outpoint, height).to_db_row(),
        &[],
    )
}
