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
    ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition,
};
use parking_lot::RwLock;

#[derive(Default)]
pub(crate) struct MemoryStore {
    cfs: RwLock<[BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()]>,
}

impl KvStore for MemoryStore {
    type WriteBatch = MemoryBatch;

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

    fn new_batch(&self) -> Self::WriteBatch {
        MemoryBatch::default()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let mut guard = self.cfs.write();
        apply_ops(&mut guard, batch.ops.into_iter());
        Ok(())
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        let mut guard = self.cfs.write();
        // Every condition observes pre-batch state; the batch is allowed to
        // put or delete a condition key itself.
        let matched = conditions.iter().all(|condition| {
            let (cf, key) = condition.location();
            condition.matches(guard[cf.index()].get(key).map(Vec::as_slice))
        });
        if !matched {
            return Ok(false);
        }
        apply_ops(&mut guard, batch.ops.into_iter());
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        let guard = self.cfs.read();
        Ok(Box::new(MemorySnapshot { cfs: guard.clone() }))
    }
}

#[derive(Default)]
pub(crate) struct MemoryBatch {
    ops: Vec<MemoryOp>,
}

impl WriteBatch for MemoryBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.ops.push(MemoryOp::Put {
            cf,
            key: key.to_vec(),
            value: value.to_vec(),
        });
    }

    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.ops.push(MemoryOp::Delete {
            cf,
            key: key.to_vec(),
        });
    }

    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]) {
        self.ops.push(MemoryOp::DeleteRange {
            cf,
            start: start.to_vec(),
            end: end.to_vec(),
        });
    }
}

enum MemoryOp {
    Put {
        cf: ColumnFamily,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        cf: ColumnFamily,
        key: Vec<u8>,
    },
    DeleteRange {
        cf: ColumnFamily,
        start: Vec<u8>,
        end: Vec<u8>,
    },
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

/// Folds one batch's operations into the column families, in order.
fn apply_ops(
    cfs: &mut [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()],
    ops: std::vec::IntoIter<MemoryOp>,
) {
    for op in ops {
        match op {
            MemoryOp::Put { cf, key, value } => {
                cfs[cf.index()].insert(key, value);
            }
            MemoryOp::Delete { cf, key } => {
                cfs[cf.index()].remove(&key);
            }
            MemoryOp::DeleteRange { cf, start, end } => {
                let keys = cfs[cf.index()]
                    .keys()
                    .filter(|key| {
                        key.as_slice() >= start.as_slice() && key.as_slice() < end.as_slice()
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                for key in keys {
                    cfs[cf.index()].remove(&key);
                }
            }
        }
    }
}
