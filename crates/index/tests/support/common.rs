//! Shared test support: a backend-free `KvStore` over `BTreeMap`.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin_rs_index::{
    PreparedBatch, PreparedBatchLimits, PreparedBlock, ScriptHash, ScriptHashRow, SpendingPrefixRow,
};
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_storage::{
    BatchOp, BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, PrefixScan,
    PrefixScanLimit, StorageError, WriteCondition,
};
use parking_lot::RwLock;

#[derive(Default)]
pub(crate) struct MemoryStore {
    cfs: RwLock<[BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()]>,
    pub(crate) fail_next_fenced_write: AtomicBool,
}

impl MemoryStore {
    pub(crate) fn count(&self, cf: ColumnFamily) -> usize {
        self.cfs.read()[cf.index()].len()
    }

    pub(crate) fn rows(&self, cf: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.cfs.read()[cf.index()]
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
}

fn scan_prefix_from(
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
    prefix: &[u8],
    start: &[u8],
    limit: PrefixScanLimit,
) -> PrefixScan {
    let seek = std::cmp::max(start, prefix);
    let mut out = Vec::new();
    let mut bytes = 0_usize;
    for (key, value) in rows.range::<[u8], _>((Bound::Included(seek), Bound::Unbounded)) {
        if !key.starts_with(prefix) {
            break;
        }
        let accepted = key
            .len()
            .checked_add(value.len())
            .and_then(|row_bytes| bytes.checked_add(row_bytes))
            .filter(|next_bytes| {
                out.len() < limit.max_rows && (out.is_empty() || *next_bytes <= limit.max_bytes)
            });
        let Some(next_bytes) = accepted else {
            return PrefixScan {
                rows: out,
                complete: false,
            };
        };
        out.push((key.clone(), value.clone()));
        bytes = next_bytes;
    }
    PrefixScan {
        rows: out,
        complete: true,
    }
}

fn apply_ops(cfs: &mut [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()], ops: Vec<BatchOp>) {
    for op in ops {
        match op {
            BatchOp::Put { cf, key, value } => {
                cfs[cf.index()].insert(key, value.into());
            }
            BatchOp::Delete { cf, key } => {
                cfs[cf.index()].remove(&key);
            }
            BatchOp::DeleteRange { cf, start, end } => {
                let doomed: Vec<Vec<u8>> = cfs[cf.index()]
                    .range(start..end)
                    .map(|(key, _value)| key.clone())
                    .collect();
                for key in doomed {
                    cfs[cf.index()].remove(&key);
                }
            }
        }
    }
}

impl KvStore for MemoryStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let guard = self.cfs.read();
        Ok(guard[cf.index()].get(key).cloned())
    }

    #[expect(clippy::needless_collect)]
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
        let guard = self.cfs.read();
        Ok(Box::new(MemorySnapshot { cfs: guard.clone() }))
    }

    fn arm_persist_fault(&self, _fault: bitcoin_rs_storage::PersistFault) {}
}

pub(crate) struct MemorySnapshot {
    cfs: [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()],
}

impl KvSnapshot for MemorySnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.cfs[cf.index()].get(key).cloned())
    }

    #[expect(clippy::needless_collect)]
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

pub(crate) fn single_block_batch(block: PreparedBlock) -> PreparedBatch {
    batch_with_limits(
        block,
        PreparedBatchLimits {
            max_rows: 100,
            max_bytes: 1_000_000,
        },
    )
}

pub(crate) fn batch_with_limits(
    block: PreparedBlock,
    limits: PreparedBatchLimits,
) -> PreparedBatch {
    let mut prepared = PreparedBatch::new(limits);
    assert!(
        prepared.try_push(block).is_ok(),
        "batch limits reject the block"
    );
    prepared
}
