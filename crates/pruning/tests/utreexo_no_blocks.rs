//! Utreexo-only pruning coverage for block-body deletion without header loss.
extern crate alloc;

use alloc::sync::Arc;
use std::collections::BTreeMap;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_pruning::{
    BLOCK_DATA_CF, BlockProcessed, PrunePolicy, UtreexoOnlyCoordinator, block_body_key,
};
use bitcoin_rs_storage::{ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch};
use parking_lot::RwLock;

#[test]
fn utreexo_only_drops_block_bodies_and_retains_headers() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut coordinator =
        UtreexoOnlyCoordinator::new(Arc::clone(&store), PrunePolicy::utreexo_only());

    for height in 1_u32..=100 {
        let hash = fake_hash(height);
        let mut batch = store.new_batch();
        batch.put(
            ColumnFamily::BlockHeaders,
            hash.as_byte_array(),
            &fake_header(height),
        );
        batch.put(
            BLOCK_DATA_CF,
            &block_body_key(height, hash),
            &fake_body(height),
        );
        store.write(batch)?;

        coordinator.block_processed(BlockProcessed {
            height,
            hash,
            body_bytes: 32,
        })?;
    }

    assert_eq!(store.count_prefix(BLOCK_DATA_CF, b"b")?, 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 100);

    Ok(())
}

fn fake_hash(height: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&height.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn fake_body(height: u32) -> [u8; 32] {
    let mut body = [0_u8; 32];
    body[..4].copy_from_slice(&height.to_be_bytes());
    body
}

fn fake_header(height: u32) -> [u8; 80] {
    let mut header = [0_u8; 80];
    header[..4].copy_from_slice(&height.to_be_bytes());
    header
}

#[derive(Default)]
struct MemoryStore {
    cfs: RwLock<[BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()]>,
}

impl MemoryStore {
    fn count(&self, cf: ColumnFamily) -> usize {
        self.cfs.read()[cf.index()].len()
    }

    fn count_prefix(&self, cf: ColumnFamily, prefix: &[u8]) -> Result<usize, StorageError> {
        Ok(self.iter_prefix(cf, prefix)?.count())
    }
}

impl KvStore for MemoryStore {
    type WriteBatch = MemoryBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let guard = self.cfs.read();
        Ok(guard[cf.index()].get(key).cloned())
    }

    // RATIONALE: `KvIter` outlives the lock guard, so test rows are cloned before returning.
    #[allow(clippy::needless_collect)]
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let rows = self
            .cfs
            .read()
            .get(cf.index())
            .into_iter()
            .flat_map(|cf_rows| {
                cf_rows
                    .range(prefix.to_vec()..)
                    .take_while(|(key, _value)| key.starts_with(prefix))
            })
            .map(|(key, value)| Ok((key.clone(), value.clone())))
            .collect::<Vec<_>>();
        Ok(Box::new(rows.into_iter()))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        MemoryBatch::default()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let mut guard = self.cfs.write();
        for op in batch.ops {
            match op {
                MemoryOp::Put { cf, key, value } => {
                    guard[cf.index()].insert(key, value);
                }
                MemoryOp::Delete { cf, key } => {
                    guard[cf.index()].remove(&key);
                }
                MemoryOp::DeleteRange { cf, start, end } => {
                    let keys = guard[cf.index()]
                        .range(start..end)
                        .map(|(key, _value)| key.clone())
                        .collect::<Vec<_>>();
                    for key in keys {
                        guard[cf.index()].remove(&key);
                    }
                }
            }
        }
        Ok(())
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
struct MemoryBatch {
    ops: Vec<MemoryOp>,
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

struct MemorySnapshot {
    cfs: [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()],
}

impl KvSnapshot for MemorySnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.cfs[cf.index()].get(key).cloned())
    }

    // RATIONALE: the returned `KvIter` must not borrow the caller-owned prefix slice.
    #[allow(clippy::needless_collect)]
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let rows = self.cfs[cf.index()]
            .range(prefix.to_vec()..)
            .take_while(|(key, _value)| key.starts_with(prefix))
            .map(|(key, value)| Ok((key.clone(), value.clone())))
            .collect::<Vec<_>>();
        Ok(Box::new(rows.into_iter()))
    }
}
