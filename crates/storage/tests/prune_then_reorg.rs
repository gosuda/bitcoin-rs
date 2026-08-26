//! Pruning retention coverage for shallow reorg safety.
extern crate alloc;

use alloc::sync::Arc;
use std::collections::BTreeMap;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::pruning::{
    BLOCK_DATA_CF, BlockPruner, PrunePolicy, block_body_key, reclaim_staged_flat_block_files,
    stage_block_and_undo_prune,
};
use bitcoin_rs_storage::{
    ColumnFamily, FlatFileBlockStore, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch,
    block_file_max_height_key, encode_block_file_max_height,
};
use parking_lot::RwLock;
use tempfile::tempdir;

#[test]
fn staged_flat_file_pruning_removes_all_selected_indexes_before_reclaim()
-> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::default();
    let data_dir = tempdir()?;
    let first_old_hash = fake_hash(1);
    let second_old_hash = fake_hash(2);
    let current_hash = fake_hash(800);
    let (first_old_position, second_old_position) = {
        let block_files = FlatFileBlockStore::open(data_dir.path())?;
        (
            block_files.append(1, *first_old_hash.as_byte_array(), b"first old body")?,
            block_files.append(2, *second_old_hash.as_byte_array(), b"second old body")?,
        )
    };
    std::fs::File::create(data_dir.path().join("blocks/blk00001.dat"))?;
    let block_files = FlatFileBlockStore::open(data_dir.path())?;
    let current_position =
        block_files.append(800, *current_hash.as_byte_array(), b"current body")?;

    assert_eq!(first_old_position.file_no, 0);
    assert_eq!(second_old_position.file_no, 0);
    assert_eq!(current_position.file_no, 1);
    let policy = PrunePolicy {
        target_size_mb: 1,
        keep_below_tip: 0,
    };
    assert!(
        u64::try_from(
            first_old_position.encode().len()
                + second_old_position.encode().len()
                + current_position.encode().len(),
        )? < policy.target_size_bytes()
    );

    let first_old_key = block_body_key(1, first_old_hash);
    let second_old_key = block_body_key(2, second_old_hash);
    let current_key = block_body_key(800, current_hash);
    let mut initial_batch = store.new_batch();
    initial_batch.put(BLOCK_DATA_CF, &first_old_key, &first_old_position.encode());
    initial_batch.put(
        BLOCK_DATA_CF,
        &second_old_key,
        &second_old_position.encode(),
    );
    initial_batch.put(BLOCK_DATA_CF, &current_key, &current_position.encode());
    initial_batch.put(
        BLOCK_DATA_CF,
        &block_file_max_height_key(first_old_position.file_no),
        &encode_block_file_max_height(2),
    );
    initial_batch.put(
        BLOCK_DATA_CF,
        &block_file_max_height_key(current_position.file_no),
        &encode_block_file_max_height(800),
    );
    store.write(initial_batch)?;

    let mut prune_batch = store.new_batch();
    let (block_outcome, undo_outcome, file_numbers) =
        stage_block_and_undo_prune(&store, &mut prune_batch, &block_files, 1_000, 1_000, policy)?;
    assert_eq!(block_outcome.blocks_removed, 2);
    assert_eq!(block_outcome.bytes_freed, 32);
    assert!(undo_outcome.is_empty());
    assert_eq!(file_numbers, vec![first_old_position.file_no]);
    assert!(store.get(BLOCK_DATA_CF, &first_old_key)?.is_some());
    assert!(store.get(BLOCK_DATA_CF, &second_old_key)?.is_some());

    store.write(prune_batch)?;
    assert!(store.get(BLOCK_DATA_CF, &first_old_key)?.is_none());
    assert!(store.get(BLOCK_DATA_CF, &second_old_key)?.is_none());
    assert!(store.get(BLOCK_DATA_CF, &current_key)?.is_some());
    assert!(
        store
            .get(
                BLOCK_DATA_CF,
                &block_file_max_height_key(first_old_position.file_no),
            )?
            .is_some()
    );
    assert!(block_files.file_path(first_old_position.file_no).exists());

    reclaim_staged_flat_block_files(&store, &block_files, &file_numbers)?;
    assert!(
        store
            .get(
                BLOCK_DATA_CF,
                &block_file_max_height_key(first_old_position.file_no),
            )?
            .is_none()
    );
    assert!(!block_files.file_path(first_old_position.file_no).exists());
    assert!(store.get(BLOCK_DATA_CF, &current_key)?.is_some());
    assert!(
        store
            .get(
                BLOCK_DATA_CF,
                &block_file_max_height_key(current_position.file_no),
            )?
            .is_some()
    );
    assert_eq!(
        block_files.load(current_position, 800, *current_hash.as_byte_array())?,
        Some(b"current body".to_vec())
    );
    Ok(())
}

#[test]
fn target_pruning_deletes_old_indexes_in_the_current_flat_file()
-> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::default();
    let data_dir = tempdir()?;
    let hash = fake_hash(1);
    let block_files = FlatFileBlockStore::open(data_dir.path())?;
    let position = block_files.append(1, *hash.as_byte_array(), b"current old body")?;
    let key = block_body_key(1, hash);
    let mut initial_batch = store.new_batch();
    initial_batch.put(BLOCK_DATA_CF, &key, &position.encode());
    initial_batch.put(
        BLOCK_DATA_CF,
        &block_file_max_height_key(position.file_no),
        &encode_block_file_max_height(1),
    );
    store.write(initial_batch)?;

    let mut prune_batch = store.new_batch();
    let (block_outcome, _undo_outcome, file_numbers) = stage_block_and_undo_prune(
        &store,
        &mut prune_batch,
        &block_files,
        1_000,
        1_000,
        // Aggressive policy: prune everything below the requested height;
        // retention_depth still floors at the 288-block reorg margin.
        PrunePolicy {
            target_size_mb: 0,
            keep_below_tip: 0,
        },
    )?;
    assert!(file_numbers.is_empty());
    assert_eq!(block_outcome.blocks_removed, 1);
    assert_eq!(block_outcome.bytes_freed, 16);

    store.write(prune_batch)?;
    assert!(store.get(BLOCK_DATA_CF, &key)?.is_none());
    assert!(block_files.file_path(position.file_no).exists());
    assert!(
        store
            .get(BLOCK_DATA_CF, &block_file_max_height_key(position.file_no))?
            .is_some()
    );
    Ok(())
}

#[test]
fn pruning_keeps_core_reorg_floor_and_shallow_reorg_succeeds()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    write_fake_blocks(&store, 500)?;

    let mut pruner = BlockPruner::new(
        Arc::clone(&store),
        PrunePolicy {
            target_size_mb: 0,
            keep_below_tip: 100,
        },
    );

    let outcome = pruner.prune_step(500)?;

    assert_eq!(outcome.blocks_removed, 211);
    assert_eq!(outcome.bytes_freed, 211 * 32);

    for height in 1_u32..=211 {
        assert!(
            store
                .get(BLOCK_DATA_CF, &block_body_key(height, fake_hash(height)))?
                .is_none(),
            "height {height} should be pruned"
        );
    }

    for height in 212_u32..=500 {
        assert!(
            store
                .get(BLOCK_DATA_CF, &block_body_key(height, fake_hash(height)))?
                .is_some(),
            "height {height} should be retained"
        );
    }

    let fork_point = 450_u32;
    for height in (fork_point + 1)..=500 {
        let key = block_body_key(height, fake_hash(height));
        assert!(
            store.get(BLOCK_DATA_CF, &key)?.is_some(),
            "50-block reorg needs retained body at height {height}"
        );
    }

    Ok(())
}

fn write_fake_blocks(store: &MemoryStore, count: u32) -> Result<(), StorageError> {
    let mut batch = store.new_batch();
    for height in 1_u32..=count {
        let hash = fake_hash(height);
        batch.put(
            BLOCK_DATA_CF,
            &block_body_key(height, hash),
            &fake_body(height),
        );
    }
    store.write(batch)
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

#[derive(Default)]
struct MemoryStore {
    cfs: RwLock<[BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()]>,
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
