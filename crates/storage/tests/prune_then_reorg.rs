//! Pruning retention coverage for shallow reorg safety.
extern crate alloc;

use alloc::sync::Arc;
use std::collections::BTreeMap;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN;
use bitcoin_rs_storage::pruning::{
    BLOCK_DATA_CF, BlockPruner, PrunePolicy, RetentionRegistry, block_body_key, load_pruneheight,
    prune_to_height, reclaim_staged_flat_block_files, stage_block_and_undo_prune,
};
use bitcoin_rs_storage::{
    BlockFilePosition, ColumnFamily, FlatFileBlockStore, KvIter, KvSnapshot, KvStore, KvUndoStore,
    StorageError, UndoStore, WriteBatch, WriteCondition, block_file_max_height_key,
    encode_block_file_max_height,
};
use parking_lot::RwLock;
use tempfile::tempdir;

/// Prune everything below the requested height; `retention_depth` still
/// floors at the 288-block reorg margin.
const AGGRESSIVE: PrunePolicy = PrunePolicy {
    target_size_mb: 0,
    keep_below_tip: 0,
};

/// Returns whether a raw key is present in the block-body family.
fn row_stored(store: &MemoryStore, key: &[u8]) -> Result<bool, StorageError> {
    Ok(store.get(BLOCK_DATA_CF, key)?.is_some())
}

/// One appended body row: height, hash, and its flat-file position.
type StoredRow = (u32, Hash256, BlockFilePosition);

/// Appends `(height, payload)` bodies into one flat file, writing each
/// locator row plus the file's max-height row.
fn write_body_rows(
    store: &MemoryStore,
    block_files: &FlatFileBlockStore,
    rows: &[(u32, &[u8])],
) -> Result<Vec<StoredRow>, Box<dyn std::error::Error>> {
    let mut appended = Vec::with_capacity(rows.len());
    let mut batch = store.new_batch();
    for &(height, payload) in rows {
        let hash = fake_hash(height);
        let position = block_files.append(height, *hash.as_byte_array(), payload)?;
        batch.put(
            BLOCK_DATA_CF,
            &block_body_key(height, hash),
            &position.encode(),
        );
        appended.push((height, hash, position));
    }
    let max_height = appended.iter().map(|&(height, _, _)| height).max();
    if let Some(max_height) = max_height {
        batch.put(
            BLOCK_DATA_CF,
            &block_file_max_height_key(appended[0].2.file_no),
            &encode_block_file_max_height(max_height),
        );
    }
    store.write(batch)?;
    Ok(appended)
}

#[test]
fn undo_pruning_keeps_records_the_durable_tip_still_needs() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(MemoryStore::default());
    let data_dir = tempdir()?;
    let block_files = FlatFileBlockStore::open(data_dir.path())?;
    write_body_rows(
        &store,
        &block_files,
        &[
            (10, b"block-body"),
            (11, b"block-body"),
            (12, b"block-body"),
        ],
    )?;
    let undo_store = KvUndoStore::new(Arc::clone(&store));
    for height in 10_u32..=12 {
        undo_store.persist_undo(height, fake_hash(height), b"undo-body")?;
    }
    let retention = Arc::new(RetentionRegistry::new());
    let staged = prune_to_height(
        &*store,
        &block_files,
        &retention,
        11 + CORE_REORG_SAFETY_MARGIN,
        0,
        11,
        |_| Ok(()),
    )?;

    assert_eq!(
        staged.undo.blocks_removed, 0,
        "no undo record may go while a crash would restore below all of them"
    );
    assert!(
        undo_store.load_undo(10, fake_hash(10))?.is_some(),
        "the record a restore would need must survive"
    );
    Ok(())
}

#[test]
fn prune_to_height_deletes_rows_below_the_line_and_persists_pruneheight()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let data_dir = tempdir()?;
    let block_files = FlatFileBlockStore::open(data_dir.path())?;
    write_body_rows(
        &store,
        &block_files,
        &[
            (10, b"block-body"),
            (11, b"block-body"),
            (12, b"block-body"),
        ],
    )?;
    let undo_store = KvUndoStore::new(Arc::clone(&store));
    for height in 10_u32..=12 {
        undo_store.persist_undo(height, fake_hash(height), b"undo-body")?;
    }
    let retention = Arc::new(RetentionRegistry::new());
    let staged = prune_to_height(
        &*store,
        &block_files,
        &retention,
        11 + CORE_REORG_SAFETY_MARGIN,
        11 + CORE_REORG_SAFETY_MARGIN,
        11,
        |_| Ok(()),
    )?;

    assert_eq!(staged.blocks.blocks_removed, 1);
    assert_eq!(staged.undo.blocks_removed, 1);
    assert!(!row_stored(&store, &block_body_key(10, fake_hash(10)))?);
    assert!(row_stored(&store, &block_body_key(11, fake_hash(11)))?);
    assert!(row_stored(&store, &block_body_key(12, fake_hash(12)))?);
    assert!(undo_store.load_undo(10, fake_hash(10))?.is_none());
    assert!(undo_store.load_undo(11, fake_hash(11))?.is_some());
    assert!(undo_store.load_undo(12, fake_hash(12))?.is_some());
    assert_eq!(load_pruneheight(&*store)?, Some(11));
    Ok(())
}

/// A live retention lease clamps the manual prune line: rows the lease
/// pins survive a prune that would otherwise delete them, the recorded
/// line only names what actually went, a floor the line crossed is
/// refused as gone, and releasing the lease hands the authority back
/// exactly once (`RCV-08`, #655).
#[test]
fn prune_to_height_respects_an_active_retention_lease() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let data_dir = tempdir()?;
    let block_files = FlatFileBlockStore::open(data_dir.path())?;
    write_body_rows(
        &store,
        &block_files,
        &[
            (10, b"block-body"),
            (11, b"block-body"),
            (12, b"block-body"),
        ],
    )?;
    let undo_store = KvUndoStore::new(Arc::clone(&store));
    for height in 10_u32..=12 {
        undo_store.persist_undo(height, fake_hash(height), b"undo-body")?;
    }
    let retention = Arc::new(RetentionRegistry::new());
    let lease = retention.acquire(10)?;

    let pinned = prune_to_height(
        &*store,
        &block_files,
        &retention,
        11 + CORE_REORG_SAFETY_MARGIN,
        11 + CORE_REORG_SAFETY_MARGIN,
        11,
        |_| Ok(()),
    )?;
    assert_eq!(pinned.blocks.blocks_removed, 0);
    assert_eq!(pinned.undo.blocks_removed, 0);
    assert!(row_stored(&store, &block_body_key(10, fake_hash(10)))?);
    assert_eq!(retention.pruned_below(), 0);
    assert!(
        retention.acquire(9).is_ok(),
        "a pass that deleted nothing must not mark any height gone"
    );

    lease.release();
    assert_eq!(retention.active_leases(), 0);
    let released = prune_to_height(
        &*store,
        &block_files,
        &retention,
        11 + CORE_REORG_SAFETY_MARGIN,
        11 + CORE_REORG_SAFETY_MARGIN,
        11,
        |_| Ok(()),
    )?;
    assert_eq!(released.blocks.blocks_removed, 1);
    assert_eq!(released.undo.blocks_removed, 1);
    assert!(!row_stored(&store, &block_body_key(10, fake_hash(10)))?);
    assert!(row_stored(&store, &block_body_key(11, fake_hash(11)))?);
    assert_eq!(retention.pruned_below(), 11);
    Ok(())
}

#[test]
fn staged_flat_file_pruning_removes_all_selected_indexes_before_reclaim()
-> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::default();
    let data_dir = tempdir()?;
    let old_rows = {
        let seeding = FlatFileBlockStore::open(data_dir.path())?;
        write_body_rows(
            &store,
            &seeding,
            &[(1, b"first old body"), (2, b"second old body")],
        )?
    };
    // A fresh file for the current tip so the old file is reclaimable.
    std::fs::File::create(data_dir.path().join("blocks/blk00001.dat"))?;
    let block_files = FlatFileBlockStore::open(data_dir.path())?;
    let current = write_body_rows(&store, &block_files, &[(800, b"current body")])?.remove(0);
    assert_eq!(old_rows[0].2.file_no, 0);
    assert_eq!(current.2.file_no, 1);

    let policy = PrunePolicy {
        target_size_mb: 1,
        keep_below_tip: 0,
    };
    let first_old_key = block_body_key(1, old_rows[0].1);
    let second_old_key = block_body_key(2, old_rows[1].1);
    let current_key = block_body_key(800, current.1);

    let retention = Arc::new(RetentionRegistry::new());
    let reservation = retention.reserve(1_000_u32.saturating_sub(policy.retention_depth()));
    let mut prune_batch = store.new_batch();
    let staged =
        stage_block_and_undo_prune(&store, &mut prune_batch, &block_files, policy, &reservation)?;
    assert_eq!(staged.blocks.blocks_removed, 2);
    assert_eq!(staged.blocks.bytes_freed, 32);
    assert!(staged.undo.is_empty());
    assert_eq!(staged.file_numbers, vec![old_rows[0].2.file_no]);
    // Rows 1 and 2 delete, so the recorded line is one past the highest
    // deleted row — not the 712 policy line the pass stopped far short of.
    assert_eq!(staged.pruned_below, 3);

    store.write(prune_batch)?;
    assert!(!row_stored(&store, &first_old_key)?);
    assert!(!row_stored(&store, &second_old_key)?);
    assert!(row_stored(&store, &current_key)?);
    assert!(block_files.file_path(old_rows[0].2.file_no).exists());

    reclaim_staged_flat_block_files(&store, &block_files, &staged.file_numbers)?;
    assert!(!row_stored(
        &store,
        &block_file_max_height_key(old_rows[0].2.file_no)
    )?);
    assert!(!block_files.file_path(old_rows[0].2.file_no).exists());
    assert!(row_stored(&store, &current_key)?);
    assert!(row_stored(
        &store,
        &block_file_max_height_key(current.2.file_no)
    )?);
    assert_eq!(
        block_files.load(current.2, current.0, *current.1.as_byte_array())?,
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

    let retention = Arc::new(RetentionRegistry::new());
    let reservation = retention.reserve(1_000_u32.saturating_sub(AGGRESSIVE.retention_depth()));
    let mut prune_batch = store.new_batch();
    let staged = stage_block_and_undo_prune(
        &store,
        &mut prune_batch,
        &block_files,
        AGGRESSIVE,
        &reservation,
    )?;
    assert!(staged.file_numbers.is_empty());
    assert_eq!(staged.blocks.blocks_removed, 1);
    assert_eq!(staged.blocks.bytes_freed, 16);

    store.write(prune_batch)?;
    assert!(!row_stored(&store, &key)?);
    assert!(block_files.file_path(position.file_no).exists());
    assert!(row_stored(
        &store,
        &block_file_max_height_key(position.file_no)
    )?);
    Ok(())
}

#[test]
fn retention_lease_stops_the_prune_line_at_its_floor() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::default();
    let data_dir = tempdir()?;
    let old_hash = fake_hash(1);
    let leased_hash = fake_hash(2);
    let block_files = FlatFileBlockStore::open(data_dir.path())?;
    let old_position = block_files.append(1, *old_hash.as_byte_array(), b"old body")?;
    let leased_position = block_files.append(2, *leased_hash.as_byte_array(), b"leased body")?;
    let old_key = block_body_key(1, old_hash);
    let leased_key = block_body_key(2, leased_hash);
    let mut initial_batch = store.new_batch();
    initial_batch.put(BLOCK_DATA_CF, &old_key, &old_position.encode());
    initial_batch.put(BLOCK_DATA_CF, &leased_key, &leased_position.encode());
    initial_batch.put(
        BLOCK_DATA_CF,
        &block_file_max_height_key(old_position.file_no),
        &encode_block_file_max_height(2),
    );
    store.write(initial_batch)?;

    let retention = Arc::new(RetentionRegistry::new());
    let lease = retention.acquire(2)?;
    assert_eq!(retention.retention_floor(), Some(2));

    let policy = PrunePolicy {
        target_size_mb: 0,
        keep_below_tip: 0,
    };
    let mut leased_batch = store.new_batch();
    let leased_pass = retention.reserve(1_000_u32.saturating_sub(policy.retention_depth()));
    // The policy line (1000 - 288) folds down to the lease floor at the
    // reservation, so the pass can only claim rows below it.
    assert_eq!(leased_pass.line(), 2);
    let staged = stage_block_and_undo_prune(
        &store,
        &mut leased_batch,
        &block_files,
        policy,
        &leased_pass,
    )?;
    // The row at the reserved floor survives; only strictly-below rows
    // delete.
    assert_eq!(staged.pruned_below, 2);
    assert_eq!(staged.blocks.blocks_removed, 1);
    store.write(leased_batch)?;
    assert!(store.get(BLOCK_DATA_CF, &old_key)?.is_none());
    assert!(store.get(BLOCK_DATA_CF, &leased_key)?.is_some());

    // Releasing hands the authority back exactly once, so the next pass
    // deletes through the policy line again.
    lease.release();
    assert_eq!(retention.retention_floor(), None);
    drop(leased_pass);
    let mut released_batch = store.new_batch();
    let released_pass = retention.reserve(1_000_u32.saturating_sub(policy.retention_depth()));
    let staged = stage_block_and_undo_prune(
        &store,
        &mut released_batch,
        &block_files,
        policy,
        &released_pass,
    )?;
    assert_eq!(staged.pruned_below, 3);
    store.write(released_batch)?;
    assert!(store.get(BLOCK_DATA_CF, &leased_key)?.is_none());
    // The committed line is what later lease requests are bounded by: a
    // floor the prune line already crossed is refused as gone.
    released_pass.commit(staged.pruned_below);
    assert!(matches!(
        retention.acquire(2),
        Err(bitcoin_rs_storage::pruning::RetentionError::PrunedBelow { .. })
    ));
    Ok(())
}

/// The reservation is the prune/retention linearization point: a lease
/// request that arrives after a pass planned its deletions but before the
/// batch commits is refused, so it can never pin rows the batch staged. A
/// pass that fails before committing releases the claim again (#1151).
#[test]
fn history_request_between_planning_and_commit_is_refused() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(MemoryStore::default());
    let data_dir = tempdir()?;
    let block_files = FlatFileBlockStore::open(data_dir.path())?;
    write_body_rows(
        &store,
        &block_files,
        &[
            (10, b"block-body"),
            (11, b"block-body"),
            (12, b"block-body"),
        ],
    )?;
    let undo_store = KvUndoStore::new(Arc::clone(&store));
    for height in 10_u32..=12 {
        undo_store.persist_undo(height, fake_hash(height), b"undo-body")?;
    }
    let retention = Arc::new(RetentionRegistry::new());

    let staged = prune_to_height(
        &*store,
        &block_files,
        &retention,
        11 + CORE_REORG_SAFETY_MARGIN,
        11 + CORE_REORG_SAFETY_MARGIN,
        11,
        |pruned_below| {
            // Mid-pass: the batch holds the deletions, nothing is committed
            // yet, and the executed line is still 0. The reservation must
            // already refuse the floor the pass is about to delete through.
            assert_eq!(retention.pruned_below(), 0);
            assert!(matches!(
                retention.acquire(pruned_below - 1),
                Err(bitcoin_rs_storage::pruning::RetentionError::PrunedBelow {
                    requested: 10,
                    pruned_below: 11,
                })
            ));
            // The reserved line itself stays grantable: the pass deletes
            // strictly below it.
            assert!(retention.acquire(pruned_below).is_ok());
            Ok(())
        },
    )?;
    assert_eq!(staged.pruned_below, 11);
    assert!(!row_stored(&store, &block_body_key(10, fake_hash(10)))?);
    assert_eq!(retention.pruned_below(), 11);

    // A pass that fails after staging releases its claim: the floor it
    // refused is grantable again and nothing above the executed line went.
    let failed = prune_to_height(
        &*store,
        &block_files,
        &retention,
        12 + CORE_REORG_SAFETY_MARGIN,
        12 + CORE_REORG_SAFETY_MARGIN,
        12,
        |pruned_below| {
            assert!(retention.acquire(pruned_below - 1).is_err());
            Err(StorageError::InvalidOperation(
                "injected pre-commit failure",
            ))
        },
    );
    assert!(failed.is_err());
    assert_eq!(retention.pruned_below(), 11);
    assert!(row_stored(&store, &block_body_key(11, fake_hash(11)))?);
    let reacquired = retention.acquire(11)?;
    assert_eq!(reacquired.floor(), 11);
    reacquired.release();
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

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: MemoryBatch,
    ) -> Result<bool, StorageError> {
        let mut guard = self.cfs.write();
        for condition in conditions {
            let (cf, key) = condition.location();
            let current = guard[cf.index()].get(key);
            if !condition.matches(current.map(Vec::as_slice)) {
                return Ok(false);
            }
        }
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
        Ok(true)
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
