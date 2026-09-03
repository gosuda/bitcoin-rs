//! Roundtrip tests for electrs-shaped index rows over a small in-memory `KvStore`.
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use bitcoin_rs_primitives::{
    Block, Hash256, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    encode::double_sha256,
};
use parking_lot::{Mutex, RwLock};

#[cfg(feature = "redb")]
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_index::types::{TxPosition, TxPositionValue};
use bitcoin_rs_index::{
    ConsumerCursorUpdate, IndexCapabilities, IndexError, IndexFormat, IndexReader, IndexRowCounts,
    IndexWatermark, IndexWatermarks, IndexWriter, Indexer, PreparedBatch, PreparedBatchLimits,
};
use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvSnapshot, KvStore, PrefixScanLimit, StorageError, WriteBatch,
    WriteCondition,
};

/// Reserved capability-reset marker slot mirrored from the index crate.
const RESET_KEY: &[u8] = &[0x00, b'R'];
const ORDINARY_STATE_REVISION_KEY: &[u8] = &[0x00, b'O'];

/// Interrupted 9-byte claim from an earlier binary: mask plus process epoch,
/// with no base version.
fn fenced_marker(mask: u8, process_epoch: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(9);
    value.push(mask);
    value.extend_from_slice(&process_epoch.to_le_bytes());
    value
}

/// Current claim grammar: mask, process epoch, base idle version.
fn claim_bytes(mask: u8, process_epoch: u64, base_version: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(17);
    value.push(mask);
    value.extend_from_slice(&process_epoch.to_le_bytes());
    value.extend_from_slice(&base_version.to_le_bytes());
    value
}

/// Permanent idle state: a reset was completed `version` times.
fn idle_bytes(version: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(9);
    value.push(0xFF);
    value.extend_from_slice(&version.to_le_bytes());
    value
}

fn is_idle_marker(bytes: &[u8]) -> bool {
    bytes.len() == idle_bytes(0).len() && bytes[0] == 0xFF
}

/// Decodes a little-endian `u64` from `bytes` at `offset`, returning `None`
/// when fewer than 8 bytes remain — total, never panics.
fn decode_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes.get(offset..offset + 8)?);
    Some(u64::from_le_bytes(arr))
}

/// Reads the durable idle version, failing if the state is absent or a claim.
fn stored_idle_version<S: KvStore>(store: &Arc<S>) -> Result<u64, Box<dyn std::error::Error>> {
    match store.get(ColumnFamily::UtxoMeta, RESET_KEY)? {
        Some(bytes) if is_idle_marker(&bytes) => Ok(decode_u64_le(&bytes, 1)
            .ok_or_else(|| std::io::Error::other("idle marker truncated"))?),
        other => Err(std::io::Error::other(format!("reset state is not idle: {other:?}")).into()),
    }
}
#[derive(Default)]
struct MemoryStore {
    cfs: RwLock<[BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()]>,
}

impl MemoryStore {
    fn count(&self, cf: ColumnFamily) -> usize {
        let guard = self.cfs.read();
        guard[cf.index()].len()
    }

    fn rows(&self, cf: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
        let guard = self.cfs.read();
        guard[cf.index()]
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
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

/// One observed store batch, for durability-order assertions (I-A/I-B).
#[derive(Clone, Debug)]
struct BatchLog {
    durable: bool,
    marker_put: Option<Vec<u8>>,
    deletes: usize,
}

#[derive(Default)]
struct CallTrackingStore {
    inner: MemoryStore,
    writes: AtomicUsize,
    durable_writes: AtomicUsize,
    flushes: AtomicUsize,
    batches: RwLock<Vec<BatchLog>>,
    read_order: Mutex<Vec<(ColumnFamily, Vec<u8>)>>,
    snapshot_read_order: Mutex<Vec<(ColumnFamily, Vec<u8>)>>,
    snapshots: AtomicUsize,
    snapshot_reset_after_tx_watermark_read: Mutex<Option<(u64, u64)>>,
    snapshot_reset_after_revision_read: Mutex<Option<(u64, u64)>>,
    cursor_race_tx_watermark: Mutex<Option<IndexWatermark>>,
    fence_reset_during_header_read: Mutex<Option<(u64, u64)>>,
    cursor_race_script_watermark: Mutex<Option<IndexWatermark>>,
}

impl CallTrackingStore {
    fn count(&self, cf: ColumnFamily) -> usize {
        self.inner.count(cf)
    }

    fn rows(&self, cf: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.inner.rows(cf)
    }

    fn logged_batches(&self) -> Vec<BatchLog> {
        self.batches.read().clone()
    }

    fn advance_fence_and_clear_index_state(
        &self,
        next_version: u64,
        next_revision: u64,
    ) -> Result<(), StorageError> {
        let mut batch = self.inner.new_batch();
        batch.put(ColumnFamily::UtxoMeta, RESET_KEY, &idle_bytes(next_version));
        batch.put(
            ColumnFamily::UtxoMeta,
            ORDINARY_STATE_REVISION_KEY,
            &next_revision.to_le_bytes(),
        );
        batch.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
        batch.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
        batch.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
        self.inner.write(batch)
    }

    fn build_log(batch: &MemoryBatch, durable: bool) -> BatchLog {
        let mut entry = BatchLog {
            durable,
            marker_put: None,
            deletes: 0,
        };
        for op in &batch.ops {
            match op {
                MemoryOp::Put { cf, key, value }
                    if *cf == ColumnFamily::UtxoMeta && key.as_slice() == RESET_KEY =>
                {
                    entry.marker_put = Some(value.clone());
                }
                MemoryOp::Delete { .. } | MemoryOp::DeleteRange { .. } => entry.deletes += 1,
                MemoryOp::Put { .. } => {}
            }
        }
        entry
    }
}

impl KvStore for CallTrackingStore {
    type WriteBatch = MemoryBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.read_order.lock().push((cf, key.to_vec()));
        if cf == ColumnFamily::BlockHeaders {
            let reset = self.fence_reset_during_header_read.lock().take();
            if let Some((next_version, next_revision)) = reset {
                self.advance_fence_and_clear_index_state(next_version, next_revision)?;
            }
        }
        self.inner.get(cf, key)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.inner.iter_prefix(cf, prefix)
    }

    fn new_batch(&self) -> Self::WriteBatch {
        self.inner.new_batch()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        let entry = Self::build_log(&batch, false);
        self.inner.write(batch)?;
        self.batches.write().push(entry);
        Ok(())
    }

    fn write_durable(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.durable_writes.fetch_add(1, Ordering::Relaxed);
        let entry = Self::build_log(&batch, true);
        self.inner.write(batch)?;
        self.batches.write().push(entry);
        Ok(())
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        let entry = Self::build_log(&batch, true);
        if batch
            .put_value(ColumnFamily::UtxoMeta, CURSOR_KEY)
            .is_some()
        {
            let tx_watermark = self.cursor_race_tx_watermark.lock().take();
            if let Some(watermark) = tx_watermark {
                self.inner.put(
                    ColumnFamily::UtxoMeta,
                    TX_WATERMARK_KEY,
                    &watermark.to_bytes(),
                )?;
            }
            let script_watermark = self.cursor_race_script_watermark.lock().take();
            if let Some(watermark) = script_watermark {
                self.inner.put(
                    ColumnFamily::UtxoMeta,
                    SCRIPT_WATERMARK_KEY,
                    &watermark.to_bytes(),
                )?;
            }
        }
        let applied = self.inner.write_durable_if(conditions, batch)?;
        if applied {
            self.durable_writes.fetch_add(1, Ordering::Relaxed);
            self.batches.write().push(entry);
        }
        Ok(applied)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        self.snapshots.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(CallTrackingSnapshot {
            captured: self.inner.snapshot()?,
            store: self,
        }))
    }
}

struct CallTrackingSnapshot<'a> {
    captured: Box<dyn KvSnapshot + 'a>,
    store: &'a CallTrackingStore,
}

impl KvSnapshot for CallTrackingSnapshot<'_> {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let observed = self.captured.get(cf, key)?;
        self.store
            .snapshot_read_order
            .lock()
            .push((cf, key.to_vec()));
        if cf == ColumnFamily::UtxoMeta && key == ORDINARY_STATE_REVISION_KEY {
            let reset = self.store.snapshot_reset_after_revision_read.lock().take();
            if let Some((next_version, next_revision)) = reset {
                self.store
                    .advance_fence_and_clear_index_state(next_version, next_revision)?;
            }
        }
        if cf == ColumnFamily::UtxoMeta && key == TX_WATERMARK_KEY {
            let reset = self
                .store
                .snapshot_reset_after_tx_watermark_read
                .lock()
                .take();
            if let Some((next_version, next_revision)) = reset {
                self.store
                    .advance_fence_and_clear_index_state(next_version, next_revision)?;
            }
        }
        if cf == ColumnFamily::BlockHeaders {
            let reset = self.store.fence_reset_during_header_read.lock().take();
            if let Some((next_version, next_revision)) = reset {
                self.store
                    .advance_fence_and_clear_index_state(next_version, next_revision)?;
            }
        }
        Ok(observed)
    }

    #[allow(clippy::needless_collect)] // SPEC: returned KvIter owns captured rows.
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.captured.iter_prefix(cf, prefix)
    }
}

#[derive(Default)]
struct MemoryBatch {
    ops: Vec<MemoryOp>,
}
impl MemoryBatch {
    fn put_value(&self, cf: ColumnFamily, key: &[u8]) -> Option<Vec<u8>> {
        self.ops.iter().find_map(|op| match op {
            MemoryOp::Put {
                cf: op_cf,
                key: op_key,
                value,
            } if *op_cf == cf && op_key.as_slice() == key => Some(value.clone()),
            _ => None,
        })
    }

    fn deletes_derived_rows(&self) -> bool {
        self.ops.iter().any(|op| {
            matches!(
                op,
                MemoryOp::Delete { cf, .. } | MemoryOp::DeleteRange { cf, .. }
                    if *cf != ColumnFamily::UtxoMeta
            )
        })
    }
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

struct MemorySnapshot {
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

#[test]
fn ingest_golden_blocks_writes_expected_electrs_rows() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            0_u32,
            IndexRowCounts {
                txids: 1,
                funding: 1,
                spending: 0,
                headers: 1,
            },
        ),
        (
            170_u32,
            IndexRowCounts {
                txids: 2,
                funding: 3,
                spending: 1,
                headers: 1,
            },
        ),
        (
            481_824_u32,
            IndexRowCounts {
                txids: 1_866,
                funding: 3_740,
                spending: 5_192,
                headers: 1,
            },
        ),
    ];

    for (height, expected) in cases {
        let store = std::sync::Arc::new(MemoryStore::default());
        let mut indexer = Indexer::new(std::sync::Arc::clone(&store));
        let block = read_fixture(height)?;

        let counts = indexer.ingest_block(&block, height)?;

        assert_eq!(counts, expected, "height {height} returned counts");
        assert_eq!(
            store.count(ColumnFamily::TxConfirmed),
            expected.txids,
            "height {height} txid rows"
        );
        assert_eq!(
            store.count(ColumnFamily::Funding),
            expected.funding,
            "height {height} funding rows"
        );
        assert_eq!(
            store.count(ColumnFamily::Spending),
            expected.spending,
            "height {height} spending rows"
        );
        assert_eq!(
            store.count(ColumnFamily::BlockHeaders),
            expected.headers,
            "height {height} header rows"
        );
    }
    Ok(())
}

#[test]
fn ingest_with_precomputed_txids_matches_standard_ingest() -> Result<(), Box<dyn std::error::Error>>
{
    let height = 170_u32;
    let block_bytes = read_fixture(height)?;
    let block = Block::consensus_decode(&block_bytes)?;
    let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();

    assert_precomputed_ingest_matches_standard(&block_bytes, height, &txids)
}

#[test]
fn ingest_with_verified_txids_matches_standard_ingest() -> Result<(), Box<dyn std::error::Error>> {
    let height = 170_u32;
    let block_bytes = read_fixture(height)?;
    let block = Block::consensus_decode(&block_bytes)?;
    let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();

    assert_verified_ingest_matches_standard(&block_bytes, height, &txids)
}

#[test]
fn ingest_with_mismatched_precomputed_txids_falls_back_to_standard_ingest()
-> Result<(), Box<dyn std::error::Error>> {
    let height = 170_u32;
    let block_bytes = read_fixture(height)?;

    assert_precomputed_ingest_matches_standard(&block_bytes, height, &[])
}

#[test]
fn ingest_with_same_length_wrong_precomputed_txids_falls_back_to_standard_ingest()
-> Result<(), Box<dyn std::error::Error>> {
    let height = 170_u32;
    let block_bytes = read_fixture(height)?;
    let block = Block::consensus_decode(&block_bytes)?;
    let stale_txids = vec![Txid(Hash256::from_le_bytes(&[0x42; 32])); block.txs.len()];

    assert_precomputed_ingest_matches_standard(&block_bytes, height, &stale_txids)
}

fn read_fixture(height: u32) -> Result<Vec<u8>, std::io::Error> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../primitives/tests/testdata")
        .join(format!("{height}.bin"));
    std::fs::read(path)
}

fn assert_precomputed_ingest_matches_standard(
    block: &[u8],
    height: u32,
    txids: &[Txid],
) -> Result<(), Box<dyn std::error::Error>> {
    assert_ingest_matches_standard(block, height, |indexer| {
        indexer.ingest_block_with_txids(block, height, txids)
    })
}

fn assert_verified_ingest_matches_standard(
    block: &[u8],
    height: u32,
    txids: &[Txid],
) -> Result<(), Box<dyn std::error::Error>> {
    assert_ingest_matches_standard(block, height, |indexer| {
        indexer.ingest_block_with_verified_txids(block, height, txids)
    })
}

fn assert_ingest_matches_standard(
    block: &[u8],
    height: u32,
    ingest: impl FnOnce(
        &mut Indexer<MemoryStore>,
    ) -> Result<IndexRowCounts, bitcoin_rs_index::IndexError>,
) -> Result<(), Box<dyn std::error::Error>> {
    let standard_store = std::sync::Arc::new(MemoryStore::default());
    let mut standard_indexer = Indexer::new(std::sync::Arc::clone(&standard_store));
    let candidate_store = std::sync::Arc::new(MemoryStore::default());
    let mut candidate_indexer = Indexer::new(std::sync::Arc::clone(&candidate_store));

    let standard_counts = standard_indexer.ingest_block(block, height)?;
    let candidate_counts = ingest(&mut candidate_indexer)?;

    assert_eq!(candidate_counts, standard_counts);
    for &cf in ColumnFamily::ALL {
        assert_eq!(candidate_store.rows(cf), standard_store.rows(cf));
    }
    Ok(())
}

fn block_hash(body: &[u8]) -> [u8; 32] {
    double_sha256(&body[..80]).to_le_bytes()
}

fn parent_hash(body: &[u8]) -> [u8; 32] {
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&body[4..36]);
    hash
}

#[test]
fn watermark_roundtrip_and_invalid_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let watermark = IndexWatermark {
        height: 123,
        hash: [0xab; 32],
    };
    let bytes = watermark.to_bytes();
    let decoded = IndexWatermark::from_bytes(&bytes)?;
    assert_eq!(decoded, watermark);

    let result = IndexWatermark::from_bytes(&bytes[..3]);
    assert!(matches!(result, Err(IndexError::InvalidWatermark)));
    Ok(())
}

#[test]
fn format_version_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[5, 0, 0, 0],
    )?;
    assert!(matches!(
        IndexWriter::open(store, 1),
        Err(IndexError::UnsupportedTxIndexFormatVersion { version: 5 })
    ));
    Ok(())
}

#[test]
fn unversioned_rows_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut indexer = Indexer::new(Arc::clone(&store));
    let body = read_fixture(0)?;
    indexer.ingest_block(&body, 0)?;

    assert!(matches!(
        IndexWriter::open(Arc::clone(&store), 1),
        Err(IndexError::LegacyCursorlessIndex)
    ));
    Ok(())
}

#[test]
fn reset_index_replaces_an_incompatible_derived_format() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &2_u32.to_le_bytes(),
    )?;
    store.put(
        bitcoin_rs_storage::ColumnFamily::TxConfirmed,
        b"old",
        b"row",
    )?;

    IndexWriter::reset_index(store.as_ref(), 1)?;

    assert!(
        IndexWriter::open(Arc::clone(&store), 1)?
            .watermark()?
            .is_none()
    );
    assert_eq!(
        store.count(bitcoin_rs_storage::ColumnFamily::TxConfirmed),
        0
    );
    Ok(())
}

#[test]
fn invalid_watermark_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[4, 0, 0, 0],
    )?;
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'T'],
        &[0u8; 2],
    )?;
    let writer = IndexWriter::open(Arc::clone(&store), 1)?;
    assert!(matches!(
        writer.watermark(),
        Err(IndexError::InvalidWatermark)
    ));
    Ok(())
}

#[test]
fn prepare_block_verifies_header_identity_and_parent() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);

    let block = writer.prepare_block(0, hash, &body)?;
    assert_eq!(block.height, 0);
    assert_eq!(block.hash, hash);
    assert_eq!(block.parent_hash, [0u8; 32]);
    assert_eq!(block.row_count, 3); // txid + funding + header
    assert_eq!(block.encoded_bytes, 120);

    let wrong_hash = [0x42u8; 32];
    assert!(matches!(
        writer.prepare_block(0, wrong_hash, &body),
        Err(IndexError::BlockIdentityMismatch {
            height: 0,
            expected,
            actual,
        }) if expected == wrong_hash && actual == hash
    ));
    Ok(())
}

#[test]
fn commit_forward_and_rollback_are_atomic_and_ordered() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body0 = read_fixture(0)?;
    let body1 = read_fixture(1)?;
    let block0 = writer.prepare_block(0, block_hash(&body0), &body0)?;
    let block1 = writer.prepare_block(1, block_hash(&body1), &body1)?;
    let block0_watermark = block0.watermark();
    let block1_watermark = block1.watermark();
    assert_eq!(block1.parent_hash, block0.hash);
    assert_eq!(block1.parent_hash, parent_hash(&body1));

    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 1_000,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block0).is_ok());
    assert!(batch.try_push(block1).is_ok());
    let watermark = writer.commit_forward(batch)?;
    assert_eq!(watermark, block1_watermark);
    assert_eq!(writer.watermark()?, Some(watermark));
    assert_eq!(
        store.count(bitcoin_rs_storage::ColumnFamily::BlockHeaders),
        2
    );

    // A mismatched parent watermark must fail without changing the tip.
    let wrong_prev = IndexWatermark {
        height: 0,
        hash: [0x42; 32],
    };
    assert!(matches!(
        writer.commit_rollback_one(Some(wrong_prev), &body1),
        Err(IndexError::WatermarkMismatch { .. })
    ));
    assert_eq!(writer.watermark()?, Some(block1_watermark));

    // Roll back block 1, returning to block 0.
    writer.commit_rollback_one(Some(block0_watermark), &body1)?;
    assert_eq!(writer.watermark()?, Some(block0_watermark));
    assert_eq!(
        store.count(bitcoin_rs_storage::ColumnFamily::BlockHeaders),
        1
    );
    assert_eq!(
        store.count(bitcoin_rs_storage::ColumnFamily::TxConfirmed),
        1
    );

    // Rolling back with a body that does not match the current watermark fails.
    assert!(matches!(
        writer.commit_rollback_one(Some(block0_watermark), &body1),
        Err(IndexError::BlockIdentityMismatch { .. })
    ));

    Ok(())
}

#[test]
fn snapshot_scan_preserves_position_values() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let block = Block::consensus_decode(&body)?;
    let txid = block.txs[0].txid();
    let prepared = writer.prepare_block(0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(prepared).is_ok());
    writer.commit_forward(batch)?;

    let snapshot = writer.snapshot()?;
    let scan = snapshot.transaction_rows(
        &txid,
        PrefixScanLimit {
            max_rows: 10,
            max_bytes: 1_024,
        },
    )?;

    assert!(scan.complete);
    assert_eq!(scan.rows.len(), 1);
    assert_eq!(scan.rows[0].row.height(), 0);
    assert_eq!(
        TxPositionValue::decode(&scan.rows[0].value).map(<[TxPosition]>::len),
        Some(1)
    );
    Ok(())
}

#[test]
fn spending_rows_carry_transaction_positions() -> Result<(), Box<dyn std::error::Error>> {
    let mut block = Network::Regtest.genesis_block();
    let funding_txid = block.txs[0].txid();
    let spending_tx = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: funding_txid,
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: block.txs[0].outputs[0].value,
            script_pubkey: Vec::new(),
        }],
    };
    block.txs.push(spending_tx.clone());
    let body = consensus_bytes(&block);
    let spending_bytes = consensus_bytes(&spending_tx);
    let position = TxPosition::new(
        u32::try_from(body.len() - spending_bytes.len())?,
        u32::try_from(spending_bytes.len())?,
    );

    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let prepared = writer.prepare_block(0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(prepared).is_ok());
    writer.commit_forward(batch)?;

    let snapshot = writer.snapshot()?;
    let outpoint = OutPoint {
        txid: funding_txid,
        vout: 0,
    };
    let scan = snapshot.spending_rows(
        &outpoint,
        PrefixScanLimit {
            max_rows: 10,
            max_bytes: 1_024,
        },
    )?;
    assert!(scan.complete);
    assert_eq!(scan.rows.len(), 1);
    let positions = TxPositionValue::decode(&scan.rows[0].value)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "spending position"))?;
    assert_eq!(positions, &[position]);
    let start = usize::try_from(position.offset())?;
    let end =
        usize::try_from(position.end().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "position end")
        })?)?;
    assert_eq!(Tx::consensus_decode(&body[start..end])?, spending_tx);
    Ok(())
}

#[test]
fn commit_forward_uses_one_durable_write() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let block = writer.prepare_block(0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());

    writer.commit_forward(batch)?;

    assert_eq!(store.durable_writes.load(Ordering::Relaxed), 1);
    assert_eq!(store.writes.load(Ordering::Relaxed), 0);
    assert_eq!(store.flushes.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn capability_commits_own_only_their_rows_and_watermarks() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);
    let limits = PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    };

    let tx_block = writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 0, hash, &body)?;
    assert_eq!(tx_block.row_count, 2, "tx row plus shared block identity");
    let mut tx_batch = PreparedBatch::new(limits);
    assert!(tx_batch.try_push(tx_block).is_ok());
    writer.commit_forward(tx_batch)?;

    let watermark = IndexWatermark { height: 0, hash };
    assert_eq!(
        writer.watermarks()?,
        bitcoin_rs_index::IndexWatermarks {
            tx_lookup: Some(watermark),
            script_history: None,
        }
    );
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 1);
    assert_eq!(store.count(ColumnFamily::Funding), 0);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 1);

    let script_index_block =
        writer.prepare_block_for(IndexCapabilities::SCRIPT_HISTORY, 0, hash, &body)?;
    assert_eq!(
        script_index_block.row_count, 2,
        "funding row plus shared block identity"
    );
    let mut script_index_batch = PreparedBatch::new(limits);
    assert!(script_index_batch.try_push(script_index_block).is_ok());
    writer.commit_forward(script_index_batch)?;

    assert_eq!(
        writer.watermarks()?,
        bitcoin_rs_index::IndexWatermarks {
            tx_lookup: Some(watermark),
            script_history: Some(watermark),
        }
    );
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 1);
    assert_eq!(store.count(ColumnFamily::Funding), 1);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 1);
    Ok(())
}

#[test]
fn aligned_capabilities_share_one_atomic_commit() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, hash, &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());

    writer.commit_forward(batch)?;

    assert_eq!(store.durable_writes.load(Ordering::Relaxed), 1);
    let watermark = IndexWatermark { height: 0, hash };
    assert_eq!(
        writer.watermarks()?,
        bitcoin_rs_index::IndexWatermarks {
            tx_lookup: Some(watermark),
            script_history: Some(watermark),
        }
    );
    Ok(())
}

#[test]
fn script_index_reset_preserves_tx_lookup_and_shared_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, hash, &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());
    writer.commit_forward(batch)?;

    writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;

    assert_eq!(
        writer.watermarks()?,
        bitcoin_rs_index::IndexWatermarks {
            tx_lookup: Some(IndexWatermark { height: 0, hash }),
            script_history: None,
        }
    );
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 1);
    assert_eq!(store.count(ColumnFamily::Funding), 0);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 1);
    assert_eq!(stored_idle_version(&store)?, 1);
    Ok(())
}

#[test]
fn rollback_preserves_shared_ancestors_for_a_disabled_capability()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body0 = read_fixture(0)?;
    let body1 = read_fixture(1)?;
    let block0 = writer.prepare_block_for(IndexCapabilities::ALL, 0, block_hash(&body0), &body0)?;
    let block1 = writer.prepare_block_for(IndexCapabilities::ALL, 1, block_hash(&body1), &body1)?;
    let watermark0 = block0.watermark();
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block0).is_ok());
    assert!(batch.try_push(block1).is_ok());
    writer.commit_forward(batch)?;

    writer.commit_rollback_one_for(IndexCapabilities::TX_LOOKUP, Some(watermark0), &body1)?;
    writer.commit_rollback_one_for(IndexCapabilities::TX_LOOKUP, None, &body0)?;
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 2);

    writer.commit_rollback_one_for(IndexCapabilities::SCRIPT_HISTORY, Some(watermark0), &body1)?;
    writer.commit_rollback_one_for(IndexCapabilities::SCRIPT_HISTORY, None, &body0)?;
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
    Ok(())
}

#[test]
fn resetting_the_only_cursor_removes_shared_identity() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());
    writer.commit_forward(batch)?;

    writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;

    assert_eq!(store.count(ColumnFamily::TxConfirmed), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
    Ok(())
}

#[test]
fn open_resumes_interrupted_capability_reset() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, hash, &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    writer.commit_forward(prepared)?;
    drop(writer);

    // A crashed fenced reset: the marker names generation 3; the next open
    // (generation 1) adopts it, finishes the deletion, and clears it.
    let mut interrupted = store.new_batch();
    interrupted.put(ColumnFamily::UtxoMeta, RESET_KEY, &fenced_marker(0b10, 3));
    interrupted.delete(ColumnFamily::UtxoMeta, &[0x00, b'S']);
    interrupted.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(interrupted)?;

    let writer = IndexWriter::open(Arc::clone(&store), 1)?;

    assert!(writer.watermarks()?.tx_lookup.is_some());
    assert!(writer.watermarks()?.script_history.is_none());
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 1);
    assert_eq!(store.count(ColumnFamily::Funding), 0);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(stored_idle_version(&store)?, 1);
    Ok(())
}

#[test]
fn reset_claim_carries_mask_epoch_and_base_version() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 7)?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, hash, &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    writer.commit_forward(prepared)?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_consumer_cursor(fence, b"before-reset")?;

    writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;

    let marker_puts: Vec<BatchLog> = store
        .logged_batches()
        .into_iter()
        .filter(|entry| entry.marker_put.is_some())
        .collect();
    assert_eq!(
        marker_puts.len(),
        2,
        "the reset writes its claim and its completion; the same-generation \
         resume must not add a redundant adoption rewrite"
    );
    assert!(marker_puts[0].durable, "the claim lands in a durable batch");
    assert_eq!(
        marker_puts[0].marker_put.as_deref(),
        Some(claim_bytes(0b10, 7, 0).as_slice()),
        "claim value is mask(1) || process_epoch(8 LE) || base_version(8 LE)"
    );
    assert_eq!(
        marker_puts[0].deletes, 2,
        "the claim atomically deletes the selected watermark and global cursor"
    );
    assert_eq!(
        marker_puts[1].marker_put.as_deref(),
        Some(idle_bytes(1).as_slice()),
        "completion CASes the exact claim to Idle(base_version + 1)"
    );
    assert_eq!(
        marker_puts[1].deletes, 0,
        "completion never deletes the state key"
    );
    assert!(writer.consumer_cursor()?.is_none());
    Ok(())
}

#[test]
fn forward_commit_is_excluded_by_a_reset_claim() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let body = read_fixture(1)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 1, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    let rows_before = store.rows(ColumnFamily::TxConfirmed);
    let (fence, _) = writer.fenced_watermarks()?;
    let mut claim = store.new_batch();
    claim.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &fenced_marker(SCRIPT_HISTORY_MASK, 9),
    );
    claim.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
    claim.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(claim)?;

    let result = writer.commit_forward_with_cursor(
        fence,
        prepared,
        ConsumerCursorUpdate::Set(b"stale-forward"),
    );

    assert!(matches!(result, Err(IndexError::ResetInProgress)));
    assert_eq!(store.rows(ColumnFamily::TxConfirmed), rows_before);
    assert_eq!(
        writer.watermarks()?.tx_lookup.map(|mark| mark.height),
        Some(0)
    );
    assert!(writer.consumer_cursor()?.is_none());
    assert_eq!(stored_idle_version(&store)?, 1);
    Ok(())
}

#[test]
fn rollback_commit_is_excluded_by_a_reset_claim() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let body = read_fixture(0)?;
    let rows_before = store.rows(ColumnFamily::TxConfirmed);
    let (fence, _) = writer.fenced_watermarks()?;
    let mut claim = store.new_batch();
    claim.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &fenced_marker(SCRIPT_HISTORY_MASK, 9),
    );
    claim.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
    claim.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(claim)?;

    let result = writer.commit_rollback_one_for_with_cursor(
        fence,
        IndexCapabilities::TX_LOOKUP,
        None,
        &body,
        ConsumerCursorUpdate::Set(b"stale-rollback"),
    );

    assert!(matches!(result, Err(IndexError::ResetInProgress)));
    assert_eq!(store.rows(ColumnFamily::TxConfirmed), rows_before);
    assert_eq!(
        writer.watermarks()?.tx_lookup.map(|mark| mark.height),
        Some(0)
    );
    assert!(writer.consumer_cursor()?.is_none());
    assert_eq!(stored_idle_version(&store)?, 1);
    Ok(())
}

#[test]
fn consumer_cursor_commit_is_excluded_by_a_reset_claim() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_consumer_cursor(fence, b"old-cursor")?;
    let mut claim = store.new_batch();
    claim.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &fenced_marker(TX_LOOKUP_MASK, 9),
    );
    claim.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
    claim.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(claim)?;

    // The claim moved the reset fence, so the captured fence is stale: the
    // write is rejected as ResetInProgress after adopting and completing the
    // pending claim, matching the forward/rollback fence-conflict path.
    let result = writer.commit_consumer_cursor(fence, b"stale-cursor");
    assert!(matches!(result, Err(IndexError::ResetInProgress)));
    assert!(writer.consumer_cursor()?.is_none());
    assert_eq!(stored_idle_version(&store)?, 1);
    Ok(())
}

#[test]
fn legacy_flush_discards_rows_rejected_by_a_reset_fence() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(MemoryStore::default());
    let mut indexer = Indexer::new(Arc::clone(&store));
    indexer.begin_batch();
    indexer.ingest_block(&read_fixture(0)?, 0)?;
    let mut claim = store.new_batch();
    claim.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &fenced_marker(TX_LOOKUP_MASK, 9),
    );
    claim.put(ColumnFamily::UtxoMeta, FORMAT_KEY, &FORMAT_VALUE);
    claim.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
    claim.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(claim)?;

    assert!(matches!(
        indexer.end_batch(),
        Err(IndexError::ResetInProgress)
    ));
    IndexWriter::open(Arc::clone(&store), 4)?;
    indexer.begin_batch();
    indexer.end_batch()?;
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
    Ok(())
}

#[test]
fn legacy_rollback_is_excluded_by_a_reset_fence() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let body = read_fixture(0)?;
    let block: Block = bitcoin_rs_primitives::deserialize(&body)?;
    let mut indexer = Indexer::new(Arc::clone(&store));
    indexer.ingest_block(&body, 0)?;
    let rows_before = store.rows(ColumnFamily::TxConfirmed);
    let mut claim = store.new_batch();
    claim.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &fenced_marker(SCRIPT_HISTORY_MASK, 9),
    );
    claim.put(ColumnFamily::UtxoMeta, FORMAT_KEY, &FORMAT_VALUE);
    claim.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
    claim.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(claim)?;

    assert!(matches!(
        indexer.rollback_block(&block, 0),
        Err(IndexError::ResetInProgress)
    ));
    assert_eq!(store.rows(ColumnFamily::TxConfirmed), rows_before);
    assert!(store.get(ColumnFamily::UtxoMeta, RESET_KEY)?.is_some());
    Ok(())
}

#[test]
fn legacy_one_byte_marker_is_adopted_durably_then_completed()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    seed_populated_store(&store, 1)?;
    // A pre-C2 binary crashed right after committing its unfenced 1-byte
    // marker and the selected watermark delete.
    let mut interrupted = store.new_batch();
    interrupted.put(ColumnFamily::UtxoMeta, RESET_KEY, &[0b10]);
    interrupted.delete(ColumnFamily::UtxoMeta, &[0x00, b'S']);
    interrupted.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(interrupted)?;
    let baseline = store.logged_batches().len();
    let tx_rows_before = store.rows(ColumnFamily::TxConfirmed);

    let writer = IndexWriter::open(Arc::clone(&store), 7)?;

    let logs = store.logged_batches();
    let post = &logs[baseline..];
    // Cooperative same-mask adoption writes no claim of its own: the only
    // marker PUT is the durable completion, CASed from the crashed writer's
    // exact raw 1-byte claim.
    let markers: Vec<BatchLog> = post
        .iter()
        .filter(|entry| entry.marker_put.is_some())
        .cloned()
        .collect();
    assert_eq!(markers.len(), 1, "no adoption rewrite: {markers:?}");
    assert!(markers[0].durable, "the completion is durable");
    assert_eq!(
        markers[0].marker_put.as_deref(),
        Some(idle_bytes(1).as_slice())
    );

    assert!(writer.watermarks()?.tx_lookup.is_some());
    assert!(writer.watermarks()?.script_history.is_none());
    assert_eq!(store.count(ColumnFamily::Funding), 0);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(
        store.count(ColumnFamily::BlockHeaders),
        1,
        "the unselected cursor keeps the shared identity rows"
    );
    assert_eq!(
        store.rows(ColumnFamily::TxConfirmed),
        tx_rows_before,
        "sibling rows are byte-identical across the adopted reset"
    );
    assert_eq!(stored_idle_version(&store)?, 1);
    assert_state_revision(&store, Some(2))?;
    Ok(())
}

/// Both stores hold one populated block of rows for every capability.
fn seed_populated_stores()
-> Result<(Arc<MemoryStore>, Arc<MemoryStore>), Box<dyn std::error::Error>> {
    let control = Arc::new(MemoryStore::default());
    let interrupted = Arc::new(MemoryStore::default());
    for store in [&control, &interrupted] {
        seed_populated_store(store, 1)?;
    }
    Ok((control, interrupted))
}

fn seed_populated_store(
    store: &Arc<impl KvStore<WriteBatch = MemoryBatch>>,
    generation: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = IndexWriter::open(Arc::clone(store), generation)?;
    let body = read_fixture(0)?;
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    writer.commit_forward(prepared)?;
    Ok(())
}

/// Crash state right after the fenced marker commit: rows intact, selected
/// watermark already gone.
fn crash_after_marker_commit(store: &MemoryStore) -> Result<(), Box<dyn std::error::Error>> {
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::UtxoMeta, RESET_KEY, &fenced_marker(0b10, 3));
    batch.delete(ColumnFamily::UtxoMeta, &[0x00, b'S']);
    batch.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(batch)?;
    Ok(())
}

/// Every column family's full byte state, marker included.
fn dump_all(store: &MemoryStore) -> Vec<(ColumnFamily, Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::new();
    for &cf in ColumnFamily::ALL {
        rows.extend(
            store
                .rows(cf)
                .into_iter()
                .map(|(key, value)| (cf, key, value)),
        );
    }
    rows
}

#[test]
fn interrupted_reset_resumes_after_marker_commit() -> Result<(), Box<dyn std::error::Error>> {
    let (control, interrupted) = seed_populated_stores()?;
    crash_after_marker_commit(&interrupted)?;

    let control_writer = IndexWriter::open(Arc::clone(&control), 1)?;
    control_writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;
    drop(control_writer);
    IndexWriter::open(Arc::clone(&interrupted), 4)?;

    assert_eq!(
        dump_all(&control),
        dump_all(&interrupted),
        "resume after a marker-commit crash converges byte-identically"
    );
    Ok(())
}

#[test]
fn interrupted_reset_resumes_mid_delete() -> Result<(), Box<dyn std::error::Error>> {
    let (control, interrupted) = seed_populated_stores()?;
    crash_after_marker_commit(&interrupted)?;
    // Crash mid-delete: half the masked Funding rows are already gone.
    let funding_rows = interrupted.rows(ColumnFamily::Funding);
    let mut partial = interrupted.new_batch();
    for (key, _) in funding_rows.into_iter().take(2) {
        partial.delete(ColumnFamily::Funding, &key);
    }
    interrupted.write_durable(partial)?;

    let control_writer = IndexWriter::open(Arc::clone(&control), 1)?;
    control_writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;
    drop(control_writer);
    IndexWriter::open(Arc::clone(&interrupted), 4)?;

    assert_eq!(
        dump_all(&control),
        dump_all(&interrupted),
        "resume mid-delete converges byte-identically"
    );
    Ok(())
}

#[test]
fn interrupted_reset_resumes_after_delete_before_clear() -> Result<(), Box<dyn std::error::Error>> {
    let (control, interrupted) = seed_populated_stores()?;
    crash_after_marker_commit(&interrupted)?;

    // Crash after the deletion loops but before the marker clear.
    for cf in [ColumnFamily::Funding, ColumnFamily::Spending] {
        let mut batch = interrupted.new_batch();
        for (key, _) in interrupted.rows(cf) {
            batch.delete(cf, &key);
        }
        interrupted.write_durable(batch)?;
    }

    let control_writer = IndexWriter::open(Arc::clone(&control), 1)?;
    control_writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;
    drop(control_writer);
    IndexWriter::open(Arc::clone(&interrupted), 4)?;

    assert_eq!(
        dump_all(&control),
        dump_all(&interrupted),
        "resume after delete converges byte-identically"
    );
    Ok(())
}

/// Capability-mask bits, mirroring `IndexCapabilities::to_mask`.
const TX_LOOKUP_MASK: u8 = 0b01;
const SCRIPT_HISTORY_MASK: u8 = 0b10;
const TX_WATERMARK_KEY: &[u8] = &[0x00, b'T'];
const SCRIPT_WATERMARK_KEY: &[u8] = &[0x00, b'S'];
const CURSOR_KEY: &[u8] = &[0x00, b'C'];
const FORMAT_KEY: &[u8] = &[0x00, b'V'];
const FORMAT_VALUE: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

/// One complete competing capability-reset claim: exactly what a correct
/// concurrent writer commits. Injection points run these claims wholesale;
/// never a blind marker write.
#[derive(Clone, Copy, Debug)]
struct CompetingClaim {
    generation: u64,
    requested_mask: u8,
}

/// Deterministically interleaves complete competing claims with reset writes.
///
/// The delete hook also fires for an unconditional write, which makes a
/// regression from exact-claim conditional deletion observable without sleeps.
struct ForeignFenceStore {
    inner: MemoryStore,
    on_claim: Mutex<Option<CompetingClaim>>,
    on_delete: Mutex<Option<CompetingClaim>>,
    on_clear: Mutex<Option<CompetingClaim>>,
    unconditional_delete_after_claim_change: AtomicBool,
}

impl ForeignFenceStore {
    fn count(&self, cf: ColumnFamily) -> usize {
        self.inner.count(cf)
    }

    fn run_competing_claim(&self, claim: CompetingClaim) -> Result<bool, StorageError> {
        let observed = self.inner.get(ColumnFamily::UtxoMeta, RESET_KEY)?;
        let (current_mask, base_version) = match observed.as_deref() {
            None => (0, 0),
            Some(bytes) if is_idle_marker(bytes) => (
                0,
                decode_u64_le(bytes, 1).ok_or_else(|| {
                    StorageError::IncompatibleData("idle marker truncated".into())
                })?,
            ),
            Some(bytes) => {
                let base = if bytes.len() == claim_bytes(0, 0, 0).len() {
                    decode_u64_le(bytes, 9).ok_or_else(|| {
                        StorageError::IncompatibleData("claim marker truncated".into())
                    })?
                } else {
                    0
                };
                (bytes[0], base)
            }
        };
        let mask = current_mask | claim.requested_mask;
        let published_claim = claim_bytes(mask, claim.generation, base_version);
        let condition = match observed.as_deref() {
            Some(expected) => WriteCondition::Equals {
                cf: ColumnFamily::UtxoMeta,
                key: RESET_KEY,
                expected,
            },
            None => WriteCondition::Absent {
                cf: ColumnFamily::UtxoMeta,
                key: RESET_KEY,
            },
        };
        let mut batch = self.inner.new_batch();
        batch.put(ColumnFamily::UtxoMeta, RESET_KEY, &published_claim);
        batch.put(ColumnFamily::UtxoMeta, FORMAT_KEY, &FORMAT_VALUE);
        if mask & TX_LOOKUP_MASK != 0 {
            batch.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
        }
        if mask & SCRIPT_HISTORY_MASK != 0 {
            batch.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
        }
        batch.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
        self.inner
            .write_durable_if(std::slice::from_ref(&condition), batch)
    }

    fn take_injection(&self, batch: &MemoryBatch) -> Option<CompetingClaim> {
        // Completion is now a marker PUT of an idle value, never a delete:
        // classify reset-key puts by shape, then keep the derived-row delete
        // hook for claim-change regressions.
        if let Some(value) = batch.put_value(ColumnFamily::UtxoMeta, RESET_KEY) {
            return if is_idle_marker(&value) {
                self.on_clear.lock().take()
            } else {
                self.on_claim.lock().take()
            };
        }
        if batch.deletes_derived_rows() {
            return self.on_delete.lock().take();
        }
        None
    }
}

impl KvStore for ForeignFenceStore {
    type WriteBatch = MemoryBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(cf, key)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.inner.iter_prefix(cf, prefix)
    }

    fn new_batch(&self) -> Self::WriteBatch {
        self.inner.new_batch()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        if let Some(claim) = self.take_injection(&batch) {
            self.run_competing_claim(claim)?;
            self.unconditional_delete_after_claim_change
                .store(true, Ordering::Release);
        }
        self.inner.write(batch)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        if let Some(claim) = self.take_injection(&batch) {
            self.run_competing_claim(claim)?;
        }
        self.inner.write_durable_if(conditions, batch)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.inner.flush()
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        self.inner.snapshot()
    }
}

#[test]
fn clear_loss_restarts_and_completes_the_merged_fence() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(ForeignFenceStore {
        inner: MemoryStore::default(),
        on_claim: Mutex::new(None),
        on_delete: Mutex::new(None),
        on_clear: Mutex::new(Some(CompetingClaim {
            generation: 9,
            requested_mask: SCRIPT_HISTORY_MASK,
        })),
        unconditional_delete_after_claim_change: AtomicBool::new(false),
    });
    seed_populated_store(&store, 1)?;
    let mut crashed = store.inner.new_batch();
    crashed.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &fenced_marker(TX_LOOKUP_MASK, 3),
    );
    crashed.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
    crashed.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.inner.write_durable(crashed)?;

    let writer = IndexWriter::open(Arc::clone(&store), 4)?;

    assert_eq!(stored_idle_version(&store)?, 1);
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 0);
    assert_eq!(store.count(ColumnFamily::Funding), 0);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
    assert_eq!(writer.watermarks()?.tx_lookup, None);
    assert_eq!(writer.watermarks()?.script_history, None);
    Ok(())
}

#[test]
fn changed_claim_prevents_stale_row_deletion() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(ForeignFenceStore {
        inner: MemoryStore::default(),
        on_claim: Mutex::new(None),
        on_delete: Mutex::new(Some(CompetingClaim {
            generation: 9,
            requested_mask: SCRIPT_HISTORY_MASK,
        })),
        on_clear: Mutex::new(None),
        unconditional_delete_after_claim_change: AtomicBool::new(false),
    });
    seed_populated_store(&store, 1)?;
    let mut crashed = store.inner.new_batch();
    crashed.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &fenced_marker(TX_LOOKUP_MASK, 4),
    );
    crashed.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
    crashed.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.inner.write_durable(crashed)?;

    IndexWriter::open(Arc::clone(&store), 4)?;

    assert!(
        !store
            .unconditional_delete_after_claim_change
            .load(Ordering::Acquire),
        "a stale reset operation deleted rows after the exact claim changed"
    );
    assert_eq!(stored_idle_version(&store)?, 1);
    for cf in [
        ColumnFamily::TxConfirmed,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
        ColumnFamily::BlockHeaders,
    ] {
        assert_eq!(store.count(cf), 0, "{cf:?} reset did not complete");
    }
    Ok(())
}

#[test]
fn competing_claim_during_claim_merges_different_masks() -> Result<(), Box<dyn std::error::Error>> {
    // Generation 4 claims TX_LOOKUP while generation 9 races a full
    // SCRIPT_HISTORY claim into the same conditional-write window. The
    // losing Absent claim must retry from fresh state, adopt the union
    // mask, and clear the union of watermarks — no sleeps, no lost claim.
    let store = Arc::new(ForeignFenceStore {
        inner: MemoryStore::default(),
        on_claim: Mutex::new(Some(CompetingClaim {
            generation: 9,
            requested_mask: SCRIPT_HISTORY_MASK,
        })),
        on_delete: Mutex::new(None),
        on_clear: Mutex::new(None),
        unconditional_delete_after_claim_change: AtomicBool::new(false),
    });
    seed_populated_store(&store, 1)?;

    let writer = IndexWriter::open(Arc::clone(&store), 4)?;
    writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;

    assert!(
        stored_idle_version(&store)? == 1,
        "the retried union claim owns and completes its fence"
    );
    assert!(
        store
            .get(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY)?
            .is_none()
    );
    assert!(
        store
            .get(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY)?
            .is_none()
    );
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 0);
    assert_eq!(
        store.count(ColumnFamily::Funding),
        0,
        "the raced-in capability joins the union and is cleared too"
    );
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
    Ok(())
}

#[test]
fn reset_index_adopts_a_foreign_fence_as_an_all_capability_reset()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut foreign = store.new_batch();
    foreign.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &fenced_marker(SCRIPT_HISTORY_MASK, 9),
    );
    foreign.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
    foreign.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(foreign)?;

    IndexWriter::reset_index(store.as_ref(), 4)?;

    let writer = IndexWriter::open(Arc::clone(&store), 4)?;
    assert_eq!(stored_idle_version(&store)?, 1);
    assert_eq!(writer.watermarks()?.tx_lookup, None);
    assert_eq!(writer.watermarks()?.script_history, None);
    assert!(writer.consumer_cursor()?.is_none());
    for cf in [
        ColumnFamily::TxConfirmed,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
        ColumnFamily::BlockHeaders,
    ] {
        assert_eq!(store.count(cf), 0, "{cf:?} survived the full reset");
    }
    Ok(())
}

#[test]
fn format_stays_current_after_reset_and_rebuild() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;

    let writer = IndexWriter::open(Arc::clone(&store), 1)?;
    writer.reset_capabilities(IndexCapabilities::ALL)?;
    drop(writer);

    // The emptied index claims the current row format before rebuilding.
    let indexer = Indexer::new(Arc::clone(&store));
    assert_eq!(indexer.ensure_format_version()?, IndexFormat::Current);
    drop(indexer);

    seed_populated_store(&store, 1)?;

    let indexer = Indexer::new(Arc::clone(&store));
    assert_eq!(indexer.ensure_format_version()?, IndexFormat::Current);
    assert_eq!(
        store
            .get(ColumnFamily::UtxoMeta, b"index:format_version")?
            .as_deref(),
        Some(2u32.to_le_bytes().as_slice()),
        "the row-format marker survives reset and rebuild"
    );
    assert!(
        store
            .rows(ColumnFamily::Funding)
            .into_iter()
            .any(|(_, value)| !value.is_empty()),
        "rebuilt rows carry transaction byte positions"
    );
    Ok(())
}

#[test]
fn batch_caps_admit_oversized_first_block() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body0 = read_fixture(0)?;
    let body1 = read_fixture(1)?;

    // Exact boundary: one block of three rows fits, a second does not.
    let block0 = writer.prepare_block(0, block_hash(&body0), &body0)?;
    let block1 = writer.prepare_block(1, block_hash(&body1), &body1)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 3,
        max_bytes: usize::MAX,
    });
    assert!(batch.try_push(block0).is_ok());
    assert!(batch.try_push(block1).is_err());
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.row_count(), 3);
    assert!(batch.is_full());
    assert_eq!(
        batch.watermark(),
        Some(IndexWatermark {
            height: 0,
            hash: block_hash(&body0),
        })
    );

    // Oversized first block: empty batch accepts it, then refuses another.
    let block0 = writer.prepare_block(0, block_hash(&body0), &body0)?;
    let block1 = writer.prepare_block(1, block_hash(&body1), &body1)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 0,
        max_bytes: 0,
    });
    assert!(batch.try_push(block0).is_ok());
    assert!(batch.try_push(block1).is_err());
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.encoded_bytes(), 120);
    assert!(batch.is_full());
    assert_eq!(
        batch.watermark(),
        Some(IndexWatermark {
            height: 0,
            hash: block_hash(&body0),
        })
    );

    Ok(())
}

#[test]
fn format_version_requires_exact_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    // Extra trailing byte must be rejected even though the prefix is version 4.
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[4, 0, 0, 0, 0],
    )?;
    assert!(matches!(
        IndexWriter::open(store, 1),
        Err(IndexError::UnsupportedTxIndexFormatVersion { version: 4 })
    ));
    Ok(())
}

#[test]
fn commit_forward_accepts_terminal_height() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let current = IndexWatermark {
        height: u32::MAX - 1,
        hash: [0; 32],
    };
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[4, 0, 0, 0],
    )?;
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'T'],
        &current.to_bytes(),
    )?;

    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let expected_hash = block_hash(&body);
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, u32::MAX, expected_hash, &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());

    let watermark = writer.commit_forward(batch)?;
    assert_eq!(
        watermark,
        IndexWatermark {
            height: u32::MAX,
            hash: expected_hash,
        }
    );
    Ok(())
}

#[test]
fn commit_forward_rejects_height_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let overflow = IndexWatermark {
        height: u32::MAX,
        hash: [0xab; 32],
    };
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[4, 0, 0, 0],
    )?;
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'T'],
        &overflow.to_bytes(),
    )?;

    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());
    assert!(matches!(
        writer.commit_forward(batch),
        Err(IndexError::NonContiguousPrepared { watermark })
            if watermark == Some(overflow)
    ));
    Ok(())
}

#[test]
fn rollback_rejects_prev_at_genesis() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let block = writer.prepare_block(0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());
    writer.commit_forward(batch)?;

    assert!(matches!(
        writer.commit_rollback_one(
            Some(IndexWatermark {
                height: 0,
                hash: [0u8; 32]
            }),
            &body
        ),
        Err(IndexError::NonContiguousPrepared { .. })
    ));
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn redb_snapshot_preserves_position_values() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let store = Arc::new(bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?);
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let body = read_fixture(0)?;
    let block = Block::consensus_decode(&body)?;
    let txid = block.txs[0].txid();
    let scripthash = ScriptHash::new(&block.txs[0].outputs[0].script_pubkey);
    let prepared = writer.prepare_block(0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(prepared).is_ok());
    writer.commit_forward(batch)?;

    let snapshot = writer.snapshot()?;
    let limit = PrefixScanLimit {
        max_rows: 10,
        max_bytes: 1_024,
    };
    let transaction_rows = snapshot.transaction_rows(&txid, limit)?;
    let funding_rows = snapshot.funding_rows(scripthash, limit)?;

    assert_eq!(transaction_rows.rows.len(), 1);
    assert_eq!(funding_rows.rows.len(), 1);
    assert_eq!(transaction_rows.rows[0].value, funding_rows.rows[0].value);
    assert_eq!(
        TxPositionValue::decode(&transaction_rows.rows[0].value).map(<[TxPosition]>::len),
        Some(1)
    );
    Ok(())
}

/// Writes a complete competing full-capability claim, exactly as a correct
/// concurrent reset publication commits it.
fn inject_full_claim(
    store: &MemoryStore,
    process_epoch: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut claim = store.new_batch();
    claim.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &claim_bytes(TX_LOOKUP_MASK | SCRIPT_HISTORY_MASK, process_epoch, 0),
    );
    claim.put(ColumnFamily::UtxoMeta, FORMAT_KEY, &FORMAT_VALUE);
    claim.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
    claim.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
    claim.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(claim)?;
    Ok(())
}

#[test]
fn full_reset_between_derive_and_commit_rejects_forward() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;
    let body = read_fixture(1)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 1, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());

    inject_full_claim(&store, 9)?;

    let result = writer.commit_forward_with_cursor(fence, prepared, ConsumerCursorUpdate::Keep);
    assert!(matches!(result, Err(IndexError::ResetInProgress)));
    // The stale forward never landed: the adoption cleared the state and the
    // block-1 watermark it would have written is absent.
    assert_eq!(writer.watermarks()?, IndexWatermarks::default());
    assert_eq!(stored_idle_version(&store)?, 1);
    Ok(())
}

#[test]
fn full_reset_between_derive_and_commit_rejects_rollback() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;
    let body = read_fixture(0)?;

    inject_full_claim(&store, 9)?;

    let result = writer.commit_rollback_one_for_with_cursor(
        fence,
        IndexCapabilities::TX_LOOKUP,
        None,
        &body,
        ConsumerCursorUpdate::Keep,
    );
    assert!(matches!(result, Err(IndexError::ResetInProgress)));
    assert_eq!(writer.watermarks()?, IndexWatermarks::default());
    assert_eq!(stored_idle_version(&store)?, 1);
    Ok(())
}

#[test]
fn full_reset_between_derive_and_commit_skips_stale_cursor()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;
    let body = read_fixture(1)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 1, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());

    inject_full_claim(&store, 9)?;

    let result = writer.commit_forward_with_cursor(
        fence,
        prepared,
        ConsumerCursorUpdate::Set(b"stale-cursor"),
    );
    assert!(matches!(result, Err(IndexError::ResetInProgress)));
    assert!(
        writer.consumer_cursor()?.is_none(),
        "stale cursor bytes are skipped, never published past a reset"
    );
    assert_eq!(stored_idle_version(&store)?, 1);
    Ok(())
}

#[test]
fn double_reset_same_generation_still_rejects_stale_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    writer.reset_capabilities(IndexCapabilities::ALL)?;
    let (stale_fence, _) = writer.fenced_watermarks()?;
    writer.reset_capabilities(IndexCapabilities::ALL)?;
    assert_eq!(stored_idle_version(&store)?, 2);

    // The batch is valid against the post-reset state, so only the stale
    // fence stands between it and the store: an Absent-style check would
    // accept it (state exists but moved), the versioned fence must not.
    let body = read_fixture(0)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 0, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    let result =
        writer.commit_forward_with_cursor(stale_fence, prepared, ConsumerCursorUpdate::Keep);
    assert!(matches!(result, Err(IndexError::ResetInProgress)));
    assert_eq!(writer.watermarks()?, IndexWatermarks::default());

    // A freshly captured fence commits normally: rejection is versioned, not
    // a permanent lockout.
    let body = read_fixture(0)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 0, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    let (fresh_fence, _) = writer.fenced_watermarks()?;
    writer.commit_forward_with_cursor(fresh_fence, prepared, ConsumerCursorUpdate::Keep)?;
    assert_eq!(writer.watermark()?.map(|mark| mark.height), Some(0));
    assert_eq!(stored_idle_version(&store)?, 2);
    Ok(())
}

#[test]
fn intermediate_rollback_deletes_cursor_and_survives_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;
    let body0 = read_fixture(0)?;
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, block_hash(&body0), &body0)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    writer.commit_forward_with_cursor(
        fence,
        prepared,
        ConsumerCursorUpdate::Set(b"cursor-at-0"),
    )?;
    assert_eq!(
        writer.consumer_cursor()?.as_deref(),
        Some(b"cursor-at-0".as_slice())
    );

    // Rollback without a valid replacement clears the cursor atomically with
    // the row mutation.
    writer.commit_rollback_one(None, &body0)?;
    assert!(writer.consumer_cursor()?.is_none());

    drop(writer);
    let reopened = IndexWriter::open(Arc::clone(&store), 4)?;
    assert!(reopened.consumer_cursor()?.is_none(), "cursor stays gone");
    assert!(reopened.watermark()?.is_none());
    assert!(store.get(ColumnFamily::UtxoMeta, RESET_KEY)?.is_none());
    Ok(())
}

#[test]
fn intermediate_rollback_removes_stale_cursor() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_consumer_cursor(fence, b"cursor-at-0")?;

    let body0 = read_fixture(0)?;
    writer.commit_rollback_one_for(IndexCapabilities::TX_LOOKUP, None, &body0)?;
    assert!(writer.consumer_cursor()?.is_none());

    // A later forward that keeps the cursor must not resurrect it.
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 0, block_hash(&body0), &body0)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_forward_with_cursor(fence, prepared, ConsumerCursorUpdate::Keep)?;
    assert_eq!(writer.watermark()?.map(|mark| mark.height), Some(0));
    assert!(
        writer.consumer_cursor()?.is_none(),
        "Keep preserves the rollback's deletion"
    );
    Ok(())
}

#[test]
fn stale_cursor_publish_is_rejected_when_watermarks_lag() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (stale_fence, _) = writer.fenced_watermarks()?;

    let body1 = read_fixture(1)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 1, block_hash(&body1), &body1)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_forward_with_cursor(fence, prepared, ConsumerCursorUpdate::Keep)?;

    // The durable watermark moved after the stale fence was captured, so the
    // cursor publish is rejected as stale state, never silently skipped.
    let result = writer.commit_consumer_cursor(stale_fence, b"lagging");
    assert!(
        matches!(result, Err(IndexError::StaleIndexState)),
        "a lagging watermark must reject the cursor publish: {result:?}"
    );
    assert!(writer.consumer_cursor()?.is_none());

    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_consumer_cursor(fence, b"current")?;
    assert_eq!(
        writer.consumer_cursor()?.as_deref(),
        Some(b"current".as_slice())
    );
    Ok(())
}

#[test]
fn cursor_publish_rejects_atomic_watermark_race() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;
    let raced = IndexWatermark {
        height: 1,
        hash: [0x42; 32],
    };
    *store.cursor_race_tx_watermark.lock() = Some(raced);

    let result = writer.commit_consumer_cursor(fence, b"stale");
    assert!(
        matches!(result, Err(IndexError::StaleIndexState)),
        "a watermark race must reject the cursor publish as stale state: {result:?}"
    );
    assert!(writer.consumer_cursor()?.is_none());
    assert_eq!(writer.watermarks()?.tx_lookup, Some(raced));
    Ok(())
}

#[test]
fn cursor_publish_rejects_absent_tx_watermark_race() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    seed_populated_store(&store, 1)?;

    // Remove the tx watermark so the caller expects Absent at the commit
    // boundary.
    let mut del = store.new_batch();
    del.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
    store.write_durable(del)?;

    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;

    let raced = IndexWatermark {
        height: 1,
        hash: [0x42; 32],
    };
    *store.cursor_race_tx_watermark.lock() = Some(raced);

    let result = writer.commit_consumer_cursor(fence, b"stale");
    assert!(
        matches!(result, Err(IndexError::StaleIndexState)),
        "an absent-watermark race must reject the cursor publish: {result:?}"
    );
    assert!(writer.consumer_cursor()?.is_none());
    assert_eq!(writer.watermarks()?.tx_lookup, Some(raced));
    Ok(())
}

#[test]
fn cursor_publish_rejects_script_watermark_race() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;

    let raced = IndexWatermark {
        height: 1,
        hash: [0x99; 32],
    };
    *store.cursor_race_script_watermark.lock() = Some(raced);

    let result = writer.commit_consumer_cursor(fence, b"stale");
    assert!(
        matches!(result, Err(IndexError::StaleIndexState)),
        "a script-watermark race must reject the cursor publish: {result:?}"
    );
    assert!(writer.consumer_cursor()?.is_none());
    assert_eq!(writer.watermarks()?.script_history, Some(raced));
    Ok(())
}

#[test]
fn oversized_first_row_does_not_escape_reset() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    // A derived row far larger than the reset scan's whole byte budget: a
    // backend that dropped it instead of admitting it as the first row would
    // leave it behind after the reset completed.
    let oversized: Vec<u8> = vec![0xAB; 300 * 1024];
    store.put(ColumnFamily::Funding, &[0x00, 0x00], &oversized)?;

    IndexWriter::reset_index(store.as_ref(), 4)?;

    assert_eq!(store.count(ColumnFamily::Funding), 0);
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 0);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
    assert_eq!(stored_idle_version(&store)?, 1);
    Ok(())
}

fn populated_idle_tracking_store() -> Result<Arc<CallTrackingStore>, Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    seed_populated_store(&store, 1)?;

    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    writer.reset_capabilities(IndexCapabilities::ALL)?;
    let body = read_fixture(0)?;
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    writer.commit_forward(prepared)?;
    assert_eq!(stored_idle_version(&store)?, 1);

    Ok(store)
}

/// Decodes the durable ordinary-state revision. Absence is logical revision
/// zero but stays byte-distinct from an encoded zero.
fn stored_state_revision(
    store: &CallTrackingStore,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    match store
        .inner
        .get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?
    {
        None => Ok(None),
        Some(bytes) => {
            let raw: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
                std::io::Error::other(format!(
                    "ordinary-state revision is not one little-endian u64: {bytes:?}"
                ))
            })?;
            Ok(Some(u64::from_le_bytes(raw)))
        }
    }
}

/// Asserts the exact durable revision bytes: `None` (absent) and `Some(0)`
/// (encoded zero) are distinct states, and any present value must be exactly
/// one little-endian `u64`.
fn assert_state_revision(
    store: &CallTrackingStore,
    expected: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = store
        .inner
        .get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?;
    let encoded = match (&expected, raw.as_deref()) {
        (None, None) => true,
        (Some(value), Some(bytes)) => bytes == value.to_le_bytes(),
        _ => false,
    };
    assert!(
        encoded,
        "ordinary-state revision {raw:?} does not encode {expected:?}"
    );
    Ok(())
}

/// Corrupts the durable tx watermark and arms a reset that completes the
/// moment the capture snapshot reads it: the read still returns the captured
/// malformed bytes while the live store moves underneath the capture.
fn arm_reset_after_malformed_watermark_read(store: &CallTrackingStore) -> Result<(), StorageError> {
    let mut batch = store.inner.new_batch();
    batch.put(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY, b"malformed");
    store.inner.write(batch)?;
    *store.snapshot_reset_after_tx_watermark_read.lock() = Some((2, 4));
    Ok(())
}

#[test]
fn rollback_commit_rejects_reset_during_header_read() -> Result<(), Box<dyn std::error::Error>> {
    let store = populated_idle_tracking_store()?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;
    let body = read_fixture(0)?;

    *store.fence_reset_during_header_read.lock() = Some((2, 4));
    let result = writer.commit_rollback_one_for_with_cursor(
        fence,
        IndexCapabilities::TX_LOOKUP,
        None,
        &body,
        ConsumerCursorUpdate::Clear,
    );

    assert!(
        matches!(result, Err(IndexError::ResetInProgress)),
        "rollback commit misclassified a reset during header validation: {result:?}"
    );
    assert_eq!(stored_idle_version(&store)?, 2);
    assert_eq!(writer.watermarks()?, IndexWatermarks::default());
    Ok(())
}

#[test]
fn fenced_watermarks_prefers_reset_over_watermark_decode_error()
-> Result<(), Box<dyn std::error::Error>> {
    let store = populated_idle_tracking_store()?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    arm_reset_after_malformed_watermark_read(&store)?;

    let result = writer.fenced_watermarks();

    assert!(
        matches!(result, Err(IndexError::ResetInProgress)),
        "fenced watermark read exposed stale corruption after reset: {result:?}"
    );
    Ok(())
}

#[test]
fn fenced_watermarks_captures_one_coherent_snapshot_across_four_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let store = populated_idle_tracking_store()?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    store.read_order.lock().clear();
    store.snapshot_read_order.lock().clear();
    let snapshots_before = store.snapshots.load(Ordering::Relaxed);

    let (_fence, watermarks) = writer.fenced_watermarks()?;

    assert!(watermarks.tx_lookup.is_some());
    assert!(watermarks.script_history.is_some());
    assert_eq!(
        store.snapshots.load(Ordering::Relaxed),
        snapshots_before + 1,
        "one successful fence capture must use one storage snapshot"
    );
    let captures = store.snapshot_read_order.lock().clone();
    assert_eq!(
        captures.len(),
        4,
        "one capture reads each fenced key exactly once: {captures:?}"
    );
    let mut captured_keys: Vec<&[u8]> = captures.iter().map(|(_cf, key)| key.as_slice()).collect();
    captured_keys.sort_unstable();
    let mut expected_keys = [
        RESET_KEY,
        ORDINARY_STATE_REVISION_KEY,
        TX_WATERMARK_KEY,
        SCRIPT_WATERMARK_KEY,
    ];
    expected_keys.sort_unstable();
    assert_eq!(captured_keys, expected_keys);
    let live = store.read_order.lock().clone();
    assert!(
        live.iter().all(|(cf, key)| !(*cf == ColumnFamily::UtxoMeta
            && (key.as_slice() == TX_WATERMARK_KEY || key.as_slice() == SCRIPT_WATERMARK_KEY))),
        "watermark state was read outside the capture snapshot: {live:?}"
    );

    // The next reset completes while the snapshot returns its frozen
    // pre-reset watermark. The live-reset recheck rejects that capture.
    *store.snapshot_reset_after_tx_watermark_read.lock() = Some((2, 4));
    let result = writer.fenced_watermarks();
    assert!(
        matches!(result, Err(IndexError::ResetInProgress)),
        "a capture spanning a concurrent reset discards derived state: {result:?}"
    );

    assert_eq!(stored_idle_version(&store)?, 2);
    let (fence, watermarks) = writer.fenced_watermarks()?;
    assert_eq!(watermarks, IndexWatermarks::default());
    let body = read_fixture(0)?;
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    writer.commit_forward_with_cursor(fence, prepared, ConsumerCursorUpdate::Keep)?;
    assert_eq!(writer.watermark()?.map(|mark| mark.height), Some(0));
    Ok(())
}

#[test]
fn unchanged_reset_surfaces_malformed_watermark_decode() -> Result<(), Box<dyn std::error::Error>> {
    let store = populated_idle_tracking_store()?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let mut batch = store.inner.new_batch();
    batch.put(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY, b"malformed");
    store.inner.write(batch)?;

    let result = writer.fenced_watermarks();

    assert!(
        matches!(result, Err(IndexError::InvalidWatermark)),
        "with the reset unchanged, the corruption itself surfaces: {result:?}"
    );
    // The decode failure moved no state.
    assert_eq!(stored_idle_version(&store)?, 1);
    assert_state_revision(&store, Some(3))?;
    Ok(())
}

#[test]
fn reset_change_takes_precedence_over_stale_reset_parse_error()
-> Result<(), Box<dyn std::error::Error>> {
    let store = populated_idle_tracking_store()?;
    let writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let mut malformed = store.inner.new_batch();
    malformed.put(ColumnFamily::UtxoMeta, RESET_KEY, b"malformed");
    store.inner.write(malformed)?;
    *store.snapshot_reset_after_revision_read.lock() = Some((2, 4));

    let result = writer.reset_capabilities(IndexCapabilities::TX_LOOKUP);

    assert!(
        matches!(result, Err(IndexError::ResetInProgress)),
        "a moved reset must supersede the stale parse error: {result:?}"
    );
    assert_eq!(stored_idle_version(&store)?, 2);
    assert_state_revision(&store, Some(4))?;
    Ok(())
}

#[test]
fn cursor_only_contention_rejects_stale_revision() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_consumer_cursor(fence, b"first")?;
    assert_state_revision(&store, Some(2))?;

    // Reset state and watermarks are untouched; only the revision moved.
    let result = writer.commit_consumer_cursor(fence, b"second");
    assert!(
        matches!(result, Err(IndexError::StaleIndexState)),
        "cursor-only contention must reject as stale state: {result:?}"
    );
    assert_eq!(
        writer.consumer_cursor()?.as_deref(),
        Some(b"first".as_slice())
    );
    assert_state_revision(&store, Some(2))?;

    let (fresh_fence, _) = writer.fenced_watermarks()?;
    writer.commit_consumer_cursor(fresh_fence, b"third")?;
    assert_eq!(
        writer.consumer_cursor()?.as_deref(),
        Some(b"third".as_slice())
    );
    assert_state_revision(&store, Some(3))?;
    Ok(())
}

#[test]
fn each_ordinary_mutator_advances_the_revision_exactly_once()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    assert_state_revision(&store, None)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;

    // 1. forward
    let body0 = read_fixture(0)?;
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, block_hash(&body0), &body0)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    writer.commit_forward(prepared)?;
    assert_state_revision(&store, Some(1))?;

    // 2. explicit consumer cursor commit
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_consumer_cursor(fence, b"cursor-1")?;
    assert_state_revision(&store, Some(2))?;

    // 3. selective rollback with a cursor disposition
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_rollback_one_for_with_cursor(
        fence,
        IndexCapabilities::TX_LOOKUP,
        None,
        &body0,
        ConsumerCursorUpdate::Clear,
    )?;
    assert_state_revision(&store, Some(3))?;

    // 4. legacy batched ingest flush
    let mut indexer = Indexer::new(Arc::clone(&store));
    indexer.begin_batch();
    indexer.ingest_block(&body0, 0)?;
    indexer.end_batch()?;
    assert_state_revision(&store, Some(4))?;

    // 5. legacy rollback
    let block: Block = bitcoin_rs_primitives::deserialize(&body0)?;
    indexer.rollback_block(&block, 0)?;
    assert_state_revision(&store, Some(5))?;
    assert_eq!(
        stored_state_revision(&store)?,
        Some(5),
        "decode helper agrees with the raw-byte assert"
    );
    Ok(())
}

#[test]
fn ordinary_revision_overflow_rejects_forward_without_destroying_state()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut near_ceiling = store.new_batch();
    near_ceiling.put(
        ColumnFamily::UtxoMeta,
        ORDINARY_STATE_REVISION_KEY,
        &(u64::MAX - 1).to_le_bytes(),
    );
    store.write_durable(near_ceiling)?;

    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_consumer_cursor(fence, b"at-ceiling")?;
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?,
        Some(u64::MAX.to_le_bytes().to_vec())
    );

    let body = read_fixture(1)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 1, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    let (fence, _) = writer.fenced_watermarks()?;
    let before = dump_all(store.as_ref());

    let result = writer.commit_forward_with_cursor(fence, prepared, ConsumerCursorUpdate::Keep);
    assert!(
        matches!(result, Err(IndexError::StateRevisionOverflow)),
        "a full revision must refuse the next ordinary mutation: {result:?}"
    );
    assert_eq!(
        dump_all(store.as_ref()),
        before,
        "revision overflow must not mutate any row or metadata"
    );
    Ok(())
}

#[test]
fn reset_version_overflow_is_rejected_before_claiming() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut near_ceiling = store.new_batch();
    near_ceiling.put(ColumnFamily::UtxoMeta, RESET_KEY, &idle_bytes(u64::MAX - 1));
    store.write_durable(near_ceiling)?;

    let writer = IndexWriter::open(Arc::clone(&store), 4)?;
    writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, RESET_KEY)?,
        Some(idle_bytes(u64::MAX))
    );
    let before = dump_all(store.as_ref());

    let result = writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY);
    assert!(
        matches!(result, Err(IndexError::ResetVersionOverflow)),
        "an idle version at u64::MAX must refuse the next reset: {result:?}"
    );
    assert_eq!(
        dump_all(store.as_ref()),
        before,
        "reset-version overflow must precede claim publication and deletion"
    );
    Ok(())
}

#[test]
fn reset_revision_overflow_is_rejected_before_claim_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut state = store.new_batch();
    state.put(ColumnFamily::UtxoMeta, RESET_KEY, &idle_bytes(1));
    state.put(
        ColumnFamily::UtxoMeta,
        ORDINARY_STATE_REVISION_KEY,
        &u64::MAX.to_le_bytes(),
    );
    store.write_durable(state)?;
    let before = dump_all(store.as_ref());

    let writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let result = writer.reset_capabilities(IndexCapabilities::TX_LOOKUP);
    assert!(
        matches!(result, Err(IndexError::StateRevisionOverflow)),
        "a full revision must refuse the reset before any claim: {result:?}"
    );
    assert_eq!(
        dump_all(store.as_ref()),
        before,
        "revision overflow must leave reset state, rows, cursors, and watermarks untouched"
    );
    Ok(())
}

/// Interrupted 9-byte claim from an earlier binary: mask plus process epoch,
/// with no base version.
fn legacy_nine_byte_claim(mask: u8, process_epoch: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(9);
    value.push(mask);
    value.extend_from_slice(&process_epoch.to_le_bytes());
    value
}

/// A fence captured before a legacy claim round-trip must not come back
/// alive just because adoption completed back to byte-identical idle bytes.
fn legacy_aba_rejection(marker: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    let mut initial = store.new_batch();
    initial.put(ColumnFamily::UtxoMeta, RESET_KEY, &idle_bytes(1));
    initial.put(
        ColumnFamily::UtxoMeta,
        ORDINARY_STATE_REVISION_KEY,
        &7_u64.to_le_bytes(),
    );
    store.write_durable(initial)?;

    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    let (stale_fence, watermarks) = writer.fenced_watermarks()?;
    assert_eq!(watermarks, IndexWatermarks::default());

    // A pre-revision binary replaces Idle(1) with a legacy claim. Completion
    // returns to the same reset bytes, so only the ordinary revision can
    // invalidate the stale fence.
    let mut crash = store.new_batch();
    crash.put(ColumnFamily::UtxoMeta, RESET_KEY, marker);
    store.write_durable(crash)?;

    let baseline = store.logged_batches().len();
    assert!(matches!(
        writer.fenced_watermarks(),
        Err(IndexError::ResetInProgress)
    ));
    assert_state_revision(&store, Some(8))?;
    let markers: Vec<BatchLog> = store.logged_batches()[baseline..]
        .iter()
        .filter(|entry| entry.marker_put.is_some())
        .cloned()
        .collect();
    assert_eq!(markers.len(), 1, "no adoption rewrite, one completion");
    assert!(markers[0].durable, "the completion is durable");
    assert_eq!(
        markers[0].marker_put.as_deref(),
        Some(idle_bytes(1).as_slice())
    );

    let result = writer.commit_consumer_cursor(stale_fence, b"stale");
    assert!(
        matches!(result, Err(IndexError::StaleIndexState)),
        "an ABA-identical idle state must reject via the revision: {result:?}"
    );
    assert!(writer.consumer_cursor()?.is_none());

    let (fresh_fence, _) = writer.fenced_watermarks()?;
    writer.commit_consumer_cursor(fresh_fence, b"fresh")?;
    assert_eq!(
        writer.consumer_cursor()?.as_deref(),
        Some(b"fresh".as_slice())
    );
    assert_state_revision(&store, Some(9))?;
    assert_eq!(stored_idle_version(&store)?, 1);
    Ok(())
}

#[test]
fn legacy_one_byte_marker_rejects_aba_commit() -> Result<(), Box<dyn std::error::Error>> {
    legacy_aba_rejection(&[TX_LOOKUP_MASK | SCRIPT_HISTORY_MASK])
}

#[test]
fn legacy_nine_byte_marker_rejects_aba_commit() -> Result<(), Box<dyn std::error::Error>> {
    legacy_aba_rejection(&legacy_nine_byte_claim(
        TX_LOOKUP_MASK | SCRIPT_HISTORY_MASK,
        9,
    ))
}

#[test]
fn same_mask_claim_is_adopted_cooperatively_without_rewrite()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    seed_populated_store(&store, 1)?;
    // A crashed script-only reset left its canonical claim and its selected
    // watermark delete committed.
    let mut crash = store.new_batch();
    crash.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &claim_bytes(SCRIPT_HISTORY_MASK, 9, 0),
    );
    crash.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
    crash.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
    store.write_durable(crash)?;

    let baseline = store.logged_batches().len();
    let writer = IndexWriter::open(Arc::clone(&store), 7)?;

    // Same-mask adoption writes nothing of its own: the only marker write is
    // the completion, CASed from the crashed writer's exact raw claim bytes.
    let markers: Vec<BatchLog> = store.logged_batches()[baseline..]
        .iter()
        .filter(|entry| entry.marker_put.is_some())
        .cloned()
        .collect();
    assert_eq!(markers.len(), 1, "no adoption rewrite: {markers:?}");
    assert!(markers[0].durable, "the completion is durable");
    assert_eq!(
        markers[0].marker_put.as_deref(),
        Some(idle_bytes(1).as_slice())
    );
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, RESET_KEY)?,
        Some(idle_bytes(1))
    );
    assert_state_revision(&store, Some(2))?;

    // Selective: sibling tx state survives the adopted script reset.
    assert!(writer.watermarks()?.tx_lookup.is_some());
    assert!(writer.watermarks()?.script_history.is_none());
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 1);
    assert_eq!(store.count(ColumnFamily::Funding), 0);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert!(writer.consumer_cursor()?.is_none());
    Ok(())
}

#[test]
fn union_growth_preserves_claim_identity_and_deletes_full_union_state()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    seed_populated_store(&store, 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 7)?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_consumer_cursor(fence, b"pending")?;

    // A crashed script-only reset left its claim; the tx watermark and the
    // consumer cursor are still live.
    let mut crash = store.new_batch();
    crash.put(
        ColumnFamily::UtxoMeta,
        RESET_KEY,
        &claim_bytes(SCRIPT_HISTORY_MASK, 9, 3),
    );
    crash.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
    store.write_durable(crash)?;

    let baseline = store.logged_batches().len();
    writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;

    // Mask growth rewrites only byte zero: same width, process epoch, and base.
    let markers: Vec<BatchLog> = store.logged_batches()[baseline..]
        .iter()
        .filter(|entry| entry.marker_put.is_some())
        .cloned()
        .collect();
    assert_eq!(
        markers.len(),
        2,
        "one grown claim, one completion: {markers:?}"
    );
    assert!(markers[0].durable, "the grown claim is durable");
    assert_eq!(
        markers[0].marker_put.as_deref(),
        Some(claim_bytes(TX_LOOKUP_MASK | SCRIPT_HISTORY_MASK, 9, 3).as_slice()),
        "growth changes byte zero only; width, process epoch, and base survive raw"
    );
    assert_eq!(
        markers[0].deletes, 3,
        "the claim deletes the union watermarks and the consumer cursor"
    );
    assert_eq!(
        markers[1].marker_put.as_deref(),
        Some(idle_bytes(4).as_slice())
    );
    assert_eq!(markers[1].deletes, 0, "completion never deletes");

    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, RESET_KEY)?,
        Some(idle_bytes(4))
    );
    assert_state_revision(&store, Some(3))?;
    assert!(writer.watermarks()?.tx_lookup.is_none());
    assert!(writer.watermarks()?.script_history.is_none());
    assert!(writer.consumer_cursor()?.is_none());
    for cf in [
        ColumnFamily::TxConfirmed,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
        ColumnFamily::BlockHeaders,
    ] {
        assert_eq!(store.count(cf), 0, "{cf:?} joined the union reset");
    }
    Ok(())
}

#[test]
fn second_writer_forward_contention_rejects_stale_fence() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut winner = IndexWriter::open(Arc::clone(&store), 4)?;
    let mut loser = IndexWriter::open(Arc::clone(&store), 5)?;

    // Both writers capture the same pre-commit state.
    let (winner_fence, _) = winner.fenced_watermarks()?;
    let (loser_fence, _) = loser.fenced_watermarks()?;

    let body = read_fixture(1)?;
    let block =
        winner.prepare_block_for(IndexCapabilities::TX_LOOKUP, 1, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    let watermark = winner.commit_forward_with_cursor(
        winner_fence,
        prepared,
        ConsumerCursorUpdate::Set(b"winner"),
    )?;
    assert_eq!(watermark.height, 1);
    let rows_after_winner = store.rows(ColumnFamily::TxConfirmed);

    // The loser replays the identical block against the shared pre-commit
    // fence: the four-condition CAS misses and nothing may move.
    let block =
        loser.prepare_block_for(IndexCapabilities::TX_LOOKUP, 1, block_hash(&body), &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    let result = loser.commit_forward_with_cursor(
        loser_fence,
        prepared,
        ConsumerCursorUpdate::Set(b"loser"),
    );
    assert!(
        matches!(result, Err(IndexError::StaleIndexState)),
        "the losing forward must lose the four-condition CAS: {result:?}"
    );

    // The winner's committed state is exact and untouched by the loser.
    assert_eq!(store.rows(ColumnFamily::TxConfirmed), rows_after_winner);
    assert_eq!(winner.watermark()?.map(|mark| mark.height), Some(1));
    assert_eq!(
        winner.watermarks()?.script_history.map(|mark| mark.height),
        Some(0)
    );
    assert_eq!(
        winner.consumer_cursor()?.as_deref(),
        Some(b"winner".as_slice())
    );
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?,
        Some(2_u64.to_le_bytes().to_vec())
    );
    Ok(())
}

#[test]
fn second_writer_rollback_contention_rejects_stale_fence() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(MemoryStore::default());
    seed_populated_store(&store, 1)?;
    let mut winner = IndexWriter::open(Arc::clone(&store), 4)?;
    let mut loser = IndexWriter::open(Arc::clone(&store), 5)?;

    // Both writers capture the same pre-commit state.
    let (winner_fence, _) = winner.fenced_watermarks()?;
    let (loser_fence, _) = loser.fenced_watermarks()?;

    let body = read_fixture(0)?;
    // The winner selectively rolls block0 back for tx lookup only.
    winner.commit_rollback_one_for_with_cursor(
        winner_fence,
        IndexCapabilities::TX_LOOKUP,
        None,
        &body,
        ConsumerCursorUpdate::Clear,
    )?;

    // The loser replays the identical selective rollback against the shared
    // pre-commit fence: the four-condition CAS misses and nothing may move.
    let result = loser.commit_rollback_one_for_with_cursor(
        loser_fence,
        IndexCapabilities::TX_LOOKUP,
        None,
        &body,
        ConsumerCursorUpdate::Clear,
    );
    assert!(
        matches!(result, Err(IndexError::StaleIndexState)),
        "the losing rollback must lose the four-condition CAS: {result:?}"
    );

    // The winner's selective state is exact and untouched by the loser.
    assert!(winner.watermarks()?.tx_lookup.is_none());
    assert_eq!(
        winner.watermarks()?.script_history.map(|mark| mark.height),
        Some(0)
    );
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 0);
    assert_eq!(store.count(ColumnFamily::Funding), 1);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 1);
    assert!(winner.consumer_cursor()?.is_none());
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?,
        Some(2_u64.to_le_bytes().to_vec())
    );
    Ok(())
}
