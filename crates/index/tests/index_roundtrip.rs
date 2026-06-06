//! Roundtrip tests for electrs-shaped index rows over a small in-memory `KvStore`.
use std::{collections::BTreeMap, path::PathBuf};

use bitcoin::hashes::Hash as _;
use parking_lot::RwLock;

use bitcoin_rs_index::{IndexRowCounts, Indexer};
use bitcoin_rs_storage::{ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch};

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
                        .keys()
                        .filter(|key| {
                            key.as_slice() >= start.as_slice() && key.as_slice() < end.as_slice()
                        })
                        .cloned()
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
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&block_bytes)?;
    let txids = block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect::<Vec<_>>();

    assert_precomputed_ingest_matches_standard(&block_bytes, height, &txids)
}

#[test]
fn ingest_with_verified_txids_matches_standard_ingest() -> Result<(), Box<dyn std::error::Error>> {
    let height = 170_u32;
    let block_bytes = read_fixture(height)?;
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&block_bytes)?;
    let txids = block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect::<Vec<_>>();

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
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&block_bytes)?;
    let stale_txids = vec![bitcoin::Txid::from_byte_array([0x42; 32]); block.txdata.len()];

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
    txids: &[bitcoin::Txid],
) -> Result<(), Box<dyn std::error::Error>> {
    assert_ingest_matches_standard(block, height, |indexer| {
        indexer.ingest_block_with_txids(block, height, txids)
    })
}

fn assert_verified_ingest_matches_standard(
    block: &[u8],
    height: u32,
    txids: &[bitcoin::Txid],
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
