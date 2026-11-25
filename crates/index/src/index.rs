mod block;
mod capability;
mod error;
mod filters;
mod prepared;
mod reader;
mod rows;
mod snapshot;
mod state;
mod tail_writes;
mod write;

pub(crate) use block::NoSpentScripts;
#[cfg(test)]
pub(crate) use block::{BodyFacts, committed_block_from_image, parse_body};
pub use block::{MAX_LIVE_SCRIPT_SIZE, SpentCoin, SpentCoins};
pub(crate) use capability::put_bulk_publish_marks;
pub(crate) use capability::read_coverage_floor;
pub use capability::{IndexCapabilities, IndexCapability, IndexWatermark, IndexWatermarks};
pub use error::IndexError;
pub use filters::BasicFilter;
pub use prepared::{PreparedBatch, PreparedBatchLimits, PreparedBlock};
pub use reader::Indexer;
pub use snapshot::{
    FundingTransaction, FundingTransactionScan, IndexReader, ScriptLiveScan, TxIndexPage,
    TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
};
pub use state::{ConsumerCursorUpdate, IndexWriteFence};
pub use write::IndexWriter;
pub use write::index_format_version;
pub(crate) use write::{rollback_prepare_capabilities, tail_rollback_group};

#[cfg(test)]
mod filter_build_tests {
    //! The live commit path builds each block's compact filter exactly once: the
    //! prepare step builds it, and the tail append consumes the prepared copy.

    use std::sync::Arc;

    use bitcoin_rs_storage::{CommittedBlock, CreatedOutput, FactsScript, RocksDbStore, TxFacts};

    use super::{IndexCapabilities, IndexWriter, PreparedBatch, PreparedBatchLimits};
    use crate::segment::tail::FILTER_BUILDS;

    fn facts(height: u32, hash: [u8; 32], parent_hash: [u8; 32], txid: u8) -> CommittedBlock {
        CommittedBlock {
            height,
            hash,
            parent_hash,
            header: [0; 80],
            txs: vec![TxFacts {
                txid: [txid; 32],
                offset: 81,
                len: 60,
                inputs: Vec::new(),
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 50,
                    script: FactsScript::copy_from_slice(&[0x51]),
                }],
            }],
        }
    }

    #[test]
    fn live_commit_builds_each_block_filter_once() -> Result<(), crate::portable::TestError> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let mut writer = IndexWriter::open(store, 1)?;
        let caps = IndexCapabilities::HISTORICAL.with_compact_filters(true);
        let first = facts(0, [1; 32], [0; 32], 1);
        let second = facts(1, [2; 32], first.hash, 2);

        FILTER_BUILDS.with(|builds| builds.set(0));
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for block in [&first, &second] {
            let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
            assert!(batch.try_push(prepared).is_ok());
        }
        writer.commit_forward(batch)?;

        let builds = FILTER_BUILDS.with(std::cell::Cell::get);
        assert_eq!(builds, 2, "one filter build per block on the live path");
        Ok(())
    }
}
#[cfg(test)]
mod tail_gate_tests {
    use super::IndexCapabilities;
    use super::IndexCapability;
    use super::IndexWriter;
    use crate::segment::tail::FILTER_BUILDS;
    use crate::segment::tail::SCRIPT_HASH_BUILDS;
    use bitcoin_rs_storage::CommittedBlock;
    use bitcoin_rs_storage::FactsScript;
    use bitcoin_rs_storage::KvStore;
    use bitcoin_rs_storage::RocksDbStore;
    use bitcoin_rs_storage::committed_facts::CreatedOutput;
    use bitcoin_rs_storage::committed_facts::SpentPrevout;
    use bitcoin_rs_storage::committed_facts::TxFacts;
    use std::sync::Arc;

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Index(#[from] crate::IndexError),
        #[error(transparent)]
        Storage(#[from] bitcoin_rs_storage::StorageError),
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Bulk(#[from] crate::segment::bulk_builder::BulkBuilderError),
        #[error("missing {0}")]
        Missing(&'static str),
    }

    impl From<&'static str> for TestError {
        fn from(value: &'static str) -> Self {
            Self::Missing(value)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TxDirEntry {
        txid: [u8; 32],
        height: u32,
        block_hash: [u8; 32],
        ordinal: u32,
        offset: u32,
        len: u32,
    }
    fn block_with_spends_at(height: u32, hash: u8, parent: [u8; 32]) -> CommittedBlock {
        let txid = hash.wrapping_add(3);
        let prev_txid = hash.wrapping_add(4);
        CommittedBlock {
            height,
            hash: [hash; 32],
            parent_hash: parent,
            header: [5; 80],
            txs: vec![TxFacts {
                txid: [txid; 32],
                offset: 0,
                len: 0,
                inputs: vec![SpentPrevout {
                    txid: [prev_txid; 32],
                    vout: 0,
                    value: 5,
                    script: FactsScript::copy_from_slice(&[0x51]),
                    height: 0,
                    coinbase: false,
                }],
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 4,
                    script: FactsScript::copy_from_slice(&[0x51]),
                }],
            }],
        }
    }

    fn block_with_spends() -> CommittedBlock {
        block_with_spends_at(1, 3, [4; 32])
    }

    fn open_writer() -> Result<(tempfile::TempDir, IndexWriter<RocksDbStore>), TestError> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        Ok((dir, IndexWriter::open(store, 1)?))
    }

    fn reset_counts() {
        FILTER_BUILDS.with(|builds| builds.set(0));
        SCRIPT_HASH_BUILDS.with(|builds| builds.set(0));
    }

    // PRJ-03
    #[test]
    fn disabled_compact_filters_skip_filter_build() -> Result<(), TestError> {
        let (_dir, writer) = open_writer()?;
        let block = block_with_spends();
        reset_counts();
        let prepared =
            writer.prepare_block_from_facts(IndexCapabilities::HISTORICAL, block.clone())?;
        assert_eq!(FILTER_BUILDS.with(std::cell::Cell::get), 0);
        assert_eq!(SCRIPT_HASH_BUILDS.with(std::cell::Cell::get), 2);
        assert!(
            prepared
                .tail
                .inputs
                .iter()
                .all(|tx| tx.iter().all(|hash| hash.is_some()))
        );
        Ok(())
    }

    // PRJ-03
    #[test]
    fn disabled_script_history_skips_script_hashes() -> Result<(), TestError> {
        let (_dir, writer) = open_writer()?;
        let block = block_with_spends();
        reset_counts();
        let caps = IndexCapabilities::TX_LOOKUP.insert(IndexCapability::CompactFilters);
        let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
        assert_eq!(FILTER_BUILDS.with(std::cell::Cell::get), 1);
        assert_eq!(SCRIPT_HASH_BUILDS.with(std::cell::Cell::get), 0);
        assert_eq!(prepared.tail.inputs.capacity(), 0);
        assert_eq!(prepared.tail.outputs.capacity(), 0);
        Ok(())
    }

    // PRJ-03
    #[test]
    fn lookup_and_history_disabled_skip_script_hashes() -> Result<(), TestError> {
        let (_dir, writer) = open_writer()?;
        let block = block_with_spends();
        reset_counts();
        let prepared =
            writer.prepare_block_from_facts(IndexCapabilities::COMPACT_FILTERS, block.clone())?;
        assert_eq!(FILTER_BUILDS.with(std::cell::Cell::get), 1);
        assert_eq!(SCRIPT_HASH_BUILDS.with(std::cell::Cell::get), 0);
        assert_eq!(prepared.tail.inputs.capacity(), 0);
        assert_eq!(prepared.tail.outputs.capacity(), 0);
        Ok(())
    }

    // PRJ-09
    #[test]
    fn all_enabled_matches_bulk_builder_rows() -> Result<(), TestError> {
        let (_dir, writer) = open_writer()?;
        let block = block_with_spends();
        reset_counts();
        let prepared = writer.prepare_block_from_facts(IndexCapabilities::ALL, block.clone())?;
        assert_eq!(FILTER_BUILDS.with(std::cell::Cell::get), 1);
        assert_eq!(SCRIPT_HASH_BUILDS.with(std::cell::Cell::get), 2);
        let scratch = tempfile::tempdir()?;
        let bulk = crate::segment::bulk_builder::BulkSegmentBuilder::new(
            std::sync::Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
            None,
            scratch.path().to_path_buf(),
        )
        .build_generation_rows(1, std::slice::from_ref(&block))?;
        assert_eq!(bulk.filters.len(), 1);
        let (_, bulk_filter_hash, _, bulk_filter) =
            crate::segment::format::decode_filter_value(&bulk.filters[0].1)
                .ok_or("bulk filter value")?;
        assert_eq!(prepared.tail.filter_bytes, bulk_filter);
        assert_eq!(prepared.tail.filter_hash, bulk_filter_hash);
        let mut prepared_hashes: Vec<[u8; 32]> = prepared
            .tail
            .inputs
            .iter()
            .flatten()
            .chain(prepared.tail.outputs.iter().flatten())
            .filter_map(|hash| *hash)
            .collect();
        prepared_hashes.sort_unstable();
        prepared_hashes.dedup();
        let mut bulk_hashes: Vec<[u8; 32]> = bulk
            .script_dict
            .iter()
            .filter_map(|(key, _)| {
                crate::segment::format::decode_script_dict_key(key).map(|(_, hash)| hash)
            })
            .collect();
        bulk_hashes.sort_unstable();
        assert_eq!(prepared_hashes, bulk_hashes);
        Ok(())
    }

    // PRJ-03
    #[test]
    fn disabled_compact_filters_seal_writes_no_filter_rows() -> Result<(), TestError> {
        let (_dir, mut writer) = open_writer()?;
        let blocks = [
            block_with_spends_at(0, 3, [0; 32]),
            block_with_spends_at(1, 8, [3; 32]),
        ];
        let caps = IndexCapabilities::HISTORICAL;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for block in &blocks {
            let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
            batch
                .try_push(prepared)
                .map_err(|_| "seal batch must admit the block")?;
        }
        writer.commit_forward(batch)?;
        let scratch = tempfile::tempdir()?;
        crate::segment::seal_tail_generation(
            writer.indexer.store.as_ref(),
            1,
            1,
            caps,
            scratch.path(),
        )?;
        let snapshot = writer.indexer.store.snapshot()?;
        let mut filters = 0u64;
        for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::Filters, &[])? {
            let _ = item?;
            filters = filters.saturating_add(1);
        }
        assert_eq!(filters, 0, "sealed generation holds no filter rows");
        let sealed =
            crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::TxLookup)?;
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].coverage.first_height, 0);
        assert_eq!(sealed[0].coverage.last_height, 1);
        assert_eq!(sealed[0].coverage.last_hash, blocks[1].hash);
        Ok(())
    }

    // PRJ-05
    #[test]
    fn compact_filters_only_seal_and_reopen_keep_coverage() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let store = std::sync::Arc::new(RocksDbStore::open(dir.path())?);
        let caps = IndexCapabilities::COMPACT_FILTERS;
        let blocks = [
            block_with_spends_at(0, 3, [0; 32]),
            block_with_spends_at(1, 8, [3; 32]),
        ];
        let mut writer = IndexWriter::open(std::sync::Arc::clone(&store), 1)?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for block in &blocks {
            let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
            batch
                .try_push(prepared)
                .map_err(|_| "seal batch must admit the block")?;
        }
        writer.commit_forward(batch)?;
        let scratch = tempfile::tempdir()?;
        crate::segment::seal_tail_generation(store.as_ref(), 1, 1, caps, scratch.path())?;
        drop(writer);
        let mut writer = IndexWriter::open(std::sync::Arc::clone(&store), 1)?;
        let third = block_with_spends_at(2, 11, [8; 32]);
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        batch
            .try_push(writer.prepare_block_from_facts(caps, third.clone())?)
            .map_err(|_| "seal batch must admit the block")?;
        writer.commit_forward(batch)?;
        crate::segment::seal_tail_generation(store.as_ref(), 2, 2, caps, scratch.path())?;
        let snapshot = store.snapshot()?;
        let sealed =
            crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::CompactFilters)?;
        assert_eq!(sealed.len(), 2);
        assert_eq!(sealed[1].coverage.first_height, 2);
        assert_eq!(sealed[1].coverage.last_height, 2);
        assert_eq!(sealed[1].coverage.last_hash, third.hash);
        let mut filters = 0u64;
        for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::Filters, &[])? {
            let _ = item?;
            filters = filters.saturating_add(1);
        }
        assert_eq!(filters, 3);
        Ok(())
    }

    #[test]
    fn seal_and_open_skip_scans_when_hashes_known() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let store = std::sync::Arc::new(RocksDbStore::open(dir.path())?);
        let caps = IndexCapabilities::HISTORICAL;
        let blocks = [
            block_with_spends_at(0, 3, [0; 32]),
            block_with_spends_at(1, 8, [3; 32]),
        ];
        let mut writer = IndexWriter::open(std::sync::Arc::clone(&store), 1)?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for block in &blocks {
            let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
            batch
                .try_push(prepared)
                .map_err(|_| "seal batch must admit the block")?;
        }
        writer.commit_forward(batch)?;
        let scratch = tempfile::tempdir()?;
        crate::segment::seal_tail_generation(store.as_ref(), 1, 1, caps, scratch.path())?;
        drop(writer);
        let _writer = IndexWriter::open(std::sync::Arc::clone(&store), 1)?;
        let snapshot = store.snapshot()?;
        let sealed =
            crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::TxLookup)?;
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].coverage.first_height, 0);
        assert_eq!(sealed[0].coverage.last_height, 1);
        assert_eq!(sealed[0].coverage.last_hash, blocks[1].hash);
        Ok(())
    }
    // PRJ-03
    #[test]
    fn compact_filters_only_leaves_no_tx_dir() -> Result<(), crate::portable::TestError> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let caps = IndexCapabilities::COMPACT_FILTERS;
        let blocks = [
            block_with_spends_at(0, 3, [0; 32]),
            block_with_spends_at(1, 8, [3; 32]),
            block_with_spends_at(2, 11, [8; 32]),
        ];
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for block in &blocks {
            let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
            batch
                .try_push(prepared)
                .map_err(|_| "seal batch must admit the block")?;
        }
        reset_counts();
        writer.commit_forward(batch)?;
        assert_eq!(SCRIPT_HASH_BUILDS.with(std::cell::Cell::get), 0);
        let snapshot = store.snapshot()?;
        let mut tx_rows = 0;
        for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::TxDir, &[])? {
            let _ = item?;
            tx_rows += 1;
        }
        assert_eq!(tx_rows, 0);
        let mut prev_header = [0u8; 32];
        let mut seen = 0;
        for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::Filters, &[])? {
            let (key, value) = item?;
            let Some((_, height)) = crate::segment::format::decode_filter_key(&key) else {
                return Err("filter key".into());
            };
            let Some((block_hash, filter_hash, header, _)) =
                crate::segment::format::decode_filter_value(&value)
            else {
                return Err("filter value".into());
            };
            let Some(expected) = blocks.iter().find(|block| block.height == height) else {
                return Err("filter height".into());
            };
            assert_eq!(block_hash, expected.hash);
            let mut hdr_in = [0u8; 64];
            hdr_in[..32].copy_from_slice(&filter_hash);
            hdr_in[32..].copy_from_slice(&prev_header);
            assert_eq!(
                header,
                bitcoin_rs_consensus::primitives::encode::double_sha256(&hdr_in).to_le_bytes()
            );
            prev_header = header;
            seen += 1;
        }
        assert_eq!(seen, blocks.len());
        drop(snapshot);
        drop(writer);
        let scratch = tempfile::tempdir()?;
        crate::segment::seal_tail_generation(store.as_ref(), 1, 0, caps, scratch.path())?;
        let snapshot = store.snapshot()?;
        let mut sealed_tx = 0;
        for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::TxDir, &[])? {
            let _ = item?;
            sealed_tx += 1;
        }
        assert_eq!(sealed_tx, 0);
        let sealed =
            crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::CompactFilters)?;
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].coverage.first_height, 0);
        assert_eq!(sealed[0].coverage.last_height, 0);
        assert_eq!(sealed[0].coverage.last_hash, blocks[0].hash);
        drop(snapshot);
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let snapshot = store.snapshot()?;
        let state = crate::segment::tail::load(snapshot.as_ref())?;
        assert_eq!(state.at, Some((2, blocks[2].hash)));
        drop(snapshot);
        drop(writer);
        let snapshot = store.snapshot()?;
        let mut batch = store.new_batch();
        let removed = crate::segment::tail::unwind_tail_block(&mut batch, snapshot.as_ref(), 2)?;
        assert!(removed);
        drop(snapshot);
        store.write_durable(batch)?;
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let snapshot = store.snapshot()?;
        let state = crate::segment::tail::load(snapshot.as_ref())?;
        assert_eq!(state.at, Some((1, blocks[1].hash)));
        drop(writer);
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let snapshot = store.snapshot()?;
        let state = crate::segment::tail::load(snapshot.as_ref())?;
        assert_eq!(state.at, Some((1, blocks[1].hash)));
        drop(snapshot);
        drop(writer);
        Ok(())
    }
    // PRJ-03
    #[test]
    fn tx_lookup_writes_expected_directory() -> Result<(), crate::portable::TestError> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let caps = IndexCapabilities::TX_LOOKUP;
        let blocks = [
            block_with_spends_at(0, 3, [0; 32]),
            block_with_spends_at(1, 8, [3; 32]),
        ];
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for block in &blocks {
            let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
            batch
                .try_push(prepared)
                .map_err(|_| "seal batch must admit the block")?;
        }
        writer.commit_forward(batch)?;
        let snapshot = store.snapshot()?;
        let mut found: Vec<TxDirEntry> = Vec::new();
        let prefix =
            crate::segment::format::tx_dir_kind_prefix(0, crate::segment::format::TX_KIND_TXID);
        for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::TxDir, &prefix)? {
            let (key, value) = item?;
            let Some((_, txid, height)) = crate::segment::format::decode_tx_dir_key(&key) else {
                continue;
            };
            let Some((block_hash, ordinal, offset, len)) =
                crate::segment::format::decode_tx_dir_value(&value)
            else {
                return Err("tx dir value".into());
            };
            found.push(TxDirEntry {
                txid,
                height,
                block_hash,
                ordinal,
                offset,
                len,
            });
        }
        found.sort_by_key(|entry| entry.ordinal);
        let mut expected: Vec<TxDirEntry> = Vec::new();
        let mut ordinal = 0;
        for block in &blocks {
            for tx in &block.txs {
                expected.push(TxDirEntry {
                    txid: tx.txid,
                    height: block.height,
                    block_hash: block.hash,
                    ordinal,
                    offset: tx.offset,
                    len: tx.len,
                });
                ordinal += 1;
            }
        }
        assert_eq!(found, expected);
        Ok(())
    }
    // PRJ-03
    #[test]
    fn script_live_only_seals_cuts_and_reopens() -> Result<(), crate::portable::TestError> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let caps = IndexCapabilities::SCRIPT_LIVE;
        let blocks = [
            block_with_spends_at(0, 3, [0; 32]),
            block_with_spends_at(1, 8, [3; 32]),
            block_with_spends_at(2, 11, [8; 32]),
        ];
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for block in &blocks {
            let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
            batch
                .try_push(prepared)
                .map_err(|_| "seal batch must admit the block")?;
        }
        writer.commit_forward(batch)?;
        let snapshot = store.snapshot()?;
        let mut tx_rows = 0;
        for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::TxDir, &[])? {
            let _ = item?;
            tx_rows += 1;
        }
        assert_eq!(tx_rows, 0);
        let mut filter_rows = 0;
        for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::Filters, &[])? {
            let _ = item?;
            filter_rows += 1;
        }
        assert_eq!(filter_rows, 0);
        drop(snapshot);
        drop(writer);
        let scratch = tempfile::tempdir()?;
        crate::segment::seal_tail_generation(store.as_ref(), 1, 0, caps, scratch.path())?;
        let snapshot = store.snapshot()?;
        let mut tx_rows = 0;
        for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::TxDir, &[])? {
            let _ = item?;
            tx_rows += 1;
        }
        assert_eq!(tx_rows, 0);
        let mut filter_rows = 0;
        for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::Filters, &[])? {
            let _ = item?;
            filter_rows += 1;
        }
        assert_eq!(filter_rows, 0);
        drop(snapshot);
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let snapshot = store.snapshot()?;
        let state = crate::segment::tail::load(snapshot.as_ref())?;
        assert_eq!(state.at, Some((2, blocks[2].hash)));
        drop(snapshot);
        drop(writer);
        let snapshot = store.snapshot()?;
        let mut batch = store.new_batch();
        let removed = crate::segment::tail::unwind_tail_block(&mut batch, snapshot.as_ref(), 2)?;
        assert!(removed);
        drop(snapshot);
        store.write_durable(batch)?;
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let snapshot = store.snapshot()?;
        let state = crate::segment::tail::load(snapshot.as_ref())?;
        assert_eq!(state.at, Some((1, blocks[1].hash)));
        drop(snapshot);
        drop(writer);
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let snapshot = store.snapshot()?;
        let state = crate::segment::tail::load(snapshot.as_ref())?;
        assert_eq!(state.at, Some((1, blocks[1].hash)));
        drop(snapshot);
        drop(writer);
        Ok(())
    }
    #[test]
    fn tail_log_without_hash_is_corrupt() -> Result<(), crate::portable::TestError> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let caps = IndexCapabilities::HISTORICAL;
        let blocks = [block_with_spends_at(0, 3, [0; 32])];
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for block in &blocks {
            let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
            batch
                .try_push(prepared)
                .map_err(|_| "seal batch must admit the block")?;
        }
        writer.commit_forward(batch)?;
        drop(writer);
        let snapshot = store.snapshot()?;
        let key = crate::segment::tail::log_key(0);
        let Some(value) = snapshot.get(bitcoin_rs_storage::ColumnFamily::IdxMeta, &key)? else {
            return Err("tail log".into());
        };
        drop(snapshot);
        let Some(stripped) = value.get(44 + 33..).map(|rest| {
            let mut rebuilt = Vec::with_capacity(44 + rest.len());
            rebuilt.extend_from_slice(&value[..44]);
            rebuilt.extend_from_slice(rest);
            rebuilt
        }) else {
            return Err("tail log".into());
        };
        let mut batch = store.new_batch();
        batch.put(bitcoin_rs_storage::ColumnFamily::IdxMeta, &key, &stripped);
        store.write_durable(batch)?;
        let snapshot = store.snapshot()?;
        let result = crate::segment::tail::plan_prefix_cut(snapshot.as_ref(), 0);
        let Err(crate::IndexError::CorruptTailLog { height }) = result else {
            return Err("plan must refuse".into());
        };
        assert_eq!(height, 0);
        Ok(())
    }

    // IDX-04
    #[test]
    fn script_live_reset_keeps_the_shared_tail_logs() -> Result<(), crate::portable::TestError> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let caps = IndexCapabilities::HISTORICAL;
        let blocks = [
            block_with_spends_at(0, 3, [0; 32]),
            block_with_spends_at(1, 8, [3; 32]),
        ];
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for block in &blocks {
            let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
            batch
                .try_push(prepared)
                .map_err(|_| "seal batch must admit the block")?;
        }
        writer.commit_forward(batch)?;
        writer.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;
        let snapshot = store.snapshot()?;
        let mut kept_logs = 0_usize;
        for item in snapshot.iter_prefix(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            crate::segment::tail::LOG_PREFIX,
        )? {
            let _ = item?;
            kept_logs += 1;
        }
        assert_eq!(
            kept_logs,
            blocks.len(),
            "a ScriptLive reset must keep the shared tail undo logs"
        );
        drop(snapshot);
        let tail_bound = IndexCapabilities::TX_LOOKUP
            .insert(IndexCapability::ScriptHistory)
            .insert(IndexCapability::CompactFilters);
        writer.reset_capabilities(tail_bound)?;
        let snapshot = store.snapshot()?;
        let mut remaining_logs = 0_usize;
        for item in snapshot.iter_prefix(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            crate::segment::tail::LOG_PREFIX,
        )? {
            let _ = item?;
            remaining_logs += 1;
        }
        assert_eq!(
            remaining_logs, 0,
            "a reset of every tail-bound capability clears the shared tail undo logs"
        );
        Ok(())
    }

    #[test]
    fn oldest_positive_floor_import_retires_to_uncovered_on_rollback()
    -> Result<(), crate::portable::TestError> {
        use crate::segment::Coverage;
        use crate::segment::import::{TxOccurrence, tx_lookup_segment};
        use crate::types::TxPosition;
        use bitcoin_rs_consensus::primitives::{Network, consensus_bytes};

        struct NoSpends;
        impl crate::SpentCoins for NoSpends {
            fn spent_coin(&self, _: &[u8; 32], _: u32) -> Option<crate::SpentCoin<'_>> {
                None
            }
        }
        let genesis = Network::Regtest.genesis_block();
        let child = bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_child_at(
            genesis.block_hash(),
            1,
        )
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        let body = consensus_bytes(&child);
        let tx = &child.txs[0];
        let tx_bytes = consensus_bytes(tx);
        let offset = body
            .windows(tx_bytes.len())
            .position(|bytes| bytes == tx_bytes)
            .ok_or("transaction position")?;
        let base = crate::IndexWatermark {
            height: 1,
            hash: child.block_hash().0.to_le_bytes(),
        };
        let imported = tx_lookup_segment(
            vec![TxOccurrence {
                txid: tx.txid().0.to_le_bytes(),
                height: 1,
                block_hash: base.hash,
                position: TxPosition::new(u32::try_from(offset)?, u32::try_from(tx_bytes.len())?),
            }],
            Coverage::new(1, 1, base.hash),
            1,
        )?;
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let genesis_header: [u8; 80] = consensus_bytes(&genesis.header)
            .try_into()
            .map_err(|_| "genesis header")?;
        let child_header: [u8; 80] = consensus_bytes(&child.header)
            .try_into()
            .map_err(|_| "child header")?;
        writer.attach_tx_lookup_segment(
            &imported,
            &crate::writer::TxLookupAttachment {
                headers: &[&genesis_header, &child_header],
                base,
                floor: 1,
                scratch: dir.path(),
            },
        )?;
        assert_eq!(writer.watermarks()?.tx_lookup, Some(base));
        let fence = writer.fenced_watermarks()?.0;
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            IndexCapabilities::TX_LOOKUP,
            Some(crate::IndexWatermark {
                height: 0,
                hash: genesis.block_hash().0.to_le_bytes(),
            }),
            &body,
            crate::ConsumerCursorUpdate::Keep,
            &NoSpends,
        )?;
        assert_eq!(writer.watermarks()?.tx_lookup, None);
        let snapshot = store.snapshot()?;
        assert!(
            crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::TxLookup)?
                .is_empty()
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::block::is_op_return_script;
    use std::sync::Arc;

    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvStore, RocksDbStore};

    use super::{
        IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWriter, Indexer, SpentCoins,
    };
    use crate::segment::tail::PreparedTail;
    use crate::{ScriptHash, ScriptLiveRow};

    type StoredRows = Vec<(ColumnFamily, Vec<u8>)>;

    struct FixtureScripts;

    static FIXTURE_SPENT_SCRIPT: [u8; 2] = [0x51, 0x01];

    use crate::SpentCoin;

    impl SpentCoins for FixtureScripts {
        fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
            Some(SpentCoin {
                script: FIXTURE_SPENT_SCRIPT.as_slice(),
                value: 0,
                height: 0,
                coinbase: false,
            })
        }
    }

    fn commit_block<S: KvStore>(
        writer: &mut IndexWriter<S>,
        height: u32,
        body: &[u8],
    ) -> Result<IndexWatermark, IndexError> {
        let header = body
            .get(..crate::types::HEADER_ROW_SIZE)
            .ok_or(IndexError::InvalidHeaderLength { len: body.len() })?;
        let hash = bitcoin_rs_consensus::primitives::encode::double_sha256(header).to_le_bytes();
        let prepared = writer.prepare_block_with_spent_scripts(
            crate::IndexCapabilities::HISTORICAL,
            height,
            hash,
            body,
            &FixtureScripts,
        )?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        if batch.try_push(prepared).is_err() {
            return Err(IndexError::NonContiguousPrepared {
                watermark: writer.watermark()?,
            });
        }
        writer.commit_forward(batch)
    }

    fn commit_rollback_one<S: KvStore>(
        writer: &mut IndexWriter<S>,
        prev: Option<crate::IndexWatermark>,
        body: &[u8],
    ) -> Result<(), IndexError> {
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            crate::IndexCapabilities::HISTORICAL,
            prev,
            body,
            crate::ConsumerCursorUpdate::Clear,
            &FixtureScripts,
        )
    }

    #[test]
    fn raw_op_return_check_matches_script_prefix_semantics() {
        assert!(!is_op_return_script(&[]));
        assert!(is_op_return_script(&[0x6a]));
        assert!(is_op_return_script(&[0x6a, 0x01, 0x00]));
        assert!(!is_op_return_script(&[0x00, 0x6a]));
    }

    #[test]
    fn iter_live_outpoints_reports_malformed_row_key_length()
    -> Result<(), crate::portable::TestError> {
        let script = vec![0x51, 0x05];
        let scripthash = ScriptHash::from_script_bytes(&script);
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;

        let outpoint = spent_outpoint(5, 0);
        let row = crate::types::ScriptLiveRow::new(scripthash, &outpoint);
        let coin = crate::types::ScriptLiveCoin::new(scripthash, 1_000, 1, false);
        let mut bytes = row.as_bytes().to_vec();
        bytes.extend_from_slice(&coin.encode_value()?);
        let rows = [bytes];
        writer.stage_script_live_rows(&mut rows.into_iter())?;
        let bare_43 = crate::types::ScriptLiveRow::new(scripthash, &outpoint)
            .as_bytes()
            .to_vec();
        assert_eq!(bare_43.len(), 43);
        assert!(matches!(
            writer.stage_script_live_rows(&mut [bare_43].into_iter()),
            Err(IndexError::InvalidLiveRowValue { len: 43 })
        ));
        writer.publish_script_live_seed(IndexWatermark {
            height: 7,
            hash: [0x07; 32],
        })?;

        let mut malformed = ScriptLiveRow::new(scripthash, &outpoint)
            .as_bytes()
            .to_vec();
        malformed.truncate(40);
        let coin = crate::types::ScriptLiveCoin::new(scripthash, 1000, 1, false);
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::ScriptLive, &malformed, &coin.encode_value()?);
        store.write(batch)?;

        let Err(error) = writer.indexer().iter_live_outpoints(scripthash) else {
            return Err(std::io::Error::other("malformed live-row key must fail").into());
        };
        assert!(
            matches!(error, IndexError::InvalidPrefixRowLength { len: 40 }),
            "malformed live-row key must report its length: {error:?}"
        );
        Ok(())
    }

    fn rollback_fixture_block() -> Block {
        let funded = tx(OutPoint::null(), vec![0x51]);
        let spender = tx(OutPoint::new(funded.txid(), 0), vec![0x52]);
        block(vec![funded, spender])
    }

    #[test]
    fn rollback_removes_every_row_a_matching_commit_wrote() -> Result<(), crate::portable::TestError>
    {
        let (_dir, mut writer) = writer()?;
        let candidate = rollback_fixture_block();
        let body = consensus_bytes(&candidate);
        let before = stored_rows(writer.indexer())?;

        commit_block(&mut writer, 0, &body)?;
        let after_commit = stored_rows(writer.indexer())?;
        assert!(
            after_commit.len() > before.len(),
            "fixture must write rows to be a meaningful rollback test"
        );
        for cf in [
            ColumnFamily::TxDir,
            ColumnFamily::ScriptPost,
            ColumnFamily::SpendDir,
            ColumnFamily::BlockHeaders,
        ] {
            assert!(
                after_commit.iter().any(|(family, _)| *family == cf),
                "fixture wrote no rows to {cf:?}"
            );
        }

        commit_rollback_one(&mut writer, None, &body)?;
        assert_eq!(
            stored_rows(writer.indexer())?,
            before,
            "rollback must restore the pre-commit row set exactly"
        );
        Ok(())
    }

    #[test]
    fn rollback_without_a_watermark_is_rejected() -> Result<(), crate::portable::TestError> {
        let (_dir, mut writer) = writer()?;
        let candidate = rollback_fixture_block();
        let body = consensus_bytes(&candidate);

        assert!(matches!(
            commit_rollback_one(&mut writer, None, &body),
            Err(IndexError::NonContiguousPrepared { watermark: None })
        ));
        assert_eq!(stored_rows(writer.indexer())?, Vec::new());
        Ok(())
    }

    #[test]
    fn a_second_rollback_is_rejected_once_the_watermark_is_gone()
    -> Result<(), crate::portable::TestError> {
        let (_dir, mut writer) = writer()?;
        let candidate = rollback_fixture_block();
        let body = consensus_bytes(&candidate);
        commit_block(&mut writer, 0, &body)?;
        commit_rollback_one(&mut writer, None, &body)?;
        let after_first = stored_rows(writer.indexer())?;

        assert!(matches!(
            commit_rollback_one(&mut writer, None, &body),
            Err(IndexError::NonContiguousPrepared { watermark: None })
        ));
        assert_eq!(
            stored_rows(writer.indexer())?,
            after_first,
            "a rejected second rollback must be observationally inert"
        );
        Ok(())
    }

    struct FailingWriteStore(RocksDbStore);

    impl bitcoin_rs_storage::KvStore for FailingWriteStore {
        fn get(
            &self,
            cf: ColumnFamily,
            key: &[u8],
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            self.0.get(cf, key)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<bitcoin_rs_storage::KvIter<'a>, bitcoin_rs_storage::StorageError> {
            self.0.iter_prefix(cf, prefix)
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: bitcoin_rs_storage::PrefixScanLimit,
        ) -> Result<bitcoin_rs_storage::PrefixScan, bitcoin_rs_storage::StorageError> {
            self.0.scan_prefix_from_bounded(cf, prefix, start, limit)
        }

        fn new_batch(&self) -> BufferedWriteBatch {
            self.0.new_batch()
        }

        fn write(
            &self,
            _batch: BufferedWriteBatch,
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected write failure".to_owned(),
            ))
        }

        fn write_durable_if(
            &self,
            _conditions: &[bitcoin_rs_storage::WriteCondition<'_>],
            _batch: BufferedWriteBatch,
        ) -> Result<bool, bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected write failure".to_owned(),
            ))
        }

        fn flush(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.0.flush()
        }

        fn arm_persist_fault(&self, fault: bitcoin_rs_storage::PersistFault) {
            self.0.arm_persist_fault(fault);
        }

        fn snapshot(
            &self,
        ) -> Result<Box<dyn bitcoin_rs_storage::KvSnapshot + '_>, bitcoin_rs_storage::StorageError>
        {
            self.0.snapshot()
        }

        fn multi_get(
            &self,
            cf: ColumnFamily,
            keys: &[&[u8]],
        ) -> Result<Vec<Option<bitcoin_rs_storage::Bytes>>, bitcoin_rs_storage::StorageError>
        {
            self.0.multi_get(cf, keys)
        }

        fn ingest_sorted(
            &self,
            _cf: ColumnFamily,
            _rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
            _scratch: &std::path::Path,
        ) -> Result<u64, bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected write failure".to_owned(),
            ))
        }

        fn delete_range(
            &self,
            _cf: ColumnFamily,
            _start: &[u8],
            _end: &[u8],
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected write failure".to_owned(),
            ))
        }

        fn checkpoint(
            &self,
            dir: &std::path::Path,
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.0.checkpoint(dir)
        }

        fn engine_cache_bytes(&self) -> u64 {
            self.0.engine_cache_bytes()
        }
    }

    #[test]
    fn rollback_deletes_nothing_when_the_write_fails() -> Result<(), crate::portable::TestError> {
        let dir = tempfile::tempdir()?;
        let candidate = rollback_fixture_block();
        let body = consensus_bytes(&candidate);

        {
            let store = Arc::new(RocksDbStore::open(dir.path())?);
            let mut writer = IndexWriter::open(store, 1)?;
            commit_block(&mut writer, 0, &body)?;
        }
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let before = stored_rows(&Indexer::new(Arc::clone(&store)))?;
        assert!(!before.is_empty(), "fixture must have rows to preserve");
        drop(store);

        let failing = Arc::new(FailingWriteStore(RocksDbStore::open(dir.path())?));
        let mut writer = IndexWriter::open(Arc::clone(&failing), 1)?;
        let outcome = commit_rollback_one(&mut writer, None, &body);
        assert!(outcome.is_err(), "a failing write must surface as an error");
        drop(writer);
        drop(failing);

        let reopened = Indexer::new(Arc::new(RocksDbStore::open(dir.path())?));
        assert_eq!(
            stored_rows(&reopened)?,
            before,
            "a failed rollback must leave every row in place"
        );
        Ok(())
    }

    #[test]
    fn a_stale_rollback_body_leaves_a_replacement_blocks_rows_alone()
    -> Result<(), crate::portable::TestError> {
        let (_dir, mut writer) = writer()?;
        let shared_script = vec![0x51];

        let mut old_block = block(vec![tx(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0xa1; 32])), 0),
            shared_script.clone(),
        )]);
        old_block.header.nonce = 1;
        let mut replacement = block(vec![tx(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0xb2; 32])), 0),
            shared_script,
        )]);
        replacement.header.nonce = 2;
        assert_ne!(
            old_block.block_hash(),
            replacement.block_hash(),
            "the two blocks must differ, or there is nothing to confuse"
        );

        let old_body = consensus_bytes(&old_block);
        commit_block(&mut writer, 0, &old_body)?;
        commit_rollback_one(&mut writer, None, &old_body)?;
        commit_block(&mut writer, 0, &consensus_bytes(&replacement))?;
        writer.indexer.store.flush()?;
        let after_replacement = stored_rows(writer.indexer())?;
        assert!(
            !after_replacement.is_empty(),
            "the replacement must have written rows"
        );

        assert!(
            commit_rollback_one(&mut writer, None, &old_body).is_err(),
            "rolling back the old body against the replacement watermark must fail"
        );
        writer.indexer.store.flush()?;

        assert_eq!(
            stored_rows(writer.indexer())?,
            after_replacement,
            "a stale rollback body must not touch the replacement's rows"
        );
        Ok(())
    }

    #[test]
    fn anchor_watermark_stamps_a_coverage_floor_that_reset_clears()
    -> Result<(), crate::portable::TestError> {
        let (_dir, writer) = writer()?;
        let anchor = IndexWatermark {
            height: 41,
            hash: [7u8; 32],
        };
        writer.anchor_watermark(crate::IndexCapabilities::TX_LOOKUP, anchor, 42)?;

        let snapshot = writer.indexer().snapshot()?;
        assert_eq!(
            snapshot.capability_floor(IndexCapability::TxLookup)?,
            42,
            "anchor records the first covered height"
        );
        assert_eq!(
            snapshot.capability_watermark(IndexCapability::TxLookup)?,
            Some(anchor)
        );
        assert_eq!(
            snapshot.capability_floor(IndexCapability::ScriptHistory)?,
            0,
            "unselected capabilities keep complete coverage"
        );
        drop(snapshot);

        writer.reset_capabilities(crate::IndexCapabilities::TX_LOOKUP)?;
        let snapshot = writer.indexer().snapshot()?;
        assert_eq!(
            snapshot.capability_floor(IndexCapability::TxLookup)?,
            0,
            "a reset rebuilds from genesis, so the floor clears"
        );
        Ok(())
    }

    fn writer() -> Result<(tempfile::TempDir, IndexWriter<RocksDbStore>), crate::portable::TestError>
    {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        Ok((dir, IndexWriter::open(store, 1)?))
    }

    fn stored_rows(
        indexer: &Indexer<RocksDbStore>,
    ) -> Result<StoredRows, crate::portable::TestError> {
        let mut rows = Vec::new();
        for cf in [
            ColumnFamily::TxDir,
            ColumnFamily::ScriptPost,
            ColumnFamily::SpendDir,
            ColumnFamily::ScriptLive,
            ColumnFamily::BlockHeaders,
        ] {
            for row in indexer.store.iter_prefix(cf, &[])? {
                let (key, _value) = row?;
                rows.push((cf, key));
            }
        }
        rows.sort_by(|left, right| {
            (left.0.name(), left.1.as_slice()).cmp(&(right.0.name(), right.1.as_slice()))
        });
        Ok(rows)
    }

    fn block(txs: Vec<Tx>) -> Block {
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txs,
        }
    }

    fn tx(previous_output: OutPoint, script_pubkey: Vec<u8>) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: script_pubkey.into(),
            }],
        }
    }

    fn spent_outpoint(label: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), vout)
    }

    fn tx_occurrences(first: u8, count: u8) -> Vec<crate::segment::import::TxOccurrence> {
        (0..count)
            .map(|i| crate::segment::import::TxOccurrence {
                txid: [first + i; 32],
                height: 1,
                block_hash: [0x77; 32],
                position: crate::types::TxPosition::new(u32::from(i) * 100, 100),
            })
            .collect()
    }

    fn tx_dir_rows(store: &RocksDbStore) -> Result<StoredRows, IndexError> {
        let snapshot = store.snapshot()?;
        snapshot
            .iter_prefix(ColumnFamily::TxDir, &[])?
            .map(|row| row.map(|(key, value)| (ColumnFamily::TxDir, [key, value].concat())))
            .collect::<Result<_, _>>()
            .map_err(IndexError::Storage)
    }

    // IDX-05
    #[test]
    fn restart_clears_a_staged_segment_and_keeps_the_published_one()
    -> Result<(), crate::portable::TestError> {
        let dir = tempfile::tempdir()?;
        let scratch = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let base = IndexWatermark {
            height: 1,
            hash: [0x77; 32],
        };
        let coverage = crate::segment::Coverage::new(0, base.height, base.hash);
        let published =
            crate::segment::import::tx_lookup_segment(tx_occurrences(0x10, 3), coverage, 0)?;
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let attachment = crate::writer::TxLookupAttachment {
            headers: &[],
            base,
            floor: 0,
            scratch: scratch.path(),
        };
        writer.attach_tx_lookup_segment(&published, &attachment)?;
        let published_rows = tx_dir_rows(&store)?;
        assert!(!published_rows.is_empty(), "the attach must publish rows");

        let staged =
            crate::segment::import::tx_lookup_segment(tx_occurrences(0x40, 2), coverage, 3)?;
        let pending = crate::segment::import::next_segment_id(store.as_ref())?;
        crate::segment::import::stage_segment(store.as_ref(), pending, &staged, scratch.path())?;
        assert!(
            tx_dir_rows(&store)?.len() > published_rows.len(),
            "the interrupted stage must leave rows on disk"
        );

        drop(writer);
        let reopened = IndexWriter::open(Arc::clone(&store), 2)?;
        assert_eq!(
            tx_dir_rows(&store)?,
            published_rows,
            "restart must clear the staged rows and leave the published segment unchanged"
        );
        let snapshot = reopened.indexer().snapshot()?;
        assert_eq!(
            snapshot.capability_watermark(IndexCapability::TxLookup)?,
            Some(base)
        );
        let bulk_dir = tempfile::tempdir()?;
        let bulk_store = RocksDbStore::open(bulk_dir.path())?;
        let block = bitcoin_rs_storage::committed_facts::CommittedBlock {
            height: 1,
            hash: [0x77; 32],
            parent_hash: [0; 32],
            header: [0; 80],
            txs: (0..3_u8)
                .map(|i| bitcoin_rs_storage::committed_facts::TxFacts {
                    txid: [0x10 + i; 32],
                    offset: u32::from(i) * 100,
                    len: 100,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                })
                .collect(),
        };
        crate::segment::bulk_builder::BulkSegmentBuilder::new(
            Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
            None,
            scratch.path().to_path_buf(),
        )
        .build_and_ingest(&bulk_store, 1, std::slice::from_ref(&block))
        .map_err(|error| std::io::Error::other(format!("bulk build: {error}")))?;
        assert_eq!(
            tx_dir_rows(&store)?,
            tx_dir_rows(&bulk_store)?,
            "the restored published segment equals a separate bulk build"
        );
        Ok(())
    }

    // PRJ-06, IDX-12
    #[test]
    fn a_spend_of_an_output_sealed_under_the_other_capability_preserves_its_identity()
    -> Result<(), crate::portable::TestError> {
        use crate::segment::format::{decode_spend_dir_key, decode_spend_dir_value};
        use bitcoin_rs_storage::committed_facts::{
            CommittedBlock, CreatedOutput, SpentPrevout, TxFacts,
        };

        let dir = tempfile::tempdir()?;
        let scratch = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let created = CommittedBlock {
            height: 1,
            hash: [1; 32],
            parent_hash: [0; 32],
            header: [0; 80],
            txs: vec![TxFacts {
                txid: [0xA1; 32],
                offset: 0,
                len: 100,
                inputs: Vec::new(),
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 5_000,
                    script: bitcoin_rs_storage::FactsScript::copy_from_slice(b"\x51creator"),
                }],
            }],
        };
        let spending = CommittedBlock {
            height: 2,
            hash: [2; 32],
            parent_hash: [1; 32],
            header: [0; 80],
            txs: vec![TxFacts {
                txid: [0xB2; 32],
                offset: 0,
                len: 100,
                inputs: vec![SpentPrevout {
                    txid: [0xA1; 32],
                    vout: 0,
                    value: 5_000,
                    script: bitcoin_rs_storage::FactsScript::copy_from_slice(b"\x51creator"),
                    height: 1,
                    coinbase: false,
                }],
                outputs: Vec::new(),
            }],
        };

        let spending_ordinal = u32::try_from(created.txs.len())?;
        let mut state = crate::segment::TailWriterState::new();
        let mut batch = store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            crate::types::INDEX_FORMAT_VERSION_KEY,
            &crate::types::INDEX_FORMAT_VERSION_VALUE,
        );
        crate::segment::append_tail_block(&mut batch, &created, &mut state)?;
        store.write_durable(batch)?;
        crate::segment::seal_tail_generation(
            store.as_ref(),
            1,
            1,
            crate::IndexCapabilities::SCRIPT_HISTORY,
            scratch.path(),
        )?;

        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let mut tail = writer.tail_for(None)?;
        let mut batch = store.new_batch();
        let prepared = PreparedTail::for_capabilities(
            &spending,
            crate::IndexCapabilities::HISTORICAL.with_compact_filters(true),
        );
        writer.append_forward_tail(&mut tail, &[(spending, prepared)], &mut batch)?;
        store.write_durable(batch)?;

        let snapshot = store.snapshot()?;
        let spends: Vec<_> = snapshot
            .iter_prefix(ColumnFamily::SpendDir, &0_u64.to_be_bytes())?
            .collect::<Result<_, _>>()?;
        assert_eq!(
            spends.len(),
            1,
            "the cross-capability spend writes one spend row"
        );
        assert_eq!(
            decode_spend_dir_key(&spends[0].0),
            Some((0, [0xA1; 32], 0, 2))
        );
        assert_eq!(
            decode_spend_dir_value(&spends[0].1),
            Some(spending_ordinal),
            "the spender follows every transaction in the sealed creation block"
        );
        Ok(())
    }

    // IDX-02
    #[test]
    fn spend_event_codec_preserves_full_identity_and_rejects_noncanonical_lengths() {
        use crate::segment::format::{
            decode_spend_dir_key, decode_spend_dir_value, encode_spend_dir_key,
            encode_spend_dir_value, spend_dir_outpoint_prefix,
        };

        let key = encode_spend_dir_key(7, &[0xA5; 32], u32::MAX, 42);
        assert_eq!(
            decode_spend_dir_key(&key),
            Some((7, [0xA5; 32], u32::MAX, 42))
        );
        assert_eq!(
            &key[..44],
            &spend_dir_outpoint_prefix(7, &[0xA5; 32], u32::MAX)
        );
        assert_ne!(key, encode_spend_dir_key(7, &[0xA5; 32], u32::MAX, 43));
        assert_eq!(decode_spend_dir_key(&key[..47]), None);
        let mut extended = key.to_vec();
        extended.push(0);
        assert_eq!(decode_spend_dir_key(&extended), None);

        let value = encode_spend_dir_value(u32::MAX);
        assert_eq!(decode_spend_dir_value(&value), Some(u32::MAX));
        assert_eq!(decode_spend_dir_value(&value[..3]), None);
        assert_eq!(decode_spend_dir_value(&[0; 5]), None);
    }
}
