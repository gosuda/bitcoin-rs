use super::IndexCapabilities;
use super::IndexCapability;
use super::IndexWriter;
use crate::segment::tail::FILTER_BUILDS;
use crate::segment::tail::SCRIPT_HASH_BUILDS;
use crate::segment::tail::TX_BLOCK_HASH_SCANS;
use bitcoin_rs_storage::Bytes;
use bitcoin_rs_storage::CommittedBlock;
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_storage::RocksDbStore;
use bitcoin_rs_storage::committed_facts::CreatedOutput;
use bitcoin_rs_storage::committed_facts::SpentPrevout;
use bitcoin_rs_storage::committed_facts::TxFacts;
use std::sync::Arc;
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
                script: Bytes::from_static(&[0x51]),
                height: 0,
                coinbase: false,
            }],
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 4,
                script: Bytes::from_static(&[0x51]),
            }],
        }],
    }
}

fn block_with_spends() -> CommittedBlock {
    block_with_spends_at(1, 3, [4; 32])
}

fn open_writer()
-> Result<(tempfile::TempDir, IndexWriter<RocksDbStore>), Box<dyn std::error::Error>> {
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
fn disabled_compact_filters_skip_filter_build() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, writer) = open_writer()?;
    let block = block_with_spends();
    reset_counts();
    let prepared = writer.prepare_block_from_facts(IndexCapabilities::HISTORICAL, block.clone())?;
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
fn disabled_script_history_skips_script_hashes() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, writer) = open_writer()?;
    let block = block_with_spends();
    reset_counts();
    let caps = IndexCapabilities::TX_LOOKUP.insert(IndexCapability::CompactFilters);
    let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
    assert_eq!(FILTER_BUILDS.with(std::cell::Cell::get), 1);
    assert_eq!(SCRIPT_HASH_BUILDS.with(std::cell::Cell::get), 0);
    assert!(
        prepared
            .tail
            .inputs
            .iter()
            .all(|tx| tx.iter().all(|hash| hash.is_none()))
    );
    assert!(
        prepared
            .tail
            .outputs
            .iter()
            .all(|tx| tx.iter().all(|hash| hash.is_none()))
    );
    Ok(())
}

// PRJ-03
#[test]
fn lookup_and_history_disabled_skip_script_hashes() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, writer) = open_writer()?;
    let block = block_with_spends();
    reset_counts();
    let prepared =
        writer.prepare_block_from_facts(IndexCapabilities::COMPACT_FILTERS, block.clone())?;
    assert_eq!(FILTER_BUILDS.with(std::cell::Cell::get), 1);
    assert_eq!(SCRIPT_HASH_BUILDS.with(std::cell::Cell::get), 0);
    assert!(
        prepared
            .tail
            .inputs
            .iter()
            .all(|tx| tx.iter().all(|hash| hash.is_none()))
    );
    Ok(())
}

// PRJ-03
#[test]
fn all_enabled_matches_bulk_builder_rows() -> Result<(), Box<dyn std::error::Error>> {
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
fn disabled_compact_filters_seal_writes_no_filter_rows() -> Result<(), Box<dyn std::error::Error>> {
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
    let sealed = crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::TxLookup)?;
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].coverage.first_height, 0);
    assert_eq!(sealed[0].coverage.last_height, 1);
    assert_eq!(sealed[0].coverage.last_hash, blocks[1].hash);
    Ok(())
}

#[test]
fn compact_filters_only_seal_and_reopen_keep_coverage() -> Result<(), Box<dyn std::error::Error>> {
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
fn seal_and_open_skip_scans_when_hashes_known() -> Result<(), Box<dyn std::error::Error>> {
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
    TX_BLOCK_HASH_SCANS.with(|scans| scans.set(0));
    crate::segment::seal_tail_generation(store.as_ref(), 1, 1, caps, scratch.path())?;
    assert_eq!(TX_BLOCK_HASH_SCANS.with(std::cell::Cell::get), 0);
    drop(writer);
    TX_BLOCK_HASH_SCANS.with(|scans| scans.set(0));
    let _writer = IndexWriter::open(std::sync::Arc::clone(&store), 1)?;
    assert_eq!(TX_BLOCK_HASH_SCANS.with(std::cell::Cell::get), 0);
    Ok(())
}
