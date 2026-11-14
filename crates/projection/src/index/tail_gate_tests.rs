use super::IndexCapabilities;
use super::IndexCapability;
use super::IndexWriter;
use crate::segment::tail::FILTER_BUILDS;
use crate::segment::tail::SCRIPT_HASH_BUILDS;
use bitcoin_rs_storage::Bytes;
use bitcoin_rs_storage::CommittedBlock;
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_storage::RocksDbStore;
use bitcoin_rs_storage::committed_facts::CreatedOutput;
use bitcoin_rs_storage::committed_facts::SpentPrevout;
use bitcoin_rs_storage::committed_facts::TxFacts;
use std::sync::Arc;

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

// PRJ-09
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

// PRJ-05
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
    crate::segment::seal_tail_generation(store.as_ref(), 1, 1, caps, scratch.path())?;
    drop(writer);
    let _writer = IndexWriter::open(std::sync::Arc::clone(&store), 1)?;
    let snapshot = store.snapshot()?;
    let sealed = crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::TxLookup)?;
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
    let key = crate::segment::tail::log_key_for(0);
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
