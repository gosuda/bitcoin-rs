use std::collections::HashMap;
use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{Hash256, encode};
use bitcoin_rs_projection::types::{ScriptHash, ScriptHashRow, TxPosition};
use bitcoin_rs_projection::{
    ConsumerCursorUpdate, IndexCapabilities, IndexError, IndexReader, IndexWatermark, IndexWriter,
    Indexer, PreparedBatch, PreparedBatchLimits, SpentCoin, SpentCoins,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit};

use crate::support::TestError;
use crate::support::common::MemoryStore;

const BLOCKS: u32 = 8;
const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
    max_rows: 100_000,
    max_bytes: 64 << 20,
};

fn script_for(seed: u32) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.push(0x00);
    script.push(0x14);
    script.extend_from_slice(&[0x22; 20]);
    script[2] = u8::try_from(seed % 251).unwrap_or(0);
    script[3] = u8::try_from((seed / 251) % 251).unwrap_or(0);
    script
}

#[derive(Default)]
struct TestScripts {
    by_txid: HashMap<[u8; 32], Vec<u8>>,
}

impl SpentCoins for TestScripts {
    fn spent_coin(&self, txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
        self.by_txid.get(txid).map(|script| SpentCoin {
            script,
            value: 0,
            height: 0,
            coinbase: false,
        })
    }
}

struct TestChain {
    blocks: Vec<Vec<u8>>,
    hashes: Vec<Hash256>,
    coinbase_txids: Vec<[u8; 32]>,
    spend_txids: Vec<[u8; 32]>,
    scripts: TestScripts,
}

fn build_test_chain(blocks_count: u32) -> TestChain {
    let count = usize::try_from(blocks_count).unwrap_or(0);
    let mut blocks = Vec::with_capacity(count);
    let mut hashes = Vec::with_capacity(count);
    let mut coinbase_txids = Vec::with_capacity(count);
    let mut spend_txids = Vec::with_capacity(count);
    let mut scripts = TestScripts::default();
    let mut prev_hash = Hash256::from_le_bytes(&[0; 32]);

    for height in 0..blocks_count {
        let coinbase_script = script_for(height);
        let mut coinbase = Vec::new();
        coinbase.extend_from_slice(&1_u32.to_le_bytes());
        coinbase.push(0x01);
        coinbase.extend_from_slice(&[0_u8; 32]);
        coinbase.extend_from_slice(&u32::MAX.to_le_bytes());
        coinbase.push(0x02);
        coinbase.extend_from_slice(&[u8::try_from(height % 251).unwrap_or(0), 0xAA]);
        coinbase.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
        coinbase.push(0x01);
        coinbase.extend_from_slice(&500_000_000_u64.to_le_bytes());
        coinbase.push(u8::try_from(coinbase_script.len()).unwrap_or(0));
        coinbase.extend_from_slice(&coinbase_script);
        coinbase.extend_from_slice(&0_u32.to_le_bytes());
        let coinbase_txid = encode::double_sha256(&coinbase);
        coinbase_txids.push(coinbase_txid.to_le_bytes());
        scripts
            .by_txid
            .insert(coinbase_txid.to_le_bytes(), coinbase_script.clone());

        let mut spend = Vec::new();
        if height > 0 {
            let spend_script = script_for(2_000 + height);
            spend.extend_from_slice(&1_u32.to_le_bytes());
            spend.push(0x01);
            spend.extend_from_slice(
                &coinbase_txids[usize::try_from(height.saturating_sub(1)).unwrap_or(0)],
            );
            spend.extend_from_slice(&0_u32.to_le_bytes());
            spend.push(0x00);
            spend.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
            spend.push(0x01);
            spend.extend_from_slice(&1_000_u64.to_le_bytes());
            spend.push(u8::try_from(spend_script.len()).unwrap_or(0));
            spend.extend_from_slice(&spend_script);
            spend.extend_from_slice(&0_u32.to_le_bytes());
            spend_txids.push(encode::double_sha256(&spend).to_le_bytes());
        }

        let mut body = Vec::new();
        body.extend_from_slice(&1_i32.to_le_bytes());
        body.extend_from_slice(&prev_hash.to_le_bytes());
        let merkle_root = if height == 0 {
            coinbase_txid
        } else {
            encode::double_sha256(
                &[
                    coinbase_txid.to_le_bytes().as_slice(),
                    spend_txids.last().unwrap_or(&[0; 32]),
                ]
                .concat(),
            )
        };
        body.extend_from_slice(&merkle_root.to_le_bytes());
        body.extend_from_slice(&1_234_567_u32.to_le_bytes());
        body.extend_from_slice(&0x1d00_ffff_u32.to_le_bytes());
        body.extend_from_slice(&height.to_le_bytes());
        let tx_count = if height == 0 { 1 } else { 2 };
        body.push(tx_count);
        body.extend_from_slice(&coinbase);
        if height > 0 {
            body.extend_from_slice(&spend);
        }
        let hash = encode::double_sha256(&body[..80]);
        prev_hash = hash;
        hashes.push(hash);
        blocks.push(body);
    }

    TestChain {
        blocks,
        hashes,
        coinbase_txids,
        spend_txids,
        scripts,
    }
}

fn commit_test_chain<S: KvStore + 'static>(
    writer: &mut IndexWriter<S>,
    chain: &TestChain,
) -> Result<Vec<IndexWatermark>, IndexError> {
    let mut watermarks = Vec::with_capacity(chain.blocks.len());
    for (height, body) in chain.blocks.iter().enumerate() {
        let hash = chain.hashes[height];
        let prepared = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            u32::try_from(height).unwrap_or(0),
            hash.to_le_bytes(),
            body,
            &chain.scripts,
        )?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(prepared).is_ok());
        watermarks.push(writer.commit_forward(batch)?);
    }
    Ok(watermarks)
}

#[test]
fn wrong_format_version_refuses_open() -> Result<(), TestError> {
    for wrong_version in [0_u32, 1, 5, 6, 7, u32::MAX] {
        let store = Arc::new(MemoryStore::default());
        store.put(
            ColumnFamily::UtxoMeta,
            &[0x00, b'V'],
            &wrong_version.to_le_bytes(),
        )?;
        let result = IndexWriter::open(Arc::clone(&store), 1);
        let Err(err) = result else {
            return Err(TestError::Message(format!(
                "version {wrong_version} must refuse open"
            )));
        };
        assert!(
            matches!(
                err,
                IndexError::UnsupportedTxIndexFormatVersion { version } if version == wrong_version
            ),
            "version {wrong_version} must refuse open with UnsupportedTxIndexFormatVersion"
        );
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("bitcoin-rs-storage-convert rebuild-index"),
            "version {wrong_version} error must contain rebuild-index guidance: {err_msg}"
        );
    }
    Ok(())
}

#[test]
fn legacy_cursorless_index_without_version_marker_refuses_open() -> Result<(), TestError> {
    let store = Arc::new(MemoryStore::default());
    store.put(ColumnFamily::Funding, &[0xAA; 12], &[0xBB; 71])?;
    let result = IndexWriter::open(Arc::clone(&store), 1);
    let Err(err) = result else {
        return Err(TestError::Message(
            "unversioned store must refuse open".into(),
        ));
    };
    assert!(
        matches!(err, IndexError::LegacyCursorlessIndex),
        "unversioned store with existing rows must refuse open with LegacyCursorlessIndex"
    );
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("bitcoin-rs-storage-convert rebuild-index"),
        "legacy unversioned store error must contain rebuild-index guidance: {err_msg}"
    );
    Ok(())
}

#[test]
fn marker_in_idx_meta_is_not_accepted_as_format_marker() -> Result<(), TestError> {
    let store = Arc::new(MemoryStore::default());
    store.put(ColumnFamily::IdxMeta, &[0x00, b'V'], &7_u32.to_le_bytes())?;
    let result = IndexWriter::open(Arc::clone(&store), 1);
    let Err(err) = result else {
        return Err(TestError::Message(
            "marker in IdxMeta must refuse open".into(),
        ));
    };
    assert!(
        matches!(err, IndexError::LegacyCursorlessIndex),
        "marker in IdxMeta must not be accepted; format marker must reside in UtxoMeta"
    );
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("bitcoin-rs-storage-convert rebuild-index"),
        "error must contain rebuild-index guidance: {err_msg}"
    );
    Ok(())
}

#[test]
fn row_ordering_invariants_hold() {
    let script = ScriptHash::from_script_bytes(&[1, 2, 3]);
    let mut previous_be = 0_u32;
    for height in 1..1_000_u32 {
        let row = ScriptHashRow::row(script, height);
        assert_eq!(row.height(), height);
        let num = u32::from_be_bytes(row.height);
        assert!(
            num > previous_be,
            "big endian height must strictly increase as height increases"
        );
        previous_be = num;
    }

    let p1 = TxPosition::new(100, 50);
    let p2 = TxPosition::new(100, 60);
    let p3 = TxPosition::new(200, 10);
    assert!(p1 < p2, "positions at same offset order by length");
    assert!(
        p2 < p3,
        "positions at earlier offset order before later offset"
    );
}

#[test]
fn query_pagination_limits_and_boundaries() -> Result<(), TestError> {
    let chain = build_test_chain(BLOCKS);
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    commit_test_chain(&mut writer, &chain)?;
    assert_eq!(
        chain.coinbase_txids.len(),
        usize::try_from(BLOCKS).unwrap_or(0)
    );
    assert_eq!(
        chain.spend_txids.len(),
        usize::try_from(BLOCKS - 1).unwrap_or(0)
    );
    let indexer = Indexer::new(Arc::clone(&store));
    let snapshot = indexer.snapshot()?;
    let script = ScriptHash::from_script_bytes(&script_for(0));

    let scan_zero = snapshot.funding_rows_from(
        script,
        u32::MAX,
        PrefixScanLimit {
            max_rows: 0,
            max_bytes: 64 << 20,
        },
    )?;
    assert_eq!(scan_zero.rows.len(), 0, "limit 0 returns zero rows");

    let scan_one = snapshot.funding_rows_from(
        script,
        u32::MAX,
        PrefixScanLimit {
            max_rows: 1,
            max_bytes: 64 << 20,
        },
    )?;
    assert_eq!(scan_one.rows.len(), 1, "limit 1 returns exactly one row");

    let scan_all = snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?;
    assert!(
        scan_all.rows.len() >= 2,
        "script has funding and spending occurrences"
    );

    let foreign_script = ScriptHash::from_script_bytes(&script_for(999));
    let scan_foreign = snapshot.funding_rows_from(foreign_script, u32::MAX, SCAN_ALL)?;
    assert_eq!(
        scan_foreign.rows.len(),
        0,
        "foreign script returns empty scan"
    );

    Ok(())
}

#[test]
fn rollback_and_catchup_crash_window_step_failures() -> Result<(), TestError> {
    let chain = build_test_chain(BLOCKS);
    let store = Arc::new(MemoryStore::default());

    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let first = writer.prepare_block_with_spent_scripts(
        IndexCapabilities::HISTORICAL,
        0,
        chain.hashes[0].to_le_bytes(),
        &chain.blocks[0],
        &chain.scripts,
    )?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    assert!(batch.try_push(first).is_ok());
    writer.commit_forward(batch)?;
    assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

    let corrupt_body = vec![0xFF; 20];
    let bad_prepare = writer.prepare_block_with_spent_scripts(
        IndexCapabilities::HISTORICAL,
        1,
        chain.hashes[1].to_le_bytes(),
        &corrupt_body,
        &chain.scripts,
    );
    assert!(
        matches!(bad_prepare, Err(IndexError::BlockParse(_))),
        "corrupt block body fails prepare"
    );
    assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

    drop(writer);
    let mut writer = IndexWriter::open(Arc::clone(&store), 2)?;
    assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

    let second = writer.prepare_block_with_spent_scripts(
        IndexCapabilities::HISTORICAL,
        1,
        chain.hashes[1].to_le_bytes(),
        &chain.blocks[1],
        &chain.scripts,
    )?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    assert!(batch.try_push(second).is_ok());
    store.arm_fenced_write_failure();
    assert!(writer.commit_forward(batch).is_err());
    assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

    drop(writer);
    let mut writer = IndexWriter::open(Arc::clone(&store), 3)?;
    assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

    let second = writer.prepare_block_with_spent_scripts(
        IndexCapabilities::HISTORICAL,
        1,
        chain.hashes[1].to_le_bytes(),
        &chain.blocks[1],
        &chain.scripts,
    )?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    assert!(batch.try_push(second).is_ok());
    writer.commit_forward(batch)?;
    assert_eq!(writer.watermark()?.map(|w| w.height), Some(1));

    let (fence, _) = writer.fenced_watermarks()?;
    let prev_watermark = IndexWatermark {
        height: 0,
        hash: chain.hashes[0].to_le_bytes(),
    };
    store.arm_fenced_write_failure();
    let rollback_result = writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
        fence,
        IndexCapabilities::HISTORICAL,
        Some(prev_watermark),
        &chain.blocks[1],
        ConsumerCursorUpdate::Keep,
        &chain.scripts,
    );
    assert!(rollback_result.is_err(), "injected rollback write failure");
    assert_eq!(writer.watermark()?.map(|w| w.height), Some(1));

    drop(writer);
    let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
    assert_eq!(writer.watermark()?.map(|w| w.height), Some(1));

    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
        fence,
        IndexCapabilities::HISTORICAL,
        Some(prev_watermark),
        &chain.blocks[1],
        ConsumerCursorUpdate::Keep,
        &chain.scripts,
    )?;
    assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

    drop(writer);
    let writer = IndexWriter::open(Arc::clone(&store), 5)?;
    assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

    Ok(())
}
